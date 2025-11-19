use anyhow::Result;
use clap::Parser;
use std::{cmp::{max}, sync::Arc, time::Duration};
use tracing::{debug, error, info, warn};
use rustls_pki_types::ServerName;

pub mod packetutil;
pub mod utils;
pub mod quicutil;
pub mod stats;
pub mod tunutil;
use stats::Stats;

const BUILD_BRANCH: &str = env!("BUILD_BRANCH");
const BUILD_TIME: &str = env!("BUILD_TIME");
const BUILD_HOST: &str = env!("BUILD_HOST");

#[derive(Parser)]
#[command(name = "tcpclient")]
#[command(about = "TCP client with separate control and data planes")]
pub struct TcpClientCli {
    /// Server hostname or IP for control plane (used for SNI)
    #[arg(long)]
    server: String,
    
    /// Server port for control plane (TLS) (e.g., 4235)
    #[arg(long, default_value = "1107")]
    port: u16,
    
    /// TUN device name
    #[arg(long, default_value = "rustvpn")]
    device: String,
    
    /// CA bundle file (PEM format) for validating server certificates
    #[arg(long, default_value = "ca.pem")]
    ca_bundle: String,
    
    /// Client certificate file (PEM format)
    #[arg(long, default_value = "client.pem")]
    client_cert: String,
    
    /// Client private key file (PEM format)
    #[arg(long, default_value = "client.key")]
    client_key: String,
    
    /// Optional: Expected peer (server) certificate common name (CN)
    #[arg(long)]
    peer_cn: Option<String>,
    
    /// Number of bidirectional streams to use (default: 30)
    #[arg(long, default_value = "5")]
    stream_count: usize,
    
    /// MTU for TUN device (100-1500, default: 1500)
    #[arg(long, default_value = "1500")]
    mtu: u16,
    
    /// IPv4 address with CIDR to assign to TUN device (e.g., 192.168.3.2/24)
    #[arg(long)]
    ipv4: Option<String>,
    
    /// IPv6 address with prefix length to assign to TUN device (e.g., 2001:db8::1/64)
    #[arg(long)]
    ipv6: Option<String>,
    
    /// Local routes to set up (CIDR format, can be specified multiple times)
    #[arg(long)]
    route: Vec<String>,

    #[arg(long, value_parser = clap::value_parser!(u64).range(10..))]
    speed_limit_in_mbps: Option<u64>,
}

async fn run_client_inner(
    child_context: tokio_tree_context::Context,
    stats: Arc<Stats>,
    server: String,
    port: u16,
    tun: Arc<tun_rs::AsyncDevice>,
    ca_bundle: String,
    client_cert: String,
    client_key: String,
    peer_cn: Option<String>,
    stream_count: usize,
    mtu: u16,
    quota: Option<Arc<precise_rate_limiter::FastQuota>>,
) -> Result<()> {
    let mut child_context = child_context;

    // Build TLS connector for control plane
    debug!("Building TLS connector for control plane");
    let connector = utils::build_tls_connector(&ca_bundle, &client_cert, &client_key)?;
    let server_clone = server.clone();
    let server_name = ServerName::try_from(server_clone).unwrap();
    let (mut tls_stream, local_addr) = utils::connect_tls_for_control_plane(
        server.clone(),
        port,
        server_name.clone(),
        connector.clone(),
        peer_cn.clone(),
    ).await?;
    info!("Control plane connection established to {}:{} with local address {}", server, port, local_addr);

    // Config exchange on control plane
    info!("Performing config exchange with server");
    let my_token = utils::generate_token();
    info!("generated my token: {}", my_token);
    let params_map = utils::do_config_exchange_client_tcp(
        &mut tls_stream,
        BUILD_BRANCH,
        &my_token,
        stream_count,
        mtu,
    ).await?;
    info!("Client received server config: {:?}", params_map);
    let server_token = params_map.get(utils::PARAM_TOKEN).unwrap();
    info!("Server token: {}", server_token);
    // Validate config exchange
    utils::validate_config_exchange(
        BUILD_BRANCH,
        stream_count,
        mtu,
        &params_map,
    )?;
    
    info!("Client intended number_of_streams={}", stream_count);
    info!("Config validation passed, negotiated number_of_streams={}", stream_count);
    
    // Now connect to data plane
    debug!("Connecting {} streams to data plane", stream_count);
    let connect_context = child_context.new_child_context();
    let raw_data_streams = utils::must_connect_n_data_connections_timeout(
        connect_context,
        connector.clone(),
        server,
        port,
        server_name,
        peer_cn.clone(),
        stream_count,
        &my_token,
        &server_token,
        Duration::from_secs(max(5, 2 * stream_count as u64)),
    ).await?;
    if raw_data_streams.is_empty() {
        error!("Failed to connect any data plane streams");
        anyhow::bail!("Failed to connect any data plane streams");
    }
    
    if raw_data_streams.len() < stream_count {
        warn!("Only connected {} out of {} data plane streams", raw_data_streams.len(), stream_count);
    } else {
        info!("Successfully connected all {} data plane streams", raw_data_streams.len());
    }
    
    let data_streams_inner1 = raw_data_streams.into_iter()
        .map(|(stream, _)| stream)
        .map(|stream| tokio::io::split(stream))
        .collect();

    // Start data forwarding
    let child_context_inner = child_context.new_child_context();
    let jh = child_context.spawn(utils::run_pipes_generic(
        child_context_inner,
        stats.clone(),
        tun.clone(),
        data_streams_inner1,
        mtu,
        quota.clone(),
    ));
    let result = jh.await;
    if let Err(e) = result {
        error!("Error running pipes: {}", e);
        return Err(e.into());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Install crypto provider before any Rustls operations
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|e| anyhow::anyhow!("Failed to install default crypto provider: {:?}", e))?;
    
    info!("TCP Client starting: build_id={}, time={}, host={}", BUILD_BRANCH, BUILD_TIME, BUILD_HOST);
    let cli = TcpClientCli::parse();
    validate_client_args(&cli)?;
    // Handle data plane (blocking)
    let speed_quota = if let Some(speed_limit_in_mbps) = cli.speed_limit_in_mbps {
        let quota =precise_rate_limiter::FastQuota::new(
            (2 * speed_limit_in_mbps * 1000 * 1000) as usize, 
            (speed_limit_in_mbps * 1000 * 10) as usize,
        Duration::from_millis(10),
        );
        info!("Speed quota: {:?} mbps for sending", speed_limit_in_mbps);
        Some(quota)
    } else {
        None
    };
    run_client(
        cli.server,
        cli.port,
        cli.device, 
        cli.ca_bundle, 
        cli.client_cert, 
        cli.client_key, 
        cli.peer_cn,
        cli.stream_count,
        cli.mtu,
        cli.ipv4,
        cli.ipv6,
        cli.route,
        speed_quota.clone(),
    ).await?;
    
    Ok(())
}

pub async fn run_client(
    server: String,
    port: u16,
    device_name: String,
    ca_bundle: String,
    client_cert: String,
    client_key: String,
    peer_cn: Option<String>,
    stream_count: usize,
    mtu: u16,
    ipv4: Option<String>,
    ipv6: Option<String>,
    local_routes: Vec<String>,
    quota: Option<Arc<precise_rate_limiter::FastQuota>>,
) -> Result<()> {
    let mut tree_context = tokio_tree_context::Context::new();
    let stats = Arc::new(Stats::new());
    stats::start_stats_reporting(&mut tree_context, stats.clone()).await;
    
    let tun = tunutil::create_tun(device_name, mtu, ipv4, ipv6, local_routes).await?;
    let tun = Arc::new(tun);
    // Create TUN device once (never recreated on reconnect)
    
    // Main reconnection loop - TUN device and routes are never touched
    loop {
        let child_context = tree_context.new_child_context();
        let result = run_client_inner(
            child_context,
            stats.clone(),
            server.clone(),
            port,
            tun.clone(),
            ca_bundle.clone(), 
            client_cert.clone(), 
            client_key.clone(), 
            peer_cn.clone(), 
            stream_count,
            mtu,
            quota.clone(),
        ).await;
        if let Err(e) = result {
            error!("Error running client: {}", e);
        } else {
            debug!("Client loop iteration completed successfully");
        }
        info!("Sleeping for 5 seconds before reconnecting...");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

pub fn validate_client_args(args: &TcpClientCli) -> Result<(), anyhow::Error> {
    debug!("Validating client arguments");
    utils::validate_ipv4_cidr(args.ipv4.clone())?;
    utils::validate_ipv6_cidr(args.ipv6.clone())?;
    debug!("Client arguments validated");
    Ok(())
}

