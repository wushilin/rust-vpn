use anyhow::{Context, Result};
use clap::Parser;
use std::{sync::Arc, time::Duration};
use tracing::{debug, error, info, warn};
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
#[command(name = "client")]
#[command(about = "QUIC client (data plane only)")]
pub struct ClientCli {
    /// Server hostname or IP (used for SNI)
    #[arg(long)]
    server: String,
    
    /// Server port (e.g., 4234)
    #[arg(long, default_value = "1105")]
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
    
    /// Number of bidirectional streams to use (default: 5)
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

// quicutil provides certificate helpers and config builders

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
    quota: Option<Arc<precise_rate_limiter::Quota>>,
) -> Result<()> {
    let mut child_context = child_context;
    // Resolve remote address
    let mut addrs = tokio::net::lookup_host((server.as_str(), port)).await
        .with_context(|| format!("Failed to resolve {}:{}", server, port))?;
    let remote_addr = addrs.next().context("No addresses found for server")?;
    
    let transport_config = quicutil::get_client_transport_config()?;

    let client_config = quicutil::build_client_config(
        &ca_bundle,
        &client_cert,
        &client_key,
        transport_config,
    )?;

    // Create endpoint and set config
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    
    info!("Connecting to data plane at {} (server={})", remote_addr, server);
    
    // Connect to data plane server
    let connection = endpoint
        .connect(remote_addr, &server)
        .with_context(|| format!("Failed to start connecting to {} (SNI hostname: {})", remote_addr, server))?
        .await
        .with_context(|| format!("Failed to connect to {} (SNI hostname: {}). This may indicate certificate validation failure - ensure the server certificate has a SAN entry matching '{}' (e.g., *.local should match {}.local)", remote_addr, server, server, server))?;
    
    debug!("Connection handshake completed");
    let (keep_alive_send, keep_alive_recv) = connection.open_bi().await?;
    child_context.spawn(utils::keep_alive(keep_alive_send, keep_alive_recv));
    info!("Data plane connection established to {} (server={})", remote_addr, server);
    
    // Validate peer CN if required
    if let Some(ref expected_cn) = peer_cn {
        debug!("Validating peer CN, expected: {}", expected_cn);
        quicutil::validate_peer_cn(&connection, expected_cn)
            .context("Peer CN validation failed")?;
        info!("Peer CN validated: {}", expected_cn);
    }

    // Config exchange (no routes - routes are local only)
    debug!("Performing config exchange with server");
    let token = utils::generate_token();
    let params_map = utils::do_config_exchange_client(&connection, &token, BUILD_BRANCH, stream_count, mtu).await?;
    debug!("Client received server config: {:?}", params_map);
    
    // Validate config exchange
    utils::validate_config_exchange(
        BUILD_BRANCH,
        stream_count,
        mtu,
        &params_map,
    )?;
    
    debug!("Client intended number_of_streams={}", stream_count);
    info!("Config validation passed, negotiated number_of_streams={}", stream_count);
    let streams = utils::open_bidi_streams_with_handshake(
        &connection,
        stream_count,
        utils::handshake_client_adapter,
    ).await?;
    
    if streams.is_empty() {
        error!("Failed to open any streams");
        anyhow::bail!("Failed to open any streams");
    }
    
    if streams.len() < stream_count {
        warn!("Only opened {} out of {} streams", streams.len(), stream_count);
    } else {
        info!("Successfully opened all {} streams", streams.len());
    }
    // Start two tasks for bidirectional forwarding
    let child_context_inner = child_context.new_child_context();
    let jh = child_context.spawn(utils::run_pipes_generic(
        child_context_inner,
        stats.clone(),
        tun.clone(),
        streams,
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

// Control plane removed

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
    
    info!("Client starting: build_id={}, time={}, host={}", BUILD_BRANCH, BUILD_TIME, BUILD_HOST);
    let cli = ClientCli::parse();
    validate_client_args(&cli)?;
    // Handle data plane (blocking)

    let speed_quota = if let Some(speed_limit_in_mbps) = cli.speed_limit_in_mbps {
        let quota =precise_rate_limiter::Quota::new(
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
        speed_quota,
    ).await?;
    
    Ok(())
}

// client config building is provided by quicutil

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
    quota: Option<Arc<precise_rate_limiter::Quota>>,
) -> Result<()> {
    let mut tree_context = tokio_tree_context::Context::new();
    let stats = Arc::new(Stats::new());
    stats::start_stats_reporting(&mut tree_context, stats.clone()).await;
    
    let tun = tunutil::create_tun(device_name, mtu, ipv4, ipv6, local_routes).await?;
    // Create TUN device once (never recreated on reconnect)
    
    let tun = Arc::new(tun);
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


pub fn validate_client_args(args: &ClientCli) -> Result<(), anyhow::Error> {
    debug!("Validating client arguments");
    utils::validate_ipv4_cidr(args.ipv4.clone())?;
    utils::validate_ipv6_cidr(args.ipv6.clone())?;
    debug!("Client arguments validated");
    Ok(())
}