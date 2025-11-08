use anyhow::Result;
use chrono::Local;
use clap::Parser;
use std::time::Duration;
use std::{process::exit, sync::Arc};
use tracing::{debug, error, info, warn};
pub mod packetutil;
pub mod quicutil;
pub mod stats;
pub mod tunutil;
pub mod utils;
use stats::Stats;

const BUILD_BRANCH: &str = env!("BUILD_BRANCH");
const BUILD_TIME: &str = env!("BUILD_TIME");
const BUILD_HOST: &str = env!("BUILD_HOST");

#[derive(Parser)]
#[command(name = "server")]
#[command(about = "QUIC VPN server")]
pub struct ServerCli {
    /// Bind address (e.g., 0.0.0.0)
    #[arg(short, long, default_value = "0.0.0.0")]
    bind_address: String,

    /// Bind port (e.g., 4234)
    #[arg(long, default_value = "1105")]
    port: u16,

    /// TUN device name
    #[arg(long, default_value = "rustvpn")]
    device: String,

    /// CA bundle file (PEM format) for validating client certificates
    #[arg(long, default_value = "ca.pem")]
    ca_bundle: String,

    /// Server certificate file (PEM format)
    #[arg(long, default_value = "server.pem")]
    server_cert: String,

    /// Server private key file (PEM format)
    #[arg(long, default_value = "server.key")]
    server_key: String,

    /// Optional: Expected peer (client) certificate common name (CN)
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

    #[arg(long)]
    speed_limit_in_mbps: Option<u64>,
}

async fn run_server_indefinitely(
    tree_context: tokio_tree_context::Context,
    stats: Arc<Stats>,
    bind_address: String,
    port: u16,
    tun: Arc<tun_rs::AsyncDevice>,
    ca_bundle: String,
    server_cert: String,
    server_key: String,
    peer_cn: Option<String>,
    stream_count: usize,
    mtu: u16,
    quota: Option<Arc<precise_rate_limiter::Quota>>,
) -> Result<()> {
    let mut tree_context = tree_context;

    // Note: TUN device is created once and passed in - never recreated
    debug!("Loading server transport configuration");
    let transport_config = quicutil::get_server_transport_config();
    if let Err(e) = transport_config {
        error!("Error getting transport config: {}", e);
        exit(1);
    }
    let transport_config = transport_config.unwrap();

    debug!("Building server configuration with certificates");
    let server_config =
        quicutil::build_server_config(&ca_bundle, &server_cert, &server_key, transport_config);

    if let Err(e) = server_config {
        error!("Error building server config: {}", e);
        exit(1);
    }
    let server_config = server_config.unwrap();

    let bind_addr = format!("{}:{}", bind_address, port).parse();
    if let Err(e) = bind_addr {
        error!("Error parsing bind address: {}", e);
        exit(1);
    }
    let bind_addr = bind_addr.unwrap();

    debug!("Creating QUIC endpoint");
    let endpoint = quinn::Endpoint::server(server_config, bind_addr);
    if let Err(e) = endpoint {
        error!("Error creating endpoint: {}", e);
        exit(1);
    }

    let endpoint = endpoint.unwrap();

    info!("Server listening on {}", bind_addr);

    loop {
        let token = utils::generate_token();
        info!("Generated token: {}", token);
        let mut child_context = tree_context.new_child_context();
        // context gets out of the scope at the end of the loop
        // all tasks launched by this context, and all child contexs spawn by this context will be cancelled
        // the cancellation is cascading.
        info!("Waiting for incoming connection");
        let connection_result = match endpoint.accept().await {
            Some(conn) => {
                debug!("Incoming connection detected, completing handshake");
                let result = conn.await;
                info!("Incoming connection await OK");
                result
            }
            None => {
                warn!("No connection received");
                continue;
            }
        };

        if let Err(e) = connection_result {
            error!("Error accepting connection: {}", e);
            continue;
        }

        let connection = connection_result.unwrap();

        debug!("Connection established");
        stats.increment_reconnections();
        stats.set_last_reconnection_time(Local::now());
        info!(
            "New connection accepted (total reconnections: {})",
            stats.get_total_reconnections()
        );
        let keep_alive_result = connection.accept_bi().await;
        if let Err(e) = keep_alive_result {
            error!("Error accepting keep-alive stream: {}", e);
            continue;
        }
        let (keep_alive_send, keep_alive_recv) = keep_alive_result.unwrap();
        child_context.spawn(utils::keep_alive(keep_alive_send, keep_alive_recv));
        info!("Keep-alive stream established");
        // Validate peer CN if required
        if let Some(ref expected_cn) = peer_cn {
            debug!("Validating peer CN, expected: {}", expected_cn);
            let validation_result = quicutil::validate_peer_cn(&connection, expected_cn);
            if let Err(e) = validation_result {
                error!("Error validating peer CN: {}", e);
                continue;
            }
            info!("Peer CN validated: {}", expected_cn);
        } else {
            info!("Peer CN validation skipped");
        }

        // Config exchange (no routes - routes are local only)
        debug!("Performing config exchange with client");
        let client_params =
            utils::do_config_exchange_server(&connection, BUILD_BRANCH, &token, stream_count, mtu)
                .await;
        if let Err(e) = client_params {
            error!("Error exchanging initialization parameters: {}", e);
            continue;
        }

        let client_params = client_params.unwrap();
        debug!("Client parameters: {:?}", client_params);
        // Validate config exchange
        let validate_result =
            utils::validate_config_exchange(BUILD_BRANCH, stream_count, mtu, &client_params);
        if let Err(e) = validate_result {
            error!("Error validating config exchange: {}", e);
            continue;
        }
        info!(
            "Config validation passed, negotiated number_of_streams={}",
            stream_count
        );
        let streams_result = utils::accept_bidi_streams_with_handshake(
            &connection,
            stream_count,
            Duration::from_secs(10),
            utils::handshake_server_adapter,
        )
        .await;
        if let Err(e) = streams_result {
            error!("Error accepting bidirectional streams: {}", e);
            continue;
        }
        let streams = streams_result.unwrap();
        if streams.is_empty() {
            error!("Failed to accept any streams from client - connection may have closed or client didn't open streams");
            continue;
        }

        if streams.len() < stream_count {
            warn!(
                "Only accepted {} out of {} streams. Client may not have opened all streams.",
                streams.len(),
                stream_count
            );
            continue;
        } else {
            info!("Successfully accepted all {} streams", streams.len());
        }
        let run_pipes_result =
            utils::run_pipes_generic(child_context, stats.clone(), tun.clone(), streams, mtu, quota.clone()).await;
        if let Err(e) = run_pipes_result {
            error!("Error running pipes: {}", e);
            continue;
        }
    }
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

    info!(
        "Server starting: build_id={}, time={}, host={}",
        BUILD_BRANCH, BUILD_TIME, BUILD_HOST
    );
    let cli = ServerCli::parse();

    validate_server_args(&cli)?;
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
    // Handle data plane (blocking)
    run_server(
        cli.bind_address,
        cli.port,
        cli.device,
        cli.ca_bundle,
        cli.server_cert,
        cli.server_key,
        cli.peer_cn,
        cli.stream_count,
        cli.mtu,
        cli.ipv4,
        cli.ipv6,
        cli.route,
        speed_quota.clone(),
    )
    .await?;

    Ok(())
}

pub async fn run_server(
    bind_address: String,
    port: u16,
    device_name: String,
    ca_bundle: String,
    server_cert: String,
    server_key: String,
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
    let tun = Arc::new(tun);
    let result = run_server_indefinitely(
        tree_context.new_child_context(),
        stats.clone(),
        bind_address.clone(),
        port,
        tun,
        ca_bundle.clone(),
        server_cert.clone(),
        server_key.clone(),
        peer_cn.clone(),
        stream_count,
        mtu,
        quota.clone(),
    )
    .await;
    if let Err(e) = result {
        error!("Error running server: {}", e);
        return Err(e.into());
    } else {
        info!("Server loop iteration completed successfully");
        return Ok(());
    }
}

pub fn validate_server_args(args: &ServerCli) -> Result<(), anyhow::Error> {
    utils::validate_ipv4_cidr(args.ipv4.clone())?;
    utils::validate_ipv6_cidr(args.ipv6.clone())?;
    Ok(())
}
