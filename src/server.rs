use anyhow::Result;
use chrono::Local;
use clap::Parser;
use std::{process::exit, sync::Arc};
use std::time::Duration;
use tracing::{debug, error, info, warn};
use tun_rs::DeviceBuilder;
pub mod packetutil;
pub mod quicutil;
pub mod utils;
pub mod stats;
use stats::Stats;
use utils::{copy_read_to_tun_multi, copy_tun_to_write_multi};

const BUILD_BRANCH: &str = env!("BUILD_BRANCH");
const BUILD_TIME: &str = env!("BUILD_TIME");
const BUILD_HOST: &str = env!("BUILD_HOST");

#[derive(Parser)]
#[command(name = "server")]
#[command(about = "QUIC server (data plane only)")]
pub struct ServerCli {
    /// Bind address (e.g., 0.0.0.0)
    #[arg(short, long)]
    bind_address: String,

    /// Bind port (e.g., 4234)
    #[arg(long)]
    port: u16,

    /// TUN device name
    #[arg(short, long)]
    device: String,

    /// CA bundle file (PEM format) for validating client certificates
    #[arg(long)]
    ca_bundle: String,

    /// Server certificate file (PEM format)
    #[arg(long)]
    server_cert: String,

    /// Server private key file (PEM format)
    #[arg(long)]
    server_key: String,

    /// Optional: Expected peer (client) certificate common name (CN)
    #[arg(long)]
    peer_cn: Option<String>,

    /// Number of bidirectional streams to use (default: 30)
    #[arg(long, default_value = "30")]
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
    
    /// Remote routes to advertise (CIDR format, can be specified multiple times)
    #[arg(long)]
    remote_route: Vec<String>,
}

async fn run_server_internal(
    tree_context: tokio_tree_context::Context,
    stats: Arc<Stats>,
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
    remote_routes: Vec<String>,
) -> Result<()> {
    let mut tree_context = tree_context;
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

    let bind_addr = format!("{}:{}", bind_address, port)
        .parse();
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
        info!("Waiting for connection");
        let mut child_context = tree_context.new_child_context();
        let connection_result = match endpoint.accept().await {
            Some(conn) => {
                debug!("Incoming connection detected, completing handshake");
                conn.await
            },
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
        info!("New connection accepted (total reconnections: {})", stats.get_total_reconnections());
        let keep_alive_result = connection.accept_bi().await;
        if let Err(e) = keep_alive_result {
            error!("Error accepting keep-alive stream: {}", e);
            continue;
        }
        let (keep_alive_send, keep_alive_recv) = keep_alive_result.unwrap();
        child_context.spawn(utils::keep_alive(keep_alive_send, keep_alive_recv));
        debug!("Keep-alive stream established");
        // Validate peer CN if required
        if let Some(ref expected_cn) = peer_cn {
            debug!("Validating peer CN, expected: {}", expected_cn);
            let validation_result =quicutil::validate_peer_cn(&connection, expected_cn);
            if let Err(e) = validation_result {
                error!("Error validating peer CN: {}", e);
                continue;
            }
            info!("Peer CN validated: {}", expected_cn);
        }

        // Wait for initialization parameters over a temporary stream
        let mut server_routes: Vec<String> = Vec::new();
        // Add local IP routes if provided
        if let Some(ref ipv4_cidr) = ipv4 {
            server_routes.push(utils::ipv4_cidr_to_network_route(ipv4_cidr).unwrap());
        }
        if let Some(ref ipv6_cidr) = ipv6 {
            server_routes.push(utils::ipv6_cidr_to_network_route(ipv6_cidr).unwrap());
        }
        // Add and normalize remote routes
        for route in &remote_routes {
            let normalize_result = utils::normalize_cidr_route(route);
            if let Err(e) = normalize_result {
                warn!("Error normalizing route {}: {}", route, e);
                continue;
            }
            let normalize_route = normalize_result.unwrap();
            server_routes.push(normalize_route);
        }
        debug!("Performing config exchange with client");
        let client_params = utils::do_config_exchange_server(
            &connection,
            BUILD_BRANCH,
            stream_count,
            mtu,
            &server_routes,
        ).await;
        if let Err(e) = client_params {
            error!("Error exchanging initialization parameters: {}", e);
            continue;
        }

        let client_params = client_params.unwrap();
        debug!("Client parameters: {:?}", client_params);
        // Validate config exchange
        let validate_result = utils::validate_config_exchange(BUILD_BRANCH, stream_count, mtu, &client_params);
        if let Err(e) = validate_result {
            error!("Error validating config exchange: {}", e);
            continue;
        }
        info!("Config validation passed, negotiated number_of_streams={}", stream_count);
    
        // Create TUN device using async IO
        let mut builder = DeviceBuilder::new()
            .mtu(mtu)
            .name(&device_name)
            .multi_queue(true);

        // Assign IPv4 address if provided
        if let Some(ref ipv4_cidr) = ipv4 {
            let (addr, mask) = utils::parse_ipv4_cidr(ipv4_cidr).unwrap();
            builder = builder.ipv4(addr, mask, None);
            info!("Will assign IPv4 {} to device {}", ipv4_cidr, device_name);
        }

        // Assign IPv6 address if provided
        if let Some(ref ipv6_cidr) = ipv6 {
            let (addr, prefix) = utils::parse_ipv6_cidr(ipv6_cidr).unwrap();
            builder = builder.ipv6(addr, prefix);
            info!("Will assign IPv6 {} to device {}", ipv6_cidr, device_name);
        }

        let build_result = builder.build_async();
        if let Err(e) = build_result {
            error!("Error building TUN device: {}", e);
            continue;
        }
        let build_result = build_result.unwrap();
        let tun = Arc::new(build_result);

        info!("Created TUN device: {}", device_name);
        let if_index = tun.if_index().unwrap();
        debug!("TUN device ifindex: {}", if_index);
        // Apply routes
        let apply_result = utils::apply_routes(if_index, &client_params).await;
        if let Err(e) = apply_result {
            error!("Error applying routes: {}", e);
            continue;
        }
        info!("Routes applied successfully");
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
        let (send_streams, recv_streams) = streams_result.unwrap();
        if send_streams.is_empty() {
            error!("Failed to accept any streams from client - connection may have closed or client didn't open streams");
            continue;
        }

        if send_streams.len() < stream_count {
            warn!("Only accepted {} out of {} streams. Client may not have opened all streams.", send_streams.len(), stream_count);
            continue;
        } else {
            info!("Successfully accepted all {} streams", send_streams.len());
        }
        // Start two tasks for bidirectional forwarding
        let child_context1 = child_context.new_child_context();
        let child_context2 = child_context.new_child_context();
        let jh1 = child_context.spawn(copy_read_to_tun_multi(child_context1, stats.clone(), recv_streams, Arc::clone(&tun)));

        let jh2 = child_context.spawn(copy_tun_to_write_multi(child_context2, stats.clone(), send_streams, Arc::clone(&tun)));

        info!("Starting bidirectional forwarding tasks");
        // Wait indefinitely (tasks handle the forwarding)
        tokio::select! {
            result = jh1 => {
                if let Err(e) = result {
                    error!("copy network to tun task error: {}", e);
                } else {
                    warn!("copy network to tun task exited");
                }
            },
            result = jh2 => {
                if let Err(e) = result {
                    error!("copy tun to network task error: {}", e);
                } else {
                    warn!("copy tun to network task exited");
                }
            }
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
        cli.remote_route,
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
    remote_routes: Vec<String>,
) -> Result<()> {
    let mut tree_context = tokio_tree_context::Context::new();
    let stats = Arc::new(Stats::new());
    stats::start_stats_reporting(&mut tree_context, stats.clone()).await;
    loop {
        let result = run_server_internal(
            tree_context.new_child_context(),
            stats.clone(),
            bind_address.clone(), 
            port, 
            device_name.clone(), 
            ca_bundle.clone(),  
            server_cert.clone(),
            server_key.clone(),
            peer_cn.clone(),
            stream_count,
            mtu,
            ipv4.clone(),
            ipv6.clone(),
            remote_routes.clone()).await;
        if let Err(e) = result {
            error!("Error running server: {}", e);
            continue;
        } 
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}




pub fn validate_server_args(args: &ServerCli) -> Result<(), anyhow::Error> {
    utils::validate_ipv4_cidr(args.ipv4.clone())?;
    utils::validate_ipv6_cidr(args.ipv6.clone())?;
    Ok(())
}