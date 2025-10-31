use anyhow::{Context, Result};
use clap::Parser;
use std::{sync::Arc, time::Duration};
use tracing::{debug, error, info, warn};
use tun_rs::DeviceBuilder;
pub mod packetutil;
pub mod utils;
pub mod quicutil;
pub mod stats;
use utils::{copy_read_to_tun_multi, copy_tun_to_write_multi};
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
    #[arg(long)]
    port: u16,
    
    /// TUN device name
    #[arg(short, long)]
    device: String,
    
    /// CA bundle file (PEM format) for validating server certificates
    #[arg(long)]
    ca_bundle: String,
    
    /// Client certificate file (PEM format)
    #[arg(long)]
    client_cert: String,
    
    /// Client private key file (PEM format)
    #[arg(long)]
    client_key: String,
    
    /// Optional: Expected peer (server) certificate common name (CN)
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

// quicutil provides certificate helpers and config builders

async fn run_client_inner(
    child_context: tokio_tree_context::Context,
    stats: Arc<Stats>,
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
    remote_routes: Vec<String>,
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

    // Initialization config exchange over a temporary stream
    let mut client_routes: Vec<String> = Vec::new();
    // Add local IP routes if provided
    if let Some(ref ipv4_cidr) = ipv4 {
        match utils::ipv4_cidr_to_network_route(ipv4_cidr) {
            Ok(route) => client_routes.push(route),
            Err(e) => {
                error!("Failed to convert IPv4 CIDR '{}' to network route: {}", ipv4_cidr, e);
                return Err(e.context(format!("Invalid IPv4 CIDR: {}", ipv4_cidr)));
            }
        }
    }
    if let Some(ref ipv6_cidr) = ipv6 {
        match utils::ipv6_cidr_to_network_route(ipv6_cidr) {
            Ok(route) => client_routes.push(route),
            Err(e) => {
                error!("Failed to convert IPv6 CIDR '{}' to network route: {}", ipv6_cidr, e);
                return Err(e.context(format!("Invalid IPv6 CIDR: {}", ipv6_cidr)));
            }
        }
    }
    // Add and normalize remote routes
    let mut route_errors = Vec::new();
    for route in remote_routes {
        match utils::normalize_cidr_route(&route) {
            Ok(normalized) => client_routes.push(normalized),
            Err(e) => {
                route_errors.push((route.clone(), e));
            }
        }
    }
    
    if !route_errors.is_empty() {
        for (route, err) in &route_errors {
            error!("Failed to normalize route '{}': {}", route, err);
        }
        anyhow::bail!(
            "Failed to normalize {} out of {} remote route(s). Please check the route format (e.g., 192.168.0.0/24 or 2001:db8::/64)",
            route_errors.len(),
            route_errors.len() + client_routes.len()
        );
    }
    debug!("Performing config exchange with server");
    let params_map = utils::do_config_exchange_client(&connection, BUILD_BRANCH, stream_count, mtu, &client_routes).await?;
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
    
    // Create TUN device using async IO
    let mut builder = DeviceBuilder::new()
        .mtu(mtu)
        .name(&device_name)
        .multi_queue(true);
    
    // Assign IPv4 address if provided
    if let Some(ref ipv4_cidr) = ipv4 {
        let (addr, mask) = utils::parse_ipv4_cidr(ipv4_cidr)?;
        builder = builder.ipv4(addr, mask, None);
        info!("Will assign IPv4 {} to device {}", ipv4_cidr, device_name);
    }
    
    // Assign IPv6 address if provided
    if let Some(ref ipv6_cidr) = ipv6 {
        let (addr, prefix) = utils::parse_ipv6_cidr(ipv6_cidr)?;
        builder = builder.ipv6(addr, prefix);
        info!("Will assign IPv6 {} to device {}", ipv6_cidr, device_name);
    }
    
    let tun = Arc::new(
        builder
            .build_async()
            .context("Failed to create TUN device")?
    );
    
    info!("Created TUN device: {}", device_name);
    let if_index = tun.if_index()
        .context(format!("TUN device '{}' does not have an interface index", device_name))?;
    debug!("TUN device ifindex: {}", if_index);
    // Apply routes
    let apply_result = utils::apply_routes(if_index, &params_map).await;
    if let Err(e) = apply_result {
        error!("Error applying routes: {}", e);
        return Err(e.into());
    }
    info!("Routes applied successfully");
    let (send_streams, recv_streams) = utils::open_bidi_streams_with_handshake(
        &connection,
        stream_count,
        utils::handshake_client_adapter,
    ).await?;
    
    if send_streams.is_empty() {
        error!("Failed to open any streams");
        anyhow::bail!("Failed to open any streams");
    }
    
    if send_streams.len() < stream_count {
        warn!("Only opened {} out of {} streams", send_streams.len(), stream_count);
    } else {
        info!("Successfully opened all {} streams", send_streams.len());
    }
    // Start two tasks for bidirectional forwarding
    let child_context1 = child_context.new_child_context();
    let child_context2 = child_context.new_child_context();
    let jh1 = child_context.spawn(copy_read_to_tun_multi(
        child_context1,
        stats.clone(),
        recv_streams,
        Arc::clone(&tun),
    ));
    
    let jh2 = child_context.spawn(copy_tun_to_write_multi(
        child_context2,
        stats.clone(),
        send_streams,
        Arc::clone(&tun),
    ));
    
    info!("Starting bidirectional forwarding tasks");
    // Wait indefinitely (tasks handle the forwarding)
    tokio::select! {
        result = jh1 => {
            if let Err(e) = result {
                error!("copy_transport_to_tun task error: {}", e);
            } else {
                warn!("copy_transport_to_tun task exited");
            }
        },
        result = jh2 => {
            if let Err(e) = result {
                error!("copy_tun_to_transport task error: {}", e);
            } else {
                warn!("copy_tun_to_transport task exited");
            }
        }
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
        cli.remote_route
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
    remote_routes: Vec<String>,
) -> Result<()> {
    let mut tree_context = tokio_tree_context::Context::new();
    let stats = Arc::new(Stats::new());
    stats::start_stats_reporting(&mut tree_context, stats.clone()).await;
    loop {
        let child_context = tree_context.new_child_context();
        let result = run_client_inner(
            child_context,
            stats.clone(),
            server.clone(), 
            port, 
            device_name.clone(), 
            ca_bundle.clone(), 
            client_cert.clone(), 
            client_key.clone(), 
            peer_cn.clone(), 
            stream_count, 
            mtu, 
            ipv4.clone(), 
            ipv6.clone(), 
            remote_routes.clone()).await;
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