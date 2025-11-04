use anyhow::{Context, Result};
use chrono::Local;
use clap::Parser;
use tokio::sync::{Mutex, mpsc};
use std::cmp::{max};
use std::collections::HashMap;
use std::{sync::Arc};
use std::time::Duration;
use tracing::{debug, error, info, warn};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream};

pub mod packetutil;
pub mod quicutil;
pub mod utils;
pub mod stats;
pub mod tunutil;
use stats::Stats;

use crate::utils::Purpose;

const BUILD_BRANCH: &str = env!("BUILD_BRANCH");
const BUILD_TIME: &str = env!("BUILD_TIME");
const BUILD_HOST: &str = env!("BUILD_HOST");

#[derive(Parser, Debug)]
#[command(name = "tcpserver")]
#[command(about = "TCP server with separate control and data planes")]
pub struct TcpServerCli {
    /// Bind address for control plane (TLS) (e.g., 0.0.0.0)
    #[arg(long, default_value = "0.0.0.0")]
    bind_address: String,

    /// Bind port for control plane (TLS) (e.g., 4235)
    #[arg(long, default_value = "1107")]
    port: u16,

    /// TUN device name
    #[arg(short, long, default_value = "rustvpn")]
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
) -> Result<()> {
    let mut tree_context = tree_context;
    
    // Build TLS acceptor for control plane
    debug!("Building TLS acceptor for control plane");
    let acceptor = utils::build_tls_acceptor(&ca_bundle, &server_cert, &server_key)?;
    
    let bind_addr = format!("{}:{}", bind_address, port)
        .parse::<std::net::SocketAddr>()
        .context("Failed to parse control bind address")?;
    
    info!("Creating TCP listeners");
    let control_listener = TcpListener::bind(bind_addr).await
        .context("Failed to bind control plane listener")?;
    
    let (control_sender, mut control_receiver) = mpsc::channel::<(TlsStream<TcpStream>, std::net::SocketAddr)>(100);
    let (data_sender, mut data_receiver) = mpsc::channel::<(TlsStream<TcpStream>, std::net::SocketAddr)>(100);
    let control_context = tree_context.new_child_context();
    
    // Send connections to the control and data plane to the acceptance loop
    let mut senders = HashMap::<String, mpsc::Sender<(TlsStream<TcpStream>, std::net::SocketAddr)>>::new();
    senders.insert(Purpose::ControlPlane.into(), control_sender);
    senders.insert(Purpose::DataPlane.into(), data_sender);

    let senders = Arc::new(Mutex::new(senders));

    tree_context.spawn(utils::run_tls_acceptance_loop(
        "ControlAndDataPlane".into(),
        control_context,
        control_listener,
        acceptor.clone(),
        peer_cn.clone(),
        senders.clone(),
    ));


    info!("ControlAndDataPlane listening on {}", bind_addr);

    loop {
        info!("Waiting for connection");
        let mut child_context = tree_context.new_child_context();
        
        // Accept control plane connection
        let receive_result = control_receiver.recv().await;
        if receive_result.is_none() {
            error!("Error receiving control plane connection");
            continue;
        }
        let (mut tls_stream, control_peer_addr) = receive_result.unwrap();
        
        stats.increment_reconnections();
        stats.set_last_reconnection_time(Local::now());
        info!("New control plane connection accepted from {} (total reconnections: {})", control_peer_addr, stats.get_total_reconnections());
        
        // Config exchange on control plane
        debug!("Performing config exchange with client");
        let my_token = utils::generate_token();
        info!("Generated my token: {}", my_token);
        let client_params = utils::do_config_exchange_server_tcp(
            &mut tls_stream,
            BUILD_BRANCH,
            &my_token,
            stream_count,
            mtu,
        ).await;
        if let Err(e) = client_params {
            error!("Error exchanging initialization parameters: {}", e);
            continue;
        }

        let client_params = client_params.unwrap();
        debug!("Client parameters: {:?}", client_params);
        let client_token = client_params.get(utils::PARAM_TOKEN).unwrap();
        info!("Client token: {}", client_token);
        
        // Validate config exchange
        let validate_result = utils::validate_config_exchange(BUILD_BRANCH, stream_count, mtu, &client_params);
        if let Err(e) = validate_result {
            error!("Error validating config exchange: {}", e);
            continue;
        }
        info!("Config validation passed, negotiated number_of_streams={}", stream_count);
        
        // Now accept data plane connections
        debug!("Waiting for {} data plane connections", stream_count);
        let child_context_inner = child_context.new_child_context();
        let raw_data_streams = utils::must_accept_n_connections_timeout(
            child_context_inner,
            &mut data_receiver,
            stream_count,
            &my_token,
            &client_token,
            Some(control_peer_addr.ip()),
            Duration::from_secs(max(5, 2 * stream_count as u64)),
        ).await;
        if let Err(e) = raw_data_streams {
            error!("Error accepting data plane streams: {}", e);
            continue;
        }
        let raw_data_streams = raw_data_streams.unwrap();

        if raw_data_streams.is_empty() {
            error!("Failed to accept any data plane streams");
            continue;
        }

        if raw_data_streams.len() < stream_count {
            warn!("Only accepted {} out of {} data plane streams", raw_data_streams.len(), stream_count);
        } else {
            info!("Successfully accepted all {} data plane streams", raw_data_streams.len());
        }
        
        let data_streams_inner1 = raw_data_streams.into_iter()
            .map(|(stream, _)| stream)
            .map(|stream| tokio::io::split(stream))
            .collect();

        let run_pipes_result = utils::run_pipes_generic(
            child_context,
            stats.clone(),
            tun.clone(),
            data_streams_inner1,
            mtu,
        ).await;
        if let Err(e) = run_pipes_result {
            error!("Error running pipes: {}", e);
            continue;
        }
    }
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

    info!(
        "TCP Server starting: build_id={}, time={}, host={}",
        BUILD_BRANCH, BUILD_TIME, BUILD_HOST
    );
    info!("Parsing server arguments");
    let cli = TcpServerCli::parse();
    info!("Server arguments parsed: {:?}", cli);
    info!("Validating server arguments");
    validate_server_args(&cli)?;
    info!("Server arguments validated");
    // Handle data plane (blocking)
    info!("Starting server");
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
) -> Result<()> {
    let mut tree_context = tokio_tree_context::Context::new();
    let stats = Arc::new(Stats::new());
    stats::start_stats_reporting(&mut tree_context, stats.clone()).await;
    
    info!("Creating TUN device");
    let tun = tunutil::create_tun(device_name, mtu, ipv4, ipv6, local_routes).await?;
    info!("TUN device created");
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
    ).await;

    if let Err(e) = result {
        error!("Error running server: {}", e);
        return Err(e.into());
    } else { 
        info!("Server loop iteration completed successfully");
        return Ok(());
    }
}

pub fn validate_server_args(args: &TcpServerCli) -> Result<(), anyhow::Error> {
    utils::validate_ipv4_cidr(args.ipv4.clone())?;
    utils::validate_ipv6_cidr(args.ipv6.clone())?;
    Ok(())
}

