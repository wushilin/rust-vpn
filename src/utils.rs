use std::net::{IpAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::quicutil;
use crate::stats::Stats;
use anyhow::Context;
use futures::future::select_all;
use net_route::{Handle, Route};
use quinn::{Connection, RecvStream, SendStream};
use rand::Rng;
use rustls_pki_types::ServerName;
use std::collections::HashMap;
use std::ops::RangeInclusive;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsConnector;
use tokio_rustls::{
    client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream, TlsAcceptor,
};
use tracing::{debug, error, info, trace, warn};
use tun_rs::AsyncDevice;

// Note: transport module is declared in files that use it
// to avoid circular dependencies

pub const PARAM_BUILD_ID: &str = "build_id";
pub const PARAM_NUMBER_OF_STREAMS: &str = "number_of_streams";
pub const PARAM_MTU: &str = "mtu";
pub const PARAM_TOKEN: &str = "token";
pub const PARAM_ROUTE_PREFIX: &str = "route_";
pub const SEED_CHARS: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
// Write length-prefixed data to a stream
async fn write_lengthed_data(write: &mut SendStream, data: &[u8]) -> Result<(), anyhow::Error> {
    let length_bytes = (data.len() as u16).to_be_bytes();
    write.write_all(&length_bytes).await?;
    write.write_all(data).await?;
    Ok(())
}

// Read length-prefixed data from a stream
async fn read_lengthed_data(
    read: &mut RecvStream,
    buffer: &mut [u8],
) -> Result<usize, anyhow::Error> {
    read.read_exact(&mut buffer[..2]).await?;
    let length = u16::from_be_bytes(buffer[..2].try_into()?);
    if length == 0 || length as usize > buffer.len() as usize {
        return Err(anyhow::anyhow!(
            "Invalid packet length or insuffient buffer: length={}, buffer_len={}",
            length,
            buffer.len()
        ));
    }
    let length = length as usize;
    let read_result = read.read_exact(&mut buffer[..length]).await;
    match read_result {
        Ok(_) => Ok(length),
        Err(e) => Err(e.into()),
    }
}

// Fast bucket function for load balancing between multiple streams
pub fn fast_bucket(src: u16, dst: u16, num_buckets: usize) -> usize {
    let (a, b) = if src < dst { (src, dst) } else { (dst, src) };
    let mut h = 2166136261u32; // FNV offset basis
    h = (h ^ (a as u32)) * 16777619;
    h = (h ^ (b as u32)) * 16777619;
    h as usize % num_buckets
}

pub fn format_init_params(
    token: &str,
    build_id: &str,
    number_of_streams: usize,
    mtu: u16,
) -> String {
    let mut parts = Vec::new();
    parts.push(format!("{}={}", PARAM_BUILD_ID, build_id));
    parts.push(format!("{}={}", PARAM_NUMBER_OF_STREAMS, number_of_streams));
    parts.push(format!("{}={}", PARAM_MTU, mtu));
    parts.push(format!("{}={}", PARAM_TOKEN, token));
    // Routes are no longer exchanged - they are set up locally
    parts.join(";")
}

pub fn parse_init_params(params: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for kv in params.split(';') {
        if kv.is_empty() {
            continue;
        }
        if let Some((k, v)) = kv.split_once('=') {
            if !k.is_empty() {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    map
}

// Client sends [0x00, 0x00] to server, server sends [0x00, 0x00] to client.
pub async fn do_stream_handshake_client(
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<(), anyhow::Error> {
    let handshake = [0x00u8, 0x00u8];
    send.write_all(&handshake).await?;
    let mut response = [0u8; 2];
    recv.read_exact(&mut response).await?;
    if response != [0x00, 0x00] {
        return Err(anyhow::anyhow!(
            "Invalid handshake response: expected [0x00, 0x00], got [{:02x}, {:02x}]",
            response[0],
            response[1]
        ));
    }
    Ok(())
}

// TCP version of handshake
pub async fn do_stream_handshake_client_tcp(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<(), anyhow::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let handshake = [0x00u8, 0x00u8];
    send.write_all(&handshake).await?;
    send.flush().await?;
    let mut response = [0u8; 2];
    recv.read_exact(&mut response).await?;
    if response != [0x00, 0x00] {
        return Err(anyhow::anyhow!(
            "Invalid handshake response: expected [0x00, 0x00], got [{:02x}, {:02x}]",
            response[0],
            response[1]
        ));
    }
    Ok(())
}

// Server waits for [0x00, 0x00] from client, sends [0x00, 0x00] to client.
pub async fn do_stream_handshake_server(
    recv: &mut RecvStream,
    send: &mut SendStream,
) -> Result<(), anyhow::Error> {
    let mut received = [0u8; 2];
    recv.read_exact(&mut received).await?;
    if received != [0x00, 0x00] {
        return Err(anyhow::anyhow!(
            "Invalid handshake request: expected [0x00, 0x00], got [{:02x}, {:02x}]",
            received[0],
            received[1]
        ));
    }
    let response = [0x00u8, 0x00u8];
    send.write_all(&response).await?;
    Ok(())
}

// TCP version of server handshake
pub async fn do_stream_handshake_server_tcp(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<(), anyhow::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut received = [0u8; 2];
    recv.read_exact(&mut received).await?;
    if received != [0x00, 0x00] {
        return Err(anyhow::anyhow!(
            "Invalid handshake request: expected [0x00, 0x00], got [{:02x}, {:02x}]",
            received[0],
            received[1]
        ));
    }
    let response = [0x00u8, 0x00u8];
    send.write_all(&response).await?;
    send.flush().await?;
    Ok(())
}

pub async fn keep_alive(send: SendStream, recv: RecvStream) -> Result<(), anyhow::Error> {
    let mut send = send;
    let mut recv = recv;
    let mut receive_buffer = [0u8; 200];
    info!("Starting keep-alive loop");
    loop {
        send.write_all(&[0x00u8]).await?;
        let result =
            tokio::time::timeout(Duration::from_secs(1), recv.read(&mut receive_buffer)).await;
        if let Err(e) = result {
            warn!("Timeout receiving keep-alive packet: {}", e);
        } else {
            let result = result.unwrap();
            if let Err(e) = result {
                warn!("Error receiving keep-alive packet: {}", e);
            } else {
                let size = result.unwrap();
                if let Some(_count) = size {
                    // If we received data, we're good
                } else {
                    warn!("Error receiving keep-live packet: no data received");
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub fn equals_and_in_range_inclusive<T>(
    numbers: &[T],
    names: &[&str],
    range: RangeInclusive<T>,
) -> Result<(), anyhow::Error>
where
    T: PartialEq + PartialOrd + Copy + std::fmt::Display,
{
    if numbers.is_empty() {
        anyhow::bail!("No numbers provided");
    }

    if numbers.len() != names.len() {
        anyhow::bail!(
            "Mismatch between numbers count ({}) and names count ({})",
            numbers.len(),
            names.len()
        );
    }

    // Check all numbers are equal
    let first = numbers[0];
    let first_name = names[0];
    for (idx, &num) in numbers.iter().enumerate().skip(1) {
        if num != first {
            anyhow::bail!("{} <> {} ({} != {})", first_name, names[idx], num, first);
        }
    }

    // Check all numbers are within range
    for (idx, &num) in numbers.iter().enumerate() {
        if num < *range.start() || num > *range.end() {
            anyhow::bail!(
                "{} = {} is out of range [{}, {}]",
                names[idx],
                num,
                range.start(),
                range.end()
            );
        }
    }

    Ok(())
}

pub fn validate_config_exchange(
    local_build_id: &str,
    local_stream_count: usize,
    local_mtu: u16,
    remote_params: &HashMap<String, String>,
) -> Result<(), anyhow::Error> {
    // Validate build_id matches
    let remote_build_id = remote_params
        .get(PARAM_BUILD_ID)
        .ok_or_else(|| anyhow::anyhow!("Missing build_id in remote config"))?;

    if remote_build_id != local_build_id {
        anyhow::bail!(
            "build_id mismatch: local='{}', remote='{}'",
            local_build_id,
            remote_build_id
        );
    }

    // Extract and validate stream count
    let remote_stream_count = remote_params
        .get(PARAM_NUMBER_OF_STREAMS)
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid number_of_streams in remote config"))?;

    equals_and_in_range_inclusive(
        &[local_stream_count, remote_stream_count],
        &["local_stream_count", "remote_stream_count"],
        1..=100,
    )?;

    // Extract and validate MTU
    let remote_mtu = remote_params
        .get(PARAM_MTU)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid mtu in remote config"))?;

    equals_and_in_range_inclusive(
        &[local_mtu, remote_mtu],
        &["local_mtu", "remote_mtu"],
        100..=65535,
    )?;

    debug!("Config validation passed");
    Ok(())
}

pub fn parse_ipv4_cidr(ip_cidr: &str) -> Result<(std::net::Ipv4Addr, u8), anyhow::Error> {
    let (ip_str, mask_str) = ip_cidr.split_once('/').ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid IPv4/CIDR format: expected format like '192.168.3.2/24', got '{}'",
            ip_cidr
        )
    })?;

    let addr = ip_str
        .parse::<std::net::Ipv4Addr>()
        .with_context(|| format!("Invalid IPv4 address: {}", ip_str))?;

    let mask = mask_str
        .parse::<u8>()
        .with_context(|| format!("Invalid subnet mask: {}", mask_str))?;

    if mask > 32 {
        anyhow::bail!("Invalid subnet mask: {} (must be 0-32)", mask);
    }

    Ok((addr, mask))
}

pub fn parse_ipv6_cidr(ip_cidr: &str) -> Result<(std::net::Ipv6Addr, u8), anyhow::Error> {
    let (ip_str, prefix_str) = ip_cidr.split_once('/').ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid IPv6/CIDR format: expected format like '2001:db8::1/64', got '{}'",
            ip_cidr
        )
    })?;

    let addr = ip_str
        .parse::<std::net::Ipv6Addr>()
        .with_context(|| format!("Invalid IPv6 address: {}", ip_str))?;

    let prefix = prefix_str
        .parse::<u8>()
        .with_context(|| format!("Invalid prefix length: {}", prefix_str))?;

    if prefix > 128 {
        anyhow::bail!("Invalid prefix length: {} (must be 0-128)", prefix);
    }

    Ok((addr, prefix))
}

pub fn ipv4_cidr_to_network_route(ipv4_cidr: &str) -> Result<String, anyhow::Error> {
    let (addr, mask) = parse_ipv4_cidr(ipv4_cidr)?;

    // Calculate network address by masking
    let addr_u32 = u32::from(addr);
    let mask_bits = (0xFFFFFFFF_u64 << (32 - mask)) as u32;
    let network_u32 = addr_u32 & mask_bits;
    let network_addr = std::net::Ipv4Addr::from(network_u32);

    Ok(format!("{}/{}", network_addr, mask))
}

pub fn ipv6_cidr_to_network_route(ipv6_cidr: &str) -> Result<String, anyhow::Error> {
    let (addr, prefix) = parse_ipv6_cidr(ipv6_cidr)?;

    // Calculate network address by masking
    let segments = addr.segments();
    let mut network_segments = [0u16; 8];

    // Copy the bits that are in the network portion
    let full_segments = (prefix / 16) as usize;
    let bits_in_partial = prefix % 16;

    for i in 0..full_segments.min(8) {
        network_segments[i] = segments[i];
    }

    if bits_in_partial > 0 && full_segments < 8 {
        let mask = (0xFFFF_u16 << (16 - bits_in_partial)) & 0xFFFF;
        network_segments[full_segments] = segments[full_segments] & mask;
    }

    let network_addr = std::net::Ipv6Addr::from(network_segments);
    Ok(format!("{}/{}", network_addr, prefix))
}

pub fn normalize_cidr_route(cidr: &str) -> Result<String, anyhow::Error> {
    // Try IPv4 first
    if let Ok(route) = ipv4_cidr_to_network_route(cidr) {
        return Ok(route);
    }

    // Try IPv6
    if let Ok(route) = ipv6_cidr_to_network_route(cidr) {
        return Ok(route);
    }

    // If both fail, return error
    anyhow::bail!("Invalid CIDR route format: expected IPv4 (e.g., 192.168.3.2/24) or IPv6 (e.g., 2001:db8::1/64), got '{}'", cidr);
}

pub async fn do_config_exchange_client(
    connection: &Connection,
    token: &str,
    client_build_id: &str,
    default_streams: usize,
    mtu: u16,
) -> Result<HashMap<String, String>, anyhow::Error> {
    let init_params_text = format_init_params(token, client_build_id, default_streams, mtu);
    let (mut tmp_send, mut tmp_recv) = connection.open_bi().await?;
    tmp_send.write_all(init_params_text.as_bytes()).await?;
    tmp_send.finish()?;
    let reply_bytes = tmp_recv.read_to_end(10 * 1024 * 1024).await?;
    let reply_str = String::from_utf8_lossy(&reply_bytes);
    debug!("Client received server config: {}", reply_str);
    Ok(parse_init_params(&reply_str))
}

pub async fn do_config_exchange_server(
    connection: &Connection,
    server_build_id: &str,
    token: &str,
    server_stream_count: usize,
    mtu: u16,
) -> Result<HashMap<String, String>, anyhow::Error> {
    let (mut tmp_send, mut tmp_recv) = connection.accept_bi().await?;
    let init_bytes = tmp_recv.read_to_end(10 * 1024 * 1024).await?;
    let init_str = String::from_utf8_lossy(&init_bytes);
    trace!("Server received client config: {}", init_str);
    let client_params_map = parse_init_params(&init_str);
    let server_params_text = format_init_params(token, server_build_id, server_stream_count, mtu);
    tmp_send.write_all(server_params_text.as_bytes()).await?;
    tmp_send.finish()?;
    Ok(client_params_map)
}

pub async fn open_bidi_streams_with_handshake(
    connection: &Connection,
    count: usize,
    handshake_fn: for<'a> fn(
        &'a mut RecvStream,
        &'a mut SendStream,
    ) -> core::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>,
    >,
) -> Result<Vec<(RecvStream, SendStream)>, anyhow::Error> {
    let mut result = Vec::with_capacity(count);
    info!("Opening {} bidirectional streams...", count);
    for i in 0..count {
        match connection.open_bi().await {
            Ok((mut send, mut recv)) => {
                if let Err(e) = (handshake_fn)(&mut recv, &mut send).await {
                    error!("Handshake failed for stream {}: {}", i + 1, e);
                    return Err(e);
                }
                result.push((recv, send));
                debug!(
                    "Stream {} opened successfully and handshake verified",
                    i + 1
                );
            }
            Err(e) => {
                error!("Error opening stream {}: {:?}", i + 1, e);
                warn!("Only opened {} streams before error", i);
                return Err(e.into());
            }
        }
    }
    info!(
        "Successfully opened {} out of {} streams",
        result.len(),
        count
    );
    Ok(result)
}

pub async fn accept_bidi_streams_with_handshake(
    connection: &Connection,
    count: usize,
    per_stream_timeout: std::time::Duration,
    handshake_fn: for<'a> fn(
        &'a mut RecvStream,
        &'a mut SendStream,
    ) -> core::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>,
    >,
) -> Result<Vec<(RecvStream, SendStream)>, anyhow::Error> {
    let mut result = Vec::with_capacity(count);
    info!("Accepting {} streams from client", count);
    for i in 0..count {
        trace!("Waiting to accept stream {} of {}...", i + 1, count);
        let stream_result = tokio::time::timeout(per_stream_timeout, connection.accept_bi()).await;
        match stream_result {
            Ok(Ok((mut send, mut recv))) => {
                if let Err(e) = (handshake_fn)(&mut recv, &mut send).await {
                    error!("Handshake failed for stream {}: {}", i + 1, e);
                    return Err(e);
                }
                result.push((recv, send));
                debug!(
                    "Stream {} accepted successfully and handshake verified",
                    i + 1
                );
            }
            Ok(Err(e)) => {
                error!("Error accepting stream {}: {:?}", i + 1, e);
                warn!("Only accepted {} streams before error", i);
                return Err(e.into());
            }
            Err(e) => {
                error!(
                    "Timeout waiting for stream {} (waited {:?})",
                    i + 1,
                    per_stream_timeout
                );
                warn!(
                    "Client may not have opened all {} streams. Accepted {} so far.",
                    count, i
                );
                return Err(e.into());
            }
        }
    }
    info!("Accepted {} out of {} streams", result.len(), count);
    Ok(result)
}

pub fn handshake_client_adapter<'a>(
    recv: &'a mut RecvStream,
    send: &'a mut SendStream,
) -> core::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
    Box::pin(do_stream_handshake_client(send, recv))
}

pub fn handshake_server_adapter<'a>(
    recv: &'a mut RecvStream,
    send: &'a mut SendStream,
) -> core::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
    Box::pin(do_stream_handshake_server(recv,send))
}

/// Apply routes directly from a vector of route strings (used for local route setup)
pub async fn apply_routes_direct(ifindex: u32, routes: &[String]) -> Result<(), anyhow::Error> {
    apply_routes_inner(ifindex, routes).await
}

async fn apply_routes_inner(ifindex: u32, routes: &[String]) -> Result<(), anyhow::Error> {
    let handler = Handle::new()?;
    for route_str in routes {
        let parse_v4_result = parse_ipv4_cidr(route_str);
        let parse_v6_result = parse_ipv6_cidr(route_str);

        let actual_ip: IpAddr;
        let actual_prefix: u8;
        if let Ok((ip, prefix)) = parse_v4_result {
            actual_ip = ip.into();
            actual_prefix = prefix;
        } else if let Ok((ip, prefix)) = parse_v6_result {
            actual_ip = ip.into();
            actual_prefix = prefix;
        } else {
            anyhow::bail!("Invalid CIDR route format: expected IPv4 (e.g., 192.168.3.2/24) or IPv6 (e.g., 2001:db8::1/64), got '{}'", route_str);
        }

        debug!(
            "Adding route {}/{} to ifindex {}",
            actual_ip, actual_prefix, ifindex
        );
        let route = Route::new(actual_ip.into(), actual_prefix).with_ifindex(ifindex);
        let add_result = handler.add(&route).await;
        match add_result {
            Ok(_) => {
                info!(
                    "Route {}/{} added to ifindex {}",
                    actual_ip, actual_prefix, ifindex
                );
            }
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("File exists") || error_str.contains("(os error 17)") {
                    info!(
                        "Route {}/{} already exists on ifindex {}",
                        actual_ip, actual_prefix, ifindex
                    );
                } else {
                    error!(
                        "Error adding route {}/{} to ifindex {}: {}",
                        actual_ip, actual_prefix, ifindex, e
                    );
                    return Err(e.into());
                }
            }
        }
    }
    Ok(())
}

pub fn validate_ipv4_cidr(ipv4: Option<String>) -> Result<(), anyhow::Error> {
    if let Some(ref ipv4_cidr) = ipv4 {
        parse_ipv4_cidr(ipv4_cidr)?;
    }
    Ok(())
}

pub fn validate_ipv6_cidr(ipv6: Option<String>) -> Result<(), anyhow::Error> {
    if let Some(ref ipv6_cidr) = ipv6 {
        parse_ipv6_cidr(ipv6_cidr)?;
    }
    Ok(())
}

pub async fn run_tls_acceptance_loop(
    name: String,
    ctx: tokio_tree_context::Context,
    listener: TcpListener,
    acceptor: TlsAcceptor,
    peer_cn: Option<String>,
    sender: mpsc::Sender<(ServerTlsStream<TcpStream>, std::net::SocketAddr)>,
) -> Result<(), anyhow::Error> {
    let mut ctx = ctx;
    info!("{} acceptance loop started", name);
    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        info!("{} Accepted new connection from {}", name, peer_addr);
        if let Err(e) = tcp_stream.set_nodelay(true) {
            warn!(
                "{} Failed to set TCP_NODELAY on control plane stream: {}",
                name, e
            );
        } else {
            info!("{} TCP_NODELAY set on new stream from {}", name, peer_addr);
        }
        let sender_clone = sender.clone();
        let acceptor_clone = acceptor.clone();
        let peer_cn_clone = peer_cn.clone();
        let name_clone = name.clone();
        ctx.spawn(async move {
            let tls_stream =
                tokio::time::timeout(Duration::from_secs(3), acceptor_clone.accept(tcp_stream))
                    .await;
            if let Err(e) = tls_stream {
                error!("{} Timeout accepting TLS stream: {}", name_clone, e);
                return;
            }
            let tls_stream = tls_stream.unwrap();
            if let Err(e) = tls_stream {
                error!("{} Error accepting TLS stream: {}", name_clone, e);
                return;
            }
            let tls_stream = tls_stream.unwrap();
            info!(
                "{} TLS handshake completed for stream from {}",
                name_clone, peer_addr
            );
            if let Some(ref expected_cn) = peer_cn_clone {
                debug!(
                    "{} Validating peer CN, expected: {}",
                    name_clone, expected_cn
                );
                let peer_certs = tls_stream.get_ref().1.peer_certificates();
                if let Some(certs) = peer_certs {
                    if !certs.is_empty() {
                        let first_cert =
                            rustls_pki_types::CertificateDer::from(certs[0].as_ref().to_vec());
                        let cn = quicutil::extract_cn_from_cert(&first_cert);
                        if let Err(e) = cn {
                            error!("{} Error extracting CN: {}", name_clone, e);
                            return;
                        }
                        let cn = cn.unwrap();
                        if cn != *expected_cn {
                            error!(
                                "{} CN mismatch: expected '{}', got '{}'",
                                name_clone, expected_cn, cn
                            );
                            return;
                        }
                        info!("{} Peer CN validated: {}", name_clone, expected_cn);
                    } else {
                        error!("{} No peer certificates available", name_clone);
                        return;
                    }
                } else {
                    error!("{} Peer certificates not available", name_clone);
                    return;
                }
            } else {
                info!("{} No peer CN expected. Not validating...", name_clone);
            }
            let send_result = sender_clone.send((tls_stream, peer_addr)).await;
            if let Err(e) = send_result {
                error!("{} Error sending connection to channel: {}", name_clone, e);
            } else {
                info!("{} Sent connection to channel: {}", name_clone, peer_addr);
            }
        });
    }
}

pub async fn must_accept_n_connections_timeout(
    context: tokio_tree_context::Context,
    receiver: &mut mpsc::Receiver<(ServerTlsStream<TcpStream>, std::net::SocketAddr)>,
    count: usize,
    my_token: &str,
    their_token: &str,
    from: Option<IpAddr>,
    timeout: Duration,
) -> Result<Vec<(ServerTlsStream<TcpStream>, std::net::SocketAddr)>, anyhow::Error> {
    info!(
        "Waiting for {} connections from {:?} timeout {} secs",
        count,
        from,
        timeout.as_secs()
    );
    let result = tokio::time::timeout(
        timeout,
        must_accept_n_connections(context, receiver, count, my_token, their_token, from),
    )
    .await?;
    if let Err(e) = result {
        error!("Error accepting {} connections: {}", count, e);
        return Err(e);
    } else {
        info!("Waiting for {} connections completed.", count);
    }
    return result;
}

async fn must_accept_n_connections(
    context: tokio_tree_context::Context,
    receiver: &mut mpsc::Receiver<(ServerTlsStream<TcpStream>, std::net::SocketAddr)>,
    count: usize,
    my_token: &str,
    their_token: &str,
    from: Option<IpAddr>,
) -> Result<Vec<(ServerTlsStream<TcpStream>, std::net::SocketAddr)>, anyhow::Error> {
    let mut streams = Vec::with_capacity(count);
    let mut context = context;
    while streams.len() < count {
        let receive_result = receiver.recv().await;
        if let Some((tls_stream, peer_addr)) = receive_result {
            // read my token and write their token to the stream
            if let Some(from) = from {
                if peer_addr.ip() != from {
                    info!("Skipping connection from {}: expected {}", peer_addr, from);
                    continue;
                } else {
                    info!("Accepting connection from {}: expected {}", peer_addr, from);
                }
            } else {
                info!("Accepting connection from {} (no source IP expected)", peer_addr);
            }
            streams.push((tls_stream, peer_addr));
        }
    }
    let mut empty_streams = Vec::with_capacity(count);
    for _ in 0..count {
        empty_streams.push(None);
    }
    info!("Accepted {} connections, now performing handshake", streams.len());
    let result_streams = Arc::new(Mutex::new(empty_streams));
    let mut join_handles = Vec::with_capacity(count);
    for (i, (mut tls_stream, peer_addr)) in streams.into_iter().enumerate() {
        let result_streams_clone = Arc::clone(&result_streams);
        let my_token_clone = my_token.to_string();
        let their_token_clone = their_token.to_string();
        let jh = context.spawn(async move {
            let mut buf = vec![0u8; 500];
            let length = read_lengthed_data_tcp(&mut tls_stream, &mut buf).await;
            if let Err(e) = length {
                error!("Error reading token: {}", e);
                return;
            }
            let length = length.unwrap();
            let read_token = String::from_utf8_lossy(&buf[..length]);
            //info!("Read token: {}", read_token);
            if read_token != my_token_clone {
                error!(
                    "Token mismatch: expected {}, got {}",
                    &my_token_clone, read_token
                );
                return;
            } else {
                debug!(
                    "Token matched: expected {}, got {}",
                    my_token_clone, read_token
                );
            }
            let write_result =
                write_lengthed_data_tcp(&mut tls_stream, their_token_clone.as_bytes()).await;
            if let Err(e) = write_result {
                error!("Error writing their token: {}", e);
                return;
            }
            //info!("Written their token: {}", their_token_clone);
            result_streams_clone.lock().await[i] = Some((tls_stream, peer_addr));
        });
        join_handles.push(jh);
    }

    let count = join_handles.len();
    info!("Waiting for {} connections handshakes to complete", join_handles.len());
    for jh in join_handles {
        let wr = jh.await;
        if let Err(e) = wr {
            error!("Error accepting connection: {}", e);
            return Err(e.into());
        }
    }
    info!("Handshake completed for {} connections", count);

    let mut result_streams_locked = result_streams.lock().await;

    for stream in result_streams_locked.iter() {
        if stream.is_none() {
            return Err(anyhow::anyhow!("Error accepting connection: stream is None"));
        }
    }
    info!("All handshakes completed, no errors");
    let result_streams =result_streams_locked.drain(..).map(|stream| stream.unwrap()).collect();
    return Ok(result_streams);
}

async fn connect_one_tls(
    connector: &TlsConnector,
    remote_addr: std::net::SocketAddr,
    server_name: ServerName<'static>,
) -> Result<(ClientTlsStream<TcpStream>, std::net::SocketAddr), anyhow::Error> {
    let tcp_stream = TcpStream::connect(remote_addr).await?;
    let local_addr = tcp_stream.local_addr()?;
    info!("TCP connection established {} -> {}", local_addr, remote_addr);
    if let Err(e) = tcp_stream.set_nodelay(true) {
        error!("Error setting TCP_NODELAY on connection {}", e);
    }
    let tls_stream = connector.connect(server_name, tcp_stream).await?;
    info!("TLS connection established {} -> {}", local_addr, remote_addr);
    Ok((tls_stream, remote_addr))
}

async fn must_connect_n_connections(
    context: tokio_tree_context::Context,
    connector: &TlsConnector,
    remote_addr: std::net::SocketAddr,
    server_name: ServerName<'static>,
    count: usize,
    my_token: &str,
    their_token: &str,
) -> Result<Vec<(ClientTlsStream<TcpStream>, std::net::SocketAddr)>, anyhow::Error> {
    info!("Connecting {} connections to {} with server name {:?}", count, remote_addr, server_name);
    let mut context = context;
    let mut streams = Vec::with_capacity(count);
    for _ in 0..count {
        streams.push(None);
    }

    let streams = Arc::new(Mutex::new(streams));
    let mut join_handles = Vec::with_capacity(count);
    for i in 0..count {
        let streams_clone = Arc::clone(&streams);
        let my_token_clone = my_token.to_string();
        let their_token_clone = their_token.to_string();
        let connector_clone = connector.clone();
        let remote_addr_clone = remote_addr.clone();
        let server_name_clone = server_name.clone();
        let jh = context.spawn(async move {
            let stream =
                connect_one_tls(&connector_clone, remote_addr_clone, server_name_clone).await;
            match stream {
                Ok((mut tls_stream, peer_addr)) => {
                    // set tcp no delay
                    info!("Connection {} connected to {}", i + 1, peer_addr);
                    let handshake_result = must_handshake_client_tcp(&mut tls_stream, &my_token_clone, &their_token_clone)
                        .await;
                    match handshake_result {
                        Ok(_) => {
                            info!("Connection {} handshake completed", i + 1);
                            streams_clone.lock().await[i] = Some((tls_stream, peer_addr));
                        }
                        Err(e) => {
                            error!("Error handshake: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Error connecting TLS stream {}: {}", i + 1, e);
                }
            }
        });
        join_handles.push(jh);
    }

    info!("Waiting for {} connections handshakes to complete", join_handles.len());
    for jh in join_handles {
        let wr = jh.await;
        if let Err(e) = wr {
            error!("Error connecting connection: {}", e);
            return Err(e.into());
        }
    }
    info!("All connections attempt completed, checking for errors");
    let mut streams_locked = streams.lock().await;
    for stream in streams_locked.iter() {
        if stream.is_none() {
            return Err(anyhow::anyhow!("Error connecting connection: stream is None"));
        }
    }
    info!("All connections handshakes completed, no errors");
    let result_streams = streams_locked.drain(..).map(|stream| stream.unwrap()).collect();
    return Ok(result_streams);
}

async fn must_handshake_client_tcp(
    tls_stream: &mut ClientTlsStream<TcpStream>,
    my_token: &str,
    their_token: &str,
) -> Result<(), anyhow::Error> {
    let mut buf = vec![0u8; 500];
    // write their token, then read my token and compare
    let _ = write_lengthed_data_tcp(tls_stream, their_token.as_bytes()).await?;
    let length = read_lengthed_data_tcp(tls_stream, &mut buf).await?;
    let read_token = String::from_utf8_lossy(&buf[..length]);
    if read_token != my_token {
        error!("Token mismatch: expected {}, got {}", my_token, read_token);
        return Err(anyhow::anyhow!(
            "Token mismatch: expected {}, got {}",
            my_token,
            read_token
        ));
    }
    //info!("Token matched: expected {}, got {}", my_token, read_token);
    Ok(())
}

pub async fn must_connect_n_connections_timeout(
    context: tokio_tree_context::Context,
    connector: &TlsConnector,
    remote_addr: std::net::SocketAddr,
    server_name: ServerName<'static>,
    count: usize,
    my_token: &str,
    their_token: &str,
    timeout: Duration,
) -> Result<Vec<(ClientTlsStream<TcpStream>, std::net::SocketAddr)>, anyhow::Error> {
    info!(
        "Waiting for {} connections to {} timeout {} secs",
        count,
        remote_addr,
        timeout.as_secs()
    );
    let result = tokio::time::timeout(
        timeout,
        must_connect_n_connections(
            context,
            connector,
            remote_addr,
            server_name,
            count,
            my_token,
            their_token,
        ),
    )
    .await;
    if let Err(e) = result {
        error!("Timeout connecting connections: {}", e);
        return Err(e.into());
    }
    let result = result.unwrap();
    if let Err(e) = result {
        error!("Error connecting connections: {}", e);
        return Err(e);
    } else {
        info!("All connections completed.");
    }
    return result;
}

pub fn generate_token() -> String {
    random_string_from_choices(SEED_CHARS, 32)
}

pub fn random_string_from_choices(choices: &str, length: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut chars = vec!['0'; length];
    for i in 0..length {
        chars[i] = choices
            .chars()
            .nth(rng.gen_range(0..choices.len()))
            .unwrap();
    }
    return chars.iter().collect();
}

pub async fn copy_recv_stream_to_tun(
    stats: Arc<Stats>,
    recv: RecvStream,
    tun: Arc<AsyncDevice>,
    mtu: u16,
) {
    let mut recv = recv;
    let mut buf = vec![0u8; mtu as usize + 5];
    loop {
        let lengthed_data_result = read_lengthed_data(&mut recv, &mut buf).await;
        match lengthed_data_result {
            Ok(n) => {
                if n > 0 {
                    if let Err(e) = tun.send(&buf[..n]).await {
                        error!("Error writing to TUN device: {}", e);
                        break;
                    }
                    stats.increment_bytes_received(n as u64);
                    stats.increment_packets_received(1);
                    trace!("Received and wrote {} bytes to TUN device", n);
                } else {
                    error!("Read <=0 bytes from recv stream: {}", n);
                }
            }
            Err(e) => {
                error!("Error reading from recv stream: {}", e);
                break;
            }
        }
    }
}

pub async fn copy_tun_to_send_stream(
    stats: Arc<Stats>,
    tun: Arc<AsyncDevice>,
    send: SendStream,
    mtu: u16,
) {
    let mut send = send;
    let mut buf = vec![0u8; mtu as usize + 5];
    loop {
        let tun_result = tun.recv(&mut buf).await;
        match tun_result {
            Ok(n) => {
                if n > 0 {
                    if let Err(e) = write_lengthed_data(&mut send, &buf[..n]).await {
                        error!("Error writing to send stream: {}", e);
                        break;
                    }
                    stats.increment_bytes_sent(n as u64);
                    stats.increment_packets_sent(1);
                    trace!("Read and wrote {} bytes to send stream", n);
                } else {
                    error!("Read <=0 bytes from tun device: {}", n);
                }
            }
            Err(e) => {
                error!("Error reading from tun device: {}", e);
                break;
            }
        }
    }
}

// TCP-specific functions

// Write length-prefixed data to a TCP stream
async fn write_lengthed_data_tcp(
    write: &mut (impl tokio::io::AsyncWrite + Unpin),
    data: &[u8],
) -> Result<(), anyhow::Error> {
    use tokio::io::AsyncWriteExt;
    let length_bytes = (data.len() as u16).to_be_bytes();
    write.write_all(&length_bytes).await?;
    write.write_all(data).await?;
    write.flush().await?;
    Ok(())
}

// Read length-prefixed data from a TCP stream
async fn read_lengthed_data_tcp(
    read: &mut (impl tokio::io::AsyncRead + Unpin),
    buffer: &mut [u8],
) -> Result<usize, anyhow::Error> {
    use tokio::io::AsyncReadExt;
    let mut length_bytes = [0u8; 2];
    read.read_exact(&mut length_bytes).await?;
    let length = u16::from_be_bytes(length_bytes);
    if length == 0 || length as usize > buffer.len() {
        return Err(anyhow::anyhow!(
            "Invalid packet length or insufficient buffer: length={}, buffer_len={}",
            length,
            buffer.len()
        ));
    }
    let length = length as usize;
    read.read_exact(&mut buffer[..length]).await?;
    Ok(length)
}

// TCP config exchange - client side (over TLS)
pub async fn do_config_exchange_client_tcp(
    tls_stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    client_build_id: &str,
    token: &str,
    default_streams: usize,
    mtu: u16,
) -> Result<HashMap<String, String>, anyhow::Error> {
    let init_params_text = format_init_params(token, client_build_id, default_streams, mtu);

    write_lengthed_data_tcp(tls_stream, init_params_text.as_bytes()).await?;
    // Read response - we'll read up to 10MB
    let mut buf = [0u8; 4096];
    let lengthed_data_result = read_lengthed_data_tcp(tls_stream, &mut buf).await?;
    let reply_str = String::from_utf8_lossy(&buf[..lengthed_data_result]);
    info!("Client received server config: {}", reply_str);
    Ok(parse_init_params(&reply_str))
}

// TCP config exchange - server side (over TLS)
pub async fn do_config_exchange_server_tcp(
    tls_stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    server_build_id: &str,
    token: &str,
    server_stream_count: usize,
    mtu: u16,
) -> Result<HashMap<String, String>, anyhow::Error> {
    // Read client params - up to 10MB
    let mut buf = [0u8; 4096];
    let lengthed_data_result = read_lengthed_data_tcp(tls_stream, &mut buf).await?;
    let init_str = String::from_utf8_lossy(&buf[..lengthed_data_result]);
    trace!("Server received client config: {}", init_str);
    let client_params_map = parse_init_params(&init_str);
    let server_params_text = format_init_params(token, server_build_id, server_stream_count, mtu);
    write_lengthed_data_tcp(tls_stream, server_params_text.as_bytes()).await?;
    Ok(client_params_map)
}

// TCP version of run_pipes - uses plain TCP streams
pub async fn run_pipes_generic<R, W>(
    child_context: tokio_tree_context::Context,
    stats: Arc<Stats>,
    device: Arc<AsyncDevice>,
    streams: Vec<(R, W)>,
    mtu: u16,
) -> Result<(), anyhow::Error>
where
    R: tokio::io::AsyncRead + Unpin + Send + Sync + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let mut child_context = child_context;
    let mut join_handles = Vec::new();
    for (i, (read_half, write_half)) in streams.into_iter().enumerate() {
        let device_clone = if i == 0 {
            debug!("Using original TUN device for IO for thread {}", i + 1);
            device.clone()
        } else {
            debug!("Opened new queue on TUN device for IO for thread {}", i + 1);
            let cloned = device.try_clone()?;
            Arc::new(cloned)
        };
        let jh1 = child_context.spawn(copy_generic_to_tun(
            stats.clone(),
            read_half,
            device_clone.clone(),
            mtu,
        ));
        join_handles.push(jh1);
        let jh2 = child_context.spawn(copy_tun_to_generic(
            stats.clone(),
            device_clone,
            write_half,
            mtu,
        ));
        join_handles.push(jh2);
    }

    info!("Spawning {} tasks for IO (sender + receiver).", join_handles.len());
    info!("VPN UP");
    let (result, _index, remaining) = select_all(join_handles).await;
    match result {
        Ok(_) => {
            warn!("One of the IO tasks completed successfully");
        }
        Err(e) => {
            error!("One of the IO tasks error: {:?}", e);
        }
    }
    for handle in remaining {
        handle.abort();
    }
    info!("All tasks cancelled");
    info!("VPN DOWN");
    Ok(())
}

async fn copy_generic_to_tun<R>(stats: Arc<Stats>, read: R, tun: Arc<AsyncDevice>, mtu: u16)
where
    R: tokio::io::AsyncRead + Unpin + Send + Sync + 'static,
{
    let mut read = read;
    let mut buf = vec![0u8; mtu as usize + 5];
    loop {
        let lengthed_data_result = read_lengthed_data_tcp(&mut read, &mut buf).await;
        match lengthed_data_result {
            Ok(n) => {
                if n > 0 {
                    if let Err(e) = tun.send(&buf[..n]).await {
                        error!("Error writing to TUN device: {}", e);
                        break;
                    }
                    stats.increment_bytes_received(n as u64);
                    stats.increment_packets_received(1);
                    trace!("Received and wrote {} bytes to TUN device", n);
                } else {
                    error!("Read <=0 bytes from TCP stream: {}", n);
                }
            }
            Err(e) => {
                error!("Error reading from TCP stream: {}", e);
                break;
            }
        }
    }
}

async fn copy_tun_to_generic<W>(stats: Arc<Stats>, tun: Arc<AsyncDevice>, write: W, mtu: u16)
where
    W: tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let mut write = write;
    let mut buf = vec![0u8; mtu as usize + 5];
    loop {
        let tun_result = tun.recv(&mut buf).await;
        match tun_result {
            Ok(n) => {
                if n > 0 {
                    if let Err(e) = write_lengthed_data_tcp(&mut write, &buf[..n]).await {
                        error!("Error writing to TCP stream: {}", e);
                        break;
                    }
                    stats.increment_bytes_sent(n as u64);
                    stats.increment_packets_sent(1);
                    trace!("Read and wrote {} bytes to TCP stream", n);
                } else {
                    error!("Read <=0 bytes from tun device: {}", n);
                }
            }
            Err(e) => {
                error!("Error reading from tun device: {}", e);
                break;
            }
        }
    }
}
