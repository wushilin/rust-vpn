use std::fmt::Display;
use std::net::{IpAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

#[derive(Debug, Clone)]
pub enum Purpose {
    ControlPlane,
    DataPlane,
}

impl Display for Purpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<Purpose> for String {
    fn from(purpose: Purpose) -> Self {
        match purpose {
            Purpose::ControlPlane => "ControlPlane".to_string(),
            Purpose::DataPlane => "DataPlane".to_string(),
        }
    }
}

impl From<Purpose> for &str {
    fn from(purpose: Purpose) -> Self {
        match purpose {
            Purpose::ControlPlane => "ControlPlane",
            Purpose::DataPlane => "DataPlane",
        }
    }
}

// Write length-prefixed data to a stream
async fn write_lengthed_data<T>(write: &mut T, data: &[u8]) -> Result<(), anyhow::Error>
    where T: tokio::io::AsyncWrite + Unpin + Send + Sync + 'static 
{
    let length_bytes = (data.len() as u16).to_be_bytes();
    write.write_all(&length_bytes).await?;
    write.write_all(data).await?;
    Ok(())
}

// Read length-prefixed data from a stream
async fn read_lengthed_data<T>(
    read: &mut T,
    buffer: &mut [u8],
) -> Result<usize, anyhow::Error> 
    where T: tokio::io::AsyncRead + Unpin + Send + Sync + 'static 
{
    read.read_exact(&mut buffer[..2]).await?;
    let length = u16::from_be_bytes(buffer[..2].try_into()?);
    if length == 0 {
        return Ok(0);
    }
    if length as usize > buffer.len() as usize {
        return Err(anyhow::anyhow!(
            "Insuffient buffer: length={}, buffer_len={}",
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
    let mut consecutive_timeouts = 0;
    let mut receive_buffer = [0u8; 200];
    info!("Starting keep-alive loop");
    loop {
        consecutive_timeouts +=1;
        let write_result = tokio::time::timeout(Duration::from_secs(1), send.write_all(&[0x00u8])).await;
        if let Err(e) = write_result {
            warn!("Error sending keep-alive packet({}): {}", consecutive_timeouts, e);
        } else {
            let write_result = write_result.unwrap();
            if let Err(e) = write_result {
                warn!("Error sending keep-alive packet({}): {}", consecutive_timeouts, e);
            } else {
                // write ok. but we do not reset error count. only reset if we receive data.
            }
        }
        // now we wait for data.
        let result =
            tokio::time::timeout(Duration::from_secs(1), recv.read(&mut receive_buffer)).await;
        if let Err(e) = result {
            warn!("Timeout receiving keep-alive packet({}): {}", consecutive_timeouts, e);
        } else {
            let result = result.unwrap();
            if let Err(e) = result {
                warn!("Error receiving keep-alive packet({}): {}", consecutive_timeouts, e);
            } else {
                let size = result.unwrap();
                if let Some(_count) = size {
                    // If we received data, we're good
                    consecutive_timeouts = 0;
                } else {
                    warn!("Error receiving keep-live packet: no data received ({})", consecutive_timeouts);
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
    if routes.is_empty() {
        info!("Apply routes OK: no routes defined");
        return Ok(());
    }
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

fn validate_peer_cn(
    certificates: Option<&[rustls_pki_types::CertificateDer<'_>]>,
    expected_cn: &str,
) -> Result<(), anyhow::Error> {
    if certificates.is_none() {
        error!("No peer certificates available (Option is None)");
        return Err(anyhow::anyhow!("No certificates available"));
    }
    let certificates = certificates.unwrap();
    if certificates.is_empty() {
        error!("No peer certificates available (Vec is empty)");
        return Err(anyhow::anyhow!("No certificates available"));
    }
    let cn = quicutil::extract_cn_from_cert(&certificates[0]);
    if let Err(e) = cn {
        error!("Error extracting CN: {}", e);
        return Err(e.into());
    }
    let cn = cn.unwrap();
    if cn != *expected_cn {
        error!("CN mismatch: expected '{}', got '{}'", expected_cn, cn);
        return Err(anyhow::anyhow!("CN mismatch: expected '{}', got '{}'", expected_cn, cn));
    }
    info!("Peer CN validated: {}", expected_cn);
    Ok(())
}

fn validate_peer_cn_server(
    tls_stream: &mut ServerTlsStream<TcpStream>,
    expected_cn: &Option<String>,
) -> Result<(), anyhow::Error> {
    if expected_cn.is_none() {
        debug!("No peer CN expected. Not validating...");
        return Ok(());
    }
    let expected_cn = expected_cn.as_ref().unwrap();
    let peer_certs = tls_stream.get_ref().1.peer_certificates();
    validate_peer_cn(peer_certs, expected_cn)?;
    Ok(())
}   

fn validate_peer_cn_client(
    tls_stream: &mut ClientTlsStream<TcpStream>,
    expected_cn: &Option<String>,
) -> Result<(), anyhow::Error> {
    if expected_cn.is_none() {
        debug!("No peer CN expected. Not validating...");
        return Ok(());
    }
    let expected_cn = expected_cn.as_ref().unwrap();
    let peer_certs = tls_stream.get_ref().1.peer_certificates();
    validate_peer_cn(peer_certs, expected_cn)?;
    Ok(())
}

pub async fn connect_tls_for_control_plane(
    server: String,
    port: u16,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    peer_cn: Option<String>,
) -> Result<(ClientTlsStream<TcpStream>, std::net::SocketAddr), anyhow::Error> {
    connect_tls_for_purpose(server, port, server_name, Purpose::ControlPlane, connector, peer_cn).await
}

pub async fn connect_tls_for_data_plane(
    server: String,
    port: u16,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    peer_cn: Option<String>,
) -> Result<(ClientTlsStream<TcpStream>, std::net::SocketAddr), anyhow::Error> {
    connect_tls_for_purpose(server, port, server_name, Purpose::DataPlane, connector, peer_cn).await
}
pub async fn connect_tls_for_purpose(
    server: String,
    port: u16,
    server_name: ServerName<'static>,
    purpose: Purpose,
    connector: TlsConnector,
    peer_cn: Option<String>,
) -> Result<(ClientTlsStream<TcpStream>, std::net::SocketAddr), anyhow::Error> {
    let addr_str = format!("{}:{}", server, port);
    info!("{} Connecting to {}", purpose, addr_str);
    let tcp_stream = TcpStream::connect(addr_str.clone()).await?;
    let remote_addr = tcp_stream.peer_addr()?;
    tcp_stream.set_nodelay(true)?;
    debug!("{} TCP_NODELAY set on new stream with remote address {}", purpose, remote_addr);
    info!("{} Connected to {}", purpose, addr_str);
    let mut tls_stream = connector.connect(
        server_name, 
        tcp_stream).await?;
    info!("{} TLS handshake completed for {}", purpose, addr_str);
    validate_peer_cn_client(&mut tls_stream, &peer_cn)?;
    debug!("{} Peer CN validated: {:?}", purpose, peer_cn);

    let purpose_str:&str = purpose.clone().into();
    let bytes = purpose_str.as_bytes();
    write_lengthed_data(&mut tls_stream, bytes).await?;
    debug!("{} Sent purpose to server: {}", purpose, purpose_str);
    Ok((tls_stream, remote_addr ))
}
pub async fn run_tls_acceptance_loop(
    name: String,
    ctx: tokio_tree_context::Context,
    listener: TcpListener,
    acceptor: TlsAcceptor,
    peer_cn: Option<String>,
    senders:Arc<Mutex<HashMap<String, mpsc::Sender<(ServerTlsStream<TcpStream>, std::net::SocketAddr)>>>>,
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
            debug!("{} TCP_NODELAY set on new stream from {}", name, peer_addr);
        }
        let senders_clone = senders.clone();
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
            let mut tls_stream = tls_stream.unwrap();
            let validate_result = validate_peer_cn_server(&mut tls_stream, &peer_cn_clone);
            if let Err(e) = validate_result {
                error!("{} Error validating peer CN: {}", name_clone, e);
                return;
            } 
            info!(
                "{} TLS handshake completed for stream from {}",
                name_clone, peer_addr
            );

            let mut purpose_bytes = vec![0u8; 100];
            let purpose = 
                tokio::time::timeout(Duration::from_secs(3), read_lengthed_data(&mut tls_stream, &mut purpose_bytes)).await;
            if let Err(e) = purpose {
                error!("{} Timeout reading purpose: {}", name_clone, e);
                return;
            }
            let purpose = purpose.unwrap();
            if let Err(e) = purpose {
                error!("{} Error reading purpose: {}", name_clone, e);
                return;
            }
            let purpose_length = purpose.unwrap();
            let purpose_str = String::from_utf8_lossy(&purpose_bytes[..purpose_length]);
            let purpose_str = purpose_str.to_string();
            debug!("{} Read purpose: {}", name_clone, purpose_str);
            let senders_locked = senders_clone.lock().await;
            let sender_by_name = senders_locked.get(&purpose_str);
            if let Some(sender) = sender_by_name {
                let send_result = sender.clone().send((tls_stream, peer_addr)).await;
                if let Err(e) = send_result {
                    error!("{} Error sending connection to channel: {}", name_clone, e);
                } else {
                    info!("{} Sent connection to channel: {}, purpose: {}", name_clone, peer_addr, purpose_str);
                }
            } else {
                error!("{} No sender found for purpose: {}", name_clone, purpose_str);
                return;
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
                    warn!("Skipping connection from {} (must be {})", peer_addr, from);
                    continue;
                } else {
                    debug!("Accepting connection from {} (must be {})", peer_addr, from);
                }
            } else {
                debug!("Accepting connection from {} (no restriction)", peer_addr);
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
            let mut buf = vec![0u8; 100];
            let length = read_lengthed_data(&mut tls_stream, &mut buf).await;
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
                write_lengthed_data(&mut tls_stream, their_token_clone.as_bytes()).await;
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

async fn connect_one_data_plane_tls(
    connector: TlsConnector,
    server: String,
    port: u16,
    server_name: ServerName<'static>,
    peer_cn: Option<String>,
) -> Result<(ClientTlsStream<TcpStream>, std::net::SocketAddr), anyhow::Error> {
    connect_tls_for_purpose(server, port, server_name, Purpose::DataPlane, connector, peer_cn).await
}

async fn must_connect_n_data_connections(
    context: tokio_tree_context::Context,
    connector: TlsConnector,
    server: String,
    port: u16,
    server_name: ServerName<'static>,
    peer_cn: Option<String>,
    count: usize,
    my_token: &str,
    their_token: &str,
) -> Result<Vec<(ClientTlsStream<TcpStream>, std::net::SocketAddr)>, anyhow::Error> {
    info!("Connecting {} connections to {}:{} with server name {:?}", count, server, port, server_name);
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
        let server_name_clone = server_name.clone();
        let server_clone = server.clone();
        let peer_cn_clone = peer_cn.clone();
        let jh = context.spawn(async move {
            let stream =
                connect_one_data_plane_tls(connector_clone, server_clone, port, server_name_clone, peer_cn_clone).await;
            match stream {
                Ok((mut tls_stream, local_addr)) => {
                    // set tcp no delay
                    info!("Connection {} connected via {}", i + 1, local_addr);
                    let handshake_result = must_handshake_client_tcp(&mut tls_stream, &my_token_clone, &their_token_clone)
                        .await;
                    match handshake_result {
                        Ok(_) => {
                            info!("Connection {} handshake completed", i + 1);
                            streams_clone.lock().await[i] = Some((tls_stream, local_addr));
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
    let mut buf = vec![0u8; 100];
    // write their token, then read my token and compare
    let _ = write_lengthed_data(tls_stream, their_token.as_bytes()).await?;
    let length = read_lengthed_data(tls_stream, &mut buf).await?;
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

pub async fn must_connect_n_data_connections_timeout(
    context: tokio_tree_context::Context,
    connector: TlsConnector,
    server: String,
    port: u16,
    server_name: ServerName<'static>,
    peer_cn: Option<String>,
    count: usize,
    my_token: &str,
    their_token: &str,
    timeout: Duration,
) -> Result<Vec<(ClientTlsStream<TcpStream>, std::net::SocketAddr)>, anyhow::Error> {
    info!(
        "Waiting for {} connections to {}:{} timeout {} secs",
        count,
        server,
        port,
        timeout.as_secs()
    );
    let result = tokio::time::timeout(
        timeout,
        must_connect_n_data_connections(
            context,
            connector,
            server,
            port,
            server_name,
            peer_cn,
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
    let mut rng = rand::rng();
    let mut chars = vec!['0'; length];
    for i in 0..length {
        chars[i] = choices
            .chars()
            .nth(rng.random_range(0..choices.len()))
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

// TCP config exchange - client side (over TLS)
pub async fn do_config_exchange_client_tcp(
    tls_stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    client_build_id: &str,
    token: &str,
    default_streams: usize,
    mtu: u16,
) -> Result<HashMap<String, String>, anyhow::Error> {
    let init_params_text = format_init_params(token, client_build_id, default_streams, mtu);

    write_lengthed_data(tls_stream, init_params_text.as_bytes()).await?;
    // Read response - we'll read up to 10MB
    let mut buf = [0u8; 4096];
    let lengthed_data_result = read_lengthed_data(tls_stream, &mut buf).await?;
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
    let lengthed_data_result = read_lengthed_data(tls_stream, &mut buf).await?;
    let init_str = String::from_utf8_lossy(&buf[..lengthed_data_result]);
    trace!("Server received client config: {}", init_str);
    let client_params_map = parse_init_params(&init_str);
    let server_params_text = format_init_params(token, server_build_id, server_stream_count, mtu);
    write_lengthed_data(tls_stream, server_params_text.as_bytes()).await?;
    Ok(client_params_map)
}

pub async fn run_pipes_generic<R, W>(
    child_context: tokio_tree_context::Context,
    stats: Arc<Stats>,
    device: Arc<AsyncDevice>,
    streams: Vec<(R, W)>,
    mtu: u16,
    quota: Option<Arc<precise_rate_limiter::Quota>>,
) -> Result<(), anyhow::Error>
where
    R: tokio::io::AsyncRead + Unpin + Send + Sync + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let mut child_context = child_context;
    let mut join_handles = Vec::new();
    for (i, (read_half, write_half)) in streams.into_iter().enumerate() {
        let index = i;
        let device_clone = if i == 0 {
            debug!("Using original TUN device for IO for thread {}", i + 1);
            device.clone()
        } else {
            debug!("Opened new queue on TUN device for IO for thread {}", i + 1);
            let cloned = device.try_clone()?;
            Arc::new(cloned)
        };
        let jh1 = child_context.spawn(copy_generic_to_tun(
            index,
            stats.clone(),
            read_half,
            device_clone.clone(),
            mtu,
        ));
        join_handles.push(jh1);
        let jh2 = child_context.spawn(copy_tun_to_generic(
            index,
            stats.clone(),
            device_clone,
            write_half,
            mtu,
            quota.clone(),
        ));
        join_handles.push(jh2);
    }

    info!("Spawning {} tasks for IO (sender + receiver).", join_handles.len());
    info!("VPN UP");
    let (result, _index, remaining) = select_all(join_handles).await;
    let error_index = _index;
    match result {
        Ok(_) => {
            warn!("Task {} completed", error_index + 1);
        }
        Err(e) => {
            error!("Task {} error: {:?}", error_index, e);
        }
    }
    for (_index, handle) in remaining.into_iter().enumerate() {
        handle.abort();
    }
    info!("All tasks cancelled");
    error!("VPN DOWN");
    Ok(())
}

async fn copy_generic_to_tun<R>(index: usize, stats: Arc<Stats>, read: R, tun: Arc<AsyncDevice>, mtu: u16)
where
    R: tokio::io::AsyncRead + Unpin + Send + Sync + 'static,
{
    let index = index + 1;
    let mut read = read;
    let mut buf = vec![0u8; mtu as usize + 5];
    loop {
        let lengthed_data_result = read_lengthed_data(&mut read, &mut buf).await;
        match lengthed_data_result {
            Ok(n) => {
                if n > 0 {
                    if let Err(e) = tun.send(&buf[..n]).await {
                        error!("Task {} Error writing to TUN device: {}", index, e);
                        break;
                    }
                    stats.increment_bytes_received(n as u64);
                    stats.increment_packets_received(1);
                    trace!("Task {} Received and wrote {} bytes to TUN device", index, n);
                } else {
                    error!("Task {} Read <=0 bytes from network stream: {}", index, n);
                }
            }
            Err(e) => {
                error!("Task {} Error reading from network stream: {}", index, e);
                break;
            }
        }
    }
}

async fn copy_tun_to_generic<W>(
    index: usize,
    stats: Arc<Stats>, 
    tun: Arc<AsyncDevice>, 
    write: W, 
    mtu: u16,
    quota: Option<Arc<precise_rate_limiter::Quota>>,
)
where
    W: tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let index = index + 1;
    let mut write = write;
    let mut buf = vec![0u8; mtu as usize + 5];
    let mut remaining_quota_bytes = 0;
    let quota_to_acquire_in_bytes = 1 * 1024 * 1024;
    let quota_to_acquire_in_bits = quota_to_acquire_in_bytes * 8;

    loop {
        let tun_result = tun.recv(&mut buf).await;
        match tun_result {
            Ok(n) => {
                if n > 0 {
                    if let Err(e) = write_lengthed_data(&mut write, &buf[..n]).await {
                        error!("Task {} Error writing to network stream: {}", index, e);
                        break;
                    }
                    stats.increment_bytes_sent(n as u64);
                    if let Some(quota) = quota.as_ref() {
                        if remaining_quota_bytes > n as usize {
                            remaining_quota_bytes -= n as usize;
                        } else {
                            // we need to acquire the remaining quota
                            let remaining_quota_bits = remaining_quota_bytes * 8;
                            // we still have balance of remaining_quota_bits
                            // each acquire should be quota_to_acquire_in_bits
                            // so we need to acquire the remaining quota_bits
                            let quota_to_acquire_bits = quota_to_acquire_in_bits - remaining_quota_bits;
                            quota.acquire(quota_to_acquire_bits).await;
                            // update the remaining quota bytes
                            remaining_quota_bytes = quota_to_acquire_bits/8 as usize;
                        }
                    }
                    stats.increment_packets_sent(1);
                    trace!("Task {} Read and wrote {} bytes to TCP stream", index, n);
                } else {
                    error!("Task {} Read <=0 bytes from tun device: {}", index, n);
                }
            }
            Err(e) => {
                error!("Task {} Error reading from tun device: {}", index, e);
                break;
            }
        }
    }
}


pub fn build_tls_connector(ca_bundle: &str, client_cert: &str, client_key: &str) -> Result<TlsConnector, anyhow::Error> {
    let cert_chain = quicutil::load_cert_chain(client_cert)?;
    let key = quicutil::load_private_key(client_key)?;
    let certs: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>> = cert_chain
        .into_iter()
        .map(|c| tokio_rustls::rustls::pki_types::CertificateDer::from(c.as_ref().to_vec()))
        .collect();
    let key_der = match key {
        rustls_pki_types::PrivateKeyDer::Pkcs8(k) => tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
            tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(k.secret_pkcs8_der().to_vec())
        ),
        rustls_pki_types::PrivateKeyDer::Pkcs1(k) => tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs1(
            tokio_rustls::rustls::pki_types::PrivatePkcs1KeyDer::from(k.secret_pkcs1_der().to_vec())
        ),
        rustls_pki_types::PrivateKeyDer::Sec1(k) => tokio_rustls::rustls::pki_types::PrivateKeyDer::Sec1(
            tokio_rustls::rustls::pki_types::PrivateSec1KeyDer::from(k.secret_sec1_der().to_vec())
        ),
        _ => anyhow::bail!("Unsupported private key format"),
    };
    let ca_store = quicutil::load_ca_bundle_tcp_tokio(ca_bundle)?;
    let client_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(ca_store)
        .with_client_auth_cert(certs, key_der)
        .map_err(|e| anyhow::anyhow!("Failed to create rustls client config: {:?}", e))?;
    let connector = TlsConnector::from(Arc::new(client_config));
    Ok(connector)
}


pub fn build_tls_acceptor(ca_bundle: &str, server_cert: &str, server_key: &str) -> Result<TlsAcceptor, anyhow::Error> {
    let cert_chain = quicutil::load_cert_chain(server_cert)?;
    let key = quicutil::load_private_key(server_key)?;
    let certs: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>> = cert_chain
        .into_iter()
        .map(|c| tokio_rustls::rustls::pki_types::CertificateDer::from(c.as_ref().to_vec()))
        .collect();
    let key_der = match key {
        rustls_pki_types::PrivateKeyDer::Pkcs8(k) => tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
            tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(k.secret_pkcs8_der().to_vec())
        ),
        rustls_pki_types::PrivateKeyDer::Pkcs1(k) => tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs1(
            tokio_rustls::rustls::pki_types::PrivatePkcs1KeyDer::from(k.secret_pkcs1_der().to_vec())
        ),
        rustls_pki_types::PrivateKeyDer::Sec1(k) => tokio_rustls::rustls::pki_types::PrivateKeyDer::Sec1(
            tokio_rustls::rustls::pki_types::PrivateSec1KeyDer::from(k.secret_sec1_der().to_vec())
        ),
        _ => anyhow::bail!("Unsupported private key format"),
    };
    let ca_store = quicutil::load_ca_bundle_tcp_tokio(ca_bundle)?;
    let client_verifier = tokio_rustls::rustls::server::WebPkiClientVerifier::builder(ca_store.into())
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create client cert verifier: {:?}", e))?;   
    let server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key_der)
        .map_err(|e| anyhow::anyhow!("Failed to create rustls server config: {:?}", e))?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    Ok(acceptor)
}