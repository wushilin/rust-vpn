use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use futures::future::select_all;
use net_route::{Handle, Route};
use quinn::{Connection, RecvStream, SendStream};
use tracing::{debug, error, info, trace, warn};
use tun_rs::AsyncDevice;
use crate::packetutil::get_ports_from_tun_frame;
use crate::stats::Stats;
use std::collections::HashMap;
use std::ops::RangeInclusive;

pub const PARAM_BUILD_ID: &str = "build_id";
pub const PARAM_NUMBER_OF_STREAMS: &str = "number_of_streams";
pub const PARAM_MTU: &str = "mtu";
pub const PARAM_ROUTE_PREFIX: &str = "route_";

async fn write_lengthed_data(write: &mut SendStream, data: &[u8]) -> Result<(), anyhow::Error> {
    let length_bytes = (data.len() as u16).to_be_bytes();
    write.write_all(&length_bytes).await?;
    write.write_all(data).await?;
    Ok(())
}

async fn read_lengthed_data(
    read: &mut RecvStream,
    buffer: &mut [u8],
) -> Result<usize, anyhow::Error> {
    read.read_exact(&mut buffer[..2]).await?;
    let length = u16::from_be_bytes(buffer[..2].try_into()?);
    if length == 0 || length > buffer.len() as u16 {
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

pub async fn copy_tun_to_write_multi(
    _child_context: tokio_tree_context::Context,
    stats: Arc<Stats>,
    writes: Vec<SendStream>,
    tun: Arc<AsyncDevice>,
) {
    let mut buf = vec![0u8; 1600];
    let mut counter = 0;
    let mut writes = writes;
    loop {
        match tun.recv(&mut buf).await {
            Ok(n) => {
                if n > 0 {
                    let ports = get_ports_from_tun_frame(&buf[..n]);
                    let mut next_stream_index = counter % writes.len();
                    counter += 1;
                    if writes.len() > 1 {
                        if let Some((src_port, dst_port)) = ports {
                            let sticky_u16 = (src_port ^ dst_port) as usize;
                            next_stream_index = sticky_u16 % writes.len();
                        }
                    }

                    let target_write = writes.get_mut(next_stream_index).unwrap();
                    let write_result = write_lengthed_data(target_write, &buf[..n]).await;
                    match write_result {
                        Ok(_) => {
                            stats.increment_bytes_sent(n as u64);
                            stats.increment_packets_sent(1);
                            trace!("Sent {} bytes to stream {}", n, next_stream_index);
                        }
                        Err(e) => {
                            error!("Error writing to write stream {}: {}", next_stream_index, e);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Error reading from TUN device: {}", e);
                break;
            }
        }
    }
}

pub async fn copy_read_to_tun_multi(
    child_context: tokio_tree_context::Context,
    stats: Arc<Stats>,
    reads: Vec<RecvStream>,
    tun: Arc<AsyncDevice>,
) {
    let mut child_context = child_context;
    let mut join_handles = Vec::new();
    for read in reads {
        let tun_clone = Arc::clone(&tun);
        let new_child_context = child_context.new_child_context();
        let jh = child_context.spawn(copy_read_to_tun(new_child_context, stats.clone(), read, tun_clone));
        join_handles.push(jh);
    }

    if join_handles.is_empty() {
        return;
    }

    // Select the first completed handle
    let (result, _index, remaining) = select_all(join_handles).await;

    // Abort all remaining tasks
    for handle in remaining {
        handle.abort();
    }
    // Process the result of the first completed task
    match result {
        Ok(_) => {
            warn!("One copy_read_to_tun task completed successfully");
        }
        Err(e) => {
            error!("copy_read_to_tun task error: {:?}", e);
        }
    }
}

pub async fn copy_read_to_tun(
    _child_context: tokio_tree_context::Context,
    stats: Arc<Stats>,
    read: RecvStream,
    tun: Arc<AsyncDevice>,
) {
    let mut read = read;
    let mut buf = vec![0u8; 1600];
    loop {
        let read_result = read_lengthed_data(&mut read, &mut buf).await;
        match read_result {
            Ok(size) => {
                if let Err(e) = tun.send(&buf[..size]).await {
                    error!("Error writing to TUN device: {}", e);
                    break;
                }
                stats.increment_bytes_received(size as u64);
                stats.increment_packets_received(1);
                trace!("Received and wrote {} bytes to TUN device", size);
            }
            Err(e) => {
                error!("Error reading from read stream: {}", e);
                break;
            }
        }
    }
}

pub fn format_init_params(
    build_id: &str,
    number_of_streams: usize,
    mtu: u16,
    routes: &[String],
) -> String {
    let mut parts = Vec::new();
    parts.push(format!("{}={}", PARAM_BUILD_ID, build_id));
    parts.push(format!("{}={}", PARAM_NUMBER_OF_STREAMS, number_of_streams));
    parts.push(format!("{}={}", PARAM_MTU, mtu));
    for (idx, route) in routes.iter().enumerate() {
        parts.push(format!("{}{}={}", PARAM_ROUTE_PREFIX, idx, route));
    }
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

// Server waits for [0x00, 0x00] from client, sends [0x00, 0x00] to client.
pub async fn do_stream_handshake_server(
    send: &mut SendStream,
    recv: &mut RecvStream,
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

pub async fn keep_alive(send: SendStream, recv: RecvStream) -> Result<(), anyhow::Error> {
    let mut send = send;
    let mut recv = recv;
    let mut receive_buffer = [0u8; 200];
    //eprintln!("Starting keep-alive loop");
    loop {
        send.write_all(&[0x00u8]).await?;
        //println!("Sent keep-alive packet");
        let _n =
            tokio::time::timeout(Duration::from_secs(1), recv.read(&mut receive_buffer)).await?;
        //println!("Received keep-alive packet size {:?}", n);
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
        100..=1500,
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
    client_build_id: &str,
    default_streams: usize,
    mtu: u16,
    client_routes: &[String],
) -> Result<HashMap<String, String>, anyhow::Error> {
    let init_params_text = format_init_params(client_build_id, default_streams, mtu, client_routes);
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
    server_stream_count: usize,
    mtu: u16,
    server_routes: &[String],
) -> Result<HashMap<String, String>, anyhow::Error> {
    let (mut tmp_send, mut tmp_recv) = connection.accept_bi().await?;
    let init_bytes = tmp_recv.read_to_end(10 * 1024 * 1024).await?;
    let init_str = String::from_utf8_lossy(&init_bytes);
    trace!("Server received client config: {}", init_str);
    let client_params_map = parse_init_params(&init_str);
    let server_params_text =
        format_init_params(server_build_id, server_stream_count, mtu, server_routes);
    tmp_send.write_all(server_params_text.as_bytes()).await?;
    tmp_send.finish()?;
    Ok(client_params_map)
}

pub async fn open_bidi_streams_with_handshake(
    connection: &Connection,
    count: usize,
    handshake_fn: for<'a> fn(
        &'a mut SendStream,
        &'a mut RecvStream,
    ) -> core::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>,
    >,
) -> Result<(Vec<SendStream>, Vec<RecvStream>), anyhow::Error> {
    let mut send_streams = Vec::with_capacity(count);
    let mut recv_streams = Vec::with_capacity(count);
    info!("Opening {} bidirectional streams...", count);
    for i in 0..count {
        match connection.open_bi().await {
            Ok((mut send, mut recv)) => {
                if let Err(e) = (handshake_fn)(&mut send, &mut recv).await {
                    error!("Handshake failed for stream {}: {}", i + 1, e);
                    return Err(e);
                }
                send_streams.push(send);
                recv_streams.push(recv);
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
        send_streams.len(),
        count
    );
    Ok((send_streams, recv_streams))
}

pub async fn accept_bidi_streams_with_handshake(
    connection: &Connection,
    count: usize,
    per_stream_timeout: std::time::Duration,
    handshake_fn: for<'a> fn(
        &'a mut SendStream,
        &'a mut RecvStream,
    ) -> core::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>,
    >,
) -> Result<(Vec<SendStream>, Vec<RecvStream>), anyhow::Error> {
    let mut send_streams = Vec::with_capacity(count);
    let mut recv_streams = Vec::with_capacity(count);
    info!("Accepting {} streams from client", count);
    for i in 0..count {
        trace!("Waiting to accept stream {} of {}...", i + 1, count);
        let stream_result = tokio::time::timeout(per_stream_timeout, connection.accept_bi()).await;
        match stream_result {
            Ok(Ok((mut send, mut recv))) => {
                if let Err(e) = (handshake_fn)(&mut send, &mut recv).await {
                    error!("Handshake failed for stream {}: {}", i + 1, e);
                    return Err(e);
                }
                send_streams.push(send);
                recv_streams.push(recv);
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
    info!("Accepted {} out of {} streams", send_streams.len(), count);
    Ok((send_streams, recv_streams))
}

pub fn handshake_client_adapter<'a>(
    send: &'a mut SendStream,
    recv: &'a mut RecvStream,
) -> core::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
    Box::pin(do_stream_handshake_client(send, recv))
}

pub fn handshake_server_adapter<'a>(
    send: &'a mut SendStream,
    recv: &'a mut RecvStream,
) -> core::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
    Box::pin(do_stream_handshake_server(send, recv))
}

pub async fn apply_routes(
    ifindex: u32,
    params: &HashMap<String, String>,
) -> Result<(), anyhow::Error> {
    let mut routes_str = vec![];
    for (k, v) in params {
        if k.starts_with(PARAM_ROUTE_PREFIX) {
            routes_str.push(v.clone());
        }
    }
    apply_routes_inner(ifindex, &routes_str).await
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
                info!("Route {}/{} added to ifindex {}", actual_ip, actual_prefix, ifindex);
            }
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("File exists") || error_str.contains("(os error 17)") {
                    debug!("Route {}/{} already exists on ifindex {}", actual_ip, actual_prefix, ifindex);
                } else {
                    error!("Error adding route {}/{} to ifindex {}: {}", actual_ip, actual_prefix, ifindex, e);
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