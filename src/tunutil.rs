use anyhow::Context;
use tracing::{debug, info};
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::utils;


async fn tun_exists(device_name: &str) -> bool {
    let sys_path = format!("/sys/class/net/{device_name}");
    if tokio::fs::metadata(&sys_path).await.is_ok() {
        return true;
    }
    return false;
}
pub async fn create_tun(
    device_name: String, 
    mtu: u16, 
    ipv4:Option<String>, 
    ipv6:Option<String>, 
    routes:Vec<String>
) -> Result<AsyncDevice, anyhow::Error> {
    if tun_exists(&device_name).await {
        info!("TUN device {} already exists", device_name);
        return Err(anyhow::anyhow!("TUN device {} already exists", device_name));
    }

    info!("Creating TUN device: {}", device_name);
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

    let tun = builder
        .build_async()
        .map_err(|e| anyhow::anyhow!("Failed to create TUN device: {}", e))?;
    info!("Created TUN device: {}", device_name);
    let if_index = tun.if_index()
        .context(format!("TUN device '{}' does not have an interface index", device_name))?;
    utils::apply_routes_direct(if_index, &routes).await?;
    info!("Routes applied successfully (one-time setup)");
    debug!("TUN device ifindex: {}", if_index);
    Ok(tun)
}