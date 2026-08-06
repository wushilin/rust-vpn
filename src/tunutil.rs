use anyhow::Context;
use std::sync::Arc;
use tracing::{debug, info};
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::utils;

/// Linux is the only platform with multi-queue TUN support (`IFF_MULTI_QUEUE` plus
/// `AsyncDevice::try_clone`). Everywhere else all workers share the single queue.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub const MULTI_QUEUE_SUPPORTED: bool = true;
#[cfg(not(all(target_os = "linux", not(target_env = "ohos"))))]
pub const MULTI_QUEUE_SUPPORTED: bool = false;

/// Open an extra queue on an already created TUN device.
///
/// On Linux this duplicates the underlying fd so each worker gets its own queue.
/// On other platforms there is no multi-queue support, so the same device is shared:
/// `AsyncDevice::send`/`recv` take `&self`, so this is correct, just less parallel.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub fn open_extra_queue(device: &Arc<AsyncDevice>) -> Result<Arc<AsyncDevice>, anyhow::Error> {
    let cloned = device.try_clone()?;
    Ok(Arc::new(cloned))
}

#[cfg(not(all(target_os = "linux", not(target_env = "ohos"))))]
pub fn open_extra_queue(device: &Arc<AsyncDevice>) -> Result<Arc<AsyncDevice>, anyhow::Error> {
    Ok(device.clone())
}

#[cfg(target_os = "linux")]
fn with_multi_queue(builder: DeviceBuilder) -> DeviceBuilder {
    builder.multi_queue(true)
}

#[cfg(not(target_os = "linux"))]
fn with_multi_queue(builder: DeviceBuilder) -> DeviceBuilder {
    builder
}

#[cfg(not(target_os = "macos"))]
fn with_device_name(builder: DeviceBuilder, device_name: &str) -> DeviceBuilder {
    builder.name(device_name)
}

/// macOS only accepts `utun<N>` names - the kernel control socket rejects anything else.
/// For any other requested name we let the system pick the next free unit instead of failing.
#[cfg(target_os = "macos")]
fn with_device_name(builder: DeviceBuilder, device_name: &str) -> DeviceBuilder {
    let is_utun = device_name
        .strip_prefix("utun")
        .map(|unit| unit.parse::<u32>().is_ok())
        .unwrap_or(false);
    if is_utun {
        builder.name(device_name)
    } else {
        tracing::warn!(
            "macOS TUN devices must be named utun<N>; ignoring requested name '{}' and letting the system assign one",
            device_name
        );
        builder
    }
}

/// Only Linux exposes interfaces through sysfs. On other platforms we skip the check:
/// creating a device that is already in use fails with a clear OS error anyway.
#[cfg(target_os = "linux")]
async fn tun_exists(device_name: &str) -> bool {
    let sys_path = format!("/sys/class/net/{device_name}");
    if tokio::fs::metadata(&sys_path).await.is_ok() {
        return true;
    }
    return false;
}

#[cfg(not(target_os = "linux"))]
async fn tun_exists(_device_name: &str) -> bool {
    false
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
    let mut builder = DeviceBuilder::new().mtu(mtu);
    builder = with_device_name(builder, &device_name);
    builder = with_multi_queue(builder);

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
    let actual_name = tun.name().unwrap_or_else(|_| device_name.clone());
    info!("Created TUN device: {}", actual_name);
    let if_index = tun.if_index()
        .context(format!("TUN device '{}' does not have an interface index", actual_name))?;
    utils::apply_routes_direct(if_index, &routes).await?;
    info!("Routes applied successfully (one-time setup)");
    debug!("TUN device ifindex: {}", if_index);
    Ok(tun)
}
