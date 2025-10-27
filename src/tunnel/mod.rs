use anyhow::Result;
use std::io::{Read, Write};
use std::net::IpAddr;
use tun::platform::Device as PlatformDevice;
use tun::{Configuration, Device, Layer};

pub struct TunDevice {
    device: PlatformDevice,
}

impl TunDevice {
    pub fn new(name: &str, ip: IpAddr, netmask: IpAddr) -> Result<Self> {
        let mut config = Configuration::default();

        config
            .name(name)
            .address(ip)
            .netmask(netmask)
            .layer(Layer::L3)
            .up();

        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(false);
        });

        let device = tun::create(&config)?;
        
        log::info!("Created TUN device: {}", name);
        log::info!("  Address: {}", ip);
        log::info!("  Netmask: {}", netmask);

        Ok(TunDevice { device })
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.device.read(buf).map_err(Into::into)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.device.write(buf).map_err(Into::into)
    }

    pub fn get_mtu(&self) -> Result<i32> {
        self.device.mtu().map_err(Into::into)
    }
}
