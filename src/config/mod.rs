use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use base64::{Engine as _, engine::general_purpose};

#[derive(Parser, Debug)]
#[command(name = "rust-vpn")]
#[command(about = "A point-to-point VPN solution written in Rust", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run VPN in server mode
    Server(ServerArgs),
    /// Run VPN in client mode
    Client(ClientArgs),
}

#[derive(Args, Debug)]
pub struct ServerArgs {
    /// Listening address
    #[arg(short, long, default_value = "0.0.0.0")]
    pub listen_addr: String,

    /// Listening port
    #[arg(short, long, default_value = "8888")]
    pub port: u16,

    /// TUN interface name
    #[arg(short, long, default_value = "tun0")]
    pub tun_name: String,

    /// TUN interface IP address
    #[arg(short, long, default_value = "10.0.0.1")]
    pub tun_ip: IpAddr,

    /// TUN interface netmask
    #[arg(short = 'm', long, default_value = "255.255.255.0")]
    pub netmask: IpAddr,

    /// Encryption key (base64 encoded, 32 bytes)
    #[arg(short, long)]
    pub key: String,
}

#[derive(Args, Debug)]
pub struct ClientArgs {
    /// Server address to connect to
    #[arg(short, long)]
    pub server: String,

    /// Server port
    #[arg(short, long, default_value = "8888")]
    pub port: u16,

    /// TUN interface name
    #[arg(short, long, default_value = "tun0")]
    pub tun_name: String,

    /// TUN interface IP address
    #[arg(short = 'i', long, default_value = "10.0.0.2")]
    pub tun_ip: IpAddr,

    /// TUN interface netmask
    #[arg(short = 'm', long, default_value = "255.255.255.0")]
    pub netmask: IpAddr,

    /// Encryption key (base64 encoded, 32 bytes)
    #[arg(short, long)]
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub tun_name: String,
    pub tun_ip: IpAddr,
    pub netmask: IpAddr,
    pub key: Vec<u8>,
}

impl Config {
    pub fn from_server_args(args: &ServerArgs) -> anyhow::Result<Self> {
        let key = general_purpose::STANDARD.decode(&args.key)?;
        if key.len() != 32 {
            anyhow::bail!("Key must be 32 bytes (256 bits)");
        }
        
        Ok(Config {
            tun_name: args.tun_name.clone(),
            tun_ip: args.tun_ip,
            netmask: args.netmask,
            key,
        })
    }

    pub fn from_client_args(args: &ClientArgs) -> anyhow::Result<Self> {
        let key = general_purpose::STANDARD.decode(&args.key)?;
        if key.len() != 32 {
            anyhow::bail!("Key must be 32 bytes (256 bits)");
        }
        
        Ok(Config {
            tun_name: args.tun_name.clone(),
            tun_ip: args.tun_ip,
            netmask: args.netmask,
            key,
        })
    }
}
