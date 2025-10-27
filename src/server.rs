use crate::config::Config;
use crate::crypto::Crypto;
use crate::tunnel::TunDevice;
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const MAX_PACKET_SIZE: usize = 2048;

pub async fn run_server(listen_addr: String, port: u16, config: Config) -> Result<()> {
    log::info!("Starting VPN server on {}:{}", listen_addr, port);

    // Create TUN device
    let mut tun = TunDevice::new(&config.tun_name, config.tun_ip, config.netmask)?;

    // Create crypto
    let crypto = Arc::new(Crypto::new(&config.key)?);

    // Bind to TCP port
    let addr = format!("{}:{}", listen_addr, port);
    let listener = TcpListener::bind(&addr).await?;
    log::info!("Server listening on {}", addr);

    // Accept only one client for point-to-point VPN
    let (socket, peer_addr) = listener.accept().await?;
    log::info!("Client connected from {}", peer_addr);

    // Split socket for reading and writing
    let (mut socket_read, socket_write) = socket.into_split();

    // Wrap socket_write in Arc<Mutex> for sharing between tasks
    let socket_write = Arc::new(Mutex::new(socket_write));
    let socket_write_clone = socket_write.clone();
    let crypto_clone = crypto.clone();

    // Task: TUN -> Socket (encrypt and send)
    let tun_to_socket = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        loop {
            match tun.read(&mut buf) {
                Ok(n) => {
                    if n == 0 {
                        continue;
                    }
                    
                    log::debug!("Read {} bytes from TUN", n);

                    // Encrypt packet
                    match crypto_clone.encrypt(&buf[..n]) {
                        Ok(encrypted) => {
                            // Send length prefix (4 bytes) + encrypted data
                            let len = encrypted.len() as u32;
                            let mut write_guard = socket_write_clone.lock().await;
                            
                            if let Err(e) = write_guard.write_all(&len.to_be_bytes()).await {
                                log::error!("Failed to write length: {}", e);
                                break;
                            }
                            
                            if let Err(e) = write_guard.write_all(&encrypted).await {
                                log::error!("Failed to write encrypted data: {}", e);
                                break;
                            }
                            
                            log::debug!("Sent {} encrypted bytes to socket", encrypted.len());
                        }
                        Err(e) => {
                            log::error!("Encryption failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to read from TUN: {}", e);
                    break;
                }
            }
        }
    });

    // Task: Socket -> TUN (receive and decrypt)
    let socket_to_tun = tokio::spawn(async move {
        let mut tun = TunDevice::new(&config.tun_name, config.tun_ip, config.netmask)
            .expect("Failed to recreate TUN device");
        
        loop {
            // Read length prefix
            let mut len_buf = [0u8; 4];
            if let Err(e) = socket_read.read_exact(&mut len_buf).await {
                log::error!("Failed to read length: {}", e);
                break;
            }
            
            let len = u32::from_be_bytes(len_buf) as usize;
            
            if len > MAX_PACKET_SIZE * 2 {
                log::error!("Packet too large: {} bytes", len);
                break;
            }

            // Read encrypted data
            let mut encrypted = vec![0u8; len];
            if let Err(e) = socket_read.read_exact(&mut encrypted).await {
                log::error!("Failed to read encrypted data: {}", e);
                break;
            }
            
            log::debug!("Received {} encrypted bytes from socket", len);

            // Decrypt packet
            match crypto.decrypt(&encrypted) {
                Ok(decrypted) => {
                    log::debug!("Decrypted {} bytes", decrypted.len());
                    
                    // Write to TUN
                    if let Err(e) = tun.write(&decrypted) {
                        log::error!("Failed to write to TUN: {}", e);
                    }
                }
                Err(e) => {
                    log::error!("Decryption failed: {}", e);
                }
            }
        }
    });

    // Wait for both tasks
    tokio::try_join!(tun_to_socket, socket_to_tun)?;

    Ok(())
}
