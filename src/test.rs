use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::sync::mpsc;
use tun_rs::{DeviceBuilder, SyncDevice};

#[derive(Parser)]
#[command(name = "test")]
#[command(about = "Test VPN client and server")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Run as server
    Server {
        /// Bind address (e.g., 0.0.0.0:4233)
        #[arg(short, long)]
        bind: String,
        /// TUN device name
        #[arg(short, long)]
        device: String,
        /// Number of connections
        #[arg(short = 'n', long, default_value = "1")]
        connections: usize,
    },
    /// Run as client
    Client {
        /// Remote server address (e.g., 123.42.33.44:4233)
        #[arg(short, long)]
        remote: String,
        /// TUN device name
        #[arg(short, long)]
        device: String,
        /// Number of connections
        #[arg(short = 'n', long, default_value = "1")]
        connections: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Server { bind, device, connections } => {
            println!("Starting test server on {} with device {}, {} connections", bind, device, connections);
            run_server(&bind, &device, connections)?;
        }
        Mode::Client { remote, device, connections } => {
            println!("Starting test client connecting to {} with device {}, {} connections", remote, device, connections);
            run_client(&remote, &device, connections)?;
        }
    }

    Ok(())
}

fn clone_streams(streams: &Vec<std::net::TcpStream>) -> Vec<std::net::TcpStream> {
    let mut streams_clone = vec![];
    for stream in streams {
        streams_clone.push(stream.try_clone().expect("Failed to clone stream"));
    }
    return streams_clone;
}

fn run_server(bind: &str, device: &str, connections: usize) -> Result<()> {
    // Create TUN device
    let tun = create_tun(device)?;
    println!("Created TUN device {}", device);

    // Listen for connections
    let listener = TcpListener::bind(bind)
        .context("Failed to bind to address")?;
    
    println!("Server listening on {}", bind);

    // Accept N connections
    let mut streams = Vec::new();
    for i in 0..connections {
        let (stream, peer_addr) = listener.accept()?;
        stream.set_nodelay(true)
            .context("Failed to set TCP_NODELAY on server stream")?;
        println!("Connection {} connected from {}", i + 1, peer_addr);
        streams.push(stream);
    }
    println!("All {} connections established", connections);

    // Wrap TUN device in Arc for sharing
    let tun = Arc::new(tun);

    let streams_clone = clone_streams(&streams);
    // Create channel to detect when any thread exits
    let (sender, receiver) = mpsc::channel();

    // Thread 1: Copy from TUN to TCP (randomly select socket)
    let tun_clone = Arc::clone(&tun);
    let sender1 = sender.clone();
    
    let handle1 = thread::spawn(move || {
        copy_tun_to_tcp_multi(tun_clone, streams_clone);
        let _ = sender1.send("tun_to_tcp".into());
    });

    // Thread 2-N+1: Copy from each TCP to TUN
    let mut handles = Vec::new();
    for (i, stream) in streams.into_iter().enumerate() {
        let tun_clone = Arc::clone(&tun);
        let sender_clone = sender.clone();
        handles.push(thread::spawn(move || {
            copy_tcp_to_tun_single(tun_clone, stream);
            let thread_name = format!("tcp_to_tun_thread_{}", i + 2);
            let _ = sender_clone.send(thread_name);
        }));
    }

    // Wait for any thread to exit
    receiver.recv().expect("Channel error");
    println!("One of the threads exited, shutting down...");
    
    // Wait for all threads to complete
    let _ = handle1.join();
    for handle in handles {
        let _ = handle.join();
    }
    println!("All threads finished.");

    Ok(())
}

fn run_client(remote: &str, device: &str, connections: usize) -> Result<()> {
    // Create TUN device
    let tun = create_tun(device)?;
    println!("Created TUN device {}", device);

    // Connect to server N times
    let mut streams = Vec::new();
    for i in 0..connections {
        let stream = std::net::TcpStream::connect(remote)
            .context("Failed to connect to server")?;
        stream.set_nodelay(true)
            .context("Failed to set TCP_NODELAY on client stream")?;
        println!("Connection {} established to server {}", i + 1, remote);
        streams.push(stream);
    }
    println!("All {} connections established", connections);

    // Wrap TUN device in Arc for sharing
    let tun = Arc::new(tun);

    let streams_clone = clone_streams(&streams);
    // Create channel to detect when any thread exits
    let (sender, receiver) = mpsc::channel();

    // Thread 1: Copy from TUN to TCP (randomly select socket)
    let tun_clone = Arc::clone(&tun);
    let sender1 = sender.clone();
    
    let handle1 = thread::spawn(move || {
        copy_tun_to_tcp_multi(tun_clone, streams_clone);
        let _ = sender1.send("tun_to_tcp".into());
    });

    // Thread 2-N+1: Copy from each TCP to TUN
    let mut handles = Vec::new();
    for (i, stream) in streams.into_iter().enumerate() {
        let tun_clone = Arc::clone(&tun);
        let sender_clone = sender.clone();
        handles.push(thread::spawn(move || {
            copy_tcp_to_tun_single(tun_clone, stream);
            let thread_name = format!("tcp_to_tun_thread_{}", i + 2);
            let _ = sender_clone.send(thread_name);
        }));
    }

    // Wait for any thread to exit
    receiver.recv().expect("Channel error");
    println!("One of the threads exited, shutting down...");
    
    // Wait for all threads to complete
    let _ = handle1.join();
    for handle in handles {
        let _ = handle.join();
    }
    println!("All threads finished.");

    Ok(())
}

fn copy_tun_to_tcp_multi(tun: Arc<SyncDevice>, mut streams: Vec<std::net::TcpStream>) {
    let mut buf = vec![0u8; 1600];
    let mut counter = 0;
    
    loop {
        match tun.recv(&mut buf) {
            Ok(n) if n > 0 => {
                // Prepend 2-byte big-endian length
                let length_bytes = (n as u16).to_be_bytes();
                
                // Round-robin selection for load balancing
                let stream_idx = counter % streams.len();
                let stream = &mut streams[stream_idx];
                
                // Write length + payload
                if let Err(e) = stream.write_all(&length_bytes) {
                    eprintln!("Error writing length to TCP: {}", e);
                    break;
                }
                if let Err(e) = stream.write_all(&buf[..n]) {
                    eprintln!("Error writing to TCP: {}", e);
                    break;
                }
                if let Err(e) = stream.flush() {
                    eprintln!("Error flushing TCP: {}", e);
                    break;
                }
                //println!("Copied {} bytes from TUN to TCP (socket {})", n, stream_idx);
                counter += 1;
            }
            Ok(_) => {
                println!("TUN device closed");
                break;
            }
            Err(e) => {
                eprintln!("Error reading from TUN: {}", e);
                break;
            }
        }
    }
}

fn copy_tcp_to_tun_single(tun: Arc<SyncDevice>, stream: std::net::TcpStream) {
    let mut length_buf = [0u8; 2];
    let mut payload = vec![0u8; 1024*1024]; // 2 bytes for length + payload
    let mut stream = stream;
    loop {
        // First, read the 2-byte length header
        match stream.read_exact(&mut length_buf) {
            Ok(_) => {
                // Parse big-endian length
                let packet_length = u16::from_be_bytes(length_buf) as usize;
                
                if packet_length == 0 || packet_length > 1024*1024 {
                    eprintln!("Invalid packet length: {}", packet_length);
                    break;
                }
                
                // Read exactly that many bytes
                match stream.read_exact(&mut payload[..packet_length]) {
                    Ok(_) => {
                        // Write to TUN device
                        if let Err(e) = tun.send(&payload[..packet_length]) {
                            eprintln!("Error writing to TUN: {}", e);
                            break;
                        }
                        //println!("Copied {} bytes from TCP to TUN", packet_length);
                    }
                    Err(e) => {
                        eprintln!("Error reading payload from TCP: {}", e);
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading length header from TCP: {}", e);
                break;
            }
        }
    }
}

fn create_tun(name: &str) -> Result<SyncDevice, anyhow::Error> {
    let dev = DeviceBuilder::new()
        .mtu(1500)
        .name(name)
        .multi_queue(true)
        .build_sync()?;

    Ok(dev)
}
