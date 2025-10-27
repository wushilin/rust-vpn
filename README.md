# rust-vpn

A point-to-point VPN solution written in Rust with ChaCha20-Poly1305 encryption.

## Features

- Point-to-point VPN tunnel using TUN/TAP interfaces
- ChaCha20-Poly1305 authenticated encryption
- TCP-based transport
- Simple client/server architecture
- Minimal dependencies

## Requirements

- Rust 1.70 or higher
- Linux (tested on Ubuntu/Debian)
- Root privileges (for creating TUN interfaces)

## Building

```bash
cargo build --release
```

## Usage

### Generate an encryption key

First, generate a 32-byte random key and encode it in base64:

```bash
# Generate a random key
openssl rand -base64 32
```

Save this key - you'll need to use the same key on both server and client.

### Server Mode

Start the VPN server:

```bash
sudo ./target/release/rust-vpn server \
    --listen-addr 0.0.0.0 \
    --port 8888 \
    --tun-name tun0 \
    --tun-ip 10.0.0.1 \
    --netmask 255.255.255.0 \
    --key YOUR_BASE64_KEY_HERE
```

### Client Mode

Connect to the VPN server:

```bash
sudo ./target/release/rust-vpn client \
    --server SERVER_IP \
    --port 8888 \
    --tun-name tun0 \
    --tun-ip 10.0.0.2 \
    --netmask 255.255.255.0 \
    --key YOUR_BASE64_KEY_HERE
```

### Testing the Connection

Once both server and client are running, test the connection:

On the client:
```bash
ping 10.0.0.1
```

On the server:
```bash
ping 10.0.0.2
```

## Configuration Options

### Server Options

- `--listen-addr`: Address to listen on (default: 0.0.0.0)
- `--port`: Port to listen on (default: 8888)
- `--tun-name`: Name of the TUN interface (default: tun0)
- `--tun-ip`: IP address of the TUN interface (default: 10.0.0.1)
- `--netmask`: Netmask for the TUN interface (default: 255.255.255.0)
- `--key`: Base64-encoded 32-byte encryption key (required)

### Client Options

- `--server`: Server address to connect to (required)
- `--port`: Server port (default: 8888)
- `--tun-name`: Name of the TUN interface (default: tun0)
- `--tun-ip`: IP address of the TUN interface (default: 10.0.0.2)
- `--netmask`: Netmask for the TUN interface (default: 255.255.255.0)
- `--key`: Base64-encoded 32-byte encryption key (required)

## Security

- All traffic is encrypted using ChaCha20-Poly1305 authenticated encryption
- Each packet uses a unique random nonce
- The encryption key must be shared securely between server and client
- Transport uses TCP for reliable delivery

## Logging

Set the `RUST_LOG` environment variable to control logging verbosity:

```bash
RUST_LOG=debug sudo ./target/release/rust-vpn server ...
```

Logging levels: `error`, `warn`, `info`, `debug`, `trace`

## Architecture

The VPN creates a TUN interface on both server and client. Traffic flow:

1. Application writes IP packets to TUN interface
2. VPN reads packets from TUN
3. Packets are encrypted with ChaCha20-Poly1305
4. Encrypted packets are sent over TCP
5. Remote side receives and decrypts packets
6. Decrypted packets are written to remote TUN interface

## License

Apache-2.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

