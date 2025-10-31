# rust-vpn

A Point-to-Point VPN implementation in Rust using QUIC over TUN interfaces with mutual TLS authentication.

## Features

- **QUIC Protocol**: Uses QUIC for efficient, multiplexed transport with multiple bidirectional streams
- **Mutual TLS (mTLS)**: Both client and server authenticate with certificates
- **TUN Interface**: Creates and manages TUN network interfaces for packet forwarding
- **IPv4 and IPv6 Support**: Full support for both IPv4 and IPv6 addresses and routes
- **Stream Multiplexing**: Configurable number of bidirectional streams for parallel packet forwarding
- **Automatic Routing**: Configures routing tables automatically for advertised networks
- **Config Exchange**: Initialization handshake for parameter negotiation (build_id, stream count, MTU, routes)
- **Structured Logging**: Uses `tracing` for comprehensive, configurable logging

## Requirements

- Linux (requires TUN/TAP support)
- Root/sudo privileges (for TUN device creation and routing)
- TLS certificates (CA bundle, client/server certificates, and private keys)

## Usage

### Server Mode

```bash
sudo ./target/debug/rust-vpn server \
  --bind-address 0.0.0.0 \
  --port 4234 \
  --device tun0 \
  --ca-bundle /path/to/ca.pem \
  --server-cert /path/to/server.crt \
  --server-key /path/to/server.key \
  --ipv4 192.168.3.1/24 \
  --ipv6 2001:db8::1/64 \
  --remote-route 10.0.0.0/8 \
  --remote-route 172.16.0.0/12 \
  --stream-count 30 \
  --mtu 1500
```

**Arguments:**
- `-b, --bind-address <BIND_ADDRESS>`: IP address to bind to (IPv4 or IPv6, e.g., `0.0.0.0`, `::`)
- `--port <PORT>`: Port to listen on (e.g., 4234)
- `-d, --device <DEVICE>`: TUN device name (e.g., tun0)
- `--ca-bundle <CA_BUNDLE>`: CA bundle file (PEM format) for validating client certificates
- `--server-cert <SERVER_CERT>`: Server certificate file (PEM format)
- `--server-key <SERVER_KEY>`: Server private key file (PEM format)
- `--peer-cn <PEER_CN>`: (Optional) Expected peer (client) certificate common name (CN)
- `--stream-count <STREAM_COUNT>`: Number of bidirectional streams to use (default: 30, range: 1-100)
- `--mtu <MTU>`: MTU for TUN device (default: 1500, range: 100-1500)
- `--ipv4 <IPV4_CIDR>`: (Optional) IPv4 address with CIDR to assign to TUN device (e.g., 192.168.3.1/24)
- `--ipv6 <IPV6_CIDR>`: (Optional) IPv6 address with prefix length to assign to TUN device (e.g., 2001:db8::1/64)
- `--remote-route <CIDR>`: Remote routes to advertise (CIDR format, can be specified multiple times)

### Client Mode

```bash
sudo ./target/debug/rust-vpn client \
  --server server.example.com \
  --port 4234 \
  --device tun0 \
  --ca-bundle /path/to/ca.pem \
  --client-cert /path/to/client.crt \
  --client-key /path/to/client.key \
  --ipv4 192.168.3.2/24 \
  --ipv6 2001:db8::2/64 \
  --remote-route 10.0.0.0/8 \
  --stream-count 30 \
  --mtu 1500
```

**Arguments:**
- `--server <SERVER>`: Server hostname or IP (used for SNI in TLS handshake)
- `--port <PORT>`: Server port (e.g., 4234)
- `-d, --device <DEVICE>`: TUN device name (e.g., tun0)
- `--ca-bundle <CA_BUNDLE>`: CA bundle file (PEM format) for validating server certificates
- `--client-cert <CLIENT_CERT>`: Client certificate file (PEM format)
- `--client-key <CLIENT_KEY>`: Client private key file (PEM format)
- `--peer-cn <PEER_CN>`: (Optional) Expected peer (server) certificate common name (CN)
- `--stream-count <STREAM_COUNT>`: Number of bidirectional streams to use (default: 30, range: 1-100)
- `--mtu <MTU>`: MTU for TUN device (default: 1500, range: 100-1500)
- `--ipv4 <IPV4_CIDR>`: (Optional) IPv4 address with CIDR to assign to TUN device (e.g., 192.168.3.2/24)
- `--ipv6 <IPV6_CIDR>`: (Optional) IPv6 address with prefix length to assign to TUN device (e.g., 2001:db8::2/64)
- `--remote-route <CIDR>`: Remote routes to advertise (CIDR format, can be specified multiple times)

### CIDR Normalization

The tool automatically normalizes CIDR notation:
- `192.168.55.12/24` → `192.168.55.0/24`
- `10.0.0.5/16` → `10.0.0.0/16`
- `172.16.100.50/8` → `172.0.0.0/8`
- `2001:db8::1234/64` → `2001:db8::/64`

This ensures that routes use proper network addresses. Both IPv4 and IPv6 CIDR formats are supported.

## Building

```bash
cargo build
```

The build process requires the following environment variables (typically set by build scripts):
- `BUILD_BRANCH`: Build identifier (used for config exchange validation)
- `BUILD_TIME`: Build timestamp
- `BUILD_HOST`: Build hostname

## Configuration Exchange

Upon initial connection, the client and server exchange configuration parameters:

1. **Client sends** (over temporary stream): `build_id`, `number_of_streams`, `mtu`, `route_0`, `route_1`, etc.
2. **Server replies** with its own parameters in the same format
3. **Validation**: Both sides validate that:
   - `build_id` matches exactly
   - `number_of_streams` is between 1 and 100 (inclusive) and matches
   - `mtu` is between 100 and 1500 (inclusive) and matches

The format is: `key=value;key=value;...` (semicolon-separated key-value pairs).

## Route Handling

Routes are automatically included in the config exchange:
- **Local routes**: If `--ipv4` or `--ipv6` are provided, the corresponding network routes are automatically included (e.g., `192.168.3.1/24` becomes `192.168.3.0/24`)
- **Remote routes**: Any routes specified via `--remote-route` are normalized and included
- **Route application**: After successful config exchange, routes from both client and server are applied to the TUN device using the Linux netlink API

## Architecture

### Protocol Stack
- **Transport**: QUIC (using `quinn` crate)
- **Security**: TLS 1.3 with mutual authentication (using `rustls` with `aws-lc-rs` provider)
- **Network**: TUN interface for packet forwarding

### Connection Flow

1. **TLS Handshake**: Client and server establish QUIC connection with mutual TLS authentication
2. **Keep-Alive Stream**: A bidirectional keep-alive stream is established immediately
3. **Config Exchange**: Client and server exchange initialization parameters over a temporary stream
4. **Validation**: Both sides validate exchanged parameters
5. **TUN Device**: TUN device is created with optional IPv4/IPv6 addresses
6. **Route Application**: Routes are applied to the TUN device
7. **Stream Multiplexing**: Client opens and server accepts the negotiated number of bidirectional streams
8. **Packet Forwarding**: Packets are forwarded between TUN device and QUIC streams using port-based stream selection for load balancing

### Stream Selection

When multiple streams are available, packets are distributed based on:
- **Port-based hashing**: Packets are assigned to streams based on source/destination port XOR for consistent routing of related flows
- **Round-robin fallback**: If ports cannot be extracted (non-TCP/UDP packets), round-robin distribution is used

### Logging

The application uses `tracing` for structured logging. Set the `RUST_LOG` environment variable to control log levels:

```bash
# Show info and above
RUST_LOG=info ./target/debug/rust-vpn server ...

# Show debug and above
RUST_LOG=debug ./target/debug/rust-vpn server ...

# Show trace (most verbose)
RUST_LOG=trace ./target/debug/rust-vpn server ...
```

## Certificate Requirements

- **CA Bundle**: Must contain the root CA that signed both client and server certificates
- **Server Certificate**: Must have a Subject Alternative Name (SAN) matching the server hostname used by clients
  - Example: If clients connect to `server.example.com`, the certificate must include `server.example.com` or `*.example.com` in SAN
  - IPv4/IPv6 addresses can also be included in SAN
- **Client Certificate**: Signed by the CA in the bundle
- **Private Keys**: Must match their respective certificates

## Limitations

1. **Point-to-point only**: Server handles one client connection at a time. When the connection is dropped, server resumes listening for a new connection.
2. **Single TUN device**: One TUN device per instance
3. **Linux only**: Requires Linux TUN/TAP support and netlink for routing

## Packet Format

Packets are length-wrapped for reliable, atomic transmission:
```
+----------+----------+----------+-----------+---------------------+
| Magic[1] | Magic[2] |   Size   |  Size...  |      Payload        |
|  (1 byte)|  (1 byte)|  (4 bytes, BE)       |   (Variable length) |
+----------+----------+----------+-----------+---------------------+
```

- Magic bytes: `0x00 0xFF`
- Size: 4-byte big-endian integer
- Payload: Actual IP packet data

## IPv6 Support

The application supports IPv6 throughout:
- **IPv6 bind addresses**: Server can bind to IPv6 addresses (e.g., `::` or `[::]`)
- **IPv6 TUN addresses**: TUN devices can be assigned IPv6 addresses with prefix length
- **IPv6 routes**: IPv6 routes in CIDR notation are fully supported
- **IPv6 packet parsing**: Source and destination ports are extracted from IPv6 packets, including traversal of extension headers

Note: Client currently binds to IPv4 only (`0.0.0.0:0`) but can connect to IPv6 servers. This may be enhanced in future versions to support dual-stack binding.
