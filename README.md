# rust-vpn

A Point-to-Point VPN implementation in Rust supporting both QUIC and TCP protocols over TUN interfaces with mutual TLS authentication.

## Features

- **Multiple Transport Protocols**: Supports both QUIC and TCP with separate implementations
- **Separate Control/Data Planes (TCP)**: TCP implementation uses dedicated control plane (TLS) and data plane (TLS) for configuration and data transfer
- **Mutual TLS (mTLS)**: Both client and server authenticate with certificates
- **Token-Based Authentication**: TCP implementation uses token-based session authentication
- **TUN Interface**: Creates and manages TUN network interfaces for packet forwarding
- **IPv4 and IPv6 Support**: Full support for both IPv4 and IPv6 addresses and routes
- **Stream Multiplexing**: Configurable number of bidirectional streams/connections for parallel packet forwarding
- **Automatic Routing**: Configures routing tables automatically for advertised networks
- **Config Exchange**: Initialization handshake for parameter negotiation (build_id, stream count, MTU, token)
- **Structured Logging**: Uses `tracing` for comprehensive, configurable logging

## Requirements

- Linux (requires TUN/TAP support)
- Root/sudo privileges (for TUN device creation and routing)
- TLS certificates (CA bundle, client/server certificates, and private keys)

## Usage

### QUIC Server Mode

```bash
sudo ./target/debug/rust-vpn server \
  --bind-address 0.0.0.0 \
  --port 1105 \
  --device rustvpn \
  --ca-bundle ca.pem \
  --server-cert server.pem \
  --server-key server.key \
  --ipv4 192.168.3.1/24 \
  --ipv6 2001:db8::1/64 \
  --route 10.0.0.0/8 \
  --stream-count 5 \
  --mtu 1500
```

**Arguments:**
- `-b, --bind-address <BIND_ADDRESS>`: IP address to bind to (IPv4 or IPv6, default: `0.0.0.0`)
- `--port <PORT>`: Port to listen on (default: 1105)
- `-d, --device <DEVICE>`: TUN device name (default: `rustvpn`)
- `--ca-bundle <CA_BUNDLE>`: CA bundle file (PEM format) for validating client certificates (default: `ca.pem`)
- `--server-cert <SERVER_CERT>`: Server certificate file (PEM format) (default: `server.pem`)
- `--server-key <SERVER_KEY>`: Server private key file (PEM format) (default: `server.key`)
- `--peer-cn <PEER_CN>`: (Optional) Expected peer (client) certificate common name (CN)
- `--stream-count <STREAM_COUNT>`: Number of bidirectional streams to use (default: 5, range: 1-100)
- `--mtu <MTU>`: MTU for TUN device (default: 1500, range: 100-1500)
- `--ipv4 <IPV4_CIDR>`: (Optional) IPv4 address with CIDR to assign to TUN device (e.g., 192.168.3.1/24)
- `--ipv6 <IPV6_CIDR>`: (Optional) IPv6 address with prefix length to assign to TUN device (e.g., 2001:db8::1/64)
- `--route <CIDR>`: Local routes to set up (CIDR format, can be specified multiple times)

### QUIC Client Mode

```bash
sudo ./target/debug/rust-vpn client \
  --server server.example.com \
  --port 1105 \
  --device rustvpn \
  --ca-bundle ca.pem \
  --client-cert client.pem \
  --client-key client.key \
  --ipv4 192.168.3.2/24 \
  --ipv6 2001:db8::2/64 \
  --route 10.0.0.0/8 \
  --stream-count 5 \
  --mtu 1500
```

**Arguments:**
- `--server <SERVER>`: Server hostname or IP (used for SNI in TLS handshake)
- `--port <PORT>`: Server port (default: 1105)
- `-d, --device <DEVICE>`: TUN device name (default: `rustvpn`)
- `--ca-bundle <CA_BUNDLE>`: CA bundle file (PEM format) for validating server certificates (default: `ca.pem`)
- `--client-cert <CLIENT_CERT>`: Client certificate file (PEM format) (default: `client.pem`)
- `--client-key <CLIENT_KEY>`: Client private key file (PEM format) (default: `client.key`)
- `--peer-cn <PEER_CN>`: (Optional) Expected peer (server) certificate common name (CN)
- `--stream-count <STREAM_COUNT>`: Number of bidirectional streams to use (default: 5, range: 1-100)
- `--mtu <MTU>`: MTU for TUN device (default: 1500, range: 100-1500)
- `--ipv4 <IPV4_CIDR>`: (Optional) IPv4 address with CIDR to assign to TUN device (e.g., 192.168.3.2/24)
- `--ipv6 <IPV6_CIDR>`: (Optional) IPv6 address with prefix length to assign to TUN device (e.g., 2001:db8::2/64)
- `--route <CIDR>`: Local routes to set up (CIDR format, can be specified multiple times)

### TCP Server Mode

The TCP server uses separate control and data planes:
- **Control Plane**: TLS connection for configuration exchange (default port: 1107)
- **Data Plane**: TLS connections for actual data transfer (default port: 1108)

```bash
sudo ./target/debug/rust-vpn tcpserver \
  --control-bind-address 0.0.0.0 \
  --control-port 1107 \
  --data-bind-address 0.0.0.0 \
  --data-port 1108 \
  --device rustvpn \
  --ca-bundle ca.pem \
  --server-cert server.pem \
  --server-key server.key \
  --ipv4 192.168.3.1/24 \
  --ipv6 2001:db8::1/64 \
  --route 10.0.0.0/8 \
  --stream-count 5 \
  --mtu 1500
```

**Arguments:**
- `--control-bind-address <ADDRESS>`: IP address to bind control plane to (default: `0.0.0.0`)
- `--control-port <PORT>`: Port for control plane (TLS) (default: 1107)
- `--data-bind-address <ADDRESS>`: IP address to bind data plane to (default: `0.0.0.0`)
- `--data-port <PORT>`: Port for data plane (TLS) (default: 1108)
- `-d, --device <DEVICE>`: TUN device name (default: `rustvpn`)
- `--ca-bundle <CA_BUNDLE>`: CA bundle file (PEM format) for validating client certificates (default: `ca.pem`)
- `--server-cert <SERVER_CERT>`: Server certificate file (PEM format) (default: `server.pem`)
- `--server-key <SERVER_KEY>`: Server private key file (PEM format) (default: `server.key`)
- `--peer-cn <PEER_CN>`: (Optional) Expected peer (client) certificate common name (CN)
- `--stream-count <STREAM_COUNT>`: Number of data plane connections to use (default: 5)
- `--mtu <MTU>`: MTU for TUN device (default: 1500, range: 100-1500)
- `--ipv4 <IPV4_CIDR>`: (Optional) IPv4 address with CIDR to assign to TUN device (e.g., 192.168.3.1/24)
- `--ipv6 <IPV6_CIDR>`: (Optional) IPv6 address with prefix length to assign to TUN device (e.g., 2001:db8::1/64)
- `--route <CIDR>`: Local routes to set up (CIDR format, can be specified multiple times)

### TCP Client Mode

```bash
sudo ./target/debug/rust-vpn tcpclient \
  --server server.example.com \
  --control-port 1107 \
  --data-port 1108 \
  --device rustvpn \
  --ca-bundle ca.pem \
  --client-cert client.pem \
  --client-key client.key \
  --ipv4 192.168.3.2/24 \
  --ipv6 2001:db8::2/64 \
  --route 10.0.0.0/8 \
  --stream-count 5 \
  --mtu 1500
```

**Arguments:**
- `--server <SERVER>`: Server hostname or IP (used for SNI in TLS handshake)
- `--control-port <PORT>`: Control plane port (TLS) (default: 1107)
- `--data-port <PORT>`: Data plane port (TLS) (default: 1108)
- `-d, --device <DEVICE>`: TUN device name (default: `rustvpn`)
- `--ca-bundle <CA_BUNDLE>`: CA bundle file (PEM format) for validating server certificates (default: `ca.pem`)
- `--client-cert <CLIENT_CERT>`: Client certificate file (PEM format) (default: `client.pem`)
- `--client-key <CLIENT_KEY>`: Client private key file (PEM format) (default: `client.key`)
- `--peer-cn <PEER_CN>`: (Optional) Expected peer (server) certificate common name (CN)
- `--stream-count <STREAM_COUNT>`: Number of data plane connections to establish (default: 5)
- `--mtu <MTU>`: MTU for TUN device (default: 1500, range: 100-1500)
- `--ipv4 <IPV4_CIDR>`: (Optional) IPv4 address with CIDR to assign to TUN device (e.g., 192.168.3.2/24)
- `--ipv6 <IPV6_CIDR>`: (Optional) IPv6 address with prefix length to assign to TUN device (e.g., 2001:db8::2/64)
- `--route <CIDR>`: Local routes to set up (CIDR format, can be specified multiple times)

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

### QUIC Protocol

1. **Client sends** (over temporary stream): `build_id`, `number_of_streams`, `mtu`, etc.
2. **Server replies** with its own parameters in the same format
3. **Validation**: Both sides validate that:
   - `build_id` matches exactly
   - `number_of_streams` is between 1 and 100 (inclusive) and matches
   - `mtu` is between 100 and 1500 (inclusive) and matches

### TCP Protocol

1. **Control Plane Connection**: Client establishes TLS connection to control plane port
2. **Token Generation**: Both client and server generate authentication tokens
3. **Config Exchange**: Client and server exchange:
   - `build_id`
   - `token` (authentication token for session)
   - `number_of_streams`
   - `mtu`
4. **Data Plane Connection**: Client establishes multiple TLS connections to data plane port, each presenting the token for authentication
5. **Validation**: Both sides validate exchanged parameters

The format is: `key=value;key=value;...` (semicolon-separated key-value pairs).

## Route Handling

Routes are configured locally on each side:
- **Local routes**: If `--ipv4` or `--ipv6` are provided, the corresponding network routes are automatically included (e.g., `192.168.3.1/24` becomes `192.168.3.0/24`)
- **Explicit routes**: Any routes specified via `--route` are normalized and applied
- **Route application**: Routes are applied to the TUN device using the Linux netlink API

## Architecture

### Protocol Stack

**QUIC Implementation:**
- **Transport**: QUIC (using `quinn` crate)
- **Security**: TLS 1.3 with mutual authentication (using `rustls` with `aws-lc-rs` provider)
- **Network**: TUN interface for packet forwarding

**TCP Implementation:**
- **Transport**: TCP with TLS for both control and data planes
- **Security**: TLS 1.3 with mutual authentication (using `tokio-rustls` with `rustls` and `aws-lc-rs` provider)
- **Network**: TUN interface for packet forwarding
- **Control Plane**: Separate TLS connection for configuration exchange
- **Data Plane**: Multiple TLS connections for parallel data transfer
- **Authentication**: Token-based session authentication for data plane connections

### Connection Flow

**QUIC:**
1. **TLS Handshake**: Client and server establish QUIC connection with mutual TLS authentication
2. **Keep-Alive Stream**: A bidirectional keep-alive stream is established immediately
3. **Config Exchange**: Client and server exchange initialization parameters over a temporary stream
4. **Validation**: Both sides validate exchanged parameters
5. **TUN Device**: TUN device is created with optional IPv4/IPv6 addresses
6. **Route Application**: Routes are applied to the TUN device
7. **Stream Multiplexing**: Client opens and server accepts the negotiated number of bidirectional streams
8. **Packet Forwarding**: Packets are forwarded between TUN device and QUIC streams using port-based stream selection for load balancing

**TCP:**
1. **Control Plane TLS**: Client establishes TLS connection to control plane port
2. **Token Generation**: Both sides generate authentication tokens
3. **Config Exchange**: Client and server exchange configuration and tokens over control plane
4. **TUN Device**: TUN device is created with optional IPv4/IPv6 addresses
5. **Route Application**: Routes are applied to the TUN device
6. **Data Plane Connections**: Client establishes multiple TLS connections to data plane port, authenticating with tokens
7. **Packet Forwarding**: Packets are forwarded between TUN device and TCP connections

### Stream Selection

When multiple streams/connections are available, packets are distributed based on:
- **Port-based hashing**: Packets are assigned to streams based on source/destination port XOR for consistent routing of related flows
- **Round-robin fallback**: If ports cannot be extracted (non-TCP/UDP packets), round-robin distribution is used

### TCP No-Delay

All TCP sockets have `TCP_NODELAY` enabled to reduce latency by disabling Nagle's algorithm.

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

**Default Certificate File Names:**
- CA bundle: `ca.pem`
- Server certificate: `server.pem`
- Server key: `server.key`
- Client certificate: `client.pem`
- Client key: `client.key`

## Limitations

1. **Point-to-point only**: Server handles one client connection at a time. When the connection is dropped, server resumes listening for a new connection.
2. **Single TUN device**: One TUN device per instance
3. **Linux only**: Requires Linux TUN/TAP support and netlink for routing

## Packet Format

Packets are length-prefixed for reliable, atomic transmission:

```
+----------+---------------------+
|   Size   |      Payload        |
| (2 bytes, BE) | (Variable length) |
+----------+---------------------+
```

- Size: 2-byte big-endian integer (u16)
- Payload: Actual IP packet data

## IPv6 Support

The application supports IPv6 throughout:
- **IPv6 bind addresses**: Server can bind to IPv6 addresses (e.g., `::` or `[::]`)
- **IPv6 TUN addresses**: TUN devices can be assigned IPv6 addresses with prefix length
- **IPv6 routes**: IPv6 routes in CIDR notation are fully supported
- **IPv6 packet parsing**: Source and destination ports are extracted from IPv6 packets, including traversal of extension headers

Note: Client currently binds to IPv4 only (`0.0.0.0:0`) but can connect to IPv6 servers. This may be enhanced in future versions to support dual-stack binding.
