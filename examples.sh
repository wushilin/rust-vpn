#!/bin/bash
# Example usage script for rust-vpn
# This demonstrates setting up a local test environment

set -e

echo "Building rust-vpn..."
cargo build --release

echo ""
echo "Generating encryption key..."
KEY=$(openssl rand -base64 32)
echo "Key: $KEY"

echo ""
echo "This script will set up a local VPN tunnel between two TUN interfaces."
echo "You'll need to run the server and client commands in separate terminals."
echo ""
echo "=========================================="
echo "TERMINAL 1 - Run VPN Server:"
echo "=========================================="
echo "sudo RUST_LOG=info ./target/release/rust-vpn server \\"
echo "    --listen-addr 127.0.0.1 \\"
echo "    --port 8888 \\"
echo "    --tun-name tun0 \\"
echo "    --tun-ip 10.0.0.1 \\"
echo "    --netmask 255.255.255.0 \\"
echo "    --key \"$KEY\""
echo ""
echo "=========================================="
echo "TERMINAL 2 - Run VPN Client:"
echo "=========================================="
echo "sudo RUST_LOG=info ./target/release/rust-vpn client \\"
echo "    --server 127.0.0.1 \\"
echo "    --port 8888 \\"
echo "    --tun-name tun1 \\"
echo "    --tun-ip 10.0.0.2 \\"
echo "    --netmask 255.255.255.0 \\"
echo "    --key \"$KEY\""
echo ""
echo "=========================================="
echo "After both are running, test the connection:"
echo "=========================================="
echo "ping 10.0.0.1  # Ping server from anywhere"
echo "ping 10.0.0.2  # Ping client from anywhere"
echo ""
