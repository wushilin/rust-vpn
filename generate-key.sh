#!/bin/bash
# Helper script to generate a secure encryption key for rust-vpn

echo "Generating a 32-byte (256-bit) encryption key..."
KEY=$(openssl rand -base64 32)

echo ""
echo "Your encryption key (base64-encoded):"
echo "======================================"
echo "$KEY"
echo "======================================"
echo ""
echo "IMPORTANT: Keep this key secure and use the same key on both server and client!"
echo ""
echo "Example server command:"
echo "sudo ./target/release/rust-vpn server --key \"$KEY\""
echo ""
echo "Example client command:"
echo "sudo ./target/release/rust-vpn client --server SERVER_IP --key \"$KEY\""
