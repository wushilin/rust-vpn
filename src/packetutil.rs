pub fn get_ports_from_tun_frame(frame: &[u8]) -> Option<(u16, u16)> {
    if frame.len() < 1 {
        return None;
    }

    let version = frame[0] >> 4;

    match version {
        4 => {
            // IPv4
            if frame.len() < 20 {
                return None;
            }

            let version_ihl = frame[0];
            let ihl = version_ihl & 0x0F; // header length in 32-bit words
            let ip_header_len = (ihl as usize) * 4;

            if frame.len() < ip_header_len + 4 {
                return None;
            }

            let protocol = frame[9];
            if protocol != 6 && protocol != 17 {
                // not TCP (6) or UDP (17)
                return None;
            }

            // Extract ports
            let src_port = u16::from_be_bytes([frame[ip_header_len], frame[ip_header_len + 1]]);
            let dst_port = u16::from_be_bytes([frame[ip_header_len + 2], frame[ip_header_len + 3]]);

            Some((src_port, dst_port))
        }
        6 => {
            // IPv6
            if frame.len() < 40 {
                // IPv6 base header is 40 bytes
                return None;
            }

            // Find TCP/UDP header by following extension header chain
            let mut offset = 40; // Start after IPv6 base header
            let mut next_header = frame[6]; // Next header field in IPv6 header

            // Follow extension headers (max 255 hops to prevent infinite loops)
            for _ in 0..255 {
                // Check if we have enough bytes
                if frame.len() < offset + 4 {
                    return None;
                }

                match next_header {
                    6 | 17 => {
                        // TCP (6) or UDP (17) - found the transport header
                        let src_port = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
                        let dst_port = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
                        return Some((src_port, dst_port));
                    }
                    0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140 | 253 | 254 => {
                        // Extension headers that have a "next header" field
                        // 0: Hop-by-Hop Options
                        // 43: Routing
                        // 44: Fragment
                        // 50: Encapsulating Security Payload
                        // 51: Authentication Header
                        // 60: Destination Options
                        // 135: Mobility Header
                        // 139: Host Identity Protocol
                        // 140: Shim6 Protocol
                        // 253: Use for experimentation and testing
                        // 254: Use for experimentation and testing
                        
                        if offset + 2 > frame.len() {
                            return None;
                        }
                        
                        // Extension header length field is at offset + 1
                        // For most extension headers, length is in units of 8 octets (excluding first 8)
                        // But Fragment header is fixed 8 bytes
                        let ext_header_len = if next_header == 44 {
                            // Fragment header is fixed 8 bytes
                            8
                        } else if next_header == 50 {
                            // ESP header doesn't have a length field in the standard location
                            // ESP starts with Security Parameters Index (4 bytes), then Sequence Number (4 bytes)
                            // We can't easily determine the length without parsing the full ESP structure
                            // Skip ESP for now
                            return None;
                        } else if next_header == 51 {
                            // Authentication Header: length is at offset + 1, in units of 4 octets (excluding first 8)
                            if offset + 2 > frame.len() {
                                return None;
                            }
                            let ah_len = frame[offset + 1] as usize;
                            (ah_len + 2) * 4 // (len + 2) * 4 octets
                        } else {
                            // Other extension headers: length is at offset + 1, in units of 8 octets (excluding first 8)
                            if offset + 2 > frame.len() {
                                return None;
                            }
                            let ext_len = frame[offset + 1] as usize;
                            (ext_len + 1) * 8 // (len + 1) * 8 octets
                        };

                        if offset + ext_header_len >= frame.len() {
                            return None;
                        }

                        // Get next header from extension header (first byte is next header)
                        next_header = frame[offset];
                        offset += ext_header_len;
                    }
                    _ => {
                        // Unknown or unsupported protocol
                        return None;
                    }
                }
            }

            None // Too many extension headers or invalid chain
        }
        _ => None, // Unknown IP version
    }
}