//! Internet Protocol (IPv4 and IPv6) parser.
//!
//! Defined in RFC 791 (IPv4) and RFC 8200 (IPv6), the Internet Protocol provides
//! connectionless best-effort delivery of packets across network boundaries.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Unified representation of an IP layer header (IPv4 or IPv6).
#[derive(Debug, Clone)]
pub enum IpInfo {
    /// Internet Protocol version 4 header.
    V4(Ipv4Info),
    /// Internet Protocol version 6 header.
    V6(Ipv6Info),
}

impl IpInfo {
    /// Returns the source IP address as an [`IpAddr`].
    pub fn src_ip(&self) -> IpAddr {
        match self {
            IpInfo::V4(v4) => IpAddr::V4(v4.src),
            IpInfo::V6(v6) => IpAddr::V6(v6.src),
        }
    }

    /// Returns the destination IP address as an [`IpAddr`].
    pub fn dst_ip(&self) -> IpAddr {
        match self {
            IpInfo::V4(v4) => IpAddr::V4(v4.dst),
            IpInfo::V6(v6) => IpAddr::V6(v6.dst),
        }
    }

    /// Returns the encapsulated transport layer protocol number (e.g. 6 for TCP, 17 for UDP).
    pub fn protocol(&self) -> u8 {
        match self {
            IpInfo::V4(v4) => v4.protocol,
            IpInfo::V6(v6) => v6.next_header,
        }
    }

    /// Returns the standard protocol name for the encapsulated layer.
    pub fn protocol_name(&self) -> &'static str {
        ip_proto_to_str(self.protocol())
    }
}

/// Decoded IPv4 header fields.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Ipv4Info {
    /// Internet Header Length (IHL) in 32-bit words (typically 5, meaning 20 bytes).
    pub ihl: u8,
    /// Differentiated Services Code Point (DSCP) for QoS.
    pub dscp: u8,
    /// Explicit Congestion Notification (ECN).
    pub ecn: u8,
    /// Total length of IP packet including header and data in bytes.
    pub total_length: u16,
    /// Identification field used for assembling fragments.
    pub identification: u16,
    /// Don't Fragment (DF) flag.
    pub dont_fragment: bool,
    /// More Fragments (MF) flag.
    pub more_fragments: bool,
    /// Fragment offset measured in units of 8-byte blocks.
    pub fragment_offset: u16,
    /// Time To Live (TTL) hop count.
    pub ttl: u8,
    /// Encapsulated transport protocol number.
    pub protocol: u8,
    /// Human-readable protocol name.
    pub protocol_name: &'static str,
    /// IPv4 header checksum.
    pub checksum: u16,
    /// Source IPv4 address.
    pub src: Ipv4Addr,
    /// Destination IPv4 address.
    pub dst: Ipv4Addr,
}

/// Decoded IPv6 header fields.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Ipv6Info {
    /// Traffic class (equivalent to IPv4 DSCP/ECN).
    pub traffic_class: u8,
    /// Flow label for packet classification.
    pub flow_label: u32,
    /// Length of the IPv6 payload in bytes following the 40-byte base header.
    pub payload_length: u16,
    /// Next header protocol number.
    pub next_header: u8,
    /// Human-readable next header protocol name.
    pub next_header_name: &'static str,
    /// Hop limit (equivalent to IPv4 TTL).
    pub hop_limit: u8,
    /// Source IPv6 address.
    pub src: Ipv6Addr,
    /// Destination IPv6 address.
    pub dst: Ipv6Addr,
}

/// Maps standard IANA IP protocol numbers to human-readable names.
pub fn ip_proto_to_str(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6 Encapsulation",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        115 => "L2TP",
        132 => "SCTP",
        _ => "Unknown IP Protocol",
    }
}

/// Parses an IPv4 header from raw bytes.
///
/// # Arguments
/// * `slice` - Byte slice containing the packet starting at the IPv4 header.
///
/// # Returns
/// `Some((Ipv4Info, remaining_payload_slice))` or `None` if the slice is invalid.
pub fn parse_ipv4(slice: &[u8]) -> Option<(Ipv4Info, &[u8])> {
    if slice.len() < 20 {
        return None;
    }

    let version = slice[0] >> 4;
    if version != 4 {
        return None;
    }

    let ihl = slice[0] & 0x0F;
    let header_len = (ihl as usize) * 4;
    if header_len < 20 || slice.len() < header_len {
        return None;
    }

    let dscp = slice[1] >> 2;
    let ecn = slice[1] & 0x03;
    let total_length = u16::from_be_bytes([slice[2], slice[3]]);
    let identification = u16::from_be_bytes([slice[4], slice[5]]);

    let flags_and_frag = u16::from_be_bytes([slice[6], slice[7]]);
    let dont_fragment = (flags_and_frag & 0x4000) != 0;
    let more_fragments = (flags_and_frag & 0x2000) != 0;
    let fragment_offset = flags_and_frag & 0x1FFF;

    let ttl = slice[8];
    let protocol = slice[9];
    let checksum = u16::from_be_bytes([slice[10], slice[11]]);

    let src = Ipv4Addr::new(slice[12], slice[13], slice[14], slice[15]);
    let dst = Ipv4Addr::new(slice[16], slice[17], slice[18], slice[19]);

    let info = Ipv4Info {
        ihl,
        dscp,
        ecn,
        total_length,
        identification,
        dont_fragment,
        more_fragments,
        fragment_offset,
        ttl,
        protocol,
        protocol_name: ip_proto_to_str(protocol),
        checksum,
        src,
        dst,
    };

    // Calculate actual payload bounds respecting total_length if valid
    let available_len = slice.len();
    let expected_len = total_length as usize;
    let end = if expected_len >= header_len && expected_len <= available_len {
        expected_len
    } else {
        available_len
    };

    Some((info, &slice[header_len..end]))
}

/// Parses an IPv6 header from raw bytes, skipping known extension headers.
///
/// # Arguments
/// * `slice` - Byte slice containing the packet starting at the IPv6 header.
///
/// # Returns
/// `Some((Ipv6Info, remaining_payload_slice))` or `None` if the slice is invalid.
pub fn parse_ipv6(slice: &[u8]) -> Option<(Ipv6Info, &[u8])> {
    if slice.len() < 40 {
        return None;
    }

    let version = slice[0] >> 4;
    if version != 6 {
        return None;
    }

    let traffic_class = ((slice[0] & 0x0F) << 4) | (slice[1] >> 4);
    let flow_label = (((slice[1] & 0x0F) as u32) << 16)
        | ((slice[2] as u32) << 8)
        | (slice[3] as u32);
    let payload_length = u16::from_be_bytes([slice[4], slice[5]]);
    let mut next_header = slice[6];
    let hop_limit = slice[7];

    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&slice[8..24]);
    dst_bytes.copy_from_slice(&slice[24..40]);
    let src = Ipv6Addr::from(src_bytes);
    let dst = Ipv6Addr::from(dst_bytes);

    let mut offset = 40;

    // Skip well-known IPv6 extension headers if present
    while offset < slice.len() {
        match next_header {
            0 | 43 | 60 => {
                // Hop-by-hop (0), Routing (43), Destination Options (60)
                if slice.len() < offset + 8 {
                    break;
                }
                next_header = slice[offset];
                let ext_len = (slice[offset + 1] as usize + 1) * 8;
                offset += ext_len;
            }
            44 => {
                // Fragment header (fixed 8 bytes)
                if slice.len() < offset + 8 {
                    break;
                }
                next_header = slice[offset];
                offset += 8;
            }
            _ => break,
        }
    }

    let info = Ipv6Info {
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        next_header_name: ip_proto_to_str(next_header),
        hop_limit,
        src,
        dst,
    };

    Some((info, &slice[offset..]))
}
