/*
 * Internet Protocol (IPv4 and IPv6) parser.
 *
 * flow of control in Network Layer (L3) decoding:
 * 1. entry point: called from `protocols::PacketParser::parse()` when EtherType is
 *    `0x0800` (`parse_ipv4`) or `0x86DD` (`parse_ipv6`).
 * 2. IPv4 decoding flow:
 *    - validates 20-byte minimum header length and checks version == 4.
 *    - calculates header size via IHL * 4 to account for optional IP options.
 *    - extracts QoS fields (DSCP, ECN), total packet length, and fragmentation flags (DF, MF).
 *    - extracts TTL hop count and protocol number (6 for TCP, 17 for UDP, 1 for ICMP).
 *    - parses 32-bit source and destination IPv4 addresses.
 *    - bounds payload by `total_length` and returns slice to L4 transport parser.
 * 3. IPv6 decoding flow:
 *    - validates 40-byte fixed base header and checks version == 6.
 *    - extracts traffic class, 20-bit flow label, payload length, and next header protocol.
 *    - parses 128-bit source and destination IPv6 addresses.
 *    - skips through chained extension headers (Hop-by-hop, Routing, Fragment, Destination Options).
 *    - returns unpacked transport slice and final next header protocol to L4 transport parser.
 */

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/*
 * unified representation of an IP layer header (IPv4 or IPv6).
 * provides common accessors for source/destination IP and encapsulated protocol.
 */
#[derive(Debug, Clone)]
pub enum IpInfo {
    /* internet Protocol version 4 header. */
    V4(Ipv4Info),
    /* internet Protocol version 6 header. */
    V6(Ipv6Info),
}

impl IpInfo {
    /*
     * returns the source IP address as an `IpAddr`.
     */
    pub fn src_ip(&self) -> IpAddr {
        match self {
            IpInfo::V4(v4) => IpAddr::V4(v4.src),
            IpInfo::V6(v6) => IpAddr::V6(v6.src),
        }
    }

    /*
     * returns the destination IP address as an `IpAddr`.
     */
    pub fn dst_ip(&self) -> IpAddr {
        match self {
            IpInfo::V4(v4) => IpAddr::V4(v4.dst),
            IpInfo::V6(v6) => IpAddr::V6(v6.dst),
        }
    }

    /*
     * returns the encapsulated transport layer protocol number (e.g. 6 for TCP, 17 for UDP).
     */
    pub fn protocol(&self) -> u8 {
        match self {
            IpInfo::V4(v4) => v4.protocol,
            IpInfo::V6(v6) => v6.next_header,
        }
    }

    /*
     * returns the standard protocol name for the encapsulated layer.
     */
    pub fn protocol_name(&self) -> &'static str {
        ip_proto_to_str(self.protocol())
    }
}

/*
 * decoded IPv4 header fields.
 * corresponds to RFC 791 specifications.
 */
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Ipv4Info {
    /* internet Header Length (IHL) in 32-bit words (typically 5, meaning 20 bytes). */
    pub ihl: u8,
    /* differentiated Services Code Point (DSCP) for quality of service. */
    pub dscp: u8,
    /* explicit Congestion Notification (ECN). */
    pub ecn: u8,
    /* total length of IP packet including header and data in bytes. */
    pub total_length: u16,
    /* identification field used for assembling fragments. */
    pub identification: u16,
    /* don't Fragment (DF) flag. */
    pub dont_fragment: bool,
    /* more Fragments (MF) flag. */
    pub more_fragments: bool,
    /* fragment offset measured in units of 8-byte blocks. */
    pub fragment_offset: u16,
    /* time To Live (TTL) hop count. */
    pub ttl: u8,
    /* encapsulated transport protocol number. */
    pub protocol: u8,
    /* human-readable protocol name. */
    pub protocol_name: &'static str,
    /* IPv4 header checksum. */
    pub checksum: u16,
    /* source IPv4 address. */
    pub src: Ipv4Addr,
    /* destination IPv4 address. */
    pub dst: Ipv4Addr,
}

/*
 * decoded IPv6 header fields.
 * corresponds to RFC 8200 specifications.
 */
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Ipv6Info {
    /* traffic class (equivalent to IPv4 DSCP/ECN). */
    pub traffic_class: u8,
    /* flow label for QoS and packet classification. */
    pub flow_label: u32,
    /* length of the IPv6 payload in bytes following the 40-byte base header. */
    pub payload_length: u16,
    /* next header protocol number. */
    pub next_header: u8,
    /* human-readable next header protocol name. */
    pub next_header_name: &'static str,
    /* hop limit (equivalent to IPv4 TTL). */
    pub hop_limit: u8,
    /* source IPv6 address. */
    pub src: Ipv6Addr,
    /* destination IPv6 address. */
    pub dst: Ipv6Addr,
}

/*
 * maps standard IANA IP protocol numbers to human-readable names.
 */
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

/*
 * parses an IPv4 header from raw bytes.
 *
 * arguments:
 * * `slice` - byte slice containing the packet starting at the IPv4 header.
 *
 * returns:
 * `Some((Ipv4Info, remaining_payload_slice))` or `None` if the slice is invalid.
 */
pub fn parse_ipv4(slice: &[u8]) -> Option<(Ipv4Info, &[u8])> {
    /* minimum IPv4 header length is 20 bytes */
    if slice.len() < 20 {
        return None;
    }

    /* verify IP version in upper 4 bits of first byte is 4 */
    let version = slice[0] >> 4;
    if version != 4 {
        return None;
    }

    /* calculate header length from lower 4 bits (IHL in 32-bit words) */
    let ihl = slice[0] & 0x0F;
    let header_len = (ihl as usize) * 4;
    if header_len < 20 || slice.len() < header_len {
        return None;
    }

    /* extract DSCP (top 6 bits) and ECN (bottom 2 bits) */
    let dscp = slice[1] >> 2;
    let ecn = slice[1] & 0x03;
    let total_length = u16::from_be_bytes([slice[2], slice[3]]);
    let identification = u16::from_be_bytes([slice[4], slice[5]]);

    /* parse flags and fragment offset */
    let flags_and_frag = u16::from_be_bytes([slice[6], slice[7]]);
    let dont_fragment = (flags_and_frag & 0x4000) != 0;
    let more_fragments = (flags_and_frag & 0x2000) != 0;
    let fragment_offset = flags_and_frag & 0x1FFF;

    let ttl = slice[8];
    let protocol = slice[9];
    let checksum = u16::from_be_bytes([slice[10], slice[11]]);

    /* parse 4-byte source and destination IPv4 addresses */
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

    /* calculate actual payload bounds respecting total_length if valid */
    let available_len = slice.len();
    let expected_len = total_length as usize;
    let end = if expected_len >= header_len && expected_len <= available_len {
        expected_len
    } else {
        available_len
    };

    /* hand off encapsulated transport payload slice */
    Some((info, &slice[header_len..end]))
}

/*
 * parses an IPv6 header from raw bytes, skipping known extension headers.
 *
 * arguments:
 * * `slice` - byte slice containing the packet starting at the IPv6 header.
 *
 * returns:
 * `Some((Ipv6Info, remaining_payload_slice))` or `None` if the slice is invalid.
 */
pub fn parse_ipv6(slice: &[u8]) -> Option<(Ipv6Info, &[u8])> {
    /* minimum IPv6 header length is 40 bytes fixed */
    if slice.len() < 40 {
        return None;
    }

    /* verify IP version in upper 4 bits is 6 */
    let version = slice[0] >> 4;
    if version != 6 {
        return None;
    }

    /* extract 8-bit traffic class and 20-bit flow label */
    let traffic_class = ((slice[0] & 0x0F) << 4) | (slice[1] >> 4);
    let flow_label = (((slice[1] & 0x0F) as u32) << 16)
        | ((slice[2] as u32) << 8)
        | (slice[3] as u32);
    let payload_length = u16::from_be_bytes([slice[4], slice[5]]);
    let mut next_header = slice[6];
    let hop_limit = slice[7];

    /* parse 16-byte source and destination IPv6 addresses */
    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&slice[8..24]);
    dst_bytes.copy_from_slice(&slice[24..40]);
    let src = Ipv6Addr::from(src_bytes);
    let dst = Ipv6Addr::from(dst_bytes);

    let mut offset = 40;

    /* skip well-known IPv6 extension headers to reach upper layer transport payload */
    while offset < slice.len() {
        match next_header {
            0 | 43 | 60 => {
                /* hop-by-hop options (0), routing header (43), destination options (60) */
                if slice.len() < offset + 8 {
                    break;
                }
                next_header = slice[offset];
                let ext_len = (slice[offset + 1] as usize + 1) * 8;
                offset += ext_len;
            }
            44 => {
                /* fragment header (fixed 8 bytes) */
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

    /* hand off transport layer slice */
    Some((info, &slice[offset..]))
}
