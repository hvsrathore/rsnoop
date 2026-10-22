//! Internet Control Message Protocol (ICMPv4 and ICMPv6) parser.
//!
//! Defined in RFC 792 (ICMPv4) and RFC 4443 (ICMPv6), ICMP is used for network diagnostics,
//! error reporting (e.g. Destination Unreachable, TTL Exceeded), and ping (Echo Request/Reply).

/// Decoded ICMP packet: either ICMP for IPv4 or ICMP for IPv6.
#[derive(Debug, Clone)]
pub enum IcmpInfo {
    /// ICMP version 4 packet.
    V4(Icmpv4Info),
    /// ICMP version 6 packet.
    V6(Icmpv6Info),
}

/// Decoded ICMPv4 header fields.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Icmpv4Info {
    /// ICMP type number (e.g. 0 for Echo Reply, 8 for Echo Request).
    pub icmp_type: u8,
    /// Sub-type code providing additional error context.
    pub code: u8,
    /// Header checksum.
    pub checksum: u16,
    /// Optional identifier for Echo requests/replies.
    pub id: Option<u16>,
    /// Optional sequence number for Echo requests/replies.
    pub seq: Option<u16>,
    /// Human-readable type name.
    pub type_name: &'static str,
    /// Detailed description of the specific code if available.
    pub code_name: Option<&'static str>,
}

/// Decoded ICMPv6 header fields.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Icmpv6Info {
    /// ICMPv6 type number (e.g. 128 for Echo Request, 135 for Neighbor Solicitation).
    pub icmp_type: u8,
    /// Sub-type code.
    pub code: u8,
    /// Header checksum.
    pub checksum: u16,
    /// Optional identifier for Echo requests/replies.
    pub id: Option<u16>,
    /// Optional sequence number for Echo requests/replies.
    pub seq: Option<u16>,
    /// Human-readable type name.
    pub type_name: &'static str,
    /// Detailed description of the code if available.
    pub code_name: Option<&'static str>,
}

impl IcmpInfo {
    /// Returns a human-readable summary of the ICMP message.
    pub fn summary(&self) -> String {
        match self {
            IcmpInfo::V4(v4) => {
                if let (Some(id), Some(seq)) = (v4.id, v4.seq) {
                    format!("ICMPv4 {} id={:#06x} seq={}", v4.type_name, id, seq)
                } else if let Some(code) = v4.code_name {
                    format!("ICMPv4 {} ({})", v4.type_name, code)
                } else {
                    format!("ICMPv4 {} (type={} code={})", v4.type_name, v4.icmp_type, v4.code)
                }
            }
            IcmpInfo::V6(v6) => {
                if let (Some(id), Some(seq)) = (v6.id, v6.seq) {
                    format!("ICMPv6 {} id={:#06x} seq={}", v6.type_name, id, seq)
                } else if let Some(code) = v6.code_name {
                    format!("ICMPv6 {} ({})", v6.type_name, code)
                } else {
                    format!("ICMPv6 {} (type={} code={})", v6.type_name, v6.icmp_type, v6.code)
                }
            }
        }
    }
}

/// Parses an ICMPv4 header from raw bytes.
///
/// # Arguments
/// * `slice` - Byte slice containing the ICMPv4 packet.
pub fn parse_icmpv4(slice: &[u8]) -> Option<Icmpv4Info> {
    if slice.len() < 4 {
        return None;
    }

    let icmp_type = slice[0];
    let code = slice[1];
    let checksum = u16::from_be_bytes([slice[2], slice[3]]);

    let mut id = None;
    let mut seq = None;

    // For Echo Request (8) and Echo Reply (0), bytes 4..8 contain identifier and sequence
    if (icmp_type == 0 || icmp_type == 8 || icmp_type == 13 || icmp_type == 14) && slice.len() >= 8 {
        id = Some(u16::from_be_bytes([slice[4], slice[5]]));
        seq = Some(u16::from_be_bytes([slice[6], slice[7]]));
    }

    let (type_name, code_name) = match icmp_type {
        0 => ("Echo (Ping) Reply", None),
        3 => {
            let desc = match code {
                0 => "Network Unreachable",
                1 => "Host Unreachable",
                2 => "Protocol Unreachable",
                3 => "Port Unreachable",
                4 => "Fragmentation Needed and DF set",
                5 => "Source Route Failed",
                _ => "Destination Unreachable",
            };
            ("Destination Unreachable", Some(desc))
        }
        4 => ("Source Quench", None),
        5 => ("Redirect", None),
        8 => ("Echo (Ping) Request", None),
        9 => ("Router Advertisement", None),
        10 => ("Router Solicitation", None),
        11 => {
            let desc = match code {
                0 => "Time to Live exceeded in transit",
                1 => "Fragment reassembly time exceeded",
                _ => "Time Exceeded",
            };
            ("Time Exceeded", Some(desc))
        }
        12 => ("Parameter Problem", None),
        13 => ("Timestamp Request", None),
        14 => ("Timestamp Reply", None),
        _ => ("Unknown ICMPv4 Type", None),
    };

    Some(Icmpv4Info {
        icmp_type,
        code,
        checksum,
        id,
        seq,
        type_name,
        code_name,
    })
}

/// Parses an ICMPv6 header from raw bytes.
///
/// # Arguments
/// * `slice` - Byte slice containing the ICMPv6 packet.
pub fn parse_icmpv6(slice: &[u8]) -> Option<Icmpv6Info> {
    if slice.len() < 4 {
        return None;
    }

    let icmp_type = slice[0];
    let code = slice[1];
    let checksum = u16::from_be_bytes([slice[2], slice[3]]);

    let mut id = None;
    let mut seq = None;

    if (icmp_type == 128 || icmp_type == 129) && slice.len() >= 8 {
        id = Some(u16::from_be_bytes([slice[4], slice[5]]));
        seq = Some(u16::from_be_bytes([slice[6], slice[7]]));
    }

    let (type_name, code_name) = match icmp_type {
        1 => {
            let desc = match code {
                0 => "No route to destination",
                1 => "Communication prohibited",
                3 => "Address unreachable",
                4 => "Port unreachable",
                _ => "Destination Unreachable",
            };
            ("Destination Unreachable", Some(desc))
        }
        2 => ("Packet Too Big", None),
        3 => ("Time Exceeded", None),
        4 => ("Parameter Problem", None),
        128 => ("Echo (Ping) Request", None),
        129 => ("Echo (Ping) Reply", None),
        133 => ("Router Solicitation", None),
        134 => ("Router Advertisement", None),
        135 => ("Neighbor Solicitation", None),
        136 => ("Neighbor Advertisement", None),
        137 => ("Redirect Message", None),
        _ => ("Unknown ICMPv6 Type", None),
    };

    Some(Icmpv6Info {
        icmp_type,
        code,
        checksum,
        id,
        seq,
        type_name,
        code_name,
    })
}
