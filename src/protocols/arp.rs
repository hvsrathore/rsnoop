//! Address Resolution Protocol (ARP) parser.
//!
//! ARP is defined in RFC 826 and is used on local area networks (LANs)
//! to map an IP address (Network Layer) to a physical MAC address (Data Link Layer).

use super::ethernet::format_mac;
use std::net::Ipv4Addr;

/// Decoded Address Resolution Protocol (ARP) header and payload.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ArpInfo {
    /// Hardware type (e.g. 1 for Ethernet).
    pub htype: u16,
    /// Protocol type (e.g. 0x0800 for IPv4).
    pub ptype: u16,
    /// ARP operation code (1 = Request, 2 = Reply, 3 = RARP Request, 4 = RARP Reply).
    pub opcode: u16,
    /// Human-readable name for the ARP opcode.
    pub opcode_name: &'static str,
    /// Hardware (MAC) address of the sender.
    pub sender_mac: [u8; 6],
    /// IPv4 address of the sender.
    pub sender_ip: Ipv4Addr,
    /// Hardware (MAC) address of the target (zeroed out in requests).
    pub target_mac: [u8; 6],
    /// IPv4 address of the target being queried.
    pub target_ip: Ipv4Addr,
}

impl ArpInfo {
    /// Formats a human-readable summary of the ARP transaction:
    /// - For requests: "Who has 192.168.1.1? Tell 192.168.1.50"
    /// - For replies:  "192.168.1.1 is at 00:11:22:33:44:55"
    pub fn summary(&self) -> String {
        match self.opcode {
            1 => format!(
                "Who has {}? Tell {}",
                self.target_ip, self.sender_ip
            ),
            2 => format!(
                "{} is at {}",
                self.sender_ip,
                format_mac(&self.sender_mac)
            ),
            3 => format!("RARP Request for {}", format_mac(&self.target_mac)),
            4 => format!("RARP Reply: {} is at {}", self.target_ip, format_mac(&self.target_mac)),
            _ => format!("ARP Opcode {}", self.opcode),
        }
    }
}

/// Parses raw bytes into an [`ArpInfo`] struct.
///
/// # Arguments
/// * `slice` - Byte slice containing the ARP packet starting at the hardware type.
///
/// # Returns
/// `Some(ArpInfo)` if successfully parsed, or `None` if the slice is too short
/// or unsupported (e.g. non-Ethernet or non-IPv4 ARP).
pub fn parse_arp(slice: &[u8]) -> Option<ArpInfo> {
    // ARP packet length for Ethernet (6-byte MAC) + IPv4 (4-byte IP) is 28 bytes
    if slice.len() < 28 {
        return None;
    }

    // Hardware Type: 2 bytes (1 = Ethernet)
    let htype = u16::from_be_bytes([slice[0], slice[1]]);
    // Protocol Type: 2 bytes (0x0800 = IPv4)
    let ptype = u16::from_be_bytes([slice[2], slice[3]]);
    // Hardware Address Length: 1 byte (6 for MAC)
    let hlen = slice[4];
    // Protocol Address Length: 1 byte (4 for IPv4)
    let plen = slice[5];
    // Operation: 2 bytes (1 = Request, 2 = Reply)
    let opcode = u16::from_be_bytes([slice[6], slice[7]]);

    // Verify this is standard Ethernet + IPv4 ARP
    if hlen != 6 || plen != 4 {
        return None;
    }

    // Sender Hardware Address (MAC): bytes 8..14
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&slice[8..14]);
    // Sender Protocol Address (IP): bytes 14..18
    let sender_ip = Ipv4Addr::new(slice[14], slice[15], slice[16], slice[17]);

    // Target Hardware Address (MAC): bytes 18..24
    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&slice[18..24]);
    // Target Protocol Address (IP): bytes 24..28
    let target_ip = Ipv4Addr::new(slice[24], slice[25], slice[26], slice[27]);

    let opcode_name = match opcode {
        1 => "Request",
        2 => "Reply",
        3 => "RARP-Request",
        4 => "RARP-Reply",
        _ => "Unknown",
    };

    Some(ArpInfo {
        htype,
        ptype,
        opcode,
        opcode_name,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}
