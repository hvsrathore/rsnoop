//! Linux Cooked Capture (SLL v1 and SLL2) header parser.
//!
//! Libpcap on Linux synthesizes SLL ("Linux Cooked") headers when capturing on
//! the pseudo-device "any" or on interfaces that do not have standard Ethernet headers.
//! SLL headers explicitly declare packet direction (incoming, outgoing, broadcast).

use super::ethernet::ether_type_to_str;

/// Decoded Linux Cooked Capture header information.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SllInfo {
    /// Linux packet type (0 = Host, 1 = Broadcast, 2 = Multicast, 3 = Other Host, 4 = Outgoing).
    pub packet_type: u16,
    /// Human-readable packet direction name.
    pub packet_type_name: &'static str,
    /// Hardware address type (e.g. 1 for ARPHRD_ETHER).
    pub arphrd_type: u16,
    /// Encapsulated protocol EtherType (e.g. 0x0800 for IPv4).
    pub protocol: u16,
    /// Protocol name.
    pub protocol_name: &'static str,
    /// Sender link-layer MAC address if available.
    pub sender_lladdr: Option<[u8; 6]>,
}

/// Maps Linux SLL packet type codes to descriptive direction strings.
pub fn sll_pkttype_to_str(pkttype: u16) -> &'static str {
    match pkttype {
        0 => "Incoming (Host)",
        1 => "Incoming (Broadcast)",
        2 => "Incoming (Multicast)",
        3 => "Promiscuous (Other Host)",
        4 => "Outgoing (Sent)",
        _ => "Unknown",
    }
}

/// Parses a 16-byte Linux Cooked Capture (SLL v1) header.
///
/// # Arguments
/// * `slice` - Raw packet byte slice starting at the SLL header.
///
/// # Returns
/// `Some((SllInfo, remaining_payload_slice))` or `None` if slice is shorter than 16 bytes.
pub fn parse_sll(slice: &[u8]) -> Option<(SllInfo, &[u8])> {
    if slice.len() < 16 {
        return None;
    }

    let packet_type = u16::from_be_bytes([slice[0], slice[1]]);
    let arphrd_type = u16::from_be_bytes([slice[2], slice[3]]);
    let lladdr_len = u16::from_be_bytes([slice[4], slice[5]]);
    let mut sender_lladdr = None;
    if lladdr_len == 6 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&slice[6..12]);
        sender_lladdr = Some(mac);
    }
    let protocol = u16::from_be_bytes([slice[14], slice[15]]);

    let info = SllInfo {
        packet_type,
        packet_type_name: sll_pkttype_to_str(packet_type),
        arphrd_type,
        protocol,
        protocol_name: ether_type_to_str(protocol),
        sender_lladdr,
    };

    Some((info, &slice[16..]))
}

/// Parses a 20-byte Linux Cooked Capture v2 (SLL2) header.
///
/// # Arguments
/// * `slice` - Raw packet byte slice starting at the SLL2 header.
///
/// # Returns
/// `Some((SllInfo, remaining_payload_slice))` or `None` if slice is shorter than 20 bytes.
pub fn parse_sll2(slice: &[u8]) -> Option<(SllInfo, &[u8])> {
    if slice.len() < 20 {
        return None;
    }

    let protocol = u16::from_be_bytes([slice[0], slice[1]]);
    let arphrd_type = u16::from_be_bytes([slice[8], slice[9]]);
    let packet_type = slice[10] as u16;
    let lladdr_len = slice[11] as usize;
    let mut sender_lladdr = None;
    if lladdr_len == 6 && slice.len() >= 18 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&slice[12..18]);
        sender_lladdr = Some(mac);
    }

    let info = SllInfo {
        packet_type,
        packet_type_name: sll_pkttype_to_str(packet_type),
        arphrd_type,
        protocol,
        protocol_name: ether_type_to_str(protocol),
        sender_lladdr,
    };

    Some((info, &slice[20..]))
}
