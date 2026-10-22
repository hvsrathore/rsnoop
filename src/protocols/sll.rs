/*
 * Linux Cooked capture (SLL v1 and SLL2) header parser.
 *
 * flow of control in Linux cooked capture:
 * 1. entry point: called by `protocols::PacketParser::parse()` when datalink type is
 *    `Linktype::LINUX_SLL` or `Linktype::LINUX_SLL2`.
 * 2. libpcap synthesizes this header on Linux when capturing on the "any" device or non-Ethernet links.
 * 3. packet type extraction: reads packet direction code (PACKET_HOST = 0, PACKET_OUTGOING = 4, etc.)
 *    which feeds directly into `direction::determine_direction()` for high-accuracy flow tracking.
 * 4. sender address extraction: extracts hardware MAC address of the sender if available.
 * 5. protocol demuxing: extracts encapsulated EtherType protocol number (e.g. 0x0800 for IPv4).
 * 6. hand-off to L3: slices past the 16-byte (SLL) or 20-byte (SLL2) header to provide L3 payload.
 */

use super::ethernet::ether_type_to_str;

/*
 * decoded Linux Cooked Capture header information.
 * holds packet direction indicators, hardware address types, and inner protocol codes.
 */
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SllInfo {
    /* linux packet type (0 = Host, 1 = Broadcast, 2 = Multicast, 3 = Other Host, 4 = Outgoing). */
    pub packet_type: u16,
    /* human-readable packet direction name. */
    pub packet_type_name: &'static str,
    /* hardware address type (e.g. 1 for ARPHRD_ETHER). */
    pub arphrd_type: u16,
    /* encapsulated protocol EtherType (e.g. 0x0800 for IPv4). */
    pub protocol: u16,
    /* protocol name. */
    pub protocol_name: &'static str,
    /* sender link-layer MAC address if available. */
    pub sender_lladdr: Option<[u8; 6]>,
}

/*
 * maps Linux SLL packet type codes to descriptive direction strings.
 */
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

/*
 * parses a 16-byte Linux Cooked Capture (SLL v1) header.
 *
 * arguments:
 * * `slice` - raw packet byte slice starting at the SLL header.
 *
 * returns:
 * `Some((SllInfo, remaining_payload_slice))` or `None` if slice is shorter than 16 bytes.
 */
pub fn parse_sll(slice: &[u8]) -> Option<(SllInfo, &[u8])> {
    /* verify minimum length for SLL v1 header (16 bytes) */
    if slice.len() < 16 {
        return None;
    }

    /* bytes 0..2: packet type (direction flag assigned by Linux kernel) */
    let packet_type = u16::from_be_bytes([slice[0], slice[1]]);
    /* bytes 2..4: link layer address type */
    let arphrd_type = u16::from_be_bytes([slice[2], slice[3]]);
    /* bytes 4..6: link layer address length */
    let lladdr_len = u16::from_be_bytes([slice[4], slice[5]]);
    let mut sender_lladdr = None;
    if lladdr_len == 6 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&slice[6..12]);
        sender_lladdr = Some(mac);
    }
    /* bytes 14..16: protocol number in network byte order */
    let protocol = u16::from_be_bytes([slice[14], slice[15]]);

    let info = SllInfo {
        packet_type,
        packet_type_name: sll_pkttype_to_str(packet_type),
        arphrd_type,
        protocol,
        protocol_name: ether_type_to_str(protocol),
        sender_lladdr,
    };

    /* return parsed SLL header and remaining payload slice */
    Some((info, &slice[16..]))
}

/*
 * parses a 20-byte Linux Cooked Capture v2 (SLL2) header.
 *
 * arguments:
 * * `slice` - raw packet byte slice starting at the SLL2 header.
 *
 * returns:
 * `Some((SllInfo, remaining_payload_slice))` or `None` if slice is shorter than 20 bytes.
 */
pub fn parse_sll2(slice: &[u8]) -> Option<(SllInfo, &[u8])> {
    /* verify minimum length for SLL v2 header (20 bytes) */
    if slice.len() < 20 {
        return None;
    }

    /* bytes 0..2: protocol number */
    let protocol = u16::from_be_bytes([slice[0], slice[1]]);
    /* bytes 8..10: link layer address type */
    let arphrd_type = u16::from_be_bytes([slice[8], slice[9]]);
    /* byte 10: packet type */
    let packet_type = slice[10] as u16;
    /* byte 11: link layer address length */
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

    /* return parsed SLL2 header and remaining payload slice */
    Some((info, &slice[20..]))
}
