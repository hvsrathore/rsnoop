//! Ethernet II and IEEE 802.1Q (VLAN) framing parser.
//!
//! Defined in IEEE 802.3, Ethernet II frames are the predominant Data Link Layer
//! framing mechanism in modern networks.

/// Decoded Ethernet II frame information.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EthernetInfo {
    /// 6-byte source hardware MAC address.
    pub src_mac: [u8; 6],
    /// 6-byte destination hardware MAC address.
    pub dst_mac: [u8; 6],
    /// 16-bit EtherType indicating the payload protocol (e.g. 0x0800 for IPv4, 0x0806 for ARP).
    pub ether_type: u16,
    /// Human-readable EtherType protocol name.
    pub ether_type_name: &'static str,
    /// Optional 12-bit VLAN identifier from an IEEE 802.1Q tag.
    pub vlan_id: Option<u16>,
}

/// Formats a 6-byte MAC address into standard colon-separated hex string (e.g. "00:11:22:33:44:55").
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Maps numeric EtherType values to standard protocol names.
pub fn ether_type_to_str(ether_type: u16) -> &'static str {
    match ether_type {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86DD => "IPv6",
        0x8100 => "802.1Q VLAN",
        0x88A8 => "802.1ad QinQ",
        0x88E5 => "MACsec",
        0x88F7 => "PTP (Precision Time)",
        0x88CC => "LLDP",
        0x8864 => "PPPoE Session",
        0x8863 => "PPPoE Discovery",
        0x9000 => "Loopback Configuration",
        _ => "Unknown EtherType",
    }
}

/// Parses an Ethernet II frame header, automatically extracting IEEE 802.1Q VLAN tags if present.
///
/// # Arguments
/// * `slice` - Raw packet byte slice starting at the Ethernet destination MAC.
///
/// # Returns
/// `Some((EthernetInfo, remaining_payload_slice))` or `None` if the slice is shorter than 14 bytes.
pub fn parse_ethernet(slice: &[u8]) -> Option<(EthernetInfo, &[u8])> {
    if slice.len() < 14 {
        return None;
    }

    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&slice[0..6]);
    src_mac.copy_from_slice(&slice[6..12]);

    let mut ether_type = u16::from_be_bytes([slice[12], slice[13]]);
    let mut offset = 14;
    let mut vlan_id = None;

    // Check for 802.1Q / 802.1ad VLAN tagging (0x8100 or 0x88A8)
    // 4-byte VLAN tag: 2 bytes TCI (Priority + Drop + VLAN ID) + 2 bytes encapsulated EtherType
    if (ether_type == 0x8100 || ether_type == 0x88A8) && slice.len() >= offset + 4 {
        let tci = u16::from_be_bytes([slice[offset], slice[offset + 1]]);
        vlan_id = Some(tci & 0x0FFF);
        ether_type = u16::from_be_bytes([slice[offset + 2], slice[offset + 3]]);
        offset += 4;
    }

    let info = EthernetInfo {
        src_mac,
        dst_mac,
        ether_type,
        ether_type_name: ether_type_to_str(ether_type),
        vlan_id,
    };

    Some((info, &slice[offset..]))
}
