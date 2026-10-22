//! User Datagram Protocol (UDP) datagram parser.
//!
//! Defined in RFC 768, UDP provides connectionless, lightweight datagram delivery
//! with minimal protocol overhead.

use super::tcp::port_to_service;

/// Decoded User Datagram Protocol (UDP) header fields.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UdpInfo {
    /// 16-bit source port number.
    pub src_port: u16,
    /// 16-bit destination port number.
    pub dst_port: u16,
    /// Recognized service name for source port (e.g. "DNS", "DHCP", "NTP").
    pub src_port_name: Option<&'static str>,
    /// Recognized service name for destination port.
    pub dst_port_name: Option<&'static str>,
    /// Length in bytes of the UDP header and data combined.
    pub length: u16,
    /// 16-bit checksum covering IPv4/IPv6 pseudo-header, UDP header, and data.
    pub checksum: u16,
    /// Length of the extracted payload in bytes.
    pub payload_len: usize,
}

/// Parses a UDP header from raw bytes.
///
/// # Arguments
/// * `slice` - Byte slice starting at the UDP source port.
///
/// # Returns
/// `Some((UdpInfo, application_payload_slice))` or `None` if slice is shorter than 8 bytes.
pub fn parse_udp(slice: &[u8]) -> Option<(UdpInfo, &[u8])> {
    if slice.len() < 8 {
        return None;
    }

    let src_port = u16::from_be_bytes([slice[0], slice[1]]);
    let dst_port = u16::from_be_bytes([slice[2], slice[3]]);
    let length = u16::from_be_bytes([slice[4], slice[5]]);
    let checksum = u16::from_be_bytes([slice[6], slice[7]]);

    let payload_len = if (length as usize) >= 8 && (length as usize) <= slice.len() {
        (length as usize) - 8
    } else {
        slice.len() - 8
    };

    let payload = &slice[8..(8 + payload_len)];

    let info = UdpInfo {
        src_port,
        dst_port,
        src_port_name: port_to_service(src_port),
        dst_port_name: port_to_service(dst_port),
        length,
        checksum,
        payload_len,
    };

    Some((info, payload))
}
