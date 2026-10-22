/*
 * User Datagram Protocol (UDP) datagram parser.
 *
 * flow of control in UDP decoding:
 * 1. entry point: called from `protocols::PacketParser::parse()` when IP protocol number is 17.
 * 2. length check: validates 8-byte fixed header length.
 * 3. endpoint parsing: extracts 16-bit source and destination port numbers.
 * 4. service lookup: maps ports to well-known application protocol names (e.g. 53 -> DNS, 67/68 -> DHCP, 123 -> NTP).
 * 5. datagram sizing: reads 16-bit total length (header + data) and bounds application payload.
 * 6. hand-off to L7: slices past the 8-byte header and forwards payload to L7 application parsers
 *    (DNS, DHCP, NTP).
 */

use super::tcp::port_to_service;

/*
 * decoded User Datagram Protocol (UDP) header fields.
 * corresponds to RFC 768 specifications.
 */
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UdpInfo {
    /* 16-bit source port number. */
    pub src_port: u16,
    /* 16-bit destination port number. */
    pub dst_port: u16,
    /* recognized service name for source port (e.g. "DNS", "DHCP", "NTP"). */
    pub src_port_name: Option<&'static str>,
    /* recognized service name for destination port. */
    pub dst_port_name: Option<&'static str>,
    /* length in bytes of the UDP header and data combined. */
    pub length: u16,
    /* 16-bit checksum covering IPv4/IPv6 pseudo-header, UDP header, and data. */
    pub checksum: u16,
    /* length of the extracted payload in bytes. */
    pub payload_len: usize,
}

/*
 * parses a UDP header from raw bytes.
 *
 * arguments:
 * * `slice` - byte slice starting at the UDP source port.
 *
 * returns:
 * `Some((UdpInfo, application_payload_slice))` or `None` if slice is shorter than 8 bytes.
 */
pub fn parse_udp(slice: &[u8]) -> Option<(UdpInfo, &[u8])> {
    /* verify minimum length for standard fixed UDP header (8 bytes) */
    if slice.len() < 8 {
        return None;
    }

    /* extract 16-bit source and destination port numbers */
    let src_port = u16::from_be_bytes([slice[0], slice[1]]);
    let dst_port = u16::from_be_bytes([slice[2], slice[3]]);
    let length = u16::from_be_bytes([slice[4], slice[5]]);
    let checksum = u16::from_be_bytes([slice[6], slice[7]]);

    /* calculate payload bounds respecting UDP declared length field */
    let payload_len = if (length as usize) >= 8 && (length as usize) <= slice.len() {
        (length as usize) - 8
    } else {
        slice.len() - 8
    };

    /* slice out application layer payload bytes */
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

    /* hand off UDP info and application payload slice */
    Some((info, payload))
}
