//! Transmission Control Protocol (TCP) segment parser.
//!
//! Defined in RFC 793 / RFC 9293, TCP provides reliable, ordered, and error-checked
//! delivery of a stream of octets between applications running on hosts.

/// Decoded Transmission Control Protocol (TCP) header fields.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TcpInfo {
    /// 16-bit source port number.
    pub src_port: u16,
    /// 16-bit destination port number.
    pub dst_port: u16,
    /// Well-known service name for source port (e.g. "HTTPS", "SSH") if recognized.
    pub src_port_name: Option<&'static str>,
    /// Well-known service name for destination port if recognized.
    pub dst_port_name: Option<&'static str>,
    /// 32-bit sequence number.
    pub seq_number: u32,
    /// 32-bit acknowledgment number.
    pub ack_number: u32,
    /// Data offset in bytes (length of TCP header including options).
    pub data_offset: u8,
    /// SYN (Synchronize sequence numbers) flag.
    pub syn: bool,
    /// ACK (Acknowledgment field significant) flag.
    pub ack: bool,
    /// FIN (No more data from sender) flag.
    pub fin: bool,
    /// RST (Reset the connection) flag.
    pub rst: bool,
    /// PSH (Push function) flag.
    pub psh: bool,
    /// URG (Urgent pointer field significant) flag.
    pub urg: bool,
    /// ECE (ECN-Echo) flag.
    pub ece: bool,
    /// CWR (Congestion Window Reduced) flag.
    pub cwr: bool,
    /// 16-bit receive window size.
    pub window_size: u16,
    /// 16-bit TCP header & payload checksum.
    pub checksum: u16,
    /// 16-bit urgent pointer offset.
    pub urgent_pointer: u16,
    /// Formatted bracketed flags string (e.g. "[SYN, ACK]").
    pub flags_str: String,
    /// Length of the encapsulated application data payload in bytes.
    pub payload_len: usize,
}

/// Maps common well-known and registered port numbers to protocol service names.
pub fn port_to_service(port: u16) -> Option<&'static str> {
    match port {
        20 | 21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        67 | 68 => Some("DHCP"),
        69 => Some("TFTP"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        123 => Some("NTP"),
        143 => Some("IMAP"),
        161 | 162 => Some("SNMP"),
        179 => Some("BGP"),
        443 => Some("HTTPS/TLS"),
        445 => Some("SMB"),
        465 => Some("SMTPS"),
        587 => Some("SMTP-Submission"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1080 => Some("SOCKS"),
        1433 => Some("MSSQL"),
        1521 => Some("Oracle DB"),
        1883 | 8883 => Some("MQTT"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        5353 => Some("mDNS"),
        5432 => Some("PostgreSQL"),
        6379 => Some("Redis"),
        8000 | 8080 | 8888 => Some("HTTP-Alt"),
        8443 => Some("HTTPS-Alt"),
        9000 => Some("FastCGI"),
        9092 => Some("Kafka"),
        9200 | 9300 => Some("Elasticsearch"),
        27017 => Some("MongoDB"),
        _ => None,
    }
}

/// Parses a TCP header and returns the extracted information alongside remaining payload.
///
/// # Arguments
/// * `slice` - Byte slice containing the TCP packet starting at the source port.
///
/// # Returns
/// `Some((TcpInfo, application_payload_slice))` or `None` if slice is invalid or truncated.
pub fn parse_tcp(slice: &[u8]) -> Option<(TcpInfo, &[u8])> {
    if slice.len() < 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([slice[0], slice[1]]);
    let dst_port = u16::from_be_bytes([slice[2], slice[3]]);
    let seq_number = u32::from_be_bytes([slice[4], slice[5], slice[6], slice[7]]);
    let ack_number = u32::from_be_bytes([slice[8], slice[9], slice[10], slice[11]]);

    let data_offset_byte = slice[12];
    let data_offset = (data_offset_byte >> 4) * 4;
    if (data_offset as usize) < 20 || slice.len() < (data_offset as usize) {
        return None;
    }

    // Flags are in the lower 6 bits of byte 13 + 2 ECN bits
    let flags_byte = slice[13];
    let cwr = (flags_byte & 0x80) != 0;
    let ece = (flags_byte & 0x40) != 0;
    let urg = (flags_byte & 0x20) != 0;
    let ack = (flags_byte & 0x10) != 0;
    let psh = (flags_byte & 0x08) != 0;
    let rst = (flags_byte & 0x04) != 0;
    let syn = (flags_byte & 0x02) != 0;
    let fin = (flags_byte & 0x01) != 0;

    let window_size = u16::from_be_bytes([slice[14], slice[15]]);
    let checksum = u16::from_be_bytes([slice[16], slice[17]]);
    let urgent_pointer = u16::from_be_bytes([slice[18], slice[19]]);

    let mut flags_vec = Vec::new();
    if syn {
        flags_vec.push("SYN");
    }
    if ack {
        flags_vec.push("ACK");
    }
    if fin {
        flags_vec.push("FIN");
    }
    if rst {
        flags_vec.push("RST");
    }
    if psh {
        flags_vec.push("PSH");
    }
    if urg {
        flags_vec.push("URG");
    }
    if ece {
        flags_vec.push("ECE");
    }
    if cwr {
        flags_vec.push("CWR");
    }
    let flags_str = format!("[{}]", flags_vec.join(", "));

    let payload = &slice[(data_offset as usize)..];

    let info = TcpInfo {
        src_port,
        dst_port,
        src_port_name: port_to_service(src_port),
        dst_port_name: port_to_service(dst_port),
        seq_number,
        ack_number,
        data_offset,
        syn,
        ack,
        fin,
        rst,
        psh,
        urg,
        ece,
        cwr,
        window_size,
        checksum,
        urgent_pointer,
        flags_str,
        payload_len: payload.len(),
    };

    Some((info, payload))
}
