//! Transport Layer Security (TLS 1.0 - 1.3) parser.
//!
//! Defined in RFC 5246 (TLS 1.2) and RFC 8446 (TLS 1.3), TLS provides cryptographic security
//! for communications over computer networks.
//!
//! This parser extracts:
//! - Record Layer content types (Handshake, Application Data, Alert, ChangeCipherSpec).
//! - Protocol version numbers.
//! - Handshake messages (Client Hello, Server Hello).
//! - **Server Name Indication (SNI)** extension: extracts the targeted server hostname
//!   unencrypted during the initial TLS Client Hello handshake!
//! - **ALPN (Application-Layer Protocol Negotiation)**: negotiated protocols like "h2" and "http/1.1".

/// Decoded Transport Layer Security (TLS) record and handshake info.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TlsInfo {
    /// 8-bit record layer content type (20 = ChangeCipherSpec, 21 = Alert, 22 = Handshake, 23 = AppData).
    pub content_type: u8,
    /// Human-readable record content type name.
    pub content_type_name: &'static str,
    /// 16-bit TLS protocol version number (e.g. 0x0303 for TLS 1.2, 0x0304 for TLS 1.3).
    pub version: u16,
    /// Human-readable version string.
    pub version_name: &'static str,
    /// Length of the TLS record payload in bytes.
    pub length: u16,
    /// 8-bit handshake type code (1 = Client Hello, 2 = Server Hello, etc.).
    pub handshake_type: Option<u8>,
    /// Human-readable handshake type name.
    pub handshake_type_name: Option<&'static str>,
    /// Server Name Indication (SNI) hostname extracted from Client Hello extensions.
    pub sni: Option<String>,
    /// Application-Layer Protocol Negotiation (ALPN) protocols (e.g. ["h2", "http/1.1"]).
    pub alpn: Vec<String>,
}

impl TlsInfo {
    /// Produces a human-readable one-line summary of the TLS packet.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        parts.push(self.version_name);

        if let Some(hs_name) = self.handshake_type_name {
            parts.push(hs_name);
            if let Some(sni) = &self.sni {
                return format!("TLS {} {} (SNI: {})", self.version_name, hs_name, sni);
            }
            if !self.alpn.is_empty() {
                return format!("TLS {} {} (ALPN: {})", self.version_name, hs_name, self.alpn.join(", "));
            }
            format!("TLS {} {}", self.version_name, hs_name)
        } else {
            format!("TLS {} {} ({} bytes)", self.version_name, self.content_type_name, self.length)
        }
    }
}

/// Converts a 16-bit TLS version identifier to its standard string name.
pub fn tls_version_to_str(ver: u16) -> &'static str {
    match ver {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "TLS Unknown",
    }
}

/// Converts a TLS record layer content type byte to a readable string.
pub fn tls_content_type_to_str(ct: u8) -> &'static str {
    match ct {
        20 => "ChangeCipherSpec",
        21 => "Alert",
        22 => "Handshake",
        23 => "Application Data",
        24 => "Heartbeat",
        _ => "Unknown Record",
    }
}

/// Converts a TLS handshake message type byte to its name.
pub fn tls_handshake_type_to_str(ht: u8) -> &'static str {
    match ht {
        0 => "Hello Request",
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        _ => "Handshake",
    }
}

/// Parses extensions within a TLS Client Hello message.
/// Extracts Server Name Indication (SNI) and ALPN protocol list.
fn parse_client_hello_extensions(slice: &[u8]) -> (Option<String>, Vec<String>) {
    let mut sni = None;
    let mut alpn = Vec::new();

    // Client Hello format:
    // client_version (2 bytes) + random (32 bytes) = 34 bytes
    if slice.len() < 34 {
        return (None, alpn);
    }

    let mut offset = 34;

    // session_id: length (1 byte) + data
    if offset >= slice.len() {
        return (None, alpn);
    }
    let session_id_len = slice[offset] as usize;
    offset += 1 + session_id_len;

    // cipher_suites: length (2 bytes) + data
    if offset + 2 > slice.len() {
        return (None, alpn);
    }
    let cipher_suites_len = u16::from_be_bytes([slice[offset], slice[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    // compression_methods: length (1 byte) + data
    if offset >= slice.len() {
        return (None, alpn);
    }
    let compression_len = slice[offset] as usize;
    offset += 1 + compression_len;

    // extensions: length (2 bytes) + list of extensions
    if offset + 2 > slice.len() {
        return (None, alpn);
    }
    let extensions_len = u16::from_be_bytes([slice[offset], slice[offset + 1]]) as usize;
    offset += 2;

    let end = (offset + extensions_len).min(slice.len());

    // Iterate through TLV extensions
    while offset + 4 <= end {
        let ext_type = u16::from_be_bytes([slice[offset], slice[offset + 1]]);
        let ext_len = u16::from_be_bytes([slice[offset + 2], slice[offset + 3]]) as usize;
        offset += 4;

        if offset + ext_len > end {
            break;
        }

        let ext_data = &slice[offset..offset + ext_len];

        // Extension 0x0000: server_name (SNI - RFC 6066)
        if ext_type == 0x0000 && ext_len >= 5 {
            // server_name_list_length (2) + name_type (1, 0=host_name) + name_length (2)
            let name_type = ext_data[2];
            let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
            if name_type == 0 && ext_len >= 5 + name_len {
                if let Ok(s) = std::str::from_utf8(&ext_data[5..5 + name_len]) {
                    sni = Some(s.to_string());
                }
            }
        }

        // Extension 0x0010: ALPN (Application-Layer Protocol Negotiation - RFC 7301)
        if ext_type == 0x0010 && ext_len >= 2 {
            let mut alpn_offset = 2; // skip alpn_list_length (2 bytes)
            while alpn_offset < ext_data.len() {
                let proto_len = ext_data[alpn_offset] as usize;
                alpn_offset += 1;
                if alpn_offset + proto_len <= ext_data.len() {
                    let proto = String::from_utf8_lossy(&ext_data[alpn_offset..alpn_offset + proto_len]);
                    alpn.push(proto.to_string());
                    alpn_offset += proto_len;
                } else {
                    break;
                }
            }
        }

        offset += ext_len;
    }

    (sni, alpn)
}

/// Parses raw TCP stream bytes into a [`TlsInfo`] record structure.
///
/// # Arguments
/// * `slice` - TCP payload bytes.
///
/// # Returns
/// `Some(TlsInfo)` if the bytes match a TLS Record Layer header.
pub fn parse_tls(slice: &[u8]) -> Option<TlsInfo> {
    if slice.len() < 5 {
        return None;
    }

    let content_type = slice[0];
    // TLS record content types are between 20 (ChangeCipherSpec) and 24 (Heartbeat)
    if !(20..=24).contains(&content_type) {
        return None;
    }

    let raw_version = u16::from_be_bytes([slice[1], slice[2]]);
    let length = u16::from_be_bytes([slice[3], slice[4]]);

    // Validate version: SSL 3.0 (0x0300) through TLS 1.3 (0x0304)
    if !(0x0300..=0x0304).contains(&raw_version) {
        return None;
    }

    let mut handshake_type = None;
    let mut handshake_type_name = None;
    let mut sni = None;
    let mut alpn = Vec::new();
    let mut version = raw_version;

    if content_type == 22 && slice.len() >= 9 {
        // Handshake record
        let ht = slice[5];
        handshake_type = Some(ht);
        handshake_type_name = Some(tls_handshake_type_to_str(ht));

        let hs_len = (((slice[6] as usize) << 16) | ((slice[7] as usize) << 8) | (slice[8] as usize)).min(slice.len() - 9);
        let hs_body = &slice[9..9 + hs_len];

        if ht == 1 {
            // Client Hello: parse SNI and ALPN
            let (parsed_sni, parsed_alpn) = parse_client_hello_extensions(hs_body);
            sni = parsed_sni;
            alpn = parsed_alpn;
        } else if ht == 2 && hs_body.len() >= 2 {
            // Server Hello: extract negotiated server version
            let sh_version = u16::from_be_bytes([hs_body[0], hs_body[1]]);
            if (0x0300..=0x0304).contains(&sh_version) {
                version = sh_version;
            }
        }
    }

    Some(TlsInfo {
        content_type,
        content_type_name: tls_content_type_to_str(content_type),
        version,
        version_name: tls_version_to_str(version),
        length,
        handshake_type,
        handshake_type_name,
        sni,
        alpn,
    })
}
