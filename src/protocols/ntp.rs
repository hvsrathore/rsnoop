//! Network Time Protocol (NTP) parser.
//!
//! Defined in RFC 5905, NTP is a networking protocol for clock synchronization
//! between computer systems over packet-switched, variable-latency data networks.

/// Decoded Network Time Protocol (NTP) header.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NtpInfo {
    /// 2-bit warning of an impending leap second to be inserted/deleted.
    pub leap_indicator: u8,
    /// NTP protocol version number (typically 3 or 4).
    pub version: u8,
    /// 3-bit mode code (e.g. 3 = Client, 4 = Server, 5 = Broadcast).
    pub mode: u8,
    /// Human-readable mode description.
    pub mode_name: &'static str,
    /// Stratum level of the local clock (1 = primary reference, 2-15 = secondary).
    pub stratum: u8,
    /// Stratum description.
    pub stratum_name: &'static str,
    /// Maximum interval between successive messages (in log2 seconds).
    pub poll: i8,
    /// Precision of the local clock (in log2 seconds).
    pub precision: i8,
}

impl NtpInfo {
    /// Returns a concise one-line summary of the NTP packet.
    pub fn summary(&self) -> String {
        format!(
            "NTP v{} {} (Stratum {}, Poll {})",
            self.version, self.mode_name, self.stratum, self.poll
        )
    }
}

/// Maps numeric NTP mode codes to human-readable names.
pub fn ntp_mode_to_str(mode: u8) -> &'static str {
    match mode {
        1 => "Symmetric Active",
        2 => "Symmetric Passive",
        3 => "Client",
        4 => "Server",
        5 => "Broadcast",
        6 => "NTP Control Message",
        7 => "Private",
        _ => "Reserved",
    }
}

/// Maps numeric NTP stratum levels to descriptive names.
pub fn ntp_stratum_to_str(stratum: u8) -> &'static str {
    match stratum {
        0 => "Unspecified / Kiss-o'-Death",
        1 => "Primary Reference (e.g. GPS/atomic)",
        2..=15 => "Secondary Reference",
        16 => "Unsynchronized",
        _ => "Reserved",
    }
}

/// Parses an NTP packet from raw UDP payload.
///
/// # Arguments
/// * `slice` - UDP payload bytes starting at the NTP header.
///
/// # Returns
/// `Some(NtpInfo)` if the slice is at least 48 bytes and has a valid NTP version.
pub fn parse_ntp(slice: &[u8]) -> Option<NtpInfo> {
    // Standard NTP packet size is 48 bytes
    if slice.len() < 48 {
        return None;
    }

    let b0 = slice[0];
    let leap_indicator = b0 >> 6;
    let version = (b0 >> 3) & 0x07;
    let mode = b0 & 0x07;

    // Validate plausible NTP version (v2, v3, or v4)
    if version < 2 || version > 4 {
        return None;
    }

    let stratum = slice[1];
    let poll = slice[2] as i8;
    let precision = slice[3] as i8;

    Some(NtpInfo {
        leap_indicator,
        version,
        mode,
        mode_name: ntp_mode_to_str(mode),
        stratum,
        stratum_name: ntp_stratum_to_str(stratum),
        poll,
        precision,
    })
}
