/*
 * Network Time Protocol (NTP) parser.
 *
 * flow of control in NTP decoding:
 * 1. entry point: called from `protocols::PacketParser::parse()` when UDP source or destination
 *    port is 123.
 * 2. length check: validates 48-byte standard fixed NTP datagram length.
 * 3. byte 0 bit-unpacking:
 *    - bits 6..7 -> leap indicator (warning of upcoming leap second).
 *    - bits 3..5 -> NTP version number (verifies plausible v2, v3, or v4).
 *    - bits 0..2 -> mode code (3 = Client, 4 = Server, 5 = Broadcast).
 * 4. stratum and poll: extracts clock stratum level (primary GPS vs secondary) and polling rate.
 * 5. summary construction: formats clock synchronization status for compact and verbose output.
 */

/*
 * decoded Network Time Protocol (NTP) header.
 * corresponds to RFC 5905 specifications.
 */
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NtpInfo {
    /* 2-bit warning of an impending leap second to be inserted/deleted. */
    pub leap_indicator: u8,
    /* NTP protocol version number (typically 3 or 4). */
    pub version: u8,
    /* 3-bit mode code (e.g. 3 = Client, 4 = Server, 5 = Broadcast). */
    pub mode: u8,
    /* human-readable mode description. */
    pub mode_name: &'static str,
    /* stratum level of the local clock (1 = primary reference, 2-15 = secondary). */
    pub stratum: u8,
    /* stratum description. */
    pub stratum_name: &'static str,
    /* maximum interval between successive messages (in log2 seconds). */
    pub poll: i8,
    /* precision of the local clock (in log2 seconds). */
    pub precision: i8,
}

impl NtpInfo {
    /*
     * returns a concise one-line summary of the NTP packet.
     */
    pub fn summary(&self) -> String {
        format!(
            "NTP v{} {} (Stratum {}, Poll {})",
            self.version, self.mode_name, self.stratum, self.poll
        )
    }
}

/*
 * maps numeric NTP mode codes to human-readable names.
 */
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

/*
 * maps numeric NTP stratum levels to descriptive names.
 */
pub fn ntp_stratum_to_str(stratum: u8) -> &'static str {
    match stratum {
        0 => "Unspecified / Kiss-o'-Death",
        1 => "Primary Reference (e.g. GPS/atomic)",
        2..=15 => "Secondary Reference",
        16 => "Unsynchronized",
        _ => "Reserved",
    }
}

/*
 * parses an NTP packet from raw UDP payload.
 *
 * arguments:
 * * `slice` - UDP payload bytes starting at the NTP header.
 *
 * returns:
 * `Some(NtpInfo)` if the slice is at least 48 bytes and has a valid NTP version.
 */
pub fn parse_ntp(slice: &[u8]) -> Option<NtpInfo> {
    /* standard NTP packet size is 48 bytes */
    if slice.len() < 48 {
        return None;
    }

    let b0 = slice[0];
    let leap_indicator = b0 >> 6;
    let version = (b0 >> 3) & 0x07;
    let mode = b0 & 0x07;

    /* validate plausible NTP version (v2, v3, or v4) */
    if !(2..=4).contains(&version) {
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
