/*
 * Secure Shell (SSH) Protocol parser.
 *
 * flow of control in SSH decoding:
 * 1. entry point: called from `protocols::PacketParser::parse()` when TCP port is 22
 *    or when TCP payload begins with the byte sequence `b"SSH-"`.
 * 2. identification banner check: defined in RFC 4253, every SSH connection initiates with
 *    a cleartext identification string terminated by CR/LF.
 * 3. string extraction: scans up to delimiter or 128 bytes to capture the full banner string.
 * 4. version split: splits on hyphen '-' to extract protocol version (e.g. "2.0") and
 *    remote software identity (e.g. "OpenSSH_9.6p1 Ubuntu-3ubuntu13.8").
 * 5. summary construction: formats banner for display and stats collection.
 */

/*
 * information extracted from an SSH protocol identification string.
 */
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SshInfo {
    /* full identification banner string sent over the wire. */
    pub banner: String,
    /* protocol version (e.g. "2.0"). */
    pub proto_version: String,
    /* remote software identity and version (e.g. "OpenSSH_9.6p1"). */
    pub software_version: String,
}

impl SshInfo {
    /*
     * returns a formatted summary of the SSH identification banner.
     */
    pub fn summary(&self) -> String {
        format!("SSH Identification: {}", self.banner)
    }
}

/*
 * parses an SSH identification banner from raw TCP stream payload.
 *
 * arguments:
 * * `slice` - TCP payload bytes.
 *
 * returns:
 * `Some(SshInfo)` if the payload starts with "SSH-".
 */
pub fn parse_ssh(slice: &[u8]) -> Option<SshInfo> {
    if !slice.starts_with(b"SSH-") {
        return None;
    }

    /* SSH banner ends at newline '\n' or carriage return '\r' */
    let end_idx = slice.iter().position(|&b| b == b'\n' || b == b'\r').unwrap_or(slice.len().min(128));
    let banner_slice = &slice[..end_idx];
    let banner = String::from_utf8_lossy(banner_slice).trim().to_string();

    /* split banner components: "SSH-<proto_version>-<software_version>" */
    let parts: Vec<&str> = banner.splitn(3, '-').collect();
    if parts.len() >= 3 {
        let proto_version = parts[1].to_string();
        let software_version = parts[2].to_string();
        Some(SshInfo {
            banner,
            proto_version,
            software_version,
        })
    } else {
        Some(SshInfo {
            proto_version: "Unknown".to_string(),
            software_version: banner.clone(),
            banner,
        })
    }
}
