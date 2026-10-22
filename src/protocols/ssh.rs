//! Secure Shell (SSH) Protocol parser.
//!
//! Defined in RFC 4253, the SSH transport layer protocol begins with an identification
//! string exchange (e.g. "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.8\r\n").

/// Information extracted from an SSH protocol identification string.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SshInfo {
    /// Full identification banner string sent over the wire.
    pub banner: String,
    /// Protocol version (e.g. "2.0").
    pub proto_version: String,
    /// Remote software identity and version (e.g. "OpenSSH_9.6p1").
    pub software_version: String,
}

impl SshInfo {
    /// Returns a formatted summary of the SSH identification banner.
    pub fn summary(&self) -> String {
        format!("SSH Identification: {}", self.banner)
    }
}

/// Parses an SSH identification banner from raw TCP stream payload.
///
/// # Arguments
/// * `slice` - TCP payload bytes.
///
/// # Returns
/// `Some(SshInfo)` if the payload starts with "SSH-".
pub fn parse_ssh(slice: &[u8]) -> Option<SshInfo> {
    if !slice.starts_with(b"SSH-") {
        return None;
    }

    // SSH banner ends at newline '\n' or carriage return '\r'
    let end_idx = slice.iter().position(|&b| b == b'\n' || b == b'\r').unwrap_or(slice.len().min(128));
    let banner_slice = &slice[..end_idx];
    let banner = String::from_utf8_lossy(banner_slice).trim().to_string();

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
