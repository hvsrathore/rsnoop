//! Dynamic Host Configuration Protocol (DHCP) and Bootstrap Protocol (BOOTP) parser.
//!
//! Defined in RFC 2131 and RFC 2132, DHCP operates over UDP (server port 67, client port 68)
//! to automatically assign IP addresses and network configuration parameters to client devices.

use super::ethernet::format_mac;
use std::net::Ipv4Addr;

/// Decoded Dynamic Host Configuration Protocol (DHCP) packet information.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DhcpInfo {
    /// Message op code: 1 = BOOTREQUEST, 2 = BOOTREPLY.
    pub op: u8,
    /// Human-readable message op name.
    pub op_name: &'static str,
    /// Transaction ID chosen by the client to match requests with replies.
    pub xid: u32,
    /// Client IP address (filled in if client already has an active lease).
    pub ciaddr: Ipv4Addr,
    /// "Your" (client) IP address offered or assigned by the DHCP server.
    pub yiaddr: Ipv4Addr,
    /// Next server IP address to use in bootstrap process.
    pub siaddr: Ipv4Addr,
    /// Relay agent (gateway) IP address.
    pub giaddr: Ipv4Addr,
    /// Client hardware MAC address (from chaddr field).
    pub chaddr: [u8; 6],
    /// DHCP message type from Option 53 (e.g. Discover, Offer, Request, ACK).
    pub message_type: Option<DhcpMessageType>,
    /// Requested IP address from Option 50.
    pub requested_ip: Option<Ipv4Addr>,
    /// DHCP server identifier from Option 54.
    pub server_identifier: Option<Ipv4Addr>,
    /// Client host name from Option 12.
    pub hostname: Option<String>,
}

/// DHCP message types defined in RFC 2132 Option 53.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    /// Client broadcast to locate available DHCP servers.
    Discover = 1,
    /// Server response offering IP address parameters.
    Offer = 2,
    /// Client request to accept offered lease or renew existing lease.
    Request = 3,
    /// Client indication that offered address is already in use.
    Decline = 4,
    /// Server acknowledgment committing the lease parameters.
    Ack = 5,
    /// Server negative acknowledgment rejecting client request.
    Nak = 6,
    /// Client notification releasing its assigned lease.
    Release = 7,
    /// Client request for local configuration parameters without lease assignment.
    Inform = 8,
}

impl DhcpMessageType {
    /// Returns the standard display name for the DHCP message type.
    pub fn name(&self) -> &'static str {
        match self {
            DhcpMessageType::Discover => "Discover",
            DhcpMessageType::Offer => "Offer",
            DhcpMessageType::Request => "Request",
            DhcpMessageType::Decline => "Decline",
            DhcpMessageType::Ack => "ACK",
            DhcpMessageType::Nak => "NAK",
            DhcpMessageType::Release => "Release",
            DhcpMessageType::Inform => "Inform",
        }
    }
}

impl DhcpInfo {
    /// Produces a concise summary string representing the DHCP packet.
    pub fn summary(&self) -> String {
        let msg_name = self
            .message_type
            .map(|m| m.name())
            .unwrap_or(self.op_name);

        let details = if !self.yiaddr.is_unspecified() {
            format!("Your IP={}", self.yiaddr)
        } else if let Some(req_ip) = self.requested_ip {
            format!("Req IP={}", req_ip)
        } else {
            format!("Client MAC={}", format_mac(&self.chaddr))
        };

        let host = self
            .hostname
            .as_deref()
            .map(|h| format!(" Host={}", h))
            .unwrap_or_default();

        format!("DHCP {} (xid={:#010x}, {}{})", msg_name, self.xid, details, host)
    }
}

/// Parses raw UDP payload into a [`DhcpInfo`] struct.
///
/// # Arguments
/// * `slice` - Byte slice containing the BOOTP/DHCP message.
///
/// # Returns
/// `Some(DhcpInfo)` if the packet contains a valid BOOTP/DHCP header and magic cookie.
pub fn parse_dhcp(slice: &[u8]) -> Option<DhcpInfo> {
    // Minimum BOOTP header size is 236 bytes + 4 bytes magic cookie = 240
    if slice.len() < 240 {
        return None;
    }

    // Byte 0: Op code
    let op = slice[0];
    let op_name = match op {
        1 => "BOOTREQUEST",
        2 => "BOOTREPLY",
        _ => return None,
    };

    // Bytes 4..8: Transaction ID (xid)
    let xid = u32::from_be_bytes([slice[4], slice[5], slice[6], slice[7]]);
    // Bytes 12..16: Client IP (ciaddr)
    let ciaddr = Ipv4Addr::new(slice[12], slice[13], slice[14], slice[15]);
    // Bytes 16..20: "Your" IP (yiaddr)
    let yiaddr = Ipv4Addr::new(slice[16], slice[17], slice[18], slice[19]);
    // Bytes 20..24: Server IP (siaddr)
    let siaddr = Ipv4Addr::new(slice[20], slice[21], slice[22], slice[23]);
    // Bytes 24..28: Gateway IP (giaddr)
    let giaddr = Ipv4Addr::new(slice[24], slice[25], slice[26], slice[27]);

    // Bytes 28..34: Client Hardware Address (chaddr - first 6 bytes for Ethernet MAC)
    let mut chaddr = [0u8; 6];
    chaddr.copy_from_slice(&slice[28..34]);

    // Check DHCP Magic Cookie at bytes 236..240: 0x63 0x82 0x53 0x63
    let magic_cookie = &slice[236..240];
    if magic_cookie != [99, 130, 83, 99] {
        return None;
    }

    let mut message_type = None;
    let mut requested_ip = None;
    let mut server_identifier = None;
    let mut hostname = None;

    // Parse variable-length TLV (Type-Length-Value) DHCP options starting at offset 240
    let mut offset = 240;
    while offset < slice.len() {
        let opt_type = slice[offset];
        if opt_type == 255 {
            // End Option (0xFF) marks completion of DHCP options
            break;
        }
        if opt_type == 0 {
            // Pad Option (0x00) for byte alignment
            offset += 1;
            continue;
        }

        if offset + 1 >= slice.len() {
            break;
        }
        let opt_len = slice[offset + 1] as usize;
        offset += 2;

        if offset + opt_len > slice.len() {
            break;
        }
        let opt_val = &slice[offset..offset + opt_len];

        match opt_type {
            53 if opt_len == 1 => {
                // Option 53: DHCP Message Type
                message_type = match opt_val[0] {
                    1 => Some(DhcpMessageType::Discover),
                    2 => Some(DhcpMessageType::Offer),
                    3 => Some(DhcpMessageType::Request),
                    4 => Some(DhcpMessageType::Decline),
                    5 => Some(DhcpMessageType::Ack),
                    6 => Some(DhcpMessageType::Nak),
                    7 => Some(DhcpMessageType::Release),
                    8 => Some(DhcpMessageType::Inform),
                    _ => None,
                };
            }
            50 if opt_len == 4 => {
                // Option 50: Requested IP Address
                requested_ip = Some(Ipv4Addr::new(opt_val[0], opt_val[1], opt_val[2], opt_val[3]));
            }
            54 if opt_len == 4 => {
                // Option 54: Server Identifier
                server_identifier = Some(Ipv4Addr::new(opt_val[0], opt_val[1], opt_val[2], opt_val[3]));
            }
            12 if opt_len > 0 => {
                // Option 12: Host Name
                hostname = Some(String::from_utf8_lossy(opt_val).to_string());
            }
            _ => {}
        }

        offset += opt_len;
    }

    Some(DhcpInfo {
        op,
        op_name,
        xid,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        chaddr,
        message_type,
        requested_ip,
        server_identifier,
        hostname,
    })
}
