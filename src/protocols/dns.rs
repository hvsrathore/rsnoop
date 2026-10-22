//! Domain Name System (DNS) protocol parser.
//!
//! Defined in RFC 1035, DNS translates human-readable hostnames into numeric IP addresses
//! and queries resource records across distributed authoritative name servers.
//!
//! This module implements a zero-copy wire-format DNS parser supporting:
//! - Header parsing (Transaction ID, QR flag, Opcode, RCode, Section counts).
//! - Question section parsing with DNS label pointer compression handling (0xC0 prefix).
//! - Resource record answer parsing for A, AAAA, CNAME, MX, TXT, PTR, SRV, etc.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Decoded DNS header, question list, and answer list.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DnsInfo {
    /// 16-bit identifier assigned by the program generating the query.
    pub transaction_id: u16,
    /// Query (false) or Response (true) flag.
    pub is_response: bool,
    /// 4-bit operation code (0 = Standard Query, 1 = Inverse Query, 2 = Status).
    pub opcode: u8,
    /// 4-bit response code (0 = NoError, 3 = NXDomain, etc.).
    pub rcode: u8,
    /// Human-readable response code description.
    pub rcode_name: &'static str,
    /// Number of entries in the question section.
    pub qd_count: u16,
    /// Number of resource records in the answer section.
    pub an_count: u16,
    /// Number of name server resource records in the authority records section.
    pub ns_count: u16,
    /// Number of resource records in the additional records section.
    pub ar_count: u16,
    /// Parsed queries from the question section.
    pub questions: Vec<DnsQuestion>,
    /// Parsed resource records from the answer section.
    pub answers: Vec<DnsAnswer>,
}

/// A single DNS query entry from the Question section.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DnsQuestion {
    /// Fully qualified domain name queried (e.g. "www.example.com").
    pub name: String,
    /// Resource record type number (e.g. 1 for A, 28 for AAAA).
    pub qtype: u16,
    /// Human-readable query type name (e.g. "A", "AAAA", "CNAME").
    pub qtype_name: &'static str,
    /// Query class (e.g. 1 for IN / Internet).
    pub qclass: u16,
}

/// A single DNS resource record from the Answer section.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DnsAnswer {
    /// Domain name to which this resource record pertains.
    pub name: String,
    /// Resource record type number.
    pub atype: u16,
    /// Human-readable type name.
    pub atype_name: &'static str,
    /// Time-to-live in seconds before the record should be discarded from cache.
    pub ttl: u32,
    /// Formatted string representation of the record's RDATA (e.g. IP address or CNAME target).
    pub data: String,
}

impl DnsInfo {
    /// Returns a concise one-line summary of the DNS exchange.
    pub fn summary(&self) -> String {
        let op_str = if self.is_response {
            "response"
        } else {
            "query"
        };
        let q_str = if let Some(q) = self.questions.first() {
            format!("{} {}", q.qtype_name, q.name)
        } else {
            "".to_string()
        };

        if self.is_response {
            if let Some(ans) = self.answers.first() {
                format!(
                    "DNS {} {:#06x} {} -> {} ({} ans)",
                    op_str, self.transaction_id, q_str, ans.data, self.an_count
                )
            } else if self.rcode != 0 {
                format!(
                    "DNS {} {:#06x} {} -> {}",
                    op_str, self.transaction_id, q_str, self.rcode_name
                )
            } else {
                format!("DNS {} {:#06x} {}", op_str, self.transaction_id, q_str)
            }
        } else {
            format!("DNS {} {:#06x} {}", op_str, self.transaction_id, q_str)
        }
    }
}

/// Converts a numeric DNS record type to its standard mnemonic.
pub fn dns_type_to_str(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        255 => "ANY",
        _ => "TYPE?",
    }
}

/// Converts a 4-bit DNS response code (RCODE) to its standard name.
pub fn dns_rcode_to_str(rcode: u8) -> &'static str {
    match rcode {
        0 => "NoError",
        1 => "FormatError",
        2 => "ServerFailure",
        3 => "NXDomain",
        4 => "NotImplemented",
        5 => "Refused",
        _ => "UnknownError",
    }
}

/// Parses a DNS domain name from wire format, following RFC 1035 compression pointers.
///
/// In RFC 1035:
/// - A normal label starts with a length octet (0..63) followed by that many characters.
/// - A compression pointer starts with top 2 bits set (0xC0), followed by a 14-bit offset
///   pointing to where the domain name continues elsewhere in the packet.
fn parse_domain_name(slice: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut final_offset = offset;
    let mut jump_count = 0;

    loop {
        // Guard against malformed packets with circular pointer loops
        if offset >= slice.len() || jump_count > 10 {
            return None;
        }

        let len = slice[offset] as usize;

        // Pointer (compression): top 2 bits are 11 (0xC0)
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= slice.len() {
                return None;
            }
            let pointer_offset = (((len & 0x3F) as usize) << 8) | (slice[offset + 1] as usize);
            if !jumped {
                final_offset = offset + 2;
                jumped = true;
            }
            offset = pointer_offset;
            jump_count += 1;
            continue;
        }

        offset += 1;
        // Zero length marks root label (end of name)
        if len == 0 {
            if !jumped {
                final_offset = offset;
            }
            break;
        }

        if offset + len > slice.len() {
            return None;
        }

        let label = String::from_utf8_lossy(&slice[offset..offset + len]).to_string();
        labels.push(label);
        offset += len;
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    Some((name, final_offset))
}

/// Parses raw UDP or TCP application payload into a [`DnsInfo`] structure.
///
/// # Arguments
/// * `slice` - Byte slice containing the DNS packet.
///
/// # Returns
/// `Some(DnsInfo)` if parsed successfully, or `None` if slice is not a valid DNS packet.
pub fn parse_dns(slice: &[u8]) -> Option<DnsInfo> {
    // DNS header is 12 bytes fixed
    if slice.len() < 12 {
        return None;
    }

    let transaction_id = u16::from_be_bytes([slice[0], slice[1]]);
    let flags = u16::from_be_bytes([slice[2], slice[3]]);
    let is_response = (flags & 0x8000) != 0;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let rcode = (flags & 0x0F) as u8;
    let rcode_name = dns_rcode_to_str(rcode);

    let qd_count = u16::from_be_bytes([slice[4], slice[5]]);
    let an_count = u16::from_be_bytes([slice[6], slice[7]]);
    let ns_count = u16::from_be_bytes([slice[8], slice[9]]);
    let ar_count = u16::from_be_bytes([slice[10], slice[11]]);

    let mut offset = 12;
    let mut questions = Vec::new();

    // Parse question section (capped at 20 questions for safety)
    for _ in 0..qd_count.min(20) {
        let (name, next_offset) = parse_domain_name(slice, offset)?;
        if next_offset + 4 > slice.len() {
            break;
        }
        let qtype = u16::from_be_bytes([slice[next_offset], slice[next_offset + 1]]);
        let qclass = u16::from_be_bytes([slice[next_offset + 2], slice[next_offset + 3]]);
        questions.push(DnsQuestion {
            name,
            qtype,
            qtype_name: dns_type_to_str(qtype),
            qclass,
        });
        offset = next_offset + 4;
    }

    let mut answers = Vec::new();
    // Parse answer section (capped at 20 answers for safety)
    for _ in 0..an_count.min(20) {
        let (name, next_offset) = parse_domain_name(slice, offset)?;
        if next_offset + 10 > slice.len() {
            break;
        }
        let atype = u16::from_be_bytes([slice[next_offset], slice[next_offset + 1]]);
        let ttl = u32::from_be_bytes([
            slice[next_offset + 4],
            slice[next_offset + 5],
            slice[next_offset + 6],
            slice[next_offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([slice[next_offset + 8], slice[next_offset + 9]]) as usize;
        let rdata_start = next_offset + 10;
        let rdata_end = rdata_start + rdlength;

        if rdata_end > slice.len() {
            break;
        }

        // Format RDATA based on record type
        let data = match atype {
            1 if rdlength == 4 => {
                // A Record: 4-byte IPv4 address
                let ip = Ipv4Addr::new(
                    slice[rdata_start],
                    slice[rdata_start + 1],
                    slice[rdata_start + 2],
                    slice[rdata_start + 3],
                );
                ip.to_string()
            }
            28 if rdlength == 16 => {
                // AAAA Record: 16-byte IPv6 address
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&slice[rdata_start..rdata_end]);
                let ip = Ipv6Addr::from(ip_bytes);
                ip.to_string()
            }
            5 | 12 | 2 => {
                // CNAME, PTR, or NS record (domain name)
                if let Some((target, _)) = parse_domain_name(slice, rdata_start) {
                    target
                } else {
                    format!("<{} bytes>", rdlength)
                }
            }
            16 => {
                // TXT record
                if rdlength > 1 {
                    String::from_utf8_lossy(&slice[rdata_start + 1..rdata_end]).to_string()
                } else {
                    "".to_string()
                }
            }
            _ => format!("<{} bytes>", rdlength),
        };

        answers.push(DnsAnswer {
            name,
            atype,
            atype_name: dns_type_to_str(atype),
            ttl,
            data,
        });

        offset = rdata_end;
    }

    Some(DnsInfo {
        transaction_id,
        is_response,
        opcode,
        rcode,
        rcode_name,
        qd_count,
        an_count,
        ns_count,
        ar_count,
        questions,
        answers,
    })
}
