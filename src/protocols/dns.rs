/*
 * Domain Name System (DNS) protocol parser.
 *
 * flow of control in DNS decoding:
 * 1. entry point: called from `protocols::PacketParser::parse()` when source or destination
 *    port is 53 (standard DNS) or 5353 (multicast DNS / mDNS).
 * 2. header verification: validates 12-byte fixed header (Transaction ID, flags, opcode, rcode, counts).
 * 3. question parsing: loops through question records; parses domain names by handling RFC 1035
 *    label length prefixes and compression pointers (0xC0).
 * 4. answer parsing: loops through resource records; decodes record types (A, AAAA, CNAME, PTR, TXT),
 *    extracts TTL, and formats RDATA into human-readable strings (e.g. IPv4/IPv6 addresses or canonical names).
 * 5. summary construction: produces concise query/response summary string for terminal output.
 */

use std::net::{Ipv4Addr, Ipv6Addr};

/*
 * decoded DNS header, question list, and answer list.
 * corresponds to RFC 1035 wire specifications.
 */
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DnsInfo {
    /* 16-bit identifier assigned by the program generating the query. */
    pub transaction_id: u16,
    /* query (false) or response (true) flag. */
    pub is_response: bool,
    /* 4-bit operation code (0 = Standard Query, 1 = Inverse Query, 2 = Status). */
    pub opcode: u8,
    /* 4-bit response code (0 = NoError, 3 = NXDomain, etc.). */
    pub rcode: u8,
    /* human-readable response code description. */
    pub rcode_name: &'static str,
    /* number of entries in the question section. */
    pub qd_count: u16,
    /* number of resource records in the answer section. */
    pub an_count: u16,
    /* number of name server resource records in the authority records section. */
    pub ns_count: u16,
    /* number of resource records in the additional records section. */
    pub ar_count: u16,
    /* parsed queries from the question section. */
    pub questions: Vec<DnsQuestion>,
    /* parsed resource records from the answer section. */
    pub answers: Vec<DnsAnswer>,
}

/*
 * a single DNS query entry from the Question section.
 */
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DnsQuestion {
    /* fully qualified domain name queried (e.g. "www.example.com"). */
    pub name: String,
    /* resource record type number (e.g. 1 for A, 28 for AAAA). */
    pub qtype: u16,
    /* human-readable query type name (e.g. "A", "AAAA", "CNAME"). */
    pub qtype_name: &'static str,
    /* query class (e.g. 1 for IN / Internet). */
    pub qclass: u16,
}

/*
 * a single DNS resource record from the Answer section.
 */
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DnsAnswer {
    /* domain name to which this resource record pertains. */
    pub name: String,
    /* resource record type number. */
    pub atype: u16,
    /* human-readable type name. */
    pub atype_name: &'static str,
    /* time-to-live in seconds before the record should be discarded from cache. */
    pub ttl: u32,
    /* formatted string representation of the record's RDATA (e.g. IP address or CNAME target). */
    pub data: String,
}

impl DnsInfo {
    /*
     * returns a concise one-line summary of the DNS exchange.
     */
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

/*
 * converts a numeric DNS record type to its standard mnemonic.
 */
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

/*
 * converts a 4-bit DNS response code (RCODE) to its standard name.
 */
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

/*
 * parses a DNS domain name from wire format, following RFC 1035 compression pointers.
 *
 * in RFC 1035:
 * - a normal label starts with a length octet (0..63) followed by that many characters.
 * - a compression pointer starts with top 2 bits set (0xC0), followed by a 14-bit offset
 *   pointing to where the domain name continues elsewhere in the packet.
 */
fn parse_domain_name(slice: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut final_offset = offset;
    let mut jump_count = 0;

    loop {
        /* guard against malformed packets with circular pointer loops */
        if offset >= slice.len() || jump_count > 10 {
            return None;
        }

        let len = slice[offset] as usize;

        /* pointer (compression): top 2 bits are 11 (0xC0) */
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
        /* zero length marks root label (end of name) */
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

/*
 * parses raw UDP or TCP application payload into a `DnsInfo` structure.
 *
 * arguments:
 * * `slice` - byte slice containing the DNS packet.
 *
 * returns:
 * `Some(DnsInfo)` if parsed successfully, or `None` if slice is not a valid DNS packet.
 */
pub fn parse_dns(slice: &[u8]) -> Option<DnsInfo> {
    /* DNS header is 12 bytes fixed */
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

    /* parse question section (capped at 20 questions for safety) */
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
    /* parse answer section (capped at 20 answers for safety) */
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

        /* format RDATA based on record type */
        let data = match atype {
            1 if rdlength == 4 => {
                /* A Record: 4-byte IPv4 address */
                let ip = Ipv4Addr::new(
                    slice[rdata_start],
                    slice[rdata_start + 1],
                    slice[rdata_start + 2],
                    slice[rdata_start + 3],
                );
                ip.to_string()
            }
            28 if rdlength == 16 => {
                /* AAAA Record: 16-byte IPv6 address */
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&slice[rdata_start..rdata_end]);
                let ip = Ipv6Addr::from(ip_bytes);
                ip.to_string()
            }
            5 | 12 | 2 => {
                /* CNAME, PTR, or NS record (domain name) */
                if let Some((target, _)) = parse_domain_name(slice, rdata_start) {
                    target
                } else {
                    format!("<{} bytes>", rdlength)
                }
            }
            16 => {
                /* TXT record */
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
