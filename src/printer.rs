use crate::direction::PacketDirection;
use crate::protocols::ethernet::format_mac;
use crate::protocols::{AppProtocol, L2Info, ParsedPacket};
use colored::Colorize;

/// Terminal output renderer for network packets.
///
/// Supports three display modes:
/// 1. Compact mode: A single high-density colored line per packet (similar to tcpdump/tshark).
/// 2. Verbose mode: A structured, multi-layer hierarchical breakdown (similar to Wireshark packet details).
/// 3. Hexdump mode: Side-by-side hexadecimal and ASCII view of packet payload.
pub struct PacketPrinter;

impl PacketPrinter {
    /// Formats and displays a packet according to verbose and hexdump settings.
    pub fn print(packet: &ParsedPacket, verbose: bool, hexdump: bool) {
        if verbose {
            Self::print_verbose(packet);
        } else {
            Self::print_compact(packet);
        }

        if hexdump && !packet.payload.is_empty() {
            Self::print_hexdump(&packet.payload);
        }
    }

    /// Renders a single-line summary of the packet with colors:
    /// [Index] [Timestamp] [Direction] [Protocol] [Endpoints] [Protocol Details / Summary]
    pub fn print_compact(packet: &ParsedPacket) {
        let time_str = packet.timestamp.format("%H:%M:%S%.6f").to_string();
        let num_str = format!("#{:05}", packet.packet_num).dimmed();
        let dir_badge = packet.direction.badge();
        let proto_badge = Self::protocol_badge(packet.display_protocol());

        // Extract endpoints (Source -> Destination)
        let endpoints = if let Some(ip) = &packet.ip {
            let src = ip.src_ip();
            let dst = ip.dst_ip();

            if let Some(tcp) = &packet.tcp {
                let src_name = tcp.src_port_name.unwrap_or("");
                let dst_name = tcp.dst_port_name.unwrap_or("");
                format!(
                    "{}:{} -> {}:{}",
                    src,
                    if !src_name.is_empty() {
                        format!("{}({})", tcp.src_port, src_name).cyan()
                    } else {
                        tcp.src_port.to_string().cyan()
                    },
                    dst,
                    if !dst_name.is_empty() {
                        format!("{}({})", tcp.dst_port, dst_name).cyan()
                    } else {
                        tcp.dst_port.to_string().cyan()
                    }
                )
            } else if let Some(udp) = &packet.udp {
                let src_name = udp.src_port_name.unwrap_or("");
                let dst_name = udp.dst_port_name.unwrap_or("");
                format!(
                    "{}:{} -> {}:{}",
                    src,
                    if !src_name.is_empty() {
                        format!("{}({})", udp.src_port, src_name).cyan()
                    } else {
                        udp.src_port.to_string().cyan()
                    },
                    dst,
                    if !dst_name.is_empty() {
                        format!("{}({})", udp.dst_port, dst_name).cyan()
                    } else {
                        udp.dst_port.to_string().cyan()
                    }
                )
            } else {
                format!("{} -> {}", src, dst)
            }
        } else if let Some(arp) = &packet.arp {
            format!("{} -> {}", arp.sender_ip, arp.target_ip)
        } else if let Some(L2Info::Ethernet(eth)) = &packet.l2 {
            format!("{} -> {}", format_mac(&eth.src_mac), format_mac(&eth.dst_mac))
        } else {
            "Unknown Endpoints".to_string()
        };

        // Extract protocol specific info / summary
        let details = if let Some(app) = &packet.app {
            match app {
                AppProtocol::Dns(dns) => dns.summary().green(),
                AppProtocol::Http(http) => http.summary().yellow().bold(),
                AppProtocol::Tls(tls) => tls.summary().magenta(),
                AppProtocol::Dhcp(dhcp) => dhcp.summary().cyan(),
                AppProtocol::Ntp(ntp) => ntp.summary().blue(),
                AppProtocol::Ssh(ssh) => ssh.summary().bright_white(),
            }
        } else if let Some(tcp) = &packet.tcp {
            format!(
                "{} Seq={} Ack={} Win={} Len={}",
                tcp.flags_str.yellow(),
                tcp.seq_number,
                tcp.ack_number,
                tcp.window_size,
                tcp.payload_len
            )
            .normal()
        } else if let Some(udp) = &packet.udp {
            format!("Len={}", udp.length).dimmed()
        } else if let Some(icmp) = &packet.icmp {
            icmp.summary().bright_red()
        } else if let Some(arp) = &packet.arp {
            arp.summary().bright_cyan()
        } else if let Some(ip) = &packet.ip {
            format!("Protocol {}", ip.protocol_name()).dimmed()
        } else {
            format!("Raw packet ({} bytes)", packet.raw_len).dimmed()
        };

        println!(
            "{} {} {} {} {:<45} {}",
            num_str,
            time_str.dimmed(),
            dir_badge,
            proto_badge,
            endpoints,
            details
        );
    }

    /// Renders a multi-line tree breakdown of every network layer in the packet.
    pub fn print_verbose(packet: &ParsedPacket) {
        println!();
        println!(
            "{}",
            format!(
                "┌─── [Packet #{}] [{} bytes] [Captured: {}] [{}] ───",
                packet.packet_num,
                packet.raw_len,
                packet.timestamp.format("%Y-%m-%d %H:%M:%S%.6f"),
                match packet.direction {
                    PacketDirection::Sent => "TRANSMITTED / OUTGOING",
                    PacketDirection::Received => "RECEIVED / INCOMING",
                    PacketDirection::Loopback => "LOCAL LOOPBACK",
                    PacketDirection::Promiscuous => "PROMISCUOUS / TRANSIT",
                    PacketDirection::Unknown => "DIRECTION UNKNOWN",
                }
            )
            .bold()
            .white()
        );

        // Layer 2: Data Link Layer
        if let Some(l2) = &packet.l2 {
            match l2 {
                L2Info::Ethernet(eth) => {
                    let vlan_str = eth
                        .vlan_id
                        .map(|v| format!(" VLAN ID: {}", v))
                        .unwrap_or_default();
                    println!(
                        "│ {} Ethernet II: {} -> {} (Type: {:#06x} {}){}",
                        "├─►".blue(),
                        format_mac(&eth.src_mac).yellow(),
                        format_mac(&eth.dst_mac).yellow(),
                        eth.ether_type,
                        eth.ether_type_name.bold(),
                        vlan_str.cyan()
                    );
                }
                L2Info::Sll(sll) => {
                    let sender_str = sll
                        .sender_lladdr
                        .map(|m| format!(" Sender MAC: {}", format_mac(&m)))
                        .unwrap_or_default();
                    println!(
                        "│ {} Linux Cooked SLL: Type: {} (Proto: {:#06x} {}){}",
                        "├─►".blue(),
                        sll.packet_type_name.yellow(),
                        sll.protocol,
                        sll.protocol_name.bold(),
                        sender_str
                    );
                }
            }
        }

        // Layer 3: ARP or IP
        if let Some(arp) = &packet.arp {
            println!(
                "│ {} Address Resolution Protocol (ARP):",
                "├─►".cyan()
            );
            println!(
                "│   Opcode: {} ({}), Sender: {} [{}] -> Target: {} [{}]",
                arp.opcode_name.bold(),
                arp.opcode,
                arp.sender_ip,
                format_mac(&arp.sender_mac),
                arp.target_ip,
                format_mac(&arp.target_mac)
            );
        } else if let Some(ip) = &packet.ip {
            match ip {
                crate::protocols::ip::IpInfo::V4(v4) => {
                    println!(
                        "│ {} IPv4 Header: {} -> {} (TTL: {}, Proto: {} {}, ID: {:#06x}, Frag: DF={}, MF={}, Off={})",
                        "├─►".green(),
                        v4.src.to_string().yellow(),
                        v4.dst.to_string().yellow(),
                        v4.ttl,
                        v4.protocol,
                        v4.protocol_name.bold(),
                        v4.identification,
                        v4.dont_fragment,
                        v4.more_fragments,
                        v4.fragment_offset
                    );
                }
                crate::protocols::ip::IpInfo::V6(v6) => {
                    println!(
                        "│ {} IPv6 Header: {} -> {} (Hop Limit: {}, Next Header: {} {})",
                        "├─►".green(),
                        v6.src.to_string().yellow(),
                        v6.dst.to_string().yellow(),
                        v6.hop_limit,
                        v6.next_header,
                        v6.next_header_name.bold()
                    );
                }
            }
        }

        // Layer 4: TCP, UDP, or ICMP
        if let Some(tcp) = &packet.tcp {
            let src_name = tcp.src_port_name.map(|n| format!(" ({})", n)).unwrap_or_default();
            let dst_name = tcp.dst_port_name.map(|n| format!(" ({})", n)).unwrap_or_default();
            println!(
                "│ {} Transmission Control Protocol (TCP): {}{} -> {}{}",
                "├─►".magenta(),
                tcp.src_port,
                src_name.cyan(),
                tcp.dst_port,
                dst_name.cyan()
            );
            println!(
                "│   Seq: {}, Ack: {}, Flags: {}, Win: {}, Checksum: {:#06x}, Payload: {} bytes",
                tcp.seq_number,
                tcp.ack_number,
                tcp.flags_str.bold().yellow(),
                tcp.window_size,
                tcp.checksum,
                tcp.payload_len
            );
        } else if let Some(udp) = &packet.udp {
            let src_name = udp.src_port_name.map(|n| format!(" ({})", n)).unwrap_or_default();
            let dst_name = udp.dst_port_name.map(|n| format!(" ({})", n)).unwrap_or_default();
            println!(
                "│ {} User Datagram Protocol (UDP): {}{} -> {}{}, Len: {}, Checksum: {:#06x}",
                "├─►".magenta(),
                udp.src_port,
                src_name.cyan(),
                udp.dst_port,
                dst_name.cyan(),
                udp.length,
                udp.checksum
            );
        } else if let Some(icmp) = &packet.icmp {
            println!(
                "│ {} Internet Control Message Protocol: {}",
                "├─►".bright_red(),
                icmp.summary().bold()
            );
        }

        // Layer 5/7: Application Protocols
        if let Some(app) = &packet.app {
            match app {
                AppProtocol::Dns(dns) => {
                    println!("│ {} Domain Name System (DNS):", "├─►".yellow());
                    println!(
                        "│   Transaction ID: {:#06x}, Response: {}, RCode: {} ({})",
                        dns.transaction_id, dns.is_response, dns.rcode, dns.rcode_name
                    );
                    for q in &dns.questions {
                        println!("│   [Question] {} (Type: {})", q.name.cyan(), q.qtype_name);
                    }
                    for a in &dns.answers {
                        println!(
                            "│   [Answer] {} -> {} (Type: {}, TTL: {}s)",
                            a.name.cyan(),
                            a.data.green().bold(),
                            a.atype_name,
                            a.ttl
                        );
                    }
                }
                AppProtocol::Http(http) => {
                    println!("│ {} Hypertext Transfer Protocol (HTTP):", "├─►".yellow());
                    match http {
                        crate::protocols::http::HttpInfo::Request(req) => {
                            println!(
                                "│   Request: {} {} HTTP/1.{}",
                                req.method.bold().green(),
                                req.path.cyan(),
                                req.version
                            );
                            if let Some(host) = &req.host {
                                println!("│   Host: {}", host);
                            }
                            if let Some(ua) = &req.user_agent {
                                println!("│   User-Agent: {}", ua);
                            }
                        }
                        crate::protocols::http::HttpInfo::Response(resp) => {
                            println!(
                                "│   Response: HTTP/1.{} {} {}",
                                resp.version,
                                resp.code.to_string().bold().yellow(),
                                resp.reason
                            );
                            if let Some(ct) = &resp.content_type {
                                println!("│   Content-Type: {}", ct);
                            }
                        }
                    }
                }
                AppProtocol::Tls(tls) => {
                    println!("│ {} Transport Layer Security (TLS):", "├─►".yellow());
                    println!(
                        "│   Version: {}, Record Type: {} ({})",
                        tls.version_name.bold(),
                        tls.content_type_name,
                        tls.content_type
                    );
                    if let Some(hs_name) = tls.handshake_type_name {
                        println!("│   Handshake Type: {}", hs_name.cyan());
                    }
                    if let Some(sni) = &tls.sni {
                        println!("│   Server Name Indication (SNI): {}", sni.green().bold());
                    }
                    if !tls.alpn.is_empty() {
                        println!("│   ALPN Protocols: {}", tls.alpn.join(", "));
                    }
                }
                AppProtocol::Dhcp(dhcp) => {
                    println!("│ {} Dynamic Host Configuration Protocol (DHCP):", "├─►".yellow());
                    println!("│   {}", dhcp.summary().bold());
                }
                AppProtocol::Ntp(ntp) => {
                    println!("│ {} Network Time Protocol (NTP):", "├─►".yellow());
                    println!("│   {}", ntp.summary().bold());
                }
                AppProtocol::Ssh(ssh) => {
                    println!("│ {} Secure Shell (SSH):", "├─►".yellow());
                    println!("│   {}", ssh.summary().bold());
                }
            }
        }

        if !packet.payload.is_empty() {
            println!(
                "│ {} Payload Data: {} unparsed bytes",
                "└─►".dimmed(),
                packet.payload.len()
            );
        } else {
            println!("└───");
        }
    }

    /// Outputs a formatted hexadecimal and printable ASCII dump of raw bytes (hexdump -C style).
    pub fn print_hexdump(data: &[u8]) {
        println!("{}", "--- Hex Dump ---".dimmed());
        for chunk in data.chunks(16) {
            let mut hex_part = String::with_capacity(50);
            let mut ascii_part = String::with_capacity(18);

            for (i, byte) in chunk.iter().enumerate() {
                if i == 8 {
                    hex_part.push(' ');
                }
                hex_part.push_str(&format!("{:02x} ", byte));

                if byte.is_ascii_graphic() || *byte == b' ' {
                    ascii_part.push(*byte as char);
                } else {
                    ascii_part.push('.');
                }
            }

            // Pad remaining space if last chunk is shorter than 16 bytes
            let pad_len = 16 - chunk.len();
            let mut pad_spaces = pad_len * 3;
            if chunk.len() <= 8 {
                pad_spaces += 1;
            }
            for _ in 0..pad_spaces {
                hex_part.push(' ');
            }

            println!("  {:<49} |{}|", hex_part, ascii_part.green());
        }
        println!();
    }

    /// Color-coded badge for protocol names.
    fn protocol_badge(proto: &str) -> colored::ColoredString {
        match proto {
            "DNS" => "[DNS ]".bold().green(),
            "HTTP" => "[HTTP]".bold().yellow(),
            "TLS" => "[TLS ]".bold().magenta(),
            "DHCP" => "[DHCP]".bold().bright_blue(),
            "NTP" => "[NTP ]".bold().blue(),
            "SSH" => "[SSH ]".bold().bright_white(),
            "TCP" => "[TCP ]".bold().white(),
            "UDP" => "[UDP ]".bold().cyan(),
            "ICMP" => "[ICMP]".bold().bright_red(),
            "ARP" => "[ARP ]".bold().bright_cyan(),
            "IPv4" => "[IPv4]".bold().normal(),
            "IPv6" => "[IPv6]".bold().normal(),
            _ => "[RAW ]".dimmed(),
        }
    }
}
