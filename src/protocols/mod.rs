//! Protocol decoding engine and multi-layer packet representation.
//!
//! Handles sequential decoding of packets across network protocol layers:
//! - Data Link Layer (L2): Ethernet II, IEEE 802.1Q (VLAN), Linux Cooked SLL/SLL2, BSD Loopback.
//! - Network Layer (L3): IPv4, IPv6, ARP.
//! - Transport Layer (L4): TCP, UDP, ICMPv4, ICMPv6.
//! - Application Layer (L5/L7): DNS, HTTP, TLS, DHCP, NTP, SSH.

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod ethernet;
pub mod http;
pub mod icmp;
pub mod ip;
pub mod ntp;
pub mod sll;
pub mod ssh;
pub mod tcp;
pub mod tls;
pub mod udp;

use crate::args::ProtocolFilter;
use crate::direction::{determine_direction, PacketDirection};
use crate::interface::LocalIdentity;
use chrono::{DateTime, Local, TimeZone};
use pcap::Linktype;
use std::net::IpAddr;

/// Container for decoded Data Link Layer (L2) frame information.
#[derive(Debug, Clone)]
pub enum L2Info {
    /// Standard Ethernet II frame.
    Ethernet(ethernet::EthernetInfo),
    /// Linux Cooked Capture (SLL) frame.
    Sll(sll::SllInfo),
}

/// Container for decoded Application Layer (L5/L7) protocol information.
#[derive(Debug, Clone)]
pub enum AppProtocol {
    /// Domain Name System query or response.
    Dns(dns::DnsInfo),
    /// Hypertext Transfer Protocol request or response.
    Http(http::HttpInfo),
    /// Transport Layer Security record / handshake.
    Tls(tls::TlsInfo),
    /// Dynamic Host Configuration Protocol message.
    Dhcp(dhcp::DhcpInfo),
    /// Network Time Protocol clock sync packet.
    Ntp(ntp::NtpInfo),
    /// Secure Shell version identification banner.
    Ssh(ssh::SshInfo),
}

/// Fully decoded representation of a captured network packet across all layers.
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    /// Sequential capture index (1-based).
    pub packet_num: usize,
    /// Wall-clock timestamp when the packet was captured.
    pub timestamp: DateTime<Local>,
    /// Total wire length of the packet in bytes.
    pub raw_len: usize,
    /// Traffic flow direction: Sent (TX), Received (RX), Loopback, or Promiscuous.
    pub direction: PacketDirection,
    /// Decoded Data Link Layer (L2) header if available.
    pub l2: Option<L2Info>,
    /// Decoded Address Resolution Protocol (ARP) header if present.
    pub arp: Option<arp::ArpInfo>,
    /// Decoded Internet Protocol (IPv4 or IPv6) header if present.
    pub ip: Option<ip::IpInfo>,
    /// Decoded Transmission Control Protocol (TCP) header if present.
    pub tcp: Option<tcp::TcpInfo>,
    /// Decoded User Datagram Protocol (UDP) header if present.
    pub udp: Option<udp::UdpInfo>,
    /// Decoded Internet Control Message Protocol (ICMP) header if present.
    pub icmp: Option<icmp::IcmpInfo>,
    /// Decoded Application Layer (L5/L7) protocol if recognized.
    pub app: Option<AppProtocol>,
    /// Remaining unparsed payload bytes (used for hex dumps and deep inspection).
    pub payload: Vec<u8>,
}

impl ParsedPacket {
    /// Returns the primary protocol name for display badges (e.g. "DNS", "TLS", "TCP", "ARP").
    pub fn display_protocol(&self) -> &'static str {
        if let Some(app) = &self.app {
            match app {
                AppProtocol::Dns(_) => "DNS",
                AppProtocol::Http(_) => "HTTP",
                AppProtocol::Tls(_) => "TLS",
                AppProtocol::Dhcp(_) => "DHCP",
                AppProtocol::Ntp(_) => "NTP",
                AppProtocol::Ssh(_) => "SSH",
            }
        } else if self.tcp.is_some() {
            "TCP"
        } else if self.udp.is_some() {
            "UDP"
        } else if self.icmp.is_some() {
            "ICMP"
        } else if self.arp.is_some() {
            "ARP"
        } else if let Some(ip) = &self.ip {
            match ip {
                ip::IpInfo::V4(_) => "IPv4",
                ip::IpInfo::V6(_) => "IPv6",
            }
        } else {
            "RAW"
        }
    }

    /// Evaluates whether this packet satisfies the user's protocol filter option.
    pub fn matches_protocol(&self, filter: ProtocolFilter) -> bool {
        match filter {
            ProtocolFilter::All => true,
            ProtocolFilter::Tcp => self.tcp.is_some(),
            ProtocolFilter::Udp => self.udp.is_some(),
            ProtocolFilter::Icmp => self.icmp.is_some(),
            ProtocolFilter::Arp => self.arp.is_some(),
            ProtocolFilter::Dns => matches!(self.app, Some(AppProtocol::Dns(_))),
            ProtocolFilter::Http => matches!(self.app, Some(AppProtocol::Http(_))),
            ProtocolFilter::Tls => matches!(self.app, Some(AppProtocol::Tls(_))),
            ProtocolFilter::Dhcp => matches!(self.app, Some(AppProtocol::Dhcp(_))),
            ProtocolFilter::Ntp => matches!(self.app, Some(AppProtocol::Ntp(_))),
            ProtocolFilter::Ssh => matches!(self.app, Some(AppProtocol::Ssh(_))),
            ProtocolFilter::Ipv4 => matches!(self.ip, Some(ip::IpInfo::V4(_))),
            ProtocolFilter::Ipv6 => matches!(self.ip, Some(ip::IpInfo::V6(_))),
        }
    }

    /// Evaluates whether this packet satisfies the user's port filter option.
    pub fn matches_port(&self, port: Option<u16>) -> bool {
        if let Some(target_port) = port {
            if let Some(tcp) = &self.tcp {
                return tcp.src_port == target_port || tcp.dst_port == target_port;
            }
            if let Some(udp) = &self.udp {
                return udp.src_port == target_port || udp.dst_port == target_port;
            }
            false
        } else {
            true
        }
    }
}

/// Packet decoder instance holding local interface identity for directional resolution.
pub struct PacketParser<'a> {
    local_identity: &'a LocalIdentity,
}

impl<'a> PacketParser<'a> {
    /// Creates a new packet parser with reference to the capturing interface's local identity.
    pub fn new(local_identity: &'a LocalIdentity) -> Self {
        Self { local_identity }
    }

    /// Parses a raw libpcap packet into a structured [`ParsedPacket`].
    ///
    /// # Arguments
    /// * `packet_num` - Monotonically increasing packet index.
    /// * `packet` - Raw captured packet from libpcap.
    /// * `linktype` - Datalink type of the capture interface.
    pub fn parse(
        &self,
        packet_num: usize,
        packet: &pcap::Packet,
        linktype: Linktype,
    ) -> ParsedPacket {
        // Convert microsecond timestamp to chrono DateTime
        let ts = Local
            .timestamp_opt(packet.header.ts.tv_sec, (packet.header.ts.tv_usec * 1000) as u32)
            .single()
            .unwrap_or_else(Local::now);

        let raw_data = packet.data;
        let raw_len = packet.header.len as usize;

        let mut l2_info = None;
        let mut sll_pkttype = None;
        let mut src_mac = None;
        let mut dst_mac = None;
        let mut next_slice = raw_data;
        let mut ether_type = 0x0800; // default IPv4 if raw link

        // Step 1: Decode Data Link Layer (L2) based on capture datalink type
        match linktype {
            Linktype::ETHERNET => {
                if let Some((eth, rest)) = ethernet::parse_ethernet(raw_data) {
                    src_mac = Some(eth.src_mac);
                    dst_mac = Some(eth.dst_mac);
                    ether_type = eth.ether_type;
                    l2_info = Some(L2Info::Ethernet(eth));
                    next_slice = rest;
                }
            }
            Linktype::LINUX_SLL => {
                if let Some((sll, rest)) = sll::parse_sll(raw_data) {
                    sll_pkttype = Some(sll.packet_type);
                    ether_type = sll.protocol;
                    src_mac = sll.sender_lladdr;
                    l2_info = Some(L2Info::Sll(sll));
                    next_slice = rest;
                }
            }
            Linktype::LINUX_SLL2 => {
                if let Some((sll2, rest)) = sll::parse_sll2(raw_data) {
                    sll_pkttype = Some(sll2.packet_type);
                    ether_type = sll2.protocol;
                    src_mac = sll2.sender_lladdr;
                    l2_info = Some(L2Info::Sll(sll2));
                    next_slice = rest;
                }
            }
            Linktype::NULL | Linktype::LOOP => {
                // BSD Loopback format: 4-byte address family prefix
                if raw_data.len() >= 4 {
                    let family = u32::from_ne_bytes([raw_data[0], raw_data[1], raw_data[2], raw_data[3]]);
                    if family == 2 {
                        ether_type = 0x0800; // IPv4
                    } else if family == 24 || family == 28 || family == 30 {
                        ether_type = 0x86DD; // IPv6
                    }
                    next_slice = &raw_data[4..];
                }
            }
            Linktype::IPV4 => {
                ether_type = 0x0800;
            }
            Linktype::IPV6 => {
                ether_type = 0x86DD;
            }
            _ => {
                // Fallback attempt: try parsing as Ethernet if length >= 14
                if let Some((eth, rest)) = ethernet::parse_ethernet(raw_data) {
                    src_mac = Some(eth.src_mac);
                    dst_mac = Some(eth.dst_mac);
                    ether_type = eth.ether_type;
                    l2_info = Some(L2Info::Ethernet(eth));
                    next_slice = rest;
                }
            }
        }

        let mut arp_info = None;
        let mut ip_info = None;
        let mut tcp_info = None;
        let mut udp_info = None;
        let mut icmp_info = None;
        let mut app_info = None;
        let mut payload_slice = next_slice;

        let mut src_ip: Option<IpAddr> = None;
        let mut dst_ip: Option<IpAddr> = None;

        // Step 2: Decode Network Layer (L3) based on EtherType
        match ether_type {
            0x0806 => {
                // Address Resolution Protocol (ARP)
                if let Some(arp) = arp::parse_arp(next_slice) {
                    src_ip = Some(IpAddr::V4(arp.sender_ip));
                    dst_ip = Some(IpAddr::V4(arp.target_ip));
                    arp_info = Some(arp);
                    payload_slice = &[];
                }
            }
            0x0800 => {
                // Internet Protocol v4 (IPv4)
                if let Some((v4, transport_slice)) = ip::parse_ipv4(next_slice) {
                    src_ip = Some(IpAddr::V4(v4.src));
                    dst_ip = Some(IpAddr::V4(v4.dst));
                    let proto = v4.protocol;
                    ip_info = Some(ip::IpInfo::V4(v4));
                    payload_slice = transport_slice;

                    // Step 3: Decode Transport Layer (L4) for IPv4
                    match proto {
                        6 => {
                            // TCP
                            if let Some((tcp, l7_slice)) = tcp::parse_tcp(transport_slice) {
                                tcp_info = Some(tcp);
                                payload_slice = l7_slice;
                            }
                        }
                        17 => {
                            // UDP
                            if let Some((udp, l7_slice)) = udp::parse_udp(transport_slice) {
                                udp_info = Some(udp);
                                payload_slice = l7_slice;
                            }
                        }
                        1 => {
                            // ICMPv4
                            if let Some(icmp_v4) = icmp::parse_icmpv4(transport_slice) {
                                icmp_info = Some(icmp::IcmpInfo::V4(icmp_v4));
                                payload_slice = if transport_slice.len() > 8 {
                                    &transport_slice[8..]
                                } else {
                                    &[]
                                };
                            }
                        }
                        _ => {}
                    }
                }
            }
            0x86DD => {
                // Internet Protocol v6 (IPv6)
                if let Some((v6, transport_slice)) = ip::parse_ipv6(next_slice) {
                    src_ip = Some(IpAddr::V6(v6.src));
                    dst_ip = Some(IpAddr::V6(v6.dst));
                    let proto = v6.next_header;
                    ip_info = Some(ip::IpInfo::V6(v6));
                    payload_slice = transport_slice;

                    // Step 3: Decode Transport Layer (L4) for IPv6
                    match proto {
                        6 => {
                            // TCP
                            if let Some((tcp, l7_slice)) = tcp::parse_tcp(transport_slice) {
                                tcp_info = Some(tcp);
                                payload_slice = l7_slice;
                            }
                        }
                        17 => {
                            // UDP
                            if let Some((udp, l7_slice)) = udp::parse_udp(transport_slice) {
                                udp_info = Some(udp);
                                payload_slice = l7_slice;
                            }
                        }
                        58 => {
                            // ICMPv6
                            if let Some(icmp_v6) = icmp::parse_icmpv6(transport_slice) {
                                icmp_info = Some(icmp::IcmpInfo::V6(icmp_v6));
                                payload_slice = if transport_slice.len() > 8 {
                                    &transport_slice[8..]
                                } else {
                                    &[]
                                };
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        // Step 4: Decode Application Layer (L5/L7)
        if !payload_slice.is_empty() {
            let (src_p, dst_p) = if let Some(tcp) = &tcp_info {
                (tcp.src_port, tcp.dst_port)
            } else if let Some(udp) = &udp_info {
                (udp.src_port, udp.dst_port)
            } else {
                (0, 0)
            };

            // 1. DNS: UDP/TCP port 53 or 5353 (mDNS)
            if (src_p == 53 || dst_p == 53 || src_p == 5353 || dst_p == 5353) && app_info.is_none() {
                if let Some(dns) = dns::parse_dns(payload_slice) {
                    app_info = Some(AppProtocol::Dns(dns));
                }
            }

            // 2. DHCP: UDP port 67 (server) or 68 (client)
            if (src_p == 67 || dst_p == 67 || src_p == 68 || dst_p == 68) && app_info.is_none() {
                if let Some(dhcp) = dhcp::parse_dhcp(payload_slice) {
                    app_info = Some(AppProtocol::Dhcp(dhcp));
                }
            }

            // 3. NTP: UDP port 123
            if (src_p == 123 || dst_p == 123) && app_info.is_none() {
                if let Some(ntp) = ntp::parse_ntp(payload_slice) {
                    app_info = Some(AppProtocol::Ntp(ntp));
                }
            }

            // 4. SSH: TCP port 22 or SSH protocol banner prefix
            if (src_p == 22 || dst_p == 22 || payload_slice.starts_with(b"SSH-")) && app_info.is_none() {
                if let Some(ssh) = ssh::parse_ssh(payload_slice) {
                    app_info = Some(AppProtocol::Ssh(ssh));
                }
            }

            // 5. TLS: Port 443, 8443, or TLS record content type prefix (20..=24)
            if app_info.is_none() {
                if let Some(tls) = tls::parse_tls(payload_slice) {
                    app_info = Some(AppProtocol::Tls(tls));
                }
            }

            // 6. HTTP: Port 80, 8080, or HTTP method/response prefix
            if app_info.is_none() {
                if let Some(http) = http::parse_http(payload_slice) {
                    app_info = Some(AppProtocol::Http(http));
                }
            }
        }

        // Step 5: Accurately resolve packet direction (Sent vs. Received vs. Loopback)
        let direction = determine_direction(
            sll_pkttype,
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            self.local_identity,
        );

        ParsedPacket {
            packet_num,
            timestamp: ts,
            raw_len,
            direction,
            l2: l2_info,
            arp: arp_info,
            ip: ip_info,
            tcp: tcp_info,
            udp: udp_info,
            icmp: icmp_info,
            app: app_info,
            payload: payload_slice.to_vec(),
        }
    }
}
