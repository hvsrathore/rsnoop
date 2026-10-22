/*
 * protocol decoding engine and multi-layer packet representation.
 *
 * flow of control across protocol layers:
 * 1. entry point: `PacketParser::parse()` receives raw packet bytes and datalink type from `main.rs`.
 * 2. layer 2 (datalink): decodes framing based on datalink type (Ethernet, Linux SLL/SLL2, BSD loopback).
 *    extracts hardware MAC addresses and determines the encapsulated network layer EtherType.
 * 3. layer 3 (network): demuxes payload by EtherType:
 *    - 0x0806 -> ARP (`arp::parse_arp`)
 *    - 0x0800 -> IPv4 (`ip::parse_ipv4`)
 *    - 0x86DD -> IPv6 (`ip::parse_ipv6`)
 *    extracts IP addresses and encapsulated transport layer protocol number.
 * 4. layer 4 (transport): demuxes transport slice by IP protocol number:
 *    - 6 -> TCP (`tcp::parse_tcp`)
 *    - 17 -> UDP (`udp::parse_udp`)
 *    - 1 / 58 -> ICMPv4 / ICMPv6 (`icmp::parse_icmpv4` / `icmp::parse_icmpv6`)
 *    extracts ports, sequence/ack numbers, flags, and payload slice.
 * 5. layer 5/7 (application): inspects transport ports and payload magic bytes:
 *    - port 53/5353 -> DNS (`dns::parse_dns`)
 *    - port 67/68 -> DHCP (`dhcp::parse_dhcp`)
 *    - port 123 -> NTP (`ntp::parse_ntp`)
 *    - port 22 or "SSH-" prefix -> SSH (`ssh::parse_ssh`)
 *    - port 443 or TLS record prefix -> TLS (`tls::parse_tls`)
 *    - port 80 or HTTP verb/status -> HTTP (`http::parse_http`)
 * 6. directional analysis: calls `direction::determine_direction()` comparing extracted
 *    MACs/IPs against the host's `LocalIdentity`.
 * 7. return: packages all layers into a unified `ParsedPacket` struct passed back to `main.rs`.
 */

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

/*
 * container for decoded Data Link Layer (L2) frame information.
 * encapsulates either standard Ethernet II frames or Linux Cooked SLL frames.
 */
#[derive(Debug, Clone)]
pub enum L2Info {
    /* standard Ethernet II frame header. */
    Ethernet(ethernet::EthernetInfo),
    /* Linux Cooked capture (SLL or SLL2) frame header. */
    Sll(sll::SllInfo),
}

/*
 * container for decoded Application Layer (L5/L7) protocol information.
 * stores strongly-typed metadata for recognized upper-layer protocols.
 */
#[derive(Debug, Clone)]
pub enum AppProtocol {
    /* Domain Name System (DNS) query or response. */
    Dns(dns::DnsInfo),
    /* Hypertext Transfer Protocol (HTTP) request or response. */
    Http(http::HttpInfo),
    /* Transport Layer Security (TLS) record or handshake message. */
    Tls(tls::TlsInfo),
    /* Dynamic Host Configuration Protocol (DHCP) message. */
    Dhcp(dhcp::DhcpInfo),
    /* Network Time Protocol (NTP) clock synchronization packet. */
    Ntp(ntp::NtpInfo),
    /* Secure Shell (SSH) version identification banner. */
    Ssh(ssh::SshInfo),
}

/*
 * fully decoded representation of a captured network packet across all layers.
 * this struct is passed through the filtering, display, and statistics pipelines.
 */
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    /* sequential capture index (1-based counter). */
    pub packet_num: usize,
    /* wall-clock timestamp when the packet was captured. */
    pub timestamp: DateTime<Local>,
    /* total wire length of the packet in bytes. */
    pub raw_len: usize,
    /* traffic flow direction: Sent (TX), Received (RX), Loopback, or Promiscuous. */
    pub direction: PacketDirection,
    /* decoded Data Link Layer (L2) header if available. */
    pub l2: Option<L2Info>,
    /* decoded Address Resolution Protocol (ARP) header if present. */
    pub arp: Option<arp::ArpInfo>,
    /* decoded Internet Protocol (IPv4 or IPv6) header if present. */
    pub ip: Option<ip::IpInfo>,
    /* decoded Transmission Control Protocol (TCP) header if present. */
    pub tcp: Option<tcp::TcpInfo>,
    /* decoded User Datagram Protocol (UDP) header if present. */
    pub udp: Option<udp::UdpInfo>,
    /* decoded Internet Control Message Protocol (ICMP) header if present. */
    pub icmp: Option<icmp::IcmpInfo>,
    /* decoded Application Layer (L5/L7) protocol if recognized. */
    pub app: Option<AppProtocol>,
    /* remaining unparsed payload bytes (used for hex dumps and deep inspection). */
    pub payload: Vec<u8>,
}

impl ParsedPacket {
    /*
     * returns the primary protocol name for display badges (e.g. "DNS", "TLS", "TCP", "ARP").
     * prioritizes the highest decoded protocol layer for display prominence.
     */
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

    /*
     * evaluates whether this packet satisfies the user's protocol filter option.
     * checks if the requested protocol was identified during multi-layer decoding.
     */
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

    /*
     * evaluates whether this packet satisfies the user's port filter option.
     * matches either source or destination port on TCP segments or UDP datagrams.
     */
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

/*
 * packet decoder instance holding local interface identity for directional resolution.
 * retains a borrow of the capturing interface's `LocalIdentity` throughout the capture session.
 */
pub struct PacketParser<'a> {
    local_identity: &'a LocalIdentity,
}

impl<'a> PacketParser<'a> {
    /*
     * creates a new packet parser with reference to the capturing interface's local identity.
     */
    pub fn new(local_identity: &'a LocalIdentity) -> Self {
        Self { local_identity }
    }

    /*
     * parses a raw libpcap packet into a structured `ParsedPacket`.
     *
     * flow of control through parsing steps:
     * - converts hardware timestamp from microseconds to `DateTime<Local>`.
     * - step 1: demuxes link layer based on `linktype` (Ethernet II, Linux Cooked SLL/SLL2, BSD Loopback).
     * - step 2: demuxes network layer based on EtherType (IPv4, IPv6, ARP).
     * - step 3: demuxes transport layer based on IP protocol (TCP, UDP, ICMPv4, ICMPv6).
     * - step 4: demuxes application layer based on port numbers and payload signatures (DNS, DHCP, NTP, SSH, TLS, HTTP).
     * - step 5: resolves packet direction (Sent vs Received vs Loopback) using `determine_direction`.
     * - step 6: returns completed `ParsedPacket`.
     */
    pub fn parse(
        &self,
        packet_num: usize,
        packet: &pcap::Packet,
        linktype: Linktype,
    ) -> ParsedPacket {
        /* convert microsecond capture timestamp to local datetime */
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
        let mut ether_type = 0x0800; /* default to IPv4 if raw link type */

        /* step 1: decode Data Link Layer (L2) based on capture datalink type */
        match linktype {
            Linktype::ETHERNET => {
                /* parse standard IEEE 802.3 / Ethernet II framing */
                if let Some((eth, rest)) = ethernet::parse_ethernet(raw_data) {
                    src_mac = Some(eth.src_mac);
                    dst_mac = Some(eth.dst_mac);
                    ether_type = eth.ether_type;
                    l2_info = Some(L2Info::Ethernet(eth));
                    next_slice = rest;
                }
            }
            Linktype::LINUX_SLL => {
                /* parse Linux Cooked capture v1 (used by "any" pseudo-device) */
                if let Some((sll, rest)) = sll::parse_sll(raw_data) {
                    sll_pkttype = Some(sll.packet_type);
                    ether_type = sll.protocol;
                    src_mac = sll.sender_lladdr;
                    l2_info = Some(L2Info::Sll(sll));
                    next_slice = rest;
                }
            }
            Linktype::LINUX_SLL2 => {
                /* parse Linux Cooked capture v2 */
                if let Some((sll2, rest)) = sll::parse_sll2(raw_data) {
                    sll_pkttype = Some(sll2.packet_type);
                    ether_type = sll2.protocol;
                    src_mac = sll2.sender_lladdr;
                    l2_info = Some(L2Info::Sll(sll2));
                    next_slice = rest;
                }
            }
            Linktype::NULL | Linktype::LOOP => {
                /* parse BSD Loopback framing: 4-byte native endian address family prefix */
                if raw_data.len() >= 4 {
                    let family = u32::from_ne_bytes([raw_data[0], raw_data[1], raw_data[2], raw_data[3]]);
                    if family == 2 {
                        ether_type = 0x0800; /* AF_INET = IPv4 */
                    } else if family == 24 || family == 28 || family == 30 {
                        ether_type = 0x86DD; /* AF_INET6 = IPv6 */
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
                /* fallback attempt: try parsing as Ethernet if slice is at least 14 bytes */
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

        /* step 2: decode Network Layer (L3) based on EtherType */
        match ether_type {
            0x0806 => {
                /* Address Resolution Protocol (ARP) */
                if let Some(arp) = arp::parse_arp(next_slice) {
                    src_ip = Some(IpAddr::V4(arp.sender_ip));
                    dst_ip = Some(IpAddr::V4(arp.target_ip));
                    arp_info = Some(arp);
                    payload_slice = &[];
                }
            }
            0x0800 => {
                /* Internet Protocol version 4 (IPv4) */
                if let Some((v4, transport_slice)) = ip::parse_ipv4(next_slice) {
                    src_ip = Some(IpAddr::V4(v4.src));
                    dst_ip = Some(IpAddr::V4(v4.dst));
                    let proto = v4.protocol;
                    ip_info = Some(ip::IpInfo::V4(v4));
                    payload_slice = transport_slice;

                    /* step 3: decode Transport Layer (L4) for IPv4 */
                    match proto {
                        6 => {
                            /* Transmission Control Protocol (TCP) */
                            if let Some((tcp, l7_slice)) = tcp::parse_tcp(transport_slice) {
                                tcp_info = Some(tcp);
                                payload_slice = l7_slice;
                            }
                        }
                        17 => {
                            /* User Datagram Protocol (UDP) */
                            if let Some((udp, l7_slice)) = udp::parse_udp(transport_slice) {
                                udp_info = Some(udp);
                                payload_slice = l7_slice;
                            }
                        }
                        1 => {
                            /* Internet Control Message Protocol v4 (ICMPv4) */
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
                /* Internet Protocol version 6 (IPv6) */
                if let Some((v6, transport_slice)) = ip::parse_ipv6(next_slice) {
                    src_ip = Some(IpAddr::V6(v6.src));
                    dst_ip = Some(IpAddr::V6(v6.dst));
                    let proto = v6.next_header;
                    ip_info = Some(ip::IpInfo::V6(v6));
                    payload_slice = transport_slice;

                    /* step 3: decode Transport Layer (L4) for IPv6 */
                    match proto {
                        6 => {
                            /* Transmission Control Protocol (TCP) */
                            if let Some((tcp, l7_slice)) = tcp::parse_tcp(transport_slice) {
                                tcp_info = Some(tcp);
                                payload_slice = l7_slice;
                            }
                        }
                        17 => {
                            /* User Datagram Protocol (UDP) */
                            if let Some((udp, l7_slice)) = udp::parse_udp(transport_slice) {
                                udp_info = Some(udp);
                                payload_slice = l7_slice;
                            }
                        }
                        58 => {
                            /* Internet Control Message Protocol v6 (ICMPv6) */
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

        /* step 4: decode Application Layer (L5/L7) if transport payload exists */
        if !payload_slice.is_empty() {
            let (src_p, dst_p) = if let Some(tcp) = &tcp_info {
                (tcp.src_port, tcp.dst_port)
            } else if let Some(udp) = &udp_info {
                (udp.src_port, udp.dst_port)
            } else {
                (0, 0)
            };

            /* 1. DNS: UDP/TCP port 53 or 5353 (mDNS) */
            if (src_p == 53 || dst_p == 53 || src_p == 5353 || dst_p == 5353) && app_info.is_none() {
                if let Some(dns) = dns::parse_dns(payload_slice) {
                    app_info = Some(AppProtocol::Dns(dns));
                }
            }

            /* 2. DHCP: UDP port 67 (server) or 68 (client) */
            if (src_p == 67 || dst_p == 67 || src_p == 68 || dst_p == 68) && app_info.is_none() {
                if let Some(dhcp) = dhcp::parse_dhcp(payload_slice) {
                    app_info = Some(AppProtocol::Dhcp(dhcp));
                }
            }

            /* 3. NTP: UDP port 123 */
            if (src_p == 123 || dst_p == 123) && app_info.is_none() {
                if let Some(ntp) = ntp::parse_ntp(payload_slice) {
                    app_info = Some(AppProtocol::Ntp(ntp));
                }
            }

            /* 4. SSH: TCP port 22 or payload starting with "SSH-" banner prefix */
            if (src_p == 22 || dst_p == 22 || payload_slice.starts_with(b"SSH-")) && app_info.is_none() {
                if let Some(ssh) = ssh::parse_ssh(payload_slice) {
                    app_info = Some(AppProtocol::Ssh(ssh));
                }
            }

            /* 5. TLS: port 443, 8443, or TLS record content type prefix (20..=24) */
            if app_info.is_none() {
                if let Some(tls) = tls::parse_tls(payload_slice) {
                    app_info = Some(AppProtocol::Tls(tls));
                }
            }

            /* 6. HTTP: port 80, 8080, or HTTP request method / response status line prefix */
            if app_info.is_none() {
                if let Some(http) = http::parse_http(payload_slice) {
                    app_info = Some(AppProtocol::Http(http));
                }
            }
        }

        /* step 5: resolve packet direction (Sent vs. Received vs. Loopback) */
        let direction = determine_direction(
            sll_pkttype,
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            self.local_identity,
        );

        /* step 6: return the fully populated multi-layer packet descriptor */
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
