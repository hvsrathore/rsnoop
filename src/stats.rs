use crate::direction::PacketDirection;
use crate::protocols::{AppProtocol, ParsedPacket};
use colored::Colorize;
use std::time::Instant;

/// Aggregates capture metrics, protocol distributions, and directional volumes.
#[derive(Debug)]
pub struct TrafficStats {
    pub start_time: Instant,
    pub total_packets: usize,
    pub total_bytes: u64,
    pub sent_packets: usize,
    pub sent_bytes: u64,
    pub recv_packets: usize,
    pub recv_bytes: u64,
    pub loopback_packets: usize,
    pub loopback_bytes: u64,
    pub other_packets: usize,
    // Protocol counters
    pub count_ipv4: usize,
    pub count_ipv6: usize,
    pub count_arp: usize,
    pub count_tcp: usize,
    pub count_udp: usize,
    pub count_icmp: usize,
    pub count_dns: usize,
    pub count_http: usize,
    pub count_tls: usize,
    pub count_dhcp: usize,
    pub count_ntp: usize,
    pub count_ssh: usize,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_packets: 0,
            total_bytes: 0,
            sent_packets: 0,
            sent_bytes: 0,
            recv_packets: 0,
            recv_bytes: 0,
            loopback_packets: 0,
            loopback_bytes: 0,
            other_packets: 0,
            count_ipv4: 0,
            count_ipv6: 0,
            count_arp: 0,
            count_tcp: 0,
            count_udp: 0,
            count_icmp: 0,
            count_dns: 0,
            count_http: 0,
            count_tls: 0,
            count_dhcp: 0,
            count_ntp: 0,
            count_ssh: 0,
        }
    }

    /// Records metrics from a newly processed packet.
    pub fn record(&mut self, packet: &ParsedPacket) {
        let bytes = packet.raw_len as u64;
        self.total_packets += 1;
        self.total_bytes += bytes;

        // Direction metrics
        match packet.direction {
            PacketDirection::Sent => {
                self.sent_packets += 1;
                self.sent_bytes += bytes;
            }
            PacketDirection::Received => {
                self.recv_packets += 1;
                self.recv_bytes += bytes;
            }
            PacketDirection::Loopback => {
                self.loopback_packets += 1;
                self.loopback_bytes += bytes;
            }
            PacketDirection::Promiscuous | PacketDirection::Unknown => {
                self.other_packets += 1;
            }
        }

        // Layer 3 protocol distribution
        if let Some(ip) = &packet.ip {
            match ip {
                crate::protocols::ip::IpInfo::V4(_) => self.count_ipv4 += 1,
                crate::protocols::ip::IpInfo::V6(_) => self.count_ipv6 += 1,
            }
        }
        if packet.arp.is_some() {
            self.count_arp += 1;
        }

        // Layer 4 protocol distribution
        if packet.tcp.is_some() {
            self.count_tcp += 1;
        }
        if packet.udp.is_some() {
            self.count_udp += 1;
        }
        if packet.icmp.is_some() {
            self.count_icmp += 1;
        }

        // Layer 5/7 Application protocol distribution
        if let Some(app) = &packet.app {
            match app {
                AppProtocol::Dns(_) => self.count_dns += 1,
                AppProtocol::Http(_) => self.count_http += 1,
                AppProtocol::Tls(_) => self.count_tls += 1,
                AppProtocol::Dhcp(_) => self.count_dhcp += 1,
                AppProtocol::Ntp(_) => self.count_ntp += 1,
                AppProtocol::Ssh(_) => self.count_ssh += 1,
            }
        }
    }

    /// Helper to format raw byte counts into human-readable strings (KB, MB, GB).
    fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = 1024 * KB;
        const GB: u64 = 1024 * MB;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }

    /// Prints a comprehensive summary report of the capture session.
    pub fn print_summary(&self) {
        let duration = self.start_time.elapsed();
        let secs = duration.as_secs_f64().max(0.001);
        let pps = self.total_packets as f64 / secs;
        let bps = (self.total_bytes * 8) as f64 / secs;

        println!();
        println!("{}", "═══════════════════════════════════════════════════════════════════".cyan().bold());
        println!("{}", "                   CAPTURE TRAFFIC SUMMARY                        ".bold().white());
        println!("{}", "═══════════════════════════════════════════════════════════════════".cyan().bold());

        println!(
            " {:<24} {:<15} (Avg: {:.1} pkts/s)",
            "Total Packets:".bold(),
            self.total_packets.to_string().yellow().bold(),
            pps
        );
        println!(
            " {:<24} {:<15} (Avg: {}/s)",
            "Total Data Transferred:".bold(),
            Self::format_bytes(self.total_bytes).green().bold(),
            Self::format_bytes((bps / 8.0) as u64)
        );
        println!(
            " {:<24} {:.2} seconds",
            "Capture Duration:".bold(),
            secs
        );

        println!();
        println!("{}", "--- Traffic Direction Breakdown ---".bold());
        println!(
            " {:<12} {:>8} packets ({})",
            "[TX] Sent:".magenta().bold(),
            self.sent_packets,
            Self::format_bytes(self.sent_bytes)
        );
        println!(
            " {:<12} {:>8} packets ({})",
            "[RX] Received:".cyan().bold(),
            self.recv_packets,
            Self::format_bytes(self.recv_bytes)
        );
        if self.loopback_packets > 0 {
            println!(
                " {:<12} {:>8} packets ({})",
                "Loopback:".yellow(),
                self.loopback_packets,
                Self::format_bytes(self.loopback_bytes)
            );
        }
        if self.other_packets > 0 {
            println!(
                " {:<12} {:>8} packets",
                "Promiscuous:".dimmed(),
                self.other_packets
            );
        }

        println!();
        println!("{}", "--- Protocol Distribution ---".bold());
        println!(
            " {:<10} {:>6} pkts | {:<10} {:>6} pkts | {:<10} {:>6} pkts",
            "IPv4:".bold(),
            self.count_ipv4,
            "TCP:".bold(),
            self.count_tcp,
            "DNS:".bold().green(),
            self.count_dns
        );
        println!(
            " {:<10} {:>6} pkts | {:<10} {:>6} pkts | {:<10} {:>6} pkts",
            "IPv6:".bold(),
            self.count_ipv6,
            "UDP:".bold(),
            self.count_udp,
            "TLS:".bold().magenta(),
            self.count_tls
        );
        println!(
            " {:<10} {:>6} pkts | {:<10} {:>6} pkts | {:<10} {:>6} pkts",
            "ARP:".bold(),
            self.count_arp,
            "ICMP:".bold(),
            self.count_icmp,
            "HTTP:".bold().yellow(),
            self.count_http
        );
        println!(
            " {:<10} {:>6} pkts | {:<10} {:>6} pkts | {:<10} {:>6} pkts",
            "DHCP:".bold().bright_blue(),
            self.count_dhcp,
            "NTP:".bold().blue(),
            self.count_ntp,
            "SSH:".bold().bright_white(),
            self.count_ssh
        );

        println!("{}", "═══════════════════════════════════════════════════════════════════".cyan().bold());
    }
}
