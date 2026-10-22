/*
 * capture metrics and session statistics aggregation.
 *
 * tracks cumulative packet counts, byte volumes, directional distribution (TX/RX/loopback),
 * and protocol occurrences across all network layers. generates a comprehensive summary
 * report upon capture termination (e.g. Ctrl+C or count limit).
 */

use crate::direction::PacketDirection;
use crate::protocols::{AppProtocol, ParsedPacket};
use colored::Colorize;
use std::time::Instant;

/*
 * aggregates capture metrics, protocol distributions, and directional volumes.
 * tracks session start time for throughput calculations (pps and bps).
 */
#[derive(Debug)]
pub struct TrafficStats {
    /* timestamp when traffic capture commenced. */
    pub start_time: Instant,
    /* total number of packets processed across all interfaces. */
    pub total_packets: usize,
    /* total raw byte volume processed. */
    pub total_bytes: u64,
    /* count of transmitted (outgoing) packets. */
    pub sent_packets: usize,
    /* volume in bytes of transmitted (outgoing) packets. */
    pub sent_bytes: u64,
    /* count of received (incoming) packets. */
    pub recv_packets: usize,
    /* volume in bytes of received (incoming) packets. */
    pub recv_bytes: u64,
    /* count of local loopback packets. */
    pub loopback_packets: usize,
    /* volume in bytes of local loopback packets. */
    pub loopback_bytes: u64,
    /* count of promiscuous or indeterminate direction packets. */
    pub other_packets: usize,

    /* layer 3: IPv4 packet counter. */
    pub count_ipv4: usize,
    /* layer 3: IPv6 packet counter. */
    pub count_ipv6: usize,
    /* layer 2/3: ARP packet counter. */
    pub count_arp: usize,

    /* layer 4: TCP segment counter. */
    pub count_tcp: usize,
    /* layer 4: UDP datagram counter. */
    pub count_udp: usize,
    /* layer 4: ICMP/ICMPv6 control message counter. */
    pub count_icmp: usize,

    /* layer 7: DNS message counter. */
    pub count_dns: usize,
    /* layer 7: HTTP message counter. */
    pub count_http: usize,
    /* layer 7: TLS record counter. */
    pub count_tls: usize,
    /* layer 7: DHCP message counter. */
    pub count_dhcp: usize,
    /* layer 7: NTP packet counter. */
    pub count_ntp: usize,
    /* layer 7: SSH banner counter. */
    pub count_ssh: usize,
}

impl TrafficStats {
    /*
     * constructs a new zeroed `TrafficStats` instance with start_time recorded as now.
     */
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

    /*
     * records metrics from a newly processed packet.
     * updates directional counters, byte totals, and protocol breakdowns.
     */
    pub fn record(&mut self, packet: &ParsedPacket) {
        let bytes = packet.raw_len as u64;
        self.total_packets += 1;
        self.total_bytes += bytes;

        /* update traffic direction counters */
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

        /* update layer 3 network protocol distribution */
        if let Some(ip) = &packet.ip {
            match ip {
                crate::protocols::ip::IpInfo::V4(_) => self.count_ipv4 += 1,
                crate::protocols::ip::IpInfo::V6(_) => self.count_ipv6 += 1,
            }
        }
        if packet.arp.is_some() {
            self.count_arp += 1;
        }

        /* update layer 4 transport protocol distribution */
        if packet.tcp.is_some() {
            self.count_tcp += 1;
        }
        if packet.udp.is_some() {
            self.count_udp += 1;
        }
        if packet.icmp.is_some() {
            self.count_icmp += 1;
        }

        /* update layer 5/7 application protocol distribution */
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

    /*
     * helper to format raw byte counts into human-readable strings (KB, MB, GB).
     * scales using binary prefix multiples of 1024.
     */
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

    /*
     * prints a comprehensive summary report of the capture session.
     * calculates average throughput rates (packets/s and bytes/s),
     * directional breakdowns, and a 3-column colorized protocol table.
     */
    pub fn print_summary(&self) {
        /* compute total elapsed time avoiding division by zero with minimum 0.001s */
        let duration = self.start_time.elapsed();
        let secs = duration.as_secs_f64().max(0.001);
        let pps = self.total_packets as f64 / secs;
        let bps = (self.total_bytes * 8) as f64 / secs;

        println!();
        println!("{}", "═══════════════════════════════════════════════════════════════════".cyan().bold());
        println!("{}", "                   CAPTURE TRAFFIC SUMMARY                        ".bold().white());
        println!("{}", "═══════════════════════════════════════════════════════════════════".cyan().bold());

        /* overall throughput statistics */
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

        /* directional breakdown statistics */
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

        /* protocol distribution breakdown */
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
