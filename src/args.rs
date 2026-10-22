//! Command-line argument definitions and configuration.
//!
//! Utilizes `clap` to provide command-line options for:
//! - Selecting live capture network interface (`-i, --interface`).
//! - Discovering and listing host network interfaces (`-l, --list-interfaces`).
//! - Applying Berkeley Packet Filter (BPF) syntax (`-f, --filter`).
//! - Filtering by protocol (`-p, --protocol`) and port (`--port`).
//! - Directional filtering (`-d, --direction in|out|all`).
//! - Controlling stdout output detail (`-v, --verbose` and `-x, --hexdump`).
//! - Limiting packet count (`-c, --count`).

use clap::{Parser, ValueEnum};

/// Filter options for packet direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DirectionFilter {
    /// Show all packets (both incoming and outgoing).
    All,
    /// Show only incoming (received) packets.
    In,
    /// Show only outgoing (sent) packets.
    Out,
}

/// Filter options for network protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProtocolFilter {
    /// Show all supported network protocols.
    All,
    /// Filter for Transmission Control Protocol (TCP).
    Tcp,
    /// Filter for User Datagram Protocol (UDP).
    Udp,
    /// Filter for Internet Control Message Protocol (ICMPv4 & ICMPv6).
    Icmp,
    /// Filter for Address Resolution Protocol (ARP).
    Arp,
    /// Filter for Domain Name System (DNS).
    Dns,
    /// Filter for Hypertext Transfer Protocol (HTTP).
    Http,
    /// Filter for Transport Layer Security (TLS/HTTPS).
    Tls,
    /// Filter for Dynamic Host Configuration Protocol (DHCP).
    Dhcp,
    /// Filter for Network Time Protocol (NTP).
    Ntp,
    /// Filter for Secure Shell (SSH).
    Ssh,
    /// Filter for Internet Protocol version 4 (IPv4).
    Ipv4,
    /// Filter for Internet Protocol version 6 (IPv6).
    Ipv6,
}

/// Command-line arguments for the packet sniffer.
#[derive(Parser, Debug)]
#[command(
    name = "packet_sniffer",
    author = "Rust Packet Sniffer",
    version = "1.0.0",
    about = "High-performance network packet sniffer in Rust with real-time stdout multi-protocol decoding and directional tracking (TX/RX)."
)]
pub struct CliArgs {
    /// Network interface to capture packets from (e.g. eth0, wlp7s0, lo, any).
    /// If not specified, the sniffer automatically selects the best active non-loopback device.
    #[arg(short = 'i', long = "interface")]
    pub interface: Option<String>,

    /// List all available network interfaces on the host system and exit.
    #[arg(short = 'l', long = "list-interfaces")]
    pub list_interfaces: bool,

    /// Berkeley Packet Filter (BPF) syntax expression (e.g. "tcp and port 443", "icmp", "udp").
    #[arg(short = 'f', long = "filter")]
    pub filter: Option<String>,

    /// Filter packets by protocol name.
    #[arg(short = 'p', long = "protocol", value_enum, default_value_t = ProtocolFilter::All)]
    pub protocol: ProtocolFilter,

    /// Filter packets by port number (matches either source or destination port).
    #[arg(long = "port")]
    pub port: Option<u16>,

    /// Filter packets by direction: in (received), out (sent), or all.
    #[arg(short = 'd', long = "direction", value_enum, default_value_t = DirectionFilter::All)]
    pub direction: DirectionFilter,

    /// Verbose output with detailed hierarchical protocol header breakdown displayed on stdout.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Show side-by-side hexadecimal and printable ASCII dump of packet payload on stdout.
    #[arg(short = 'x', long = "hexdump")]
    pub hexdump: bool,

    /// Stop capture after displaying the specified number of packets.
    #[arg(short = 'c', long = "count")]
    pub count: Option<usize>,

    /// Disable promiscuous mode on the capturing interface.
    #[arg(long = "no-promisc")]
    pub no_promisc: bool,
}
