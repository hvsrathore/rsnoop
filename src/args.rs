/*
 * command-line argument definitions and configuration.
 *
 * utilizes `clap` to provide command-line options for:
 * - selecting live capture network interface (`-i, --interface`).
 * - discovering and listing host network interfaces (`-l, --list-interfaces`).
 * - applying Berkeley Packet Filter (BPF) syntax (`-f, --filter`).
 * - filtering by protocol (`-p, --protocol`) and port (`--port`).
 * - directional filtering (`-d, --direction in|out|all`).
 * - controlling stdout output detail (`-v, --verbose` and `-x, --hexdump`).
 * - limiting packet count (`-c, --count`).
 * - controlling promiscuous mode (`--no-promisc`).
 */

use clap::{Parser, ValueEnum};

/*
 * filter options for packet direction.
 * allows filtering traffic based on whether packets are incoming (received by local host),
 * outgoing (transmitted by local host), or both.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DirectionFilter {
    /* show all packets (both incoming and outgoing). */
    #[value(help = "Show all packets (both incoming and outgoing)")]
    All,
    /* show only incoming (received) packets. */
    #[value(help = "Show only incoming (received) packets")]
    In,
    /* show only outgoing (sent) packets. */
    #[value(help = "Show only outgoing (sent) packets")]
    Out,
}

/*
 * filter options for network protocols.
 * allows users to restrict packet capture display to specific network or transport layer protocols.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProtocolFilter {
    /* show all supported network protocols. */
    #[value(help = "Show all supported network protocols")]
    All,
    /* filter for Transmission Control Protocol (TCP). */
    #[value(help = "Filter for Transmission Control Protocol (TCP)")]
    Tcp,
    /* filter for User Datagram Protocol (UDP). */
    #[value(help = "Filter for User Datagram Protocol (UDP)")]
    Udp,
    /* filter for Internet Control Message Protocol (ICMPv4 & ICMPv6). */
    #[value(help = "Filter for Internet Control Message Protocol (ICMPv4 & ICMPv6)")]
    Icmp,
    /* filter for Address Resolution Protocol (ARP). */
    #[value(help = "Filter for Address Resolution Protocol (ARP)")]
    Arp,
    /* filter for Domain Name System (DNS). */
    #[value(help = "Filter for Domain Name System (DNS)")]
    Dns,
    /* filter for Hypertext Transfer Protocol (HTTP). */
    #[value(help = "Filter for Hypertext Transfer Protocol (HTTP)")]
    Http,
    /* filter for Transport Layer Security (TLS/HTTPS). */
    #[value(help = "Filter for Transport Layer Security (TLS/HTTPS)")]
    Tls,
    /* filter for Dynamic Host Configuration Protocol (DHCP). */
    #[value(help = "Filter for Dynamic Host Configuration Protocol (DHCP)")]
    Dhcp,
    /* filter for Network Time Protocol (NTP). */
    #[value(help = "Filter for Network Time Protocol (NTP)")]
    Ntp,
    /* filter for Secure Shell (SSH). */
    #[value(help = "Filter for Secure Shell (SSH)")]
    Ssh,
    /* filter for Internet Protocol version 4 (IPv4). */
    #[value(help = "Filter for Internet Protocol version 4 (IPv4)")]
    Ipv4,
    /* filter for Internet Protocol version 6 (IPv6). */
    #[value(help = "Filter for Internet Protocol version 6 (IPv6)")]
    Ipv6,
}

/*
 * command-line arguments for the packet sniffer.
 * parsed by clap from environment arguments to configure capture behaviour,
 * filtering criteria, interface selection, and output formatting.
 */
#[derive(Parser, Debug)]
#[command(
    name = "rsnoop",
    author = "rsnoop",
    version = "1.0.0",
    about = "High-performance network packet sniffer in Rust with real-time stdout multi-protocol decoding and directional tracking (TX/RX)."
)]
pub struct CliArgs {
    /*
     * network interface to capture packets from (e.g. eth0, wlp7s0, lo, any).
     * if not specified, the sniffer automatically selects the best active non-loopback device.
     */
    #[arg(
        short = 'i',
        long = "interface",
        help = "Network interface to capture packets from (e.g. eth0, wlp7s0, lo, any). If not specified, the sniffer automatically selects the best active non-loopback device"
    )]
    pub interface: Option<String>,

    /* list all available network interfaces on the host system and exit. */
    #[arg(
        short = 'l',
        long = "list-interfaces",
        help = "List all available network interfaces on the host system and exit"
    )]
    pub list_interfaces: bool,

    /* berkeley packet filter (BPF) syntax expression (e.g. "tcp and port 443", "icmp", "udp"). */
    #[arg(
        short = 'f',
        long = "filter",
        help = "Berkeley Packet Filter (BPF) syntax expression (e.g. \"tcp and port 443\", \"icmp\", \"udp\")"
    )]
    pub filter: Option<String>,

    /* filter packets by protocol name. */
    #[arg(
        short = 'p',
        long = "protocol",
        value_enum,
        default_value_t = ProtocolFilter::All,
        help = "Filter packets by protocol name"
    )]
    pub protocol: ProtocolFilter,

    /* filter packets by port number (matches either source or destination port). */
    #[arg(
        long = "port",
        help = "Filter packets by port number (matches either source or destination port)"
    )]
    pub port: Option<u16>,

    /* filter packets by direction: in (received), out (sent), or all. */
    #[arg(
        short = 'd',
        long = "direction",
        value_enum,
        default_value_t = DirectionFilter::All,
        help = "Filter packets by direction: in (received), out (sent), or all"
    )]
    pub direction: DirectionFilter,

    /* verbose output with detailed hierarchical protocol header breakdown displayed on stdout. */
    #[arg(
        short = 'v',
        long = "verbose",
        help = "Verbose output with detailed hierarchical protocol header breakdown displayed on stdout"
    )]
    pub verbose: bool,

    /* show side-by-side hexadecimal and printable ASCII dump of packet payload on stdout. */
    #[arg(
        short = 'x',
        long = "hexdump",
        help = "Show side-by-side hexadecimal and printable ASCII dump of packet payload on stdout"
    )]
    pub hexdump: bool,

    /* stop capture after displaying the specified number of packets. */
    #[arg(
        short = 'c',
        long = "count",
        help = "Stop capture after displaying the specified number of packets"
    )]
    pub count: Option<usize>,

    /* disable promiscuous mode on the capturing interface. */
    #[arg(
        long = "no-promisc",
        help = "Disable promiscuous mode on the capturing interface"
    )]
    pub no_promisc: bool,
}
