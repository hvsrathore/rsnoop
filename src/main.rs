//! # Network Packet Sniffer in Rust
//!
//! A high-performance, real-time network packet sniffer that captures live packets
//! from network interfaces and streams rich protocol details directly to `stdout`.
//!
//! ## Capabilities:
//! - **Directional Tracking**: Accurately classifies packets as `[TX OUT]` (Transmitted),
//!   `[RX IN ]` (Received), or `[LOOPBK]` (Local host loopback).
//! - **Full Protocol Stack Support**:
//!   - **Layer 2 (Data Link)**: Ethernet II, IEEE 802.1Q (VLAN), Linux Cooked SLL/SLL2, BSD Loopback.
//!   - **Layer 3 (Network)**: IPv4, IPv6, ARP.
//!   - **Layer 4 (Transport)**: TCP (Flags, Sequence, Ack, Window, Checksum), UDP, ICMPv4, ICMPv6.
//!   - **Layer 5/7 (Application)**: DNS (Queries, Answers, Types), HTTP (Requests, Responses, Headers),
//!     TLS (Client Hello, SNI extraction, Server Hello), DHCP/BOOTP (Discover, Offer, Request, ACK),
//!     NTP, and SSH identification banner.
//! - **Real-time Terminal Output**:
//!   - Compact mode: Colorized single-line summary with timestamps, direction badges, endpoints, and protocol summaries.
//!   - Verbose mode (`-v`): Multi-level tree inspection showing all parsed protocol fields.
//!   - Hexdump mode (`-x`): Side-by-side hexadecimal and printable ASCII display of packet payloads.
//! - **Capture Filtering**:
//!   - Berkeley Packet Filter (BPF) expressions (`-f, --filter`).
//!   - Protocol selection (`-p, --protocol`).
//!   - Port number filtering (`--port`).
//!   - Directional filtering (`-d, --direction in|out|all`).
//! - **Statistics Summary**: Detailed breakdown of packet counts, byte volumes, and protocol distributions upon termination (Ctrl+C).

mod args;
mod direction;
mod interface;
mod printer;
mod protocols;
mod stats;

use args::CliArgs;
use clap::Parser;
use colored::Colorize;
use interface::{print_interface_list, select_default_interface, InterfaceInfo, LocalIdentity};
use pcap::{Capture, Device};
use printer::PacketPrinter;
use protocols::PacketParser;
use stats::TrafficStats;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
    // Parse command-line flags and options
    let args = CliArgs::parse();

    // 1. If "--list-interfaces" is requested, print host devices and exit cleanly
    if args.list_interfaces {
        if let Err(e) = print_interface_list() {
            eprintln!("{}: {}", "Error listing interfaces".red().bold(), e);
            std::process::exit(1);
        }
        return;
    }

    // 2. Set up atomic signal handler for graceful Ctrl+C (SIGINT) termination
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        println!("\n{}", "Interrupt received, stopping capture...".yellow().bold());
        r.store(false, Ordering::SeqCst);
    }) {
        eprintln!("{}: {}", "Warning: Failed to set Ctrl+C handler".yellow(), e);
    }

    // 3. Start live packet capture and stream directly to stdout
    if let Err(e) = run_live_capture(&args, &running) {
        eprintln!("{}: {}", "Sniffer Error".red().bold(), e);
        std::process::exit(1);
    }
}

/// Captures live packets from the network interface and displays decoded information on stdout.
///
/// # Arguments
/// * `args` - User-provided command-line arguments.
/// * `running` - Atomic boolean flag for tracking Ctrl+C interruption.
fn run_live_capture(args: &CliArgs, running: &Arc<AtomicBool>) -> Result<(), String> {
    // Step 1: Select network interface (either user-specified or auto-detected default)
    let device: Device = if let Some(iface_name) = &args.interface {
        let devices = Device::list().map_err(|e| format!("Failed to list devices: {}", e))?;
        devices
            .into_iter()
            .find(|d| d.name == *iface_name)
            .ok_or_else(|| {
                format!(
                    "Interface '{}' not found. Use '--list-interfaces' to view available devices.",
                    iface_name
                )
            })?
    } else {
        select_default_interface()?
    };

    // Gather local interface MAC and IP addresses for accurate direction determination
    let iface_info = InterfaceInfo::from_device(&device);
    let local_identity = LocalIdentity::new(&iface_info);

    // Print capture startup banner to stdout
    println!("{}", "============================================================".cyan());
    println!(
        "{} {}",
        "Capturing on Interface:".bold().white(),
        iface_info.name.yellow().bold()
    );
    if let Some(mac) = &iface_info.mac_str {
        println!("  MAC Address:  {}", mac);
    }
    if !iface_info.ips.is_empty() {
        let ips_str = iface_info
            .ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("  IP Addresses: {}", ips_str);
    }
    println!(
        "  Promiscuous:  {}",
        if !args.no_promisc { "Enabled".green() } else { "Disabled".red() }
    );
    if let Some(bpf) = &args.filter {
        println!("  BPF Filter:   {}", bpf.green());
    }
    println!("{}", "============================================================".cyan());
    println!("{}", "Streaming packets to stdout. Press Ctrl+C to stop and display statistics.\n".dimmed());

    // Step 2: Open capture handle via libpcap
    // - snaplen(65535): captures full unfragmented frames
    // - timeout(200): 200ms polling timeout so Ctrl+C / atomic running flag can be checked
    // - immediate_mode(true): packets are delivered to stdout immediately without driver buffering
    let mut cap = Capture::from_device(device.clone())
        .map_err(|e| explain_permission_error(&e, &device.name))?
        .promisc(!args.no_promisc)
        .snaplen(65535)
        .timeout(200)
        .immediate_mode(true)
        .open()
        .map_err(|e| explain_permission_error(&e, &device.name))?;

    // Step 3: Apply Berkeley Packet Filter (BPF) if specified
    if let Some(bpf) = &args.filter {
        cap.filter(bpf, true)
            .map_err(|e| format!("Failed to compile BPF filter '{}': {}", bpf, e))?;
    }

    let linktype = cap.get_datalink();
    let parser = PacketParser::new(&local_identity);
    let mut stats = TrafficStats::new();
    let mut packet_count = 0;

    // Step 4: Live Capture and stdout streaming loop
    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;

                // Decode packet headers across all network layers
                let parsed = parser.parse(packet_count, &packet, linktype);

                // Apply protocol filter if specified
                if !parsed.matches_protocol(args.protocol) {
                    continue;
                }

                // Apply port filter if specified
                if !parsed.matches_port(args.port) {
                    continue;
                }

                // Apply direction filter (sent / received) if specified
                if !parsed.direction.matches_filter(args.direction) {
                    continue;
                }

                // Record traffic metrics
                stats.record(&parsed);

                // Render formatted packet information directly to stdout
                PacketPrinter::print(&parsed, args.verbose, args.hexdump);

                // Stop capture if user-specified packet count limit is reached
                if let Some(limit) = args.count {
                    if stats.total_packets >= limit {
                        println!(
                            "\n{}",
                            format!("Reached limit of {} packets.", limit).green().bold()
                        );
                        break;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Timeout elapsed with no incoming packet: continue loop to inspect `running` flag
                continue;
            }
            Err(e) => {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                eprintln!("{}: {}", "Capture error".yellow(), e);
                break;
            }
        }
    }

    // Step 5: Render final comprehensive traffic statistics table to stdout
    stats.print_summary();

    Ok(())
}

/// Generates clear diagnostic messages when raw device access fails due to Linux permissions.
fn explain_permission_error(err: &pcap::Error, iface: &str) -> String {
    let err_str = err.to_string();
    if err_str.contains("Operation not permitted")
        || err_str.contains("Permission denied")
        || err_str.contains("You don't have permission")
        || err_str.contains("CAP_NET_RAW")
        || err_str.contains("socket failed")
    {
        format!(
            "Permission denied while capturing on '{}'.\n\
            Live packet capture requires elevated privileges (root or CAP_NET_RAW) on Linux.\n\
            To run live capture, please use:\n\
              1) sudo:                sudo ./target/release/rsnoop -i {}\n\
              2) Or grant capability: sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/rsnoop",
            iface, iface
        )
    } else {
        format!("Failed to open device '{}': {}", iface, err)
    }
}
