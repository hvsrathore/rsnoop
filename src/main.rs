/*
 * network packet sniffer in Rust.
 *
 * high-performance, real-time network packet sniffer that captures live packets
 * from network interfaces and streams rich protocol details directly to stdout.
 *
 * end-to-end architecture & flow of control across the project:
 * 1. CLI parsing (`src/args.rs`):
 *    - `main()` parses command-line arguments into `CliArgs` via `clap`.
 *    - if `--list-interfaces` is requested, control transfers to `interface::print_interface_list()`
 *      which queries OS devices and terminates the program cleanly.
 * 2. interface discovery & host identity (`src/interface.rs`):
 *    - selects the capture device: either the user-specified `-i` interface or auto-detected
 *      using priority heuristics (operational status via `/sys/class/net/<iface>/operstate` and assigned IPs).
 *    - reads the physical MAC address from `/sys/class/net/<iface>/address` and extracts IP addresses
 *      to construct a `LocalIdentity` instance representing the local machine.
 * 3. capture session initialization (libpcap):
 *    - initializes `pcap::Capture::from_device()` with promiscuous mode, 65535 snaplen,
 *      200ms read timeout, and immediate mode.
 *    - compiles and attaches optional Berkeley Packet Filter (BPF) expressions directly into the kernel.
 *    - queries the link-layer header format (`Linktype`) for datalink demuxing.
 * 4. asynchronous interruption handling (`ctrlc`):
 *    - installs a signal handler for `SIGINT` (Ctrl+C) that sets an atomic boolean flag (`running`).
 *    - periodic 200ms pcap timeouts wake the capture loop to check if `running` remains true.
 * 5. main packet capture loop:
 *    - packet acquisition: `cap.next_packet()` yields raw packet bytes and hardware timestamp.
 *    - multi-layer protocol decoding (`src/protocols/mod.rs`):
 *      - L2: Ethernet II (`ethernet.rs`), Linux Cooked (`sll.rs`), or BSD Loopback.
 *      - L3: IPv4 / IPv6 (`ip.rs`), ARP (`arp.rs`).
 *      - L4: TCP (`tcp.rs`), UDP (`udp.rs`), ICMPv4 / ICMPv6 (`icmp.rs`).
 *      - L5/L7: DNS (`dns.rs`), HTTP (`http.rs`), TLS (`tls.rs`), DHCP (`dhcp.rs`), NTP (`ntp.rs`), SSH (`ssh.rs`).
 *    - directional analysis (`src/direction.rs`):
 *      - `determine_direction()` compares packet addresses against `LocalIdentity` to classify
 *        traffic flow as `[TX OUT]` (Sent), `[RX IN ]` (Received), or `[LOOPBK]` (Local host).
 *    - filtering pipeline (`src/args.rs`):
 *      - evaluates user filters: protocol (`-p`), port (`--port`), direction (`-d`).
 *      - skipped packets are bypassed without recording or rendering.
 *    - metrics accumulation (`src/stats.rs`):
 *      - `TrafficStats::record()` updates cumulative packet counts, byte volumes, and protocol counters.
 *    - terminal output rendering (`src/printer.rs`):
 *      - `PacketPrinter::print()` renders either a single-line compact summary or a multi-level tree breakdown,
 *        optionally followed by a formatted side-by-side hex/ASCII dump.
 *    - packet limit evaluation: checks if user-specified count limit (`-c`) is reached.
 * 6. session termination & report generation (`src/stats.rs`):
 *    - upon loop exit (Ctrl+C or packet limit), `stats.print_summary()` renders total transferred
 *      bytes, average packet/byte throughput rates, directional breakdown, and protocol distribution.
 */

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

/*
 * application entry point.
 * parses CLI options, handles interface listing, registers signal handlers,
 * and initiates live packet capture.
 */
fn main() {
    /* step 1: parse command-line arguments using clap */
    let args = CliArgs::parse();

    /* step 2: if "--list-interfaces" is passed, display available devices and exit */
    if args.list_interfaces {
        if let Err(e) = print_interface_list() {
            eprintln!("{}: {}", "Error listing interfaces".red().bold(), e);
            std::process::exit(1);
        }
        return;
    }

    /* step 3: configure atomic boolean flag for graceful Ctrl+C (SIGINT) termination */
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        println!("\n{}", "Interrupt received, stopping capture...".yellow().bold());
        r.store(false, Ordering::SeqCst);
    }) {
        eprintln!("{}: {}", "Warning: Failed to set Ctrl+C handler".yellow(), e);
    }

    /* step 4: enter live capture session streaming decoded packets to stdout */
    if let Err(e) = run_live_capture(&args, &running) {
        eprintln!("{}: {}", "Sniffer Error".red().bold(), e);
        std::process::exit(1);
    }
}

/*
 * captures live packets from the network interface and displays decoded information on stdout.
 *
 * flow of control inside live capture:
 * 1. interface selection: uses `-i` option or auto-detects active non-loopback device.
 * 2. identity discovery: inspects interface sysfs attributes to construct `LocalIdentity`.
 * 3. libpcap initialization: sets buffer parameters, timeout, immediate mode, and BPF filters.
 * 4. live capture loop: continuously captures, parses, filters, records, and displays packets.
 * 5. shutdown summary: outputs formatted session metrics report on loop termination.
 */
fn run_live_capture(args: &CliArgs, running: &Arc<AtomicBool>) -> Result<(), String> {
    /* step 1: select network interface (user-specified or auto-detected default) */
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

    /* step 2: gather local interface MAC and IP addresses for accurate direction determination */
    let iface_info = InterfaceInfo::from_device(&device);
    let local_identity = LocalIdentity::new(&iface_info);

    /* print capture startup banner to stdout */
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

    /*
     * step 3: open capture handle via libpcap:
     * - snaplen(65535): captures complete unfragmented frames
     * - timeout(200): 200ms polling timeout so the atomic running flag can be evaluated
     * - immediate_mode(true): packets are delivered immediately without driver buffering
     */
    let mut cap = Capture::from_device(device.clone())
        .map_err(|e| explain_permission_error(&e, &device.name))?
        .promisc(!args.no_promisc)
        .snaplen(65535)
        .timeout(200)
        .immediate_mode(true)
        .open()
        .map_err(|e| explain_permission_error(&e, &device.name))?;

    /* step 4: compile and apply Berkeley Packet Filter (BPF) if specified */
    if let Some(bpf) = &args.filter {
        cap.filter(bpf, true)
            .map_err(|e| format!("Failed to compile BPF filter '{}': {}", bpf, e))?;
    }

    let linktype = cap.get_datalink();
    let parser = PacketParser::new(&local_identity);
    let mut stats = TrafficStats::new();
    let mut packet_count = 0;

    /* step 5: live capture and stdout streaming loop */
    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;

                /* 5a. decode packet headers across all network layers */
                let parsed = parser.parse(packet_count, &packet, linktype);

                /* 5b. evaluate protocol filter */
                if !parsed.matches_protocol(args.protocol) {
                    continue;
                }

                /* 5c. evaluate port filter */
                if !parsed.matches_port(args.port) {
                    continue;
                }

                /* 5d. evaluate direction filter (sent / received) */
                if !parsed.direction.matches_filter(args.direction) {
                    continue;
                }

                /* 5e. record traffic metrics for accepted packet */
                stats.record(&parsed);

                /* 5f. render formatted packet information to stdout */
                PacketPrinter::print(&parsed, args.verbose, args.hexdump);

                /* 5g. stop capture if user-specified packet count limit is reached */
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
                /* timeout elapsed with no incoming packet: continue loop to inspect `running` flag */
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

    /* step 6: render final comprehensive traffic statistics table to stdout */
    stats.print_summary();

    Ok(())
}

/*
 * generates clear diagnostic messages when raw device access fails due to Linux permissions.
 * advises user on using sudo or granting Linux CAP_NET_RAW capabilities.
 */
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
