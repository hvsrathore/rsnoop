# Packet Sniffer in Rust (`packet_sniffer_v2`)

A high-performance, real-time network packet sniffer written in pure Rust. Captures live network traffic from system interfaces, decodes all major network protocols across Layers 2 through 7, accurately identifies whether each packet was **Sent (TX)** or **Received (RX)**, and formats the output directly to `stdout`.

---

## Features

- **Live Capture & Real-time Streaming**:
  - Direct live interface packet capture with zero-latency immediate mode (`immediate_mode(true)`).
  - Streams formatted packet decodings directly to `stdout`.
- **Directional Tracking**:
  - Identifies traffic direction: `[TX OUT]` (Transmitted / Sent), `[RX IN ]` (Received / Incoming), or `[LOOPBK]` (Local host loopback).
  - Uses hardware MAC matching against local interface addresses, Linux Cooked SLL packet type metadata, and IP address bindings.
- **Comprehensive Protocol Coverage**:
  - **Data Link (L2)**: Ethernet II, IEEE 802.1Q (VLAN tags), Linux Cooked SLL/SLL2, BSD/macOS Loopback.
  - **Network (L3)**: IPv4, IPv6, ARP (Address Resolution Protocol).
  - **Transport (L4)**: TCP (Flags, Sequence, Ack, Window, Checksum), UDP, ICMPv4, ICMPv6.
  - **Application (L5/L7)**:
    - **DNS**: Transaction ID, QR flag, query domain names, record types (A, AAAA, CNAME, MX, TXT, etc.), answers.
    - **HTTP**: Request methods (GET, POST, etc.), URI paths, HTTP version, response status codes (200, 404, etc.), Host, User-Agent, Content-Type.
    - **TLS/HTTPS**: Record type, TLS versions (TLS 1.0 - 1.3), Handshake messages (Client Hello, Server Hello), **Server Name Indication (SNI)** extraction, ALPN protocols (`h2`, `http/1.1`).
    - **DHCP / BOOTP**: Message types (Discover, Offer, Request, ACK), Transaction ID, client MAC, offered/requested IP addresses.
    - **NTP**: Version, mode, stratum, polling intervals.
    - **SSH**: Protocol version and software identification banners.
- **Multiple Output Formats**:
  - **Compact Mode** (default): High-density colored summary line per packet with timestamps, direction badges, endpoints, and protocol details.
  - **Verbose Mode** (`-v`): Detailed multi-level hierarchical breakdown showing all parsed protocol fields.
  - **Hexdump Mode** (`-x`): Side-by-side hexadecimal and printable ASCII payload dump.
- **Traffic Statistics**:
  - Displays a comprehensive traffic summary report upon termination (Ctrl+C) showing total packets, total bytes, transfer rates, direction breakdown, and protocol distribution.

---

## Installation & Building

Ensure you have Rust and `libpcap` installed:

```bash
# On Debian/Ubuntu/Mint:
sudo apt install libpcap-dev

# On Arch Linux:
sudo pacman -S libpcap

# On Fedora/RHEL:
sudo dnf install libpcap-devel
```

Build the release binary:

```bash
cargo build --release
```

The compiled binary will be placed at `./target/release/packet_sniffer_v2`.

---

## Linux Permissions & Capabilities

Capturing raw packets directly from a network interface requires elevated network privileges (`CAP_NET_RAW` capability). You can either:

### Option A: Run with `sudo`
```bash
sudo ./target/release/packet_sniffer_v2 -i <interface>
```

### Option B: Grant Linux Capabilities (Run without `sudo`)
To run the sniffer as a normal unprivileged user, grant the binary `cap_net_raw` and `cap_net_admin`:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/packet_sniffer_v2
./target/release/packet_sniffer_v2 -i <interface>
```

---

## Usage & CLI Options

```
Usage: packet_sniffer_v2 [OPTIONS]

Options:
  -i, --interface <INTERFACE>    Network interface to capture on (e.g. eth0, wlp7s0, lo, any)
  -l, --list-interfaces          List all available network interfaces on host and exit
  -f, --filter <FILTER>          Berkeley Packet Filter (BPF) syntax (e.g. "tcp and port 443", "icmp")
  -p, --protocol <PROTOCOL>      Filter by protocol: all, tcp, udp, icmp, arp, dns, http, tls, dhcp, ntp, ssh, ipv4, ipv6
      --port <PORT>              Filter by port number (source or destination)
  -d, --direction <DIRECTION>    Filter by direction: in (received), out (sent), or all (default: all)
  -v, --verbose                  Verbose hierarchical protocol breakdown
  -x, --hexdump                  Side-by-side hex and printable ASCII payload dump
  -c, --count <COUNT>            Stop capture after N packets
      --no-promisc               Disable promiscuous mode
  -h, --help                     Print help
  -V, --version                  Print version
```

---

## Examples

### 1. Discover Available Network Interfaces
```bash
./target/release/packet_sniffer_v2 --list-interfaces
```

### 2. Live Capture with Real-Time stdout Streaming
```bash
sudo ./target/release/packet_sniffer_v2 -i wlp7s0
```

### 3. Filter by Protocol (e.g., DNS Queries and Answers)
```bash
sudo ./target/release/packet_sniffer_v2 -i wlp7s0 -p dns
```

### 4. Filter by Direction (e.g., Show Only Outgoing/Sent Packets)
```bash
sudo ./target/release/packet_sniffer_v2 -i wlp7s0 -d out
```

### 5. Inspect TLS Traffic with Server Name Indication (SNI) Extraction
```bash
sudo ./target/release/packet_sniffer_v2 -i wlp7s0 -p tls
```

### 6. Filter Using BPF Syntax
```bash
sudo ./target/release/packet_sniffer_v2 -i wlp7s0 -f "tcp and port 443"
```

### 7. Verbose Wireshark-Style Inspection with Hexdump
```bash
sudo ./target/release/packet_sniffer_v2 -i wlp7s0 -v -x -c 5
```

---

## Project Structure

```
packet_sniffer_v2/
├── Cargo.toml                  # Project manifest and dependencies
├── README.md                   # Project documentation
└── src/
    ├── main.rs                 # Entry point, capture loop, signal handling
    ├── args.rs                 # Clap CLI argument parsing & configuration
    ├── interface.rs            # Interface discovery & MAC/IP resolution
    ├── direction.rs            # TX (Sent) vs RX (Received) direction analyzer
    ├── printer.rs              # Stdout formatting: compact, verbose & hexdump
    ├── stats.rs                # Traffic metrics & summary statistics table
    └── protocols/
        ├── mod.rs              # Master protocol decoding engine
        ├── ethernet.rs         # Ethernet II & IEEE 802.1Q (VLAN)
        ├── sll.rs              # Linux Cooked SLL & SLL2
        ├── arp.rs              # Address Resolution Protocol (ARP)
        ├── ip.rs               # Internet Protocol (IPv4 & IPv6)
        ├── tcp.rs              # Transmission Control Protocol (TCP)
        ├── udp.rs              # User Datagram Protocol (UDP)
        ├── icmp.rs             # ICMPv4 & ICMPv6 (Ping, Unreachable, etc.)
        ├── dns.rs              # Domain Name System (DNS wire format)
        ├── http.rs             # HTTP/1.0 & HTTP/1.1 (Requests & Responses)
        ├── tls.rs              # TLS 1.0-1.3 & SNI (Server Name Indication)
        ├── dhcp.rs             # DHCP / BOOTP (Discover, Offer, Request, ACK)
        ├── ntp.rs              # Network Time Protocol (NTP)
        └── ssh.rs              # SSH protocol identification banner
```
