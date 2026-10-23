<div align="center">

# 🛰️ `rsnoop`

**High-performance, real-time network packet sniffer in pure Rust**  
*Deep OSI Layer 2–7 protocol decoding, accurate TX/RX directional tracking, and zero-latency terminal streaming.*

[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.1.0-blue)](Cargo.toml)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?logo=linux&logoColor=white)](#prerequisites--installation)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)

```text
  _ __ ___ _ __   ___   ___  _ __
 | '__/ __| '_ \ / _ \ / _ \| '_ \
 | |  \__ \ | | | (_) | (_) | |_) |
 |_|  |___/_| |_|\___/ \___/| .__/
                            |_|
```

[Features](#-features) •
[Terminal Previews](#-terminal-previews) •
[Installation](#-installation) •
[Permissions](#-linux-permissions--capabilities) •
[Usage & CLI](#-usage--cli-reference) •
[Recipes](#-practical-recipes) •
[Protocol Support](#-supported-protocols) •
[Architecture](#-architecture)

</div>

---

## 🌟 Overview

**`rsnoop`** is a modern, lightweight, command-line network sniffer built from scratch in Rust. It captures live packets directly from system network interfaces, dissects network traffic from Layer 2 up to application-level Layer 7 protocols, and streams human-readable, colorized output to your terminal with sub-millisecond latency.

Unlike traditional packet analyzers that require heavy GUIs or output raw unparsed streams, `rsnoop` focuses on **instant visibility**:
- Decodes application payloads on the fly (TLS SNI domain names, DNS questions/answers, HTTP headers, DHCP options, SSH banners).
- Identifies whether each packet was **transmitted (TX)** by your machine or **received (RX)** from the wire.
- Provides a comprehensive **session statistics report** upon exit.

---

## ⚡ Features

- **🚀 Real-Time Zero-Latency Streaming**:
  - Direct live interface capture via `libpcap` configured with `immediate_mode(true)` to eliminate kernel buffering delays.
  - Streams formatted packet decodings straight to `stdout`.

- **🧭 Directional Traffic Tracking**:
  - Accurately classifies traffic direction:
    - `[TX OUT]` — Outgoing transmission originated from the local host.
    - `[RX IN ]` — Incoming transmission addressed to or received by the local host.
    - `[LOOPBK]` — Internal host loopback communication (e.g. `127.0.0.1` or `::1`).
    - `[PROMIS]` — Promiscuous transit between external endpoints.
  - Direction is resolved using hardware MAC address matching against `/sys/class/net/<iface>/address`, Linux Cooked SLL packet metadata, and local IP bindings.

- **🔬 Comprehensive OSI Layer 2–7 Protocol Decoding**:
  - **Layer 2 (Data Link)**: Ethernet II, IEEE 802.1Q (VLAN tagging), Linux Cooked SLL / SLL2, BSD/macOS Loopback.
  - **Layer 3 (Network)**: IPv4 (flags, DF/MF, fragments, TTL, protocol), IPv6 (flow labels, next headers, hop limits), ARP (Who-has / Is-at requests and replies).
  - **Layer 4 (Transport)**: TCP (SYN, ACK, FIN, RST, PSH, URG flags, Seq/Ack numbers, window sizes, payload lengths), UDP (lengths, checksums, port names), ICMPv4 & ICMPv6 (Echo Ping requests/replies, Unreachable, TTL expired).
  - **Layer 5/7 (Application)**:
    - **DNS / mDNS**: Transaction IDs, QR flags, query domain names, query types (A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, SOA), response codes (NoError, NXDomain, ServFail), answer IP mappings.
    - **HTTP/1.0 & HTTP/1.1**: Methods (GET, POST, PUT, DELETE, HEAD), URI paths, HTTP minor version, status codes (200, 301, 404, 500), Host, User-Agent, Content-Type, Content-Length.
    - **TLS / HTTPS**: Record layers, versions (SSL 3.0, TLS 1.0–1.3), Handshake types (Client Hello, Server Hello), **Server Name Indication (SNI)** extraction, Application-Layer Protocol Negotiation (ALPN: `h2`, `http/1.1`).
    - **DHCP / BOOTP**: Message types (Discover, Offer, Request, ACK/NAK), transaction IDs, client MAC, offered and requested IP addresses.
    - **NTP**: Network Time Protocol version, mode (Client, Server), Stratum, poll interval, root delay.
    - **SSH**: Protocol version and software identification banners (e.g., `SSH-2.0-OpenSSH_9.6`).

- **🎨 Multi-Mode Output Formats**:
  - **Compact Mode** *(default)*: High-density, single-line color-coded summary per packet.
  - **Verbose Mode** (`-v`): Wireshark-like hierarchical tree view inspecting every header field across layers with box-drawing glyphs.
  - **Hexdump Mode** (`-x`): Side-by-side 16-byte aligned hexadecimal and printable ASCII columns (`hexdump -C` style).

- **📊 Session Traffic Analytics**:
  - Generates a comprehensive summary report upon capture completion (Ctrl+C or packet limit) detailing total packets, total data transferred, throughput rates (`pkts/s` and `KB/s` / `MB/s`), directional breakdown, and a 3-column protocol distribution table.

- **🎯 Flexible Filtering & Interface Management**:
  - Automatic active interface selection (no need to guess between `eth0`, `wlp7s0`, or `enp0s3`).
  - Interface discovery with status, MAC, and assigned IP addresses (`-l, --list-interfaces`).
  - Kernel-level Berkeley Packet Filter (BPF) syntax (`-f "tcp and port 443"`).
  - Protocol filtering (`-p dns`, `-p tls`, `-p http`, `-p tcp`, etc.).
  - Directional filtering (`-d in`, `-d out`, `-d all`).
  - Port filtering (`--port 53`, `--port 80`).
  - Packet count limiter (`-c 100`).
  - Promiscuous mode toggle (`--no-promisc`).

---

## 🖥️ Terminal Previews

### 1. Compact Streaming Mode (Default)

High-density colorized output showing index, microsecond timestamp, direction badge, protocol badge, source/destination endpoints, and decoded application context:

```text
#00001 07:42:15.104291 [TX OUT] [DNS ] 10.248.239.113:53412 -> 1.1.1.1:53(domain)         DNS query 0x1a2b A api.github.com
#00002 07:42:15.128405 [RX IN ] [DNS ] 1.1.1.1:53(domain) -> 10.248.239.113:53412         DNS response 0x1a2b A api.github.com -> 140.82.112.6 (1 ans)
#00003 07:42:15.130192 [TX OUT] [TCP ] 10.248.239.113:48210 -> 140.82.112.6:443(https)    [SYN] Seq=18294721 Ack=0 Win=64240 Len=0
#00004 07:42:15.152841 [RX IN ] [TCP ] 140.82.112.6:443(https) -> 10.248.239.113:48210    [SYN, ACK] Seq=99281720 Ack=18294722 Win=65535 Len=0
#00005 07:42:15.152912 [TX OUT] [TCP ] 10.248.239.113:48210 -> 140.82.112.6:443(https)    [ACK] Seq=18294722 Ack=99281721 Win=64240 Len=0
#00006 07:42:15.155318 [TX OUT] [TLS ] 10.248.239.113:48210 -> 140.82.112.6:443(https)    TLS TLS 1.3 Client Hello (SNI: api.github.com)
#00007 07:42:15.181290 [RX IN ] [TLS ] 140.82.112.6:443(https) -> 10.248.239.113:48210    TLS TLS 1.3 Server Hello (ALPN: h2)
#00008 07:42:16.002148 [TX OUT] [HTTP] 10.248.239.113:38190 -> 93.184.216.34:80(http)     HTTP GET /index.html [Host: example.com]
#00009 07:42:16.038291 [RX IN ] [HTTP] 93.184.216.34:80(http) -> 10.248.239.113:38190     HTTP 200 OK [text/html]
```

### 2. Verbose Mode (`-v`)

Wireshark-like hierarchical tree view breaking down each layer:

```text
┌─── [Packet #00001] [78 bytes] [Captured: 2026-10-23 07:42:15.104291] [TRANSMITTED / OUTGOING] ───
│ ├─► Ethernet II: 34:23:87:df:21:93 -> f4:6b:8f:12:34:56 (Type: 0x0800 IPv4)
│ ├─► IPv4 Header: 10.248.239.113 -> 1.1.1.1 (TTL: 64, Proto: 17 UDP, ID: 0x4a1b, Frag: DF=true, MF=false, Off=0)
│ ├─► User Datagram Protocol (UDP): 53412 -> 53 (domain) (Len: 44, Csum: 0xa92f)
│ ├─► Domain Name System (DNS):
│ │   ID: 0x1a2b | Type: Standard Query | Opcode: Query | Status: NoError
│ │   Counts: Questions: 1 | Answers: 0 | Authority: 0 | Additional: 0
│ │   Questions:
│ │     • api.github.com [Type: A | Class: IN]
└───
```

### 3. Hexdump Mode (`-x`)

Side-by-side hexadecimal and printable ASCII payload viewer:

```text
--- Hex Dump ---
  00 1a 2b 01 00 00 01 00  00 00 00 00 03 61 70 69 |..+..........api|
  06 67 69 74 68 75 62 03  63 6f 6d 00 00 01 00 01 |.github.com.....|
```

### 4. Capture Traffic Summary Report

Displayed automatically when stopping capture (`Ctrl+C`) or when the count limit (`-c`) is reached:

```text
═══════════════════════════════════════════════════════════════════
                   CAPTURE TRAFFIC SUMMARY                        
═══════════════════════════════════════════════════════════════════
 Total Packets:           1,428           (Avg: 118.2 pkts/s)
 Total Data Transferred:  1.24 MB         (Avg: 105.12 KB/s)
 Capture Duration:        12.08 seconds

--- Traffic Direction Breakdown ---
 [TX] Sent:         612 packets (420.50 KB)
 [RX] Received:     816 packets (850.12 KB)

--- Protocol Distribution ---
 IPv4:       1428 pkts | TCP:        1240 pkts | DNS:          42 pkts
 IPv6:          0 pkts | UDP:         188 pkts | TLS:         310 pkts
 ARP:           0 pkts | ICMP:          0 pkts | HTTP:         14 pkts
 DHCP:          0 pkts | NTP:           0 pkts | SSH:           0 pkts
═══════════════════════════════════════════════════════════════════
```

---

## 📦 Supported Protocols

| Layer | Protocol | Decoded Attributes & Capabilities |
| :--- | :--- | :--- |
| **L2 - Datalink** | **Ethernet II** | Source & Destination MAC, EtherType resolution, Frame validation |
| | **IEEE 802.1Q** | VLAN Tagging, Priority Code Point (PCP), Drop Eligible (DEI), VLAN ID |
| | **Linux Cooked** | SLL & SLL2 frame formats, packet type directional cues, protocol demux |
| | **Loopback** | BSD / macOS Loopback encapsulation (`PF_INET`, `PF_INET6`) |
| **L3 - Network** | **IPv4** | Source/Dest IP, TTL, Protocol, Header Length, Total Length, ID, DF/MF Flags, Fragment Offset |
| | **IPv6** | Source/Dest IPv6, Traffic Class, Flow Label, Payload Length, Next Header, Hop Limit |
| | **ARP** | Hardware/Protocol type, Opcode (Request / Reply), Sender MAC/IP, Target MAC/IP |
| **L4 - Transport**| **TCP** | Source/Dest Ports (with service name lookup), Flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`), Sequence & Ack numbers, Window size, Checksum |
| | **UDP** | Source/Dest Ports, Datagram Length, Checksum |
| | **ICMPv4** | Echo Request/Reply (Ping), Destination Unreachable (codes 0–15), Time Exceeded, Redirect |
| | **ICMPv6** | Echo Request/Reply, Router Solicit/Advertise, Neighbor Solicit/Advertise |
| **L5–7 - App** | **DNS / mDNS** | Transaction ID, QR Flag, Opcode, RCODE (NoError, NXDomain, ServFail), Questions (Domain names, Types: A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, SOA), Resource Record Answers |
| | **TLS / HTTPS** | TLS Versions (SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3), Content Types, Handshake parsing, **Server Name Indication (SNI)** extraction, ALPN protocols (`h2`, `http/1.1`) |
| | **HTTP/1.x** | Requests (Method, Path, Version, Host, User-Agent, Content-Type, Content-Length), Responses (Status Code, Reason Phrase, Server, Content-Type) |
| | **DHCP / BOOTP** | Message Types (Discover, Offer, Request, ACK, NAK, Decline, Release, Inform), Transaction ID, Client MAC, Offered/Requested IP, Server IP |
| | **NTP** | Leap Indicator, Version, Mode (Client/Server), Stratum, Poll interval, Precision, Root Delay |
| | **SSH** | Protocol version string and software identification banner exchange |

---

## 📥 Installation

### 1. Prerequisites

`rsnoop` relies on `libpcap` to interface with the network driver.

```bash
# Ubuntu / Debian / Linux Mint / Pop!_OS
sudo apt update && sudo apt install -y libpcap-dev build-essential

# Arch Linux / Manjaro
sudo pacman -S --needed libpcap base-devel

# Fedora / RHEL / CentOS
sudo dnf install -y libpcap-devel gcc

# openSUSE
sudo zypper install libpcap-devel

# macOS (Homebrew)
brew install libpcap
```

### 2. Build from Source

Ensure you have Rust and Cargo installed ([rustup.rs](https://rustup.rs/)):

```bash
# Clone the repository
git clone https://github.com/hvsrathore/rsnoop.git
cd rsnoop

# Build optimized release binary
cargo build --release

# The compiled executable is located at:
./target/release/rsnoop --version
```

### 3. Optional: Install to System Path

```bash
cargo install --path .
```

---

## 🔒 Linux Permissions & Capabilities

Capturing raw packets directly from a network interface requires elevated network privileges (`CAP_NET_RAW` capability). You have two options:

### Option A: Grant Linux Capabilities *(Recommended — Run without `sudo`)*

Granting the binary specific network capabilities allows any unprivileged user to run `rsnoop` securely without `sudo`:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/rsnoop
```

Now execute it directly:
```bash
./target/release/rsnoop
```

### Option B: Run with `sudo`

```bash
sudo ./target/release/rsnoop -i <interface>
```

---

## 📖 Usage & CLI Reference

```text
High-performance network packet sniffer in Rust with real-time stdout multi-protocol decoding and directional tracking (TX/RX).

Usage: rsnoop [OPTIONS]

Options:
  -i, --interface <INTERFACE>    Network interface to capture packets from (e.g. eth0, wlp7s0, lo, any).
                                 If omitted, rsnoop automatically detects the active default interface.
  -l, --list-interfaces          List all available network interfaces on the host system and exit
  -f, --filter <FILTER>          Berkeley Packet Filter (BPF) syntax expression (e.g. "tcp and port 443")
  -p, --protocol <PROTOCOL>      Filter packets by protocol name
                                 [possible values: all, tcp, udp, icmp, arp, dns, http, tls, dhcp, ntp, ssh, ipv4, ipv6]
                                 [default: all]
      --port <PORT>              Filter packets by port number (matches either source or destination)
  -d, --direction <DIRECTION>    Filter packets by direction: in (received), out (sent), or all
                                 [possible values: all, in, out]
                                 [default: all]
  -v, --verbose                  Verbose output with detailed hierarchical protocol header breakdown
  -x, --hexdump                  Show side-by-side hexadecimal and printable ASCII dump of packet payload
  -c, --count <COUNT>            Stop capture after displaying the specified number of packets
      --no-promisc               Disable promiscuous mode on the capturing interface
  -h, --help                     Print help (see a summary with '-h')
  -V, --version                  Print version
```

---

## 💡 Practical Recipes

### 1. Discover System Network Interfaces
Inspect all available network adapters, their link state (`UP`/`DOWN`), hardware MAC addresses, and assigned IPv4/IPv6 addresses:
```bash
rsnoop -l
```

### 2. Quick Sniff on Default Active Interface
`rsnoop` automatically detects your primary connected network interface:
```bash
sudo rsnoop
```

### 3. Monitor Domain Names Being Accessed (TLS SNI)
Extract the exact server hostname (Server Name Indication) from encrypted HTTPS Client Hello handshakes in real time:
```bash
sudo rsnoop -p tls
```

### 4. Audit Live DNS Traffic
Inspect all outbound DNS queries and incoming DNS record resolutions:
```bash
sudo rsnoop -p dns
```

### 5. Track Outgoing Traffic Only (TX)
Filter solely for packets sent by the local host to monitor what your system is broadcasting or transmitting:
```bash
sudo rsnoop -d out
```

### 6. Monitor Incoming Web Traffic (HTTP/HTTPS)
Track incoming traffic directed to standard web ports:
```bash
sudo rsnoop -d in --port 443
```

### 7. Filter with Kernel-Level BPF Syntax
Utilize standard Berkeley Packet Filter expressions for high-performance in-kernel filtering:
```bash
# Only capture SSH traffic to/from a specific subnet
sudo rsnoop -f "port 22 and net 192.168.1.0/24"

# Capture all ICMP (Ping) and ARP requests
sudo rsnoop -f "icmp or arp"

# Capture all TCP traffic except HTTP/HTTPS
sudo rsnoop -f "tcp and not (port 80 or port 443)"
```

### 8. Wireshark-Style Deep Dive with Hexdump
Inspect the complete protocol tree along with raw payload bytes for the next 5 packets:
```bash
sudo rsnoop -v -x -c 5
```

### 9. Monitor DHCP IP Negotiations
Troubleshoot DHCP Discover, Offer, Request, and ACK cycles:
```bash
sudo rsnoop -p dhcp
```

### 10. Capture on All Interfaces Simultaneously
Capture packets passing across any network interface on the machine:
```bash
sudo rsnoop -i any
```

---

## 🏗️ Architecture

```text
 ┌────────────────────────────────────────────────────────┐
 │                   Network Interface                    │
 │               (eth0, wlp7s0, lo, any)                  │
 └──────────────────────────┬─────────────────────────────┘
                            │ Raw frames (libpcap)
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │             Direction Engine (LocalIdentity)           │
 │  • Local MAC Cache   • Local IP Set   • SLL Metadata   │
 │       ===> Classifies [TX OUT] vs [RX IN ]             │
 └──────────────────────────┬─────────────────────────────┘
                            │
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │           Multi-Layer Protocol Parser Engine           │
 │  ├─ Layer 2: Ethernet II / 802.1Q / SLL / Loopback     │
 │  ├─ Layer 3: IPv4 / IPv6 / ARP                         │
 │  ├─ Layer 4: TCP / UDP / ICMPv4 / ICMPv6               │
 │  └─ Layer 7: DNS / HTTP / TLS (SNI) / DHCP / NTP / SSH │
 └──────────────────────────┬─────────────────────────────┘
                            │
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │               User Filtering Pipeline                  │
 │  • Protocol Filter (-p)  • Direction Filter (-d)       │
 │  • Port Filter (--port)  • BPF Kernel Filter (-f)      │
 └──────────────────────────┬─────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
 ┌─────────────────────────┐ ┌─────────────────────────────┐
 │    TrafficStats Tracker │ │    PacketPrinter Renderer   │
 │ • Cumulative pkts/bytes │ │ • Compact 1-line stream     │
 │ • Data rates (bps, pps) │ │ • Verbose protocol tree     │
 │ • Protocol distribution │ │ • Hexdump payload viewer    │
 └─────────────────────────┘ └─────────────────────────────┘
```

---

## 📂 Project Structure

```text
rsnoop/
├── Cargo.toml                  # Project manifest, dependencies & metadata
├── README.md                   # Comprehensive documentation
└── src/
    ├── main.rs                 # CLI dispatch, capture loop & SIGINT handling
    ├── args.rs                 # Clap CLI parsing, flags & validation
    ├── interface.rs            # Interface discovery & MAC/IP identity resolution
    ├── direction.rs            # TX (Sent) vs RX (Received) direction analyzer
    ├── printer.rs              # Terminal formatting: compact, verbose & hexdump
    ├── stats.rs                # Traffic metrics & session summary generator
    └── protocols/
        ├── mod.rs              # Protocol demuxing and packet parsing orchestrator
        ├── ethernet.rs         # Ethernet II & IEEE 802.1Q (VLAN) decoder
        ├── sll.rs              # Linux Cooked SLL & SLL2 decoder
        ├── arp.rs              # Address Resolution Protocol (ARP) decoder
        ├── ip.rs               # Internet Protocol (IPv4 & IPv6) decoder
        ├── tcp.rs              # TCP segment & flag decoder
        ├── udp.rs              # UDP datagram decoder
        ├── icmp.rs             # ICMPv4 & ICMPv6 control message decoder
        ├── dns.rs              # DNS wire-format parser (queries, answers, RCODEs)
        ├── http.rs             # HTTP/1.0 & HTTP/1.1 request/response parser
        ├── tls.rs              # TLS 1.0–1.3 record & SNI parser
        ├── dhcp.rs             # DHCP / BOOTP option & message parser
        ├── ntp.rs              # Network Time Protocol (NTP) parser
        └── ssh.rs              # SSH protocol banner identification
```

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome!

1. **Fork** the repository on GitHub.
2. **Create a branch** for your feature or bugfix (`git checkout -b feature/my-cool-protocol`).
3. **Commit** your changes (`git commit -m 'Add support for QUIC / HTTP3'`).
4. **Push** to the branch (`git push origin feature/my-cool-protocol`).
5. Open a **Pull Request**.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
