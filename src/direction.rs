//! Packet direction analysis engine.
//!
//! Accurately resolves whether each packet is:
//! - **Sent (TX)**: Outgoing transmission originated from the local host.
//! - **Received (RX)**: Incoming transmission addressed to or received by the local host.
//! - **Loopback**: Internal host communication (e.g. 127.0.0.1 or ::1 on lo).
//! - **Promiscuous**: Captured in transit between external network endpoints.

use crate::args::DirectionFilter;
use crate::interface::LocalIdentity;
use colored::{ColoredString, Colorize};
use std::net::IpAddr;

/// Traffic flow direction classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    /// Packet was transmitted (sent) by the local machine.
    Sent,
    /// Packet was received by the local machine.
    Received,
    /// Packet was routed locally across the loopback interface.
    Loopback,
    /// Packet was captured promiscuously between other nodes.
    Promiscuous,
    /// Direction could not be definitively determined.
    Unknown,
}

impl PacketDirection {
    /// Returns a colored terminal badge tag for compact output.
    pub fn badge(&self) -> ColoredString {
        match self {
            PacketDirection::Sent => "[TX OUT]".bold().magenta(),
            PacketDirection::Received => "[RX IN ]".bold().cyan(),
            PacketDirection::Loopback => "[LOOPBK]".bold().yellow(),
            PacketDirection::Promiscuous => "[PROMIS]".dimmed(),
            PacketDirection::Unknown => "[UNKNOW]".dimmed(),
        }
    }

    /// Evaluates whether the direction satisfies a CLI direction filter.
    pub fn matches_filter(&self, filter: DirectionFilter) -> bool {
        match filter {
            DirectionFilter::All => true,
            DirectionFilter::In => matches!(
                self,
                PacketDirection::Received | PacketDirection::Loopback
            ),
            DirectionFilter::Out => {
                matches!(self, PacketDirection::Sent | PacketDirection::Loopback)
            }
        }
    }
}

/// Resolves packet direction by combining multiple network heuristics:
/// 1. Loopback interface detection.
/// 2. Linux Cooked Capture (SLL) packet type tags.
/// 3. Source and destination MAC address matching against local interface MAC.
/// 4. Source and destination IP matching against local interface IPs.
/// 5. Broadcast / Multicast destination evaluation.
///
/// # Arguments
/// * `sll_packet_type` - Linux cooked header packet type if captured via SLL.
/// * `src_mac` - Extracted source MAC address.
/// * `dst_mac` - Extracted destination MAC address.
/// * `src_ip` - Extracted source IP address.
/// * `dst_ip` - Extracted destination IP address.
/// * `local` - Local identity parameters (interface MAC, IPs, loopback status).
pub fn determine_direction(
    sll_packet_type: Option<u16>,
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    local: &LocalIdentity,
) -> PacketDirection {
    // 1. If captured on the local loopback interface
    if local.is_loopback {
        return PacketDirection::Loopback;
    }

    // 2. Linux Cooked SLL packet type header check:
    // Linux kernel classifies packets into:
    // 0 = PACKET_HOST (to local machine)
    // 1 = PACKET_BROADCAST (broadcast to local machine)
    // 2 = PACKET_MULTICAST (multicast to local machine)
    // 3 = PACKET_OTHERHOST (promiscuous mode, intended for someone else)
    // 4 = PACKET_OUTGOING (transmitted by local machine)
    if let Some(pkt_type) = sll_packet_type {
        match pkt_type {
            4 => return PacketDirection::Sent,
            0 | 1 | 2 => return PacketDirection::Received,
            3 => return PacketDirection::Promiscuous,
            _ => {}
        }
    }

    // 3. Hardware MAC comparison against local interface MAC
    if let Some(local_mac) = local.mac {
        if let Some(smac) = src_mac {
            if smac == local_mac {
                return PacketDirection::Sent;
            }
        }
        if let Some(dmac) = dst_mac {
            if dmac == local_mac {
                return PacketDirection::Received;
            }
            // Check for broadcast MAC (FF:FF:FF:FF:FF:FF) or multicast bit
            if dmac == [0xff; 6] || (dmac[0] & 0x01 != 0) {
                // If destination is broadcast/multicast and not originated by us, it's received
                if let Some(smac) = src_mac {
                    if smac != local_mac {
                        return PacketDirection::Received;
                    }
                }
            }
        }
    }

    // 4. IP address comparison against local interface IP bindings
    if let Some(sip) = src_ip {
        if local.ips.contains(&sip) {
            return PacketDirection::Sent;
        }
    }
    if let Some(dip) = dst_ip {
        if local.ips.contains(&dip) {
            return PacketDirection::Received;
        }
    }

    // 5. Check if destination IP is broadcast (e.g. 255.255.255.255) or multicast
    if let Some(dip) = dst_ip {
        if dip.is_multicast() || dip == IpAddr::from([255, 255, 255, 255]) {
            return PacketDirection::Received;
        }
    }

    PacketDirection::Unknown
}
