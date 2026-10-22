/*
 * packet direction analysis engine.
 *
 * accurately resolves whether each packet is:
 * - sent (TX): outgoing transmission originated from the local host.
 * - received (RX): incoming transmission addressed to or received by the local host.
 * - loopback: internal host communication (e.g. 127.0.0.1 or ::1 on lo).
 * - promiscuous: captured in transit between external network endpoints.
 */

use crate::args::DirectionFilter;
use crate::interface::LocalIdentity;
use colored::{ColoredString, Colorize};
use std::net::IpAddr;

/*
 * traffic flow direction classification.
 * categorizes packet transmission path relative to the local capturing host.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    /* packet was transmitted (sent) by the local machine. */
    Sent,
    /* packet was received by the local machine. */
    Received,
    /* packet was routed locally across the loopback interface. */
    Loopback,
    /* packet was captured promiscuously between other nodes. */
    Promiscuous,
    /* direction could not be definitively determined. */
    Unknown,
}

impl PacketDirection {
    /*
     * returns a colored terminal badge tag for compact output.
     * uses distinct ANSI color codes to immediately highlight directionality in terminal streams.
     */
    pub fn badge(&self) -> ColoredString {
        match self {
            PacketDirection::Sent => "[TX OUT]".bold().magenta(),
            PacketDirection::Received => "[RX IN ]".bold().cyan(),
            PacketDirection::Loopback => "[LOOPBK]".bold().yellow(),
            PacketDirection::Promiscuous => "[PROMIS]".dimmed(),
            PacketDirection::Unknown => "[UNKNOW]".dimmed(),
        }
    }

    /*
     * evaluates whether the direction satisfies a CLI direction filter.
     * note: loopback traffic is considered both incoming and outgoing for filtering convenience.
     */
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

/*
 * resolves packet direction by combining multiple network heuristics:
 * 1. loopback interface detection.
 * 2. linux cooked capture (SLL) packet type tags.
 * 3. source and destination MAC address matching against local interface MAC.
 * 4. source and destination IP matching against local interface IPs.
 * 5. broadcast / multicast destination evaluation.
 *
 * arguments:
 * * `sll_packet_type` - linux cooked header packet type if captured via SLL.
 * * `src_mac` - extracted source MAC address.
 * * `dst_mac` - extracted destination MAC address.
 * * `src_ip` - extracted source IP address.
 * * `dst_ip` - extracted destination IP address.
 * * `local` - local identity parameters (interface MAC, IPs, loopback status).
 */
pub fn determine_direction(
    sll_packet_type: Option<u16>,
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    local: &LocalIdentity,
) -> PacketDirection {
    /* 1. if captured on the local loopback interface, categorize as loopback */
    if local.is_loopback {
        return PacketDirection::Loopback;
    }

    /*
     * 2. check linux cooked SLL packet type header:
     * the linux kernel classifies packets into:
     * 0 = PACKET_HOST (addressed directly to local machine)
     * 1 = PACKET_BROADCAST (physical broadcast received by local machine)
     * 2 = PACKET_MULTICAST (multicast frame received by local machine)
     * 3 = PACKET_OTHERHOST (promiscuous mode, intended for another host)
     * 4 = PACKET_OUTGOING (transmitted by local machine)
     */
    if let Some(pkt_type) = sll_packet_type {
        match pkt_type {
            4 => return PacketDirection::Sent,
            0 | 1 | 2 => return PacketDirection::Received,
            3 => return PacketDirection::Promiscuous,
            _ => {}
        }
    }

    /* 3. compare hardware MAC against local interface MAC */
    if let Some(local_mac) = local.mac {
        /* if source MAC matches local MAC, packet originated locally (TX) */
        if let Some(smac) = src_mac {
            if smac == local_mac {
                return PacketDirection::Sent;
            }
        }
        /* if destination MAC matches local MAC, packet was delivered to us (RX) */
        if let Some(dmac) = dst_mac {
            if dmac == local_mac {
                return PacketDirection::Received;
            }
            /* check for broadcast MAC (FF:FF:FF:FF:FF:FF) or multicast bit (least significant bit of first octet) */
            if dmac == [0xff; 6] || (dmac[0] & 0x01 != 0) {
                /* if destination is broadcast/multicast and not originated by us, it was received (RX) */
                if let Some(smac) = src_mac {
                    if smac != local_mac {
                        return PacketDirection::Received;
                    }
                }
            }
        }
    }

    /* 4. compare IP addresses against local interface IP bindings */
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

    /* 5. check if destination IP is broadcast (e.g. 255.255.255.255) or multicast */
    if let Some(dip) = dst_ip {
        if dip.is_multicast() || dip == IpAddr::from([255, 255, 255, 255]) {
            return PacketDirection::Received;
        }
    }

    /* fallback when none of the heuristics can conclusively identify direction */
    PacketDirection::Unknown
}
