/*
 * network interface discovery and local host identity resolution.
 *
 * provides utilities to inspect local network interfaces, parse hardware MAC addresses
 * directly from Linux sysfs (`/sys/class/net/<iface>/address`), discover assigned IPv4/IPv6
 * addresses, and select appropriate default capture devices.
 */

use colored::Colorize;
use pcap::Device;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;

/*
 * metadata describing a local host network interface.
 * stores physical layer parameters (MAC address), network layer parameters (IP addresses),
 * and interface operational state (up/down/loopback).
 */
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /* kernel device name (e.g. "eth0", "wlan0", "lo"). */
    pub name: String,
    /* operating system provided description if available. */
    pub description: Option<String>,
    /* 6-byte hardware MAC address if available. */
    pub mac: Option<[u8; 6]>,
    /* formatted MAC address string (e.g. "00:11:22:33:44:55"). */
    pub mac_str: Option<String>,
    /* list of assigned IPv4 and IPv6 addresses. */
    pub ips: Vec<IpAddr>,
    /* whether this interface is a loopback adapter. */
    pub is_loopback: bool,
    /* whether the interface is operational (UP). */
    pub is_up: bool,
}

impl InterfaceInfo {
    /*
     * attempts to read the hardware MAC address from Linux sysfs (`/sys/class/net/<iface>/address`).
     * reads the pseudo-filesystem file containing standard colon-separated hex octets,
     * parses each hex byte, and returns a fixed 6-byte array if valid.
     */
    pub fn read_mac(iface_name: &str) -> Option<[u8; 6]> {
        /* construct path to sysfs address file for the specified network interface */
        let path = format!("/sys/class/net/{}/address", iface_name);
        let content = fs::read_to_string(path).ok()?;
        let trimmed = content.trim();

        /* split into colon-delimited hex octet substrings */
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() == 6 {
            let mut mac = [0u8; 6];
            for (i, part) in parts.iter().enumerate() {
                /* parse each octet as a base-16 unsigned 8-bit integer */
                mac[i] = u8::from_str_radix(part, 16).ok()?;
            }
            Some(mac)
        } else {
            None
        }
    }

    /*
     * reads operational state from Linux sysfs (`/sys/class/net/<iface>/operstate`).
     * returns true if the interface state is "up" or "unknown" (loopback interfaces
     * often report "unknown" state while being fully operational).
     */
    pub fn is_iface_up(iface_name: &str) -> bool {
        let path = format!("/sys/class/net/{}/operstate", iface_name);
        if let Ok(state) = fs::read_to_string(path) {
            let s = state.trim().to_lowercase();
            /* treat both "up" and "unknown" (common for loopback) as operational */
            return s == "up" || s == "unknown";
        }
        /* default to true if sysfs is not accessible, allowing capture attempts */
        true
    }

    /*
     * constructs an `InterfaceInfo` descriptor from a libpcap `Device`.
     * queries Linux sysfs for physical MAC address and operational state,
     * and extracts all configured IPv4/IPv6 addresses.
     */
    pub fn from_device(device: &Device) -> Self {
        /* retrieve hardware MAC address from sysfs */
        let mac = Self::read_mac(&device.name);
        /* format MAC bytes into standard colon-delimited hex representation */
        let mac_str = mac.map(|m| {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )
        });
        /* extract all assigned IPv4 and IPv6 network addresses */
        let ips: Vec<IpAddr> = device.addresses.iter().map(|a| a.addr).collect();
        /* check if this device is identified as the loopback adapter */
        let is_loopback = device.name == "lo" || device.flags.is_loopback();
        /* inspect operstate to determine if interface link is UP */
        let is_up = Self::is_iface_up(&device.name);

        Self {
            name: device.name.clone(),
            description: device.desc.clone(),
            mac,
            mac_str,
            ips,
            is_loopback,
            is_up,
        }
    }
}

/*
 * enumerates all network interfaces and prints a formatted, color-coded summary table.
 * displays interface name, MAC address, UP/DOWN status, configured IP addresses,
 * and description to stdout.
 */
pub fn print_interface_list() -> Result<(), pcap::Error> {
    /* list all host network interfaces discovered by libpcap */
    let devices = Device::list()?;
    println!("{}", "=== Available Network Interfaces ===".bold().cyan());
    println!(
        "{:<15} {:<18} {:<10} {:<30} {}",
        "Interface", "MAC Address", "Status", "IP Addresses", "Description"
    );
    println!("{:-<95}", "");

    /* iterate through each discovered device and display row in table */
    for dev in devices {
        let info = InterfaceInfo::from_device(&dev);
        let mac = info.mac_str.unwrap_or_else(|| "N/A".to_string());
        let status = if info.is_up {
            "UP".green().bold()
        } else {
            "DOWN".red()
        };
        /* format comma-separated string of all assigned IP addresses */
        let ips_str = if info.ips.is_empty() {
            "None".dimmed().to_string()
        } else {
            info.ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let desc = info.description.unwrap_or_else(|| "".to_string());

        println!(
            "{:<15} {:<18} {:<19} {:<30} {}",
            info.name.yellow().bold(),
            mac,
            status,
            ips_str,
            desc.dimmed()
        );
    }
    println!("{:-<95}", "");
    Ok(())
}

/*
 * selects the most appropriate default active interface for capture.
 * priority heuristic:
 * 1. operational non-loopback device with an assigned IP address.
 * 2. any operational non-loopback device.
 * 3. loopback ("lo").
 * 4. first device listed by the OS.
 */
pub fn select_default_interface() -> Result<Device, String> {
    let devices = Device::list().map_err(|e| format!("Failed to list devices: {}", e))?;
    if devices.is_empty() {
        return Err("No network interfaces found on this system.".to_string());
    }

    /* 1. look for active non-loopback interface with an assigned IP address */
    for dev in &devices {
        let info = InterfaceInfo::from_device(dev);
        if !info.is_loopback && info.is_up && !info.ips.is_empty() {
            return Ok(dev.clone());
        }
    }

    /* 2. look for any active non-loopback interface even without an IP */
    for dev in &devices {
        let info = InterfaceInfo::from_device(dev);
        if !info.is_loopback && info.is_up {
            return Ok(dev.clone());
        }
    }

    /* 3. fall back to loopback interface if available */
    for dev in &devices {
        if dev.name == "lo" {
            return Ok(dev.clone());
        }
    }

    /* 4. fall back to the very first device in the system device list */
    Ok(devices[0].clone())
}

/*
 * represents the network identity of the local capturing machine.
 * used by the directional analyzer to distinguish TX (Sent) from RX (Received)
 * by checking if source/destination addresses match the capturing host.
 */
pub struct LocalIdentity {
    /* local hardware MAC address. */
    pub mac: Option<[u8; 6]>,
    /* set of local IP addresses (IPv4 & IPv6). */
    pub ips: HashSet<IpAddr>,
    /* whether the capturing device is loopback. */
    pub is_loopback: bool,
}

impl LocalIdentity {
    /*
     * constructs a `LocalIdentity` from interface metadata.
     * populates a hash set with local IPs for fast O(1) membership lookups during packet processing.
     */
    pub fn new(iface_info: &InterfaceInfo) -> Self {
        let mut ips = HashSet::new();
        for ip in &iface_info.ips {
            ips.insert(*ip);
        }
        Self {
            mac: iface_info.mac,
            ips,
            is_loopback: iface_info.is_loopback,
        }
    }
}
