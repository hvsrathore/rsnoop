//! Network interface discovery and local host identity resolution.
//!
//! Provides utilities to inspect local network interfaces, parse hardware MAC addresses
//! directly from Linux sysfs (`/sys/class/net/<iface>/address`), discover assigned IPv4/IPv6
//! addresses, and select appropriate default capture devices.

use colored::Colorize;
use pcap::Device;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;

/// Metadata describing a local host network interface.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Kernel device name (e.g. "eth0", "wlan0", "lo").
    pub name: String,
    /// Operating system provided description if available.
    pub description: Option<String>,
    /// 6-byte hardware MAC address if available.
    pub mac: Option<[u8; 6]>,
    /// Formatted MAC address string (e.g. "00:11:22:33:44:55").
    pub mac_str: Option<String>,
    /// List of assigned IPv4 and IPv6 addresses.
    pub ips: Vec<IpAddr>,
    /// Whether this interface is a loopback adapter.
    pub is_loopback: bool,
    /// Whether the interface is operational (UP).
    pub is_up: bool,
}

impl InterfaceInfo {
    /// Attempts to read the hardware MAC address from Linux sysfs (`/sys/class/net/<iface>/address`).
    pub fn read_mac(iface_name: &str) -> Option<[u8; 6]> {
        let path = format!("/sys/class/net/{}/address", iface_name);
        let content = fs::read_to_string(path).ok()?;
        let trimmed = content.trim();
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() == 6 {
            let mut mac = [0u8; 6];
            for (i, part) in parts.iter().enumerate() {
                mac[i] = u8::from_str_radix(part, 16).ok()?;
            }
            Some(mac)
        } else {
            None
        }
    }

    /// Reads operational state from Linux sysfs (`/sys/class/net/<iface>/operstate`).
    pub fn is_iface_up(iface_name: &str) -> bool {
        let path = format!("/sys/class/net/{}/operstate", iface_name);
        if let Ok(state) = fs::read_to_string(path) {
            let s = state.trim().to_lowercase();
            return s == "up" || s == "unknown"; // loopback is frequently reported as "unknown"
        }
        true
    }

    /// Constructs an [`InterfaceInfo`] descriptor from a libpcap [`Device`].
    pub fn from_device(device: &Device) -> Self {
        let mac = Self::read_mac(&device.name);
        let mac_str = mac.map(|m| {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )
        });
        let ips: Vec<IpAddr> = device.addresses.iter().map(|a| a.addr).collect();
        let is_loopback = device.name == "lo" || device.flags.is_loopback();
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

/// Enumerates all network interfaces and prints a formatted, color-coded summary table.
pub fn print_interface_list() -> Result<(), pcap::Error> {
    let devices = Device::list()?;
    println!("{}", "=== Available Network Interfaces ===".bold().cyan());
    println!(
        "{:<15} {:<18} {:<10} {:<30} {}",
        "Interface", "MAC Address", "Status", "IP Addresses", "Description"
    );
    println!("{:-<95}", "");

    for dev in devices {
        let info = InterfaceInfo::from_device(&dev);
        let mac = info.mac_str.unwrap_or_else(|| "N/A".to_string());
        let status = if info.is_up {
            "UP".green().bold()
        } else {
            "DOWN".red()
        };
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

/// Selects the most appropriate default active interface for capture.
/// Priority heuristic:
/// 1. Operational non-loopback device with an assigned IP address.
/// 2. Any operational non-loopback device.
/// 3. Loopback ("lo").
/// 4. First device listed by the OS.
pub fn select_default_interface() -> Result<Device, String> {
    let devices = Device::list().map_err(|e| format!("Failed to list devices: {}", e))?;
    if devices.is_empty() {
        return Err("No network interfaces found on this system.".to_string());
    }

    // 1. Look for active non-loopback interface with an assigned IP
    for dev in &devices {
        let info = InterfaceInfo::from_device(dev);
        if !info.is_loopback && info.is_up && !info.ips.is_empty() {
            return Ok(dev.clone());
        }
    }

    // 2. Look for any active non-loopback interface
    for dev in &devices {
        let info = InterfaceInfo::from_device(dev);
        if !info.is_loopback && info.is_up {
            return Ok(dev.clone());
        }
    }

    // 3. Fall back to loopback if available
    for dev in &devices {
        if dev.name == "lo" {
            return Ok(dev.clone());
        }
    }

    // 4. Fall back to first device
    Ok(devices[0].clone())
}

/// Represents the network identity of the local capturing machine.
/// Used by the directional analyzer to distinguish TX (Sent) from RX (Received).
pub struct LocalIdentity {
    /// Local hardware MAC address.
    pub mac: Option<[u8; 6]>,
    /// Set of local IP addresses (IPv4 & IPv6).
    pub ips: HashSet<IpAddr>,
    /// Whether the capturing device is loopback.
    pub is_loopback: bool,
}

impl LocalIdentity {
    /// Constructs a `LocalIdentity` from interface metadata.
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
