//! Block Device Enumeration and Hardware Fingerprinting.
//! Discovers NVMe, SATA SSD, HDD, USB Mass Storage, and loop devices via Linux sysfs.

use super::safety::SystemProtectionInfo;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDeviceInfo {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub size_gb: f64,
    pub sector_size: u32,
    pub is_rotational: bool,
    pub bus_type: String,
    pub model: String,
    pub serial_number: String,
    pub is_removable: bool,
    pub is_protected: bool,
    pub protection_reason: Option<String>,
}

/// Enumerate all storage block devices on the system
pub fn list_block_devices(include_loop: bool) -> Vec<BlockDeviceInfo> {
    let safety = SystemProtectionInfo::detect();
    let sys_block = Path::new("/sys/block");
    let mut devices = Vec::new();

    if let Ok(entries) = fs::read_dir(sys_block) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            // Skip virtual ramdisks and cdroms
            if name.starts_with("ram") || name.starts_with("sr") || name.starts_with("zram") {
                continue;
            }

            // Skip loop devices unless explicitly requested
            if name.starts_with("loop") && !include_loop {
                continue;
            }

            let path = format!("/dev/{}", name);
            let dev_sys = entry.path();

            // Read size in sectors (each sector is 512 bytes in /sys/block/*/size)
            let sectors: u64 = fs::read_to_string(dev_sys.join("size"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);

            // Skip zero-sized empty loop or optical devices
            if sectors == 0 && name.starts_with("loop") {
                continue;
            }

            let sector_size: u32 = fs::read_to_string(dev_sys.join("queue/logical_block_size"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(512);

            let size_bytes = sectors * 512;
            let size_gb = (size_bytes as f64) / (1024.0 * 1024.0 * 1024.0);

            let is_rotational = fs::read_to_string(dev_sys.join("queue/rotational"))
                .ok()
                .map(|s| s.trim() == "1")
                .unwrap_or(true);

            let is_removable = fs::read_to_string(dev_sys.join("removable"))
                .ok()
                .map(|s| s.trim() == "1")
                .unwrap_or(false);

            let model = read_device_attr(&dev_sys, "device/model")
                .or_else(|| read_device_attr(&dev_sys, "device/name"))
                .unwrap_or_else(|| {
                    if name.starts_with("nvme") {
                        "NVMe Solid State Drive".to_string()
                    } else if name.starts_with("loop") {
                        "Virtual Loopback Block Device".to_string()
                    } else {
                        "Generic Storage Drive".to_string()
                    }
                });

            let serial_number = read_device_attr(&dev_sys, "device/serial")
                .or_else(|| read_device_attr(&dev_sys, "device/wwid"))
                .unwrap_or_else(|| {
                    if name.starts_with("loop") {
                        format!("LOOP-{}", name)
                    } else {
                        format!("GEN-{:X}", sectors)
                    }
                });

            let bus_type = if name.starts_with("nvme") {
                "NVMe".to_string()
            } else if is_removable || is_usb_device(&dev_sys) {
                "USB".to_string()
            } else if name.starts_with("loop") {
                "Loopback (Virtual)".to_string()
            } else if !is_rotational {
                "SATA SSD".to_string()
            } else {
                "SATA HDD".to_string()
            };

            let (is_protected, protection_reason) = safety.is_protected(&path);

            devices.push(BlockDeviceInfo {
                name,
                path,
                size_bytes,
                size_gb,
                sector_size,
                is_rotational,
                bus_type,
                model,
                serial_number,
                is_removable,
                is_protected,
                protection_reason,
            });
        }
    }

    // Sort: physical targets first, loop devices last
    devices.sort_by(|a, b| {
        let a_loop = a.name.starts_with("loop");
        let b_loop = b.name.starts_with("loop");
        a_loop.cmp(&b_loop).then(a.name.cmp(&b.name))
    });

    devices
}

fn read_device_attr(base: &Path, rel_path: &str) -> Option<String> {
    fs::read_to_string(base.join(rel_path))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn is_usb_device(base: &Path) -> bool {
    if let Ok(target) = fs::read_link(base) {
        let s = target.to_string_lossy();
        if s.contains("/usb") {
            return true;
        }
    }
    false
}
