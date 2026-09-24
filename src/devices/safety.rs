//! Safety Interlocks & Boot Media Isolation.
//! Strictly identifies and protects the host operating system, live boot USB,
//! root mount, and current executable media from accidental destruction.

use std::fs;
use std::path::Path;

/// Information about system critical storage mounts that MUST be protected
#[derive(Debug, Clone)]
pub struct SystemProtectionInfo {
    pub root_device: Option<String>,
    pub boot_devices: Vec<String>,
    pub live_usb_devices: Vec<String>,
    pub self_exe_device: Option<String>,
}

impl SystemProtectionInfo {
    /// Detect all protected system block devices from /proc/mounts and sysfs
    pub fn detect() -> Self {
        let mut root_device = None;
        let mut boot_devices = Vec::new();
        let mut live_usb_devices = Vec::new();

        if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let dev_node = parts[0];
                    let mount_point = parts[1];

                    if dev_node.starts_with("/dev/") {
                        let base_disk = resolve_parent_disk(dev_node);

                        if mount_point == "/" {
                            root_device = Some(base_disk.clone());
                        } else if mount_point.starts_with("/boot") {
                            if !boot_devices.contains(&base_disk) {
                                boot_devices.push(base_disk.clone());
                            }
                        } else if mount_point.starts_with("/run/live")
                            || mount_point.starts_with("/run/initramfs")
                            || mount_point.starts_with("/cdrom")
                            || mount_point.starts_with("/mnt/live")
                        {
                            if !live_usb_devices.contains(&base_disk) {
                                live_usb_devices.push(base_disk.clone());
                            }
                        }
                    }
                }
            }
        }

        // Also check mountpoint of current executable
        let self_exe_device = std::env::current_exe()
            .ok()
            .and_then(|p| get_mount_device_for_path(&p))
            .map(|dev| resolve_parent_disk(&dev));

        Self {
            root_device,
            boot_devices,
            live_usb_devices,
            self_exe_device,
        }
    }

    /// Evaluates if a given device path is protected
    pub fn is_protected(&self, target_path: &str) -> (bool, Option<String>) {
        let target_base = resolve_parent_disk(target_path);

        if let Some(ref root) = self.root_device {
            if &target_base == root || target_path == root {
                return (
                    true,
                    Some(format!(
                        "HARD LOCK: Device '{}' contains active root filesystem (/) - CANNOT BE SANITIZED",
                        target_path
                    )),
                );
            }
        }

        for boot in &self.boot_devices {
            if &target_base == boot || target_path == boot {
                return (
                    true,
                    Some(format!(
                        "HARD LOCK: Device '{}' contains system /boot partition - CANNOT BE SANITIZED",
                        target_path
                    )),
                );
            }
        }

        for live in &self.live_usb_devices {
            if &target_base == live || target_path == live {
                return (
                    true,
                    Some(format!(
                        "HARD LOCK: Device '{}' is the Live USB Boot Appliance media - EXCLUDED FROM WIPE",
                        target_path
                    )),
                );
            }
        }

        if let Some(ref self_dev) = self.self_exe_device {
            if &target_base == self_dev || target_path == self_dev {
                return (
                    true,
                    Some(format!(
                        "HARD LOCK: Device '{}' hosts the currently running VeriWipe binary",
                        target_path
                    )),
                );
            }
        }

        (false, None)
    }
}

/// Strip partition numbers (e.g. /dev/sda1 -> /dev/sda, /dev/nvme0n1p2 -> /dev/nvme0n1)
pub fn resolve_parent_disk(dev_node: &str) -> String {
    let clean = dev_node.trim();
    if clean.starts_with("/dev/nvme") || clean.starts_with("/dev/mmcblk") {
        if let Some(pos) = clean.rfind('p') {
            if clean[pos + 1..].chars().all(|c| c.is_ascii_digit()) {
                return clean[..pos].to_string();
            }
        }
    } else if clean.starts_with("/dev/sd") || clean.starts_with("/dev/vd") || clean.starts_with("/dev/hd") {
        let trimmed = clean.trim_end_matches(|c: char| c.is_ascii_digit());
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    } else if clean.starts_with("/dev/loop") {
        let trimmed = clean.trim_end_matches(|c: char| c.is_ascii_digit());
        if trimmed == "/dev/loop" {
            return clean.to_string(); // loop devices are individual
        }
    }
    clean.to_string()
}

/// Find device backing a specific filesystem path
fn get_mount_device_for_path(path: &Path) -> Option<String> {
    let canonical = path.canonicalize().ok()?;
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        let mut best_match: Option<(usize, String)> = None;
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let dev = parts[0];
                let mount = parts[1];
                if canonical.starts_with(mount) {
                    let len = mount.len();
                    if best_match.as_ref().map_or(true, |(best_len, _)| len > *best_len) {
                        best_match = Some((len, dev.to_string()));
                    }
                }
            }
        }
        return best_match.map(|(_, dev)| dev);
    }
    None
}
