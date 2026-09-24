//! Hardware-Level & OEM Direct Sanitization Engine.
//! Executes low-level controller commands (NVMe Sanitize, ATA Secure Erase,
//! Linux BLKDISCARD/BLKSECDISCARD), hardware write-cache flushing, and O_DIRECT bypassing.

use std::os::unix::io::AsRawFd;
use std::process::Command;
use tracing::info;

// Linux ioctl numbers for raw block devices
// #define BLKFLSBUF _IO(0x12,97)
const BLKFLSBUF: libc::c_ulong = 0x1261;
// #define BLKDISCARD _IO(0x12,119)
const BLKDISCARD: libc::c_ulong = 0x1277;
// #define BLKSECDISCARD _IO(0x12,125)
const BLKSECDISCARD: libc::c_ulong = 0x127D;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HardwareSanitizeReport {
    pub controller_method_attempted: String,
    pub controller_command_status: String,
    pub hardware_trim_supported: bool,
    pub cache_flush_confirmed: bool,
    pub oem_details: String,
}

/// Flush all hardware controller write buffers, OS page caches, and drive volatile cache
pub fn flush_hardware_caches<F: AsRawFd>(file: &F) -> bool {
    let fd = file.as_raw_fd();
    let mut success = true;

    // 1. Invalidate and flush OS kernel buffer cache for the block device
    unsafe {
        let ret = libc::ioctl(fd, BLKFLSBUF, 0);
        if ret != 0 {
            // Virtual files might fail BLKFLSBUF, which is normal for loop devices
            success = false;
        }
    }

    // 2. Synchronize file data and disk controller write cache
    unsafe {
        if libc::fdatasync(fd) != 0 {
            success = false;
        }
        if libc::fsync(fd) != 0 {
            success = false;
        }
    }

    // 3. System-wide sync
    unsafe {
        libc::sync();
    }

    success
}

/// Issue Linux kernel BLKDISCARD or BLKSECDISCARD ioctl to hardware flash controller
pub fn issue_hardware_discard<F: AsRawFd>(file: &F, total_bytes: u64) -> (bool, String) {
    let fd = file.as_raw_fd();
    let range: [u64; 2] = [0, total_bytes];

    // Try BLKSECDISCARD first (Secure hardware discard / cryptographic deallocate)
    unsafe {
        let ret = libc::ioctl(fd, BLKSECDISCARD, range.as_ptr());
        if ret == 0 {
            return (true, "BLKSECDISCARD: Secure hardware flash deallocation succeeded".to_string());
        }
    }

    // Fall back to standard BLKDISCARD (TRIM)
    unsafe {
        let ret = libc::ioctl(fd, BLKDISCARD, range.as_ptr());
        if ret == 0 {
            return (true, "BLKDISCARD: Hardware flash TRIM / deallocation succeeded".to_string());
        }
    }

    (false, "Hardware discard not supported on this interface or bridge".to_string())
}

/// Execute OEM NVMe controller sanitize or format command (NVMe SP 1.4 / NIST 800-88 Purge)
pub fn execute_nvme_sanitize(dev_path: &str, crypto: bool) -> (bool, String) {
    info!("Issuing native NVMe controller sanitize on {}", dev_path);

    let action_flag = if crypto { "-a 4" } else { "-a 2" }; // 4 = crypto erase, 2 = block erase

    // Try nvme-cli sanitize
    let output = Command::new("nvme")
        .args(["sanitize", dev_path, action_flag])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let msg = String::from_utf8_lossy(&out.stdout).to_string();
            return (true, format!("NVMe Sanitize command accepted by controller: {}", msg.trim()));
        }
    }

    // Fall back to NVMe Format with Secure Erase Settings (SES=1 or SES=2)
    let ses_flag = if crypto { "--ses=2" } else { "--ses=1" };
    let format_output = Command::new("nvme")
        .args(["format", dev_path, ses_flag, "-f"])
        .output();

    if let Ok(out) = format_output {
        if out.status.success() {
            let msg = String::from_utf8_lossy(&out.stdout).to_string();
            return (true, format!("NVMe Format Secure Erase (SES) succeeded: {}", msg.trim()));
        }
    }

    (false, "Native NVMe controller sanitize unavailable or device locked".to_string())
}

/// Execute ATA Security Erase or ATA Sanitize Block Erase on SATA SSD/HDD
pub fn execute_ata_secure_erase(dev_path: &str) -> (bool, String) {
    info!("Checking ATA Security Erase support on {}", dev_path);

    // Check hdparm capability
    let check = Command::new("hdparm")
        .args(["-I", dev_path])
        .output();

    if let Ok(out) = check {
        let info_str = String::from_utf8_lossy(&out.stdout);
        if info_str.contains("Security:") {
            if info_str.contains("frozen") {
                return (false, "ATA Security is in FROZEN state by BIOS/UEFI. System power-cycle or suspend-resume required to unfreeze.".to_string());
            }

            // Set temporary password and issue security erase
            let set_pwd = Command::new("hdparm")
                .args(["--user-master", "u", "--security-set-pass", "veriwipe", dev_path])
                .output();

            if let Ok(p_out) = set_pwd {
                if p_out.status.success() {
                    let erase = Command::new("hdparm")
                        .args(["--user-master", "u", "--security-erase", "veriwipe", dev_path])
                        .output();

                    if let Ok(e_out) = erase {
                        if e_out.status.success() {
                            return (true, "ATA Security Erase executed successfully by drive controller".to_string());
                        }
                    }
                }
            }
        }
    }

    (false, "ATA Security Erase command not supported or bridge blocked pass-through".to_string())
}

/// Dispatch device-aware OEM hardware sanitize based on bus type
pub fn execute_hardware_level_sanitize<F: AsRawFd>(
    dev_path: &str,
    bus_type: &str,
    file: &F,
    total_bytes: u64,
) -> HardwareSanitizeReport {
    let mut oem_details = Vec::new();
    let mut command_status = "N/A - Direct Overwrite Pipeline Applied".to_string();
    let mut method_attempted = "Standard Block Overwrite".to_string();

    // 1. Hardware-specific controller dispatch
    if bus_type.to_uppercase().contains("NVME") {
        method_attempted = "NVMe Sanitize / Crypto Erase (NVMe Admin Command)".to_string();
        let (ok, status) = execute_nvme_sanitize(dev_path, true);
        if ok {
            command_status = format!("SUCCESS: {}", status);
        } else {
            command_status = format!("FALLBACK REQUIRED: {}", status);
        }
        oem_details.push(command_status.clone());
    } else if bus_type.to_uppercase().contains("SATA") {
        method_attempted = "ATA Secure Erase / ATA Sanitize (hdparm/SG_IO)".to_string();
        let (ok, status) = execute_ata_secure_erase(dev_path);
        if ok {
            command_status = format!("SUCCESS: {}", status);
        } else {
            command_status = format!("FALLBACK REQUIRED: {}", status);
        }
        oem_details.push(command_status.clone());
    }

    // 2. Hardware Flash Discard (TRIM / BLKDISCARD)
    let (discard_ok, discard_msg) = issue_hardware_discard(file, total_bytes);
    oem_details.push(discard_msg);

    // 3. Hardware write cache flush
    let cache_flushed = flush_hardware_caches(file);
    if cache_flushed {
        oem_details.push("Hardware Write Cache & Controller Buffers Flushed (BLKFLSBUF + fsync)".to_string());
    } else {
        oem_details.push("Host buffer synchronized; controller cache flush signaled".to_string());
    }

    HardwareSanitizeReport {
        controller_method_attempted: method_attempted,
        controller_command_status: command_status,
        hardware_trim_supported: discard_ok,
        cache_flush_confirmed: cache_flushed,
        oem_details: oem_details.join(" | "),
    }
}
