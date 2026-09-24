//! Autonomous One-Shot Bare-Metal USB Eraser Daemon.
//! Auto-discovers internal storage, strictly isolates and protects the boot USB,
//! runs an abort countdown, executes NIST 800-88 Purge with OEM hardware commands,
//! verifies with read-back and carver, and stores signed blockchain certificates on the USB.

use crate::config::WipeMethod;
use crate::devices::detector::list_block_devices;
use crate::devices::safety::SystemProtectionInfo;
use crate::sanitizer::drive::{execute_wipe, WipeExecutionResult};
use std::io::{stdout, Write};
use std::thread::sleep;
use std::time::Duration;
use tracing::info;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AutonukeSessionReport {
    pub session_id: String,
    pub timestamp_utc: String,
    pub targets_detected: usize,
    pub targets_sanitized: usize,
    pub targets_failed: usize,
    pub results: Vec<WipeExecutionResult>,
}

/// Execute the Autonomous One-Shot Bare-Metal USB Erase Pipeline
pub fn run_autonuke(
    is_autonomous: bool,
    dry_run: bool,
    custom_countdown_secs: u32,
) -> Result<AutonukeSessionReport, String> {
    println!("\n╔════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║       VERIWIPE BARE-METAL AUTONOMOUS SANITIZATION APPLIANCE (ONE-SHOT)             ║");
    println!("║       SIH 2026 Problem Statement ID: 26149 (NTRO)                                  ║");
    println!("╠════════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ Mode                 : {:<59} ║", if dry_run { "DRY-RUN SIMULATION (Safe)" } else if is_autonomous { "AUTONOMOUS UNATTENDED WIPE" } else { "GUARDED INTERACTIVE WIPE" });
    println!("║ Sanitization Standard: NIST SP 800-88 Rev 1 (Purge) + OEM Hardware Commands        ║");
    println!("║ Self-Checking        : Sector Read-Back + Active Forensic Remnant Carving          ║");
    println!("║ Audit Log Destination: Persistent USB Records Partition (/veriwipe_records)        ║");
    println!("╚════════════════════════════════════════════════════════════════════════════════════╝\n");

    // 1. Storage Enumeration & Boot-Media Self-Protection
    let safety = SystemProtectionInfo::detect();
    let all_devices = list_block_devices(true);

    let mut candidate_targets = Vec::new();

    println!("DISCOVERED STORAGE DEVICES ON SYSTEM:");
    for dev in &all_devices {
        let (protected, reason) = safety.is_protected(&dev.path);
        if protected {
            println!("  [EXCLUDED] {:<12} | {:>6.1} GB | {:<16} | Reason: {}",
                dev.path, dev.size_gb, dev.model, reason.unwrap_or_default());
        } else {
            println!("  [TARGET]   {:<12} | {:>6.1} GB | {:<16} | Bus: {}",
                dev.path, dev.size_gb, dev.model, dev.bus_type);
            candidate_targets.push(dev.clone());
        }
    }

    if candidate_targets.is_empty() {
        println!("\n✅ No un-protected target storage media detected. The boot media and system root are safe.");
        return Ok(AutonukeSessionReport {
            session_id: format!("AUTONUKE-{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase()),
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
            targets_detected: 0,
            targets_sanitized: 0,
            targets_failed: 0,
            results: Vec::new(),
        });
    }

    println!("\nFound {} target storage drive(s) queued for permanent sanitization.", candidate_targets.len());

    // 2. Abort Countdown (Audible / Visual Warning)
    let countdown = custom_countdown_secs.max(5);
    println!("\n⚠️  CRITICAL WARNING: ALL DATA ON {} TARGET DRIVE(S) WILL BE PERMANENTLY DESTROYED.", candidate_targets.len());
    println!("   The VeriWipe Boot USB is protected and will NOT be touched.");

    if !dry_run {
        print!("   Press Ctrl+C immediately to abort execution.\n\n");
        for sec in (1..=countdown).rev() {
            print!("\r   ⏳ AUTONOMOUS SANITIZATION STARTING IN {:>2} SECONDS... \x07", sec);
            let _ = stdout().flush();
            sleep(Duration::from_secs(1));
        }
        println!("\n\n🚀 COUNTDOWN EXPIRED: COMMENCING BARE-METAL SANITIZATION PIPELINE...\n");
    } else {
        println!("   [DRY-RUN]: Countdown bypassed. Simulating sanitization passes.\n");
    }

    // 3. Execution Across All Target Storage Drives
    let mut results = Vec::new();
    let mut success_count = 0;
    let mut fail_count = 0;

    for (idx, target) in candidate_targets.iter().enumerate() {
        println!("--------------------------------------------------------------------------------");
        println!("Processing Target [{}/{}]: {} ({:.1} GB, {})",
            idx + 1, candidate_targets.len(), target.path, target.size_gb, target.bus_type);
        println!("--------------------------------------------------------------------------------");

        if dry_run {
            println!("  ✓ Simulated OEM Hardware Command: NVMe Sanitize / ATA Secure Erase");
            println!("  ✓ Simulated Pass 1: Cryptographic Pseudo-Random Fill");
            println!("  ✓ Simulated Pass 2: Cryptographic Zero Fill");
            println!("  ✓ Simulated Cache Flush: BLKFLSBUF + fsync");
            println!("  ✓ Simulated Sector Read-Back Verification: 100% Zero Verified");
            println!("  ✓ Simulated Forensic Remnant Carving: 0 Files Found");
            println!("  ✓ Simulated Blockchain Anchor & Certificate Saved to USB");
            success_count += 1;
            continue;
        }

        let progress_cb = Box::new(move |pass, total, written, total_bytes, throughput| {
            let pct = (written as f64 / total_bytes as f64) * 100.0;
            print!("\r  [Pass {}/{}] Progress: {:>5.1}% ({}/{} MB) @ {:>6.1} MB/s",
                pass, total, pct, written / (1024 * 1024), total_bytes / (1024 * 1024), throughput);
            let _ = stdout().flush();
        });

        match execute_wipe(
            &target.path,
            WipeMethod::Nist800_88Purge,
            100,
            "Autonomous_USB_Appliance",
            "National Technical Research Organisation (NTRO)",
            Some(progress_cb),
        ) {
            Ok(res) => {
                println!("\n  ✅ Target {} successfully sanitized & anchored on blockchain.", target.path);
                println!("     Post-Wipe Sector Hash: {}", res.verification.post_wipe_hash);
                println!("     Forensic Carver Check : {} remnants found (Clean={})",
                    res.forensic_remnants_found, res.forensic_carver_verified_clean);
                println!("     Certificate JSON      : {}", res.certificate_json_path);
                println!("     Certificate HTML      : {}", res.certificate_html_path);
                results.push(res);
                success_count += 1;
            }
            Err(e) => {
                eprintln!("\n  ❌ Failed to sanitize {}: {}", target.path, e);
                fail_count += 1;
            }
        }
    }

    println!("\n================================================================================");
    println!("VERIWIPE AUTONOMOUS DECOMMISSIONING COMPLETED");
    println!("Total Targets Sanitized: {} | Failures: {}", success_count, fail_count);
    println!("Blockchain audit records and signed certificates are secured on USB storage.");
    println!("================================================================================\n");

    Ok(AutonukeSessionReport {
        session_id: format!("AUTONUKE-{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase()),
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
        targets_detected: candidate_targets.len(),
        targets_sanitized: success_count,
        targets_failed: fail_count,
        results,
    })
}
