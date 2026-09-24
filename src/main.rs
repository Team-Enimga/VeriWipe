use veriwipe::blockchain::*;
use veriwipe::config::*;
use veriwipe::config;

use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(
    name = "veriwipe",
    author = "Team @Enigm@ <enigma.sih2026@veriwipe.local>",
    version = "1.0.0",
    about = "VeriWipe: Integrated Secure Data Erasure & Digital Forensics (SIH 2026 / NTRO)",
    long_about = "Enterprise & Defense Grade Secure Storage Sanitizer, Forensic Carving Engine, and One-Shot Bare-Metal Bootable Eraser with Tamper-Evident Blockchain Audit Ledger."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Securely sanitize a physical block device, partition, or file
    Wipe {
        /// Target device (e.g. /dev/sdb, /dev/nvme0n1) or image file
        #[arg(short, long)]
        target: String,

        /// Sanitization standard: NIST_800_88_CLEAR, NIST_800_88_PURGE, DOD_5220_22_M, ZERO_QUICK
        #[arg(short, long, default_value = "NIST_800_88_PURGE")]
        method: String,

        /// Read-back verification percentage: 10, 25, 50, 100
        #[arg(short, long, default_value_t = 100)]
        verify: u32,

        /// Operator identifier
        #[arg(short, long, default_value = "Forensic_Officer_1")]
        operator: String,

        /// Bypass safety confirmation prompt (CAUTION: Destructive!)
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Extract and validate deleted/unallocated files using structure-aware carving
    Carve {
        /// Path to raw disk image or block device
        #[arg(short, long)]
        source: String,

        /// Output directory for carved artifacts
        #[arg(short, long, default_value = "./carved_evidence")]
        output: String,

        /// Filter format: JPEG, PNG, PDF, ZIP_OFFICE, MP4, ALL
        #[arg(short, long, default_value = "ALL")]
        format: String,
    },

    /// Autonomous One-Shot Bare-Metal USB auto-wiper (safely wipes all non-boot media)
    Autonuke {
        /// Run in autonomous unattended mode with 15-second abort countdown
        #[arg(long, default_value_t = false)]
        autonomous: bool,

        /// Dry-run simulation mode (safely checks targets without writing)
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },

    /// List physical block devices with bus type, capacity, and boot-media exclusion status
    Devices {
        /// Include loopback and virtual test devices
        #[arg(long, default_value_t = true)]
        include_virtual: bool,
    },

    /// Synthetic Forensic Test Lab: generate safe raw disk images with secret artifacts for SIH judges
    Lab {
        #[command(subcommand)]
        action: LabAction,
    },

    /// Verify cryptographic integrity of the append-only blockchain audit chain
    Blockchain {
        /// Command: verify, dump, or export-cert
        #[arg(default_value = "verify")]
        action: String,
    },

    /// Launch embedded Axum web server and GUI dashboard
    Serve {
        /// Bind address
        #[arg(long, default_value = "0.0.0.0")]
        host: String,

        /// Port
        #[arg(long, default_value_t = 5000)]
        port: u16,
    },

    /// Launch bare-metal console TUI (curses interface for headless live USB boot)
    Tui,
}

#[derive(Subcommand)]
pub enum LabAction {
    /// Create a synthetic forensic test disk image (e.g. 50 MB) populated with test files
    Create {
        /// Size of disk image in megabytes
        #[arg(short, long, default_value_t = 50)]
        size_mb: u64,

        /// Output image name
        #[arg(short, long, default_value = "forensic_demo.img")]
        name: String,
    },
    /// List all generated synthetic lab images
    List,
    /// Clean up synthetic lab images
    Clean,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Serve { host, port }) => {
            println!("\n╔════════════════════════════════════════════════════════════════╗");
            println!("║  VERIWIPE: INTEGRATED SECURE DATA ERASURE & DIGITAL FORENSICS  ║");
            println!("║  SIH 2026 Problem Statement ID: 26149 (NTRO)                   ║");
            println!("║  Web GUI running at: http://{}:{}                     ║", host, port);
            println!("╚════════════════════════════════════════════════════════════════╝\n");
            veriwipe::web::start_server(Some(&host), Some(port)).await?;
        }
        Some(Commands::Devices { include_virtual }) => {
            let devices = veriwipe::devices::list_block_devices(include_virtual);
            println!("\n╔════════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
            println!("║                        VERIWIPE STORAGE DEVICE DISCOVERY & SAFETY ENUMERATION                              ║");
            println!("╠══════════╦════════════════╦═════════╦══════════════╦════════════════════════════════╦══════════╦═══════════════╣");
            println!("║ DEV NODE ║ BUS TYPE       ║ SIZE    ║ ROTATIONAL   ║ MODEL                          ║ STATUS   ║ PROTECTION    ║");
            println!("╠══════════╬════════════════╬═════════╬══════════════╬════════════════════════════════╬══════════╬═══════════════╣");
            for dev in &devices {
                let status = if dev.is_protected { "LOCKED 🔒" } else { "READY  ✅" };
                let prot_desc = if dev.is_protected {
                    dev.protection_reason.clone().unwrap_or_else(|| "System protected".to_string())
                } else {
                    "Safe Target".to_string()
                };
                let prot_short = if prot_desc.len() > 13 { &prot_desc[..13] } else { &prot_desc };
                let model_short = if dev.model.len() > 30 { &dev.model[..30] } else { &dev.model };
                let rota_str = if dev.is_rotational { "HDD (Rot)" } else { "SSD/Flash" };

                println!(
                    "║ {:<8} ║ {:<14} ║ {:>5.1} GB ║ {:<12} ║ {:<30} ║ {:<8} ║ {:<13} ║",
                    dev.name, dev.bus_type, dev.size_gb, rota_str, model_short, status, prot_short
                );
            }
            println!("╚══════════╩════════════════╩═════════╩══════════════╩════════════════════════════════╩══════════╩═══════════════╝\n");
        }
        Some(Commands::Wipe { target, method, verify, operator, force }) => {
            let wipe_method = match method.to_uppercase().as_str() {
                "NIST_800_88_CLEAR" => WipeMethod::Nist800_88Clear,
                "NIST_800_88_PURGE" => WipeMethod::Nist800_88Purge,
                "DOD_5220_22_M" => WipeMethod::Dod5220_22M,
                "ZERO_QUICK" => WipeMethod::ZeroQuick,
                _ => {
                    eprintln!("Unknown wipe method: {}. Defaulting to NIST_800_88_PURGE", method);
                    WipeMethod::Nist800_88Purge
                }
            };

            let target_path = std::path::Path::new(&target);
            if !target_path.exists() {
                eprintln!("❌ Target does not exist: {}", target);
                return Ok(());
            }

            println!("\n╔════════════════════════════════════════════════════════════════╗");
            println!("║          VERIWIPE CERTIFIED MEDIA SANITIZATION ENGINE          ║");
            println!("╠════════════════════════════════════════════════════════════════╣");
            println!("║ Target Device/Image   : {:<38} ║", target);
            println!("║ Standard Applied      : {:<38} ║", wipe_method.display_name());
            println!("║ Execution Passes      : {:<38} ║", wipe_method.pass_count());
            println!("║ Verification Scope    : {:<38} ║", format!("{}% Sector Sampling", verify));
            println!("║ Certified Operator    : {:<38} ║", operator);
            println!("╚════════════════════════════════════════════════════════════════╝\n");

            if !force {
                print!("⚠️  Type 'YES' to confirm irreversible data destruction: ");
                use std::io::{stdin, stdout, Write};
                stdout().flush()?;
                let mut input = String::new();
                stdin().read_line(&mut input)?;
                if input.trim() != "YES" {
                    println!("Sanitization cancelled by operator.");
                    return Ok(());
                }
            }

            if target_path.is_dir() {
                println!("Sanitizing directory contents recursively with DoD 3-pass shredder...");
                match veriwipe::sanitizer::shred_path(&target, &operator) {
                    Ok(res) => {
                        println!("✅ Shredded {} files ({} bytes)", res.files_shredded, res.bytes_overwritten);
                        println!("Blockchain Block Hash: {}", res.blockchain_block_hash);
                    }
                    Err(e) => eprintln!("❌ Shred error: {}", e),
                }
            } else {
                let progress_cb = Box::new(|pass, total_passes, written, total, throughput| {
                    let pct = (written as f64 / total as f64) * 100.0;
                    print!(
                        "\r[Pass {}/{}] Progress: {:>5.1}% ({}/{} MB) @ {:>6.1} MB/s",
                        pass, total_passes, pct, written / (1024 * 1024), total / (1024 * 1024), throughput
                    );
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                });

                match veriwipe::sanitizer::execute_wipe(
                    &target,
                    wipe_method,
                    verify,
                    &operator,
                    "National Technical Research Organisation (NTRO)",
                    Some(progress_cb),
                ) {
                    Ok(res) => {
                        println!("\n\n╔════════════════════════════════════════════════════════════════════════════════════════╗");
                        println!("║               SANITIZATION COMPLETED & CERTIFIED ON BLOCKCHAIN ✅                      ║");
                        println!("╠════════════════════════════════════════════════════════════════════════════════════════╣");
                        println!("║ Target Media          : {:<62} ║", res.target);
                        println!("║ Capacity Sanitized    : {:>8.2} MB ({:<10} B)                                ║", (res.total_bytes as f64) / (1024.0 * 1024.0), res.total_bytes);
                        println!("║ Duration & Speed      : {:>5.2}s @ {:>6.2} MB/s                                          ║", res.duration_seconds, res.throughput_mbps);
                        println!("║ Read-Back Verification: {:<62} ║", res.verification.details);
                        println!("║ Post-Wipe Sector Hash : {}... ║", &res.verification.post_wipe_hash[..32]);
                        println!("║ Blockchain Block Hash : {}... ║", &res.blockchain_block_hash[..32]);
                        println!("║ Certificate (JSON)    : {:<62} ║", res.certificate_json_path);
                        println!("║ Certificate (HTML)    : {:<62} ║", res.certificate_html_path);
                        println!("╚════════════════════════════════════════════════════════════════════════════════════════╝\n");
                    }
                    Err(e) => eprintln!("\n❌ Sanitization Error: {}", e),
                }
            }
        }
        Some(Commands::Carve { source, output, format }) => {
            println!("\n╔════════════════════════════════════════════════════════════════╗");
            println!("║          VERIWIPE ADVANCED FORENSIC FILE CARVER                ║");
            println!("╠════════════════════════════════════════════════════════════════╣");
            println!("║ Source Media          : {:<38} ║", source);
            println!("║ Output Directory      : {:<38} ║", output);
            println!("║ Format Filter         : {:<38} ║", format);
            println!("║ Pipeline Stages       : Magic Bytes -> Structure Parser -> Provenance║");
            println!("╚════════════════════════════════════════════════════════════════╝\n");

            let source_path = std::path::Path::new(&source);
            let output_path = std::path::Path::new(&output);

            let progress_cb = Box::new(|scanned, total, count| {
                let pct = (scanned as f64 / total as f64) * 100.0;
                print!(
                    "\r[Carving] Scanned: {:>5.1}% ({}/{} MB) | Artifacts Found: {}",
                    pct, scanned / (1024 * 1024), total / (1024 * 1024), count
                );
                use std::io::Write;
                let _ = std::io::stdout().flush();
            });

            match veriwipe::recovery::carve_media(source_path, output_path, &format, true, Some(progress_cb)) {
                Ok(res) => {
                    println!("\n\n╔════════════════════════════════════════════════════════════════════════════════════════╗");
                    println!("║             FORENSIC CARVING COMPLETED & EVIDENCE ANCHORED ON CHAIN ✅                 ║");
                    println!("╠════════════════════════════════════════════════════════════════════════════════════════╣");
                    println!("║ Case Identifier       : {:<62} ║", res.provenance.case_id);
                    println!("║ Total Artifacts Carved: {:<62} ║", res.provenance.total_artifacts_recovered);
                    println!("║ Source Hash (SHA-256) : {}... ║", &res.provenance.source_sha256_before[..32]);
                    println!("║ Read-Only Preservation: {:<62} ║", if res.source_integrity_preserved { "VERIFIED INTACT (Hashes Match)" } else { "INTEGRITY WARNING" });
                    println!("║ Blockchain Block Hash : {}... ║", &res.blockchain_block_hash[..32]);
                    println!("║ Provenance Graph JSON : {:<62} ║", res.provenance_manifest_path);
                    println!("╚════════════════════════════════════════════════════════════════════════════════════════╝\n");

                    println!("Extracted Artifacts & Provenance Offsets:");
                    for (i, art) in res.provenance.artifacts.iter().enumerate() {
                        println!(
                            "  [{}] {:<28} | Confidence: {:>3}% | Offset: 0x{:08X} ({:>7} B) | Status: {}",
                            i + 1, art.filename, art.confidence_score, art.start_offset, art.length_bytes, art.structural_status
                        );
                    }
                    println!();
                }
                Err(e) => eprintln!("\n❌ Carving Error: {}", e),
            }
        }
        Some(Commands::Autonuke { autonomous, dry_run }) => {
            veriwipe::autonomous::run_autonuke(autonomous, dry_run, 15)
                .map_err(|e| Box::<dyn std::error::Error>::from(e))?;
        }
        Some(Commands::Tui) => {
            veriwipe::autonomous::run_tui()?;
        }
        Some(Commands::Lab { action }) => {
            let paths = RuntimePaths::get();
            match action {
                LabAction::Create { size_mb, name } => {
                    println!("🔧 Generating Synthetic Forensic Test Drive ({} MB)...", size_mb);
                    match veriwipe::devices::create_synthetic_disk(&paths.lab_dir, &name, size_mb) {
                        Ok(manifest) => {
                            println!("✅ Virtual Forensic Test Disk created at: {}", manifest.image_path);
                            println!("Size: {} MB ({} bytes)", manifest.size_mb, manifest.size_bytes);
                            println!("\nInjected Ground Truth Artifacts for SIH Judging Validation:");
                            for (i, art) in manifest.artifacts.iter().enumerate() {
                                println!(
                                    "  [{}] {:<22} | Format: {:<10} | Offset: 0x{:08X} ({:<7} B) | SHA256: {}...",
                                    i + 1, art.name, art.format, art.offset_bytes, art.length_bytes, &art.sha256_hash[..16]
                                );
                            }
                            println!("\n💡 You can now carve or wipe this image without touching any physical drives:");
                            println!("   veriwipe carve --source {}", manifest.image_path);
                            println!("   veriwipe wipe --target {} --method NIST_800_88_PURGE\n", manifest.image_path);
                        }
                        Err(e) => eprintln!("❌ Failed to create synthetic test drive: {}", e),
                    }
                }
                LabAction::List => {
                    let disks = veriwipe::devices::list_synthetic_disks(&paths.lab_dir);
                    if disks.is_empty() {
                        println!("No synthetic forensic disks found in {}. Run `veriwipe lab create` to generate one.", paths.lab_dir.display());
                    } else {
                        println!("Found {} synthetic forensic test drives:", disks.len());
                        for d in disks {
                            println!(" • {} ({} MB) - {} artifacts", d.image_path, d.size_mb, d.artifacts.len());
                        }
                    }
                }
                LabAction::Clean => match veriwipe::devices::cleanup_synthetic_disks(&paths.lab_dir) {
                    Ok(count) => println!("🧹 Cleaned up {} synthetic forensic test files.", count),
                    Err(e) => eprintln!("❌ Clean error: {}", e),
                },
            }
        }
        Some(Commands::Blockchain { action }) => {
            let paths = RuntimePaths::get();
            let authority = KeyAuthority::load_or_generate(&paths.authority_privkey, &paths.authority_pubkey)
                .map_err(|e| Box::<dyn std::error::Error>::from(e))?;
            let ledger = BlockchainLedger::load_or_create(&paths.ledger_file, &authority)
                .map_err(|e| Box::<dyn std::error::Error>::from(e))?;

            if action == "verify" {
                let res = ledger.verify_chain();
                if res.is_valid {
                    println!("╔════════════════════════════════════════════════════════════════╗");
                    println!("║  VERIWIPE BLOCKCHAIN AUDIT LEDGER: CRYPTOGRAPHICALLY VALID ✅  ║");
                    println!("╠════════════════════════════════════════════════════════════════╣");
                    println!("║ Total Blocks Verified : {:<38} ║", res.total_blocks);
                    println!("║ Signature Algorithm   : Ed25519 (RFC 8032)                     ║");
                    println!("║ Hash Specification    : SHA-256 (FIPS 180-4)                   ║");
                    println!("║ Authority Public Key  : {}... ║", &authority.public_key_hex()[..24]);
                    println!("╚════════════════════════════════════════════════════════════════╝");
                } else {
                    println!("❌ BLOCKCHAIN AUDIT CHAIN TAMPERED OR INVALID!");
                    println!("Discrepancy Details: {:?}", res.error_message);
                    println!("Invalid Block Index: {:?}", res.invalid_block_index);
                }
            } else if action == "dump" || action == "show" {
                println!("{}", serde_json::to_string_pretty(&ledger.blocks)?);
            } else {
                println!("Unknown blockchain action: {}. Supported: verify, show", action);
            }
        }
        None => {
            println!("VeriWipe v{} - {}", config::PRODUCT_VERSION, config::PROBLEM_STATEMENT);
            println!("Use `veriwipe --help` for available commands.");
        }
    }

    Ok(())
}
