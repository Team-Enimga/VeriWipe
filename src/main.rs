//! VeriWipe - Integrated Secure Data Erasure & Advanced Forensic Recovery Platform
//! SIH 2026 Problem Statement ID: 26149 (NTRO)

pub mod config;

use clap::{Parser, Subcommand};
use tracing::{info, Level};
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
            info!("Starting VeriWipe Embedded Web Server on http://{}:{}...", host, port);
            println!("\n╔════════════════════════════════════════════════════════════════╗");
            println!("║  VERIWIPE: INTEGRATED SECURE DATA ERASURE & DIGITAL FORENSICS  ║");
            println!("║  SIH 2026 Problem Statement ID: 26149 (NTRO)                   ║");
            println!("║  Web GUI running at: http://{}:{}                     ║", host, port);
            println!("╚════════════════════════════════════════════════════════════════╝\n");
        }
        Some(Commands::Devices { .. }) => {
            info!("Enumerating storage devices...");
        }
        Some(Commands::Wipe { target, method, .. }) => {
            info!("Preparing wipe for target: {} with method: {}", target, method);
        }
        Some(Commands::Carve { source, output, .. }) => {
            info!("Starting forensic file carving on {} -> {}", source, output);
        }
        Some(Commands::Autonuke { autonomous, dry_run }) => {
            info!("VeriWipe Autonuke initialized (autonomous={}, dry_run={})", autonomous, dry_run);
        }
        Some(Commands::Lab { action }) => match action {
            LabAction::Create { size_mb, name } => {
                info!("Creating {}MB test drive: {}", size_mb, name);
            }
            LabAction::List => {
                info!("Listing virtual lab images...");
            }
            LabAction::Clean => {
                info!("Cleaning virtual lab images...");
            }
        },
        Some(Commands::Blockchain { action }) => {
            info!("Blockchain action: {}", action);
        }
        Some(Commands::Tui) => {
            info!("Launching VeriWipe Bare-Metal TUI...");
        }
        None => {
            println!("VeriWipe v{} - {}", config::PRODUCT_VERSION, config::PROBLEM_STATEMENT);
            println!("Use `veriwipe --help` for available commands.");
        }
    }

    Ok(())
}
