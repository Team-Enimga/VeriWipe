//! VeriWipe Configuration & Policy Definitions
//! Authoritative settings for NIST SP 800-88 Rev 1, DoD 5220.22-M, and Blockchain Ledger.

use std::path::PathBuf;

pub const PRODUCT_NAME: &str = "VeriWipe";
pub const PRODUCT_VERSION: &str = "1.0.0";
pub const TEAM_NAME: &str = "@Enigm@ (Team ID 132834)";
pub const PROBLEM_STATEMENT: &str = "SIH 2026 PS 26149 (NTRO) - Secure Erasure & Digital Forensics";

pub const DEFAULT_HOST: &str = "0.0.0.0";
pub const DEFAULT_PORT: u16 = 5000;

pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MB chunk size for high-speed I/O
pub const VERIFY_CHUNK_SIZE: usize = 2 * 1024 * 1024;  // 2 MB chunk size for verification sampling

/// Paths used by the VeriWipe runtime
pub struct RuntimePaths {
    pub base_dir: PathBuf,
    pub records_dir: PathBuf,
    pub ledger_file: PathBuf,
    pub keys_dir: PathBuf,
    pub authority_privkey: PathBuf,
    pub authority_pubkey: PathBuf,
    pub lab_dir: PathBuf,
}

impl RuntimePaths {
    pub fn get() -> Self {
        let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let records_dir = base_dir.join("veriwipe_records");
        let ledger_file = records_dir.join("audit_chain.json");
        let keys_dir = records_dir.join("keys");
        let authority_privkey = keys_dir.join("authority_ed25519.pk8");
        let authority_pubkey = keys_dir.join("authority_ed25519.pub");
        let lab_dir = base_dir.join("test_artifacts");

        // Ensure directories exist
        let _ = std::fs::create_dir_all(&records_dir);
        let _ = std::fs::create_dir_all(&keys_dir);
        let _ = std::fs::create_dir_all(&lab_dir);

        Self {
            base_dir,
            records_dir,
            ledger_file,
            keys_dir,
            authority_privkey,
            authority_pubkey,
            lab_dir,
        }
    }
}

/// Supported Sanitization Standards
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WipeMethod {
    #[serde(rename = "NIST_800_88_CLEAR")]
    Nist800_88Clear,
    #[serde(rename = "NIST_800_88_PURGE")]
    Nist800_88Purge,
    #[serde(rename = "DOD_5220_22_M")]
    Dod5220_22M,
    #[serde(rename = "ZERO_QUICK")]
    ZeroQuick,
}

impl WipeMethod {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Nist800_88Clear => "NIST SP 800-88 Rev 1 (Clear)",
            Self::Nist800_88Purge => "NIST SP 800-88 Rev 1 (Purge - Cryptographic/Random + Zero)",
            Self::Dod5220_22M => "DoD 5220.22-M NISPOM (3-Pass Zero/One/Random)",
            Self::ZeroQuick => "Quick Baseline Zero Overwrite",
        }
    }

    pub fn pass_count(&self) -> u32 {
        match self {
            Self::Nist800_88Clear => 1,
            Self::Nist800_88Purge => 2,
            Self::Dod5220_22M => 3,
            Self::ZeroQuick => 1,
        }
    }

    pub fn compliance_ref(&self) -> &'static str {
        match self {
            Self::Nist800_88Clear => "NIST SP 800-88 Rev 1 Sec 2.4",
            Self::Nist800_88Purge => "NIST SP 800-88 Rev 1 Sec 2.5",
            Self::Dod5220_22M => "DoD 5220.22-M NISPOM",
            Self::ZeroQuick => "Baseline Sanitization",
        }
    }
}
