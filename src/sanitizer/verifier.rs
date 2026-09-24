//! Read-Back Verification Engine for Media Sanitization Assurance.
//! Checks physical sectors post-wipe to confirm zero/pattern clearing,
//! computing cryptographic hashes and failure counts.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationReport {
    pub is_cleared: bool,
    pub verified_percentage: u32,
    pub total_sectors: u64,
    pub sampled_sectors: u64,
    pub failed_sectors: u64,
    pub post_wipe_hash: String,
    pub details: String,
}

/// Perform read-back verification on a sanitized block device or file
pub fn verify_storage(
    path: &Path,
    sample_percentage: u32,
    expected_byte: u8,
) -> Result<VerificationReport, String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open target for verification: {}", e))?;
    let total_bytes = file.metadata().map_err(|e| e.to_string())?.len();
    let sector_size = 512u64;
    let total_sectors = total_bytes / sector_size;

    if total_bytes == 0 {
        return Ok(VerificationReport {
            is_cleared: true,
            verified_percentage: 100,
            total_sectors: 0,
            sampled_sectors: 0,
            failed_sectors: 0,
            post_wipe_hash: hex::encode(Sha256::digest(b"EMPTY")),
            details: "Target has 0 length".to_string(),
        });
    }

    let sample_pct = sample_percentage.clamp(10, 100);
    let step = match sample_pct {
        100 => 1,
        50 => 2,
        25 => 4,
        _ => 10, // 10% sampling
    };

    let mut hasher = Sha256::new();
    let mut sampled_sectors = 0u64;
    let mut failed_sectors = 0u64;

    let chunk_sectors = 128u64; // Read in 64 KB chunks
    let chunk_bytes = (chunk_sectors * sector_size) as usize;
    let mut buffer = vec![0u8; chunk_bytes];

    let mut current_sector = 0u64;

    while current_sector < total_sectors {
        let sectors_to_read = chunk_sectors.min(total_sectors - current_sector);
        let bytes_to_read = (sectors_to_read * sector_size) as usize;

        file.seek(SeekFrom::Start(current_sector * sector_size))
            .map_err(|e| e.to_string())?;

        let bytes_read = file.read(&mut buffer[..bytes_to_read]).map_err(|e| e.to_string())?;
        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);

        for s in 0..sectors_to_read {
            if (current_sector + s) % step == 0 {
                sampled_sectors += 1;
                let offset = (s * sector_size) as usize;
                let sector_slice = &buffer[offset..offset + sector_size as usize];

                let all_match = sector_slice.iter().all(|&b| b == expected_byte);
                if !all_match {
                    failed_sectors += 1;
                }
            }
        }

        current_sector += sectors_to_read;
    }

    let post_wipe_hash = hex::encode(hasher.finalize());
    let is_cleared = failed_sectors == 0;
    let details = if is_cleared {
        format!(
            "Sanitization verified: 100% of sampled sectors ({} / {}) matched expected pattern (0x{:02X})",
            sampled_sectors, sampled_sectors, expected_byte
        )
    } else {
        format!(
            "Sanitization WARNING: Found {} uncleared sectors out of {} sampled!",
            failed_sectors, sampled_sectors
        )
    };

    Ok(VerificationReport {
        is_cleared,
        verified_percentage: sample_pct,
        total_sectors,
        sampled_sectors,
        failed_sectors,
        post_wipe_hash,
        details,
    })
}
