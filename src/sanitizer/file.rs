//! Targeted File and Folder Secure Shredder.
//! Multi-pass file content overwriting, length truncation, directory metadata scrambling,
//! and unlinking with audit trail anchoring.

use crate::blockchain::{BlockchainLedger, KeyAuthority};
use crate::config::RuntimePaths;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileShredResult {
    pub target_path: String,
    pub files_shredded: usize,
    pub bytes_overwritten: u64,
    pub blockchain_block_hash: String,
}

/// Shred an individual file with multi-pass overwrite and metadata scrambling
pub fn shred_file(path: &Path) -> Result<u64, String> {
    if !path.exists() {
        return Err(format!("File does not exist: {}", path.display()));
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("Cannot open file for shredding: {}", e))?;

    let file_len = file.metadata().map_err(|e| e.to_string())?.len();
    if file_len > 0 {
        let mut rng = OsRng;
        let chunk_size = 65536.min(file_len as usize);
        let mut buf = vec![0u8; chunk_size];

        // Pass 1: Zero fill
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        buf.fill(0x00);
        let mut written = 0u64;
        while written < file_len {
            let to_write = (chunk_size as u64).min(file_len - written) as usize;
            file.write_all(&buf[..to_write]).map_err(|e| e.to_string())?;
            written += to_write as u64;
        }
        file.sync_all().map_err(|e| e.to_string())?;

        // Pass 2: One fill (0xFF)
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        buf.fill(0xFF);
        written = 0;
        while written < file_len {
            let to_write = (chunk_size as u64).min(file_len - written) as usize;
            file.write_all(&buf[..to_write]).map_err(|e| e.to_string())?;
            written += to_write as u64;
        }
        file.sync_all().map_err(|e| e.to_string())?;

        // Pass 3: CSPRNG Random noise
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        written = 0;
        while written < file_len {
            let to_write = (chunk_size as u64).min(file_len - written) as usize;
            rng.fill_bytes(&mut buf[..to_write]);
            file.write_all(&buf[..to_write]).map_err(|e| e.to_string())?;
            written += to_write as u64;
        }
        file.sync_all().map_err(|e| e.to_string())?;

        // Truncate file length to 0
        file.set_len(0).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
    }
    drop(file);

    // Scramble file name in directory table before unlinking
    let scrambled_name = format!("shred_{:016X}", rand::random::<u64>());
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let scrambled_path = parent.join(scrambled_name);

    let _ = fs::rename(path, &scrambled_path);
    let target_to_remove = if scrambled_path.exists() {
        &scrambled_path
    } else {
        path
    };

    fs::remove_file(target_to_remove).map_err(|e| format!("Failed to unlink file: {}", e))?;

    Ok(file_len)
}

/// Securely shred a file or an entire directory tree
pub fn shred_path(
    target_path: &str,
    operator: &str,
) -> Result<FileShredResult, String> {
    let path = Path::new(target_path);
    if !path.exists() {
        return Err(format!("Target does not exist: {}", target_path));
    }

    let mut files_to_shred = Vec::new();
    if path.is_file() {
        files_to_shred.push(path.to_path_buf());
    } else {
        for entry in WalkDir::new(path).into_iter().flatten() {
            if entry.path().is_file() {
                files_to_shred.push(entry.path().to_path_buf());
            }
        }
    }

    let mut total_bytes = 0u64;
    let mut shredded_count = 0usize;

    for file_path in &files_to_shred {
        match shred_file(file_path) {
            Ok(bytes) => {
                total_bytes += bytes;
                shredded_count += 1;
            }
            Err(e) => eprintln!("Warning: could not shred {}: {}", file_path.display(), e),
        }
    }

    // Clean up empty directories if it was a folder
    if path.is_dir() {
        let _ = fs::remove_dir_all(path);
    }

    // Record to Blockchain Ledger
    let paths = RuntimePaths::get();
    let authority = KeyAuthority::load_or_generate(&paths.authority_privkey, &paths.authority_pubkey)
        .map_err(|e| e.to_string())?;
    let mut ledger = BlockchainLedger::load_or_create(&paths.ledger_file, &authority)
        .map_err(|e| e.to_string())?;

    let payload = serde_json::json!({
        "action": "TARGETED_FILE_SHRED",
        "target": target_path,
        "files_shredded": shredded_count,
        "bytes_overwritten": total_bytes,
        "standard": "DoD 5220.22-M 3-Pass Overwrite + Truncate + Unlink"
    });

    let block = ledger.record_event(
        "FILE_SHRED_COMPLETED",
        target_path,
        operator,
        payload,
        &authority,
        Some(&paths.ledger_file),
    )?;

    Ok(FileShredResult {
        target_path: target_path.to_string(),
        files_shredded: shredded_count,
        bytes_overwritten: total_bytes,
        blockchain_block_hash: block.block_hash,
    })
}
