//! Tamper-Evident Hash-Chained Blockchain Event Ledger.
//! Implements an append-only cryptographic event log where every entry
//! seals the previous block hash and is signed with an Ed25519 key.

use super::crypto::{compute_merkle_root, sha256_digest, KeyAuthority};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditBlock {
    pub index: u64,
    pub timestamp: String,
    pub event_type: String,
    pub target_id: String,
    pub operator: String,
    pub payload: serde_json::Value,
    pub previous_hash: String,
    pub merkle_root: String,
    pub block_hash: String,
    pub signature: String,
    pub authority_pubkey: String,
}

impl AuditBlock {
    /// Compute the block hash from all fields except block_hash and signature
    pub fn compute_hash(
        index: u64,
        timestamp: &str,
        event_type: &str,
        target_id: &str,
        operator: &str,
        payload: &serde_json::Value,
        previous_hash: &str,
        merkle_root: &str,
    ) -> String {
        let payload_str = serde_json::to_string(payload).unwrap_or_default();
        let raw = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            index, timestamp, event_type, target_id, operator, payload_str, previous_hash, merkle_root
        );
        sha256_digest(raw.as_bytes())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerificationResult {
    pub is_valid: bool,
    pub total_blocks: usize,
    pub verified_blocks: usize,
    pub error_message: Option<String>,
    pub invalid_block_index: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainLedger {
    pub blocks: Vec<AuditBlock>,
}

impl BlockchainLedger {
    /// Load existing ledger from file or initialize with Genesis block
    pub fn load_or_create(path: &Path, authority: &KeyAuthority) -> Result<Self, String> {
        if path.exists() {
            let data = fs::read_to_string(path).map_err(|e| e.to_string())?;
            if let Ok(ledger) = serde_json::from_str::<BlockchainLedger>(&data) {
                if !ledger.blocks.is_empty() {
                    return Ok(ledger);
                }
            }
        }

        // Initialize with Genesis Block
        let timestamp = Utc::now().to_rfc3339();
        let payload = serde_json::json!({
            "message": "VeriWipe Cryptographic Ledger Genesis Block",
            "version": "1.0.0",
            "standard": "NIST SP 800-88 Rev 1 & ISO/IEC 27037",
            "organization": "National Technical Research Organisation (NTRO)",
            "team": "@Enigm@"
        });
        let previous_hash = "0".repeat(64);
        let merkle_root = compute_merkle_root(&[sha256_digest(b"GENESIS_SEED")]);
        let block_hash = AuditBlock::compute_hash(
            0,
            &timestamp,
            "GENESIS",
            "SYSTEM",
            "ROOT_AUTHORITY",
            &payload,
            &previous_hash,
            &merkle_root,
        );
        let signature = authority.sign_hex(block_hash.as_bytes());

        let genesis_block = AuditBlock {
            index: 0,
            timestamp,
            event_type: "GENESIS".to_string(),
            target_id: "SYSTEM".to_string(),
            operator: "ROOT_AUTHORITY".to_string(),
            payload,
            previous_hash,
            merkle_root,
            block_hash,
            signature,
            authority_pubkey: authority.public_key_hex(),
        };

        let ledger = Self {
            blocks: vec![genesis_block],
        };
        ledger.save_to_file(path)?;
        Ok(ledger)
    }

    /// Record a new tamper-evident event into the blockchain
    pub fn record_event(
        &mut self,
        event_type: &str,
        target_id: &str,
        operator: &str,
        payload: serde_json::Value,
        authority: &KeyAuthority,
        save_path: Option<&Path>,
    ) -> Result<AuditBlock, String> {
        let last_block = self
            .blocks
            .last()
            .ok_or_else(|| "Corrupted ledger: missing genesis block".to_string())?;

        let index = last_block.index + 1;
        let timestamp = Utc::now().to_rfc3339();
        let previous_hash = last_block.block_hash.clone();

        // Calculate transaction merkle root
        let payload_hash = sha256_digest(serde_json::to_string(&payload).unwrap_or_default().as_bytes());
        let merkle_root = compute_merkle_root(&[previous_hash.clone(), payload_hash]);

        let block_hash = AuditBlock::compute_hash(
            index,
            &timestamp,
            event_type,
            target_id,
            operator,
            &payload,
            &previous_hash,
            &merkle_root,
        );

        let signature = authority.sign_hex(block_hash.as_bytes());

        let new_block = AuditBlock {
            index,
            timestamp,
            event_type: event_type.to_string(),
            target_id: target_id.to_string(),
            operator: operator.to_string(),
            payload,
            previous_hash,
            merkle_root,
            block_hash,
            signature,
            authority_pubkey: authority.public_key_hex(),
        };

        self.blocks.push(new_block.clone());

        if let Some(path) = save_path {
            self.save_to_file(path)?;
        }

        Ok(new_block)
    }

    /// Save ledger to JSON file
    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, json).map_err(|e| e.to_string())
    }

    /// Verify the integrity of the entire blockchain
    pub fn verify_chain(&self) -> ChainVerificationResult {
        if self.blocks.is_empty() {
            return ChainVerificationResult {
                is_valid: false,
                total_blocks: 0,
                verified_blocks: 0,
                error_message: Some("Blockchain is empty".to_string()),
                invalid_block_index: None,
            };
        }

        let mut verified = 0;

        for (i, block) in self.blocks.iter().enumerate() {
            // Check index
            if block.index != i as u64 {
                return ChainVerificationResult {
                    is_valid: false,
                    total_blocks: self.blocks.len(),
                    verified_blocks: verified,
                    error_message: Some(format!(
                        "Block index mismatch at position {}: expected {}, found {}",
                        i, i, block.index
                    )),
                    invalid_block_index: Some(block.index),
                };
            }

            // Check previous hash link
            if i > 0 {
                let prev_block = &self.blocks[i - 1];
                if block.previous_hash != prev_block.block_hash {
                    return ChainVerificationResult {
                        is_valid: false,
                        total_blocks: self.blocks.len(),
                        verified_blocks: verified,
                        error_message: Some(format!(
                            "Previous hash link broken at block {}: parent {} does not match stored {}",
                            block.index, prev_block.block_hash, block.previous_hash
                        )),
                        invalid_block_index: Some(block.index),
                    };
                }
            } else if block.previous_hash != "0".repeat(64) {
                return ChainVerificationResult {
                    is_valid: false,
                    total_blocks: self.blocks.len(),
                    verified_blocks: verified,
                    error_message: Some("Genesis block has invalid previous_hash".to_string()),
                    invalid_block_index: Some(0),
                };
            }

            // Recompute and verify block hash
            let computed_hash = AuditBlock::compute_hash(
                block.index,
                &block.timestamp,
                &block.event_type,
                &block.target_id,
                &block.operator,
                &block.payload,
                &block.previous_hash,
                &block.merkle_root,
            );

            if computed_hash != block.block_hash {
                return ChainVerificationResult {
                    is_valid: false,
                    total_blocks: self.blocks.len(),
                    verified_blocks: verified,
                    error_message: Some(format!(
                        "Hash recalculation mismatch at block {}: stored {}, computed {}",
                        block.index, block.block_hash, computed_hash
                    )),
                    invalid_block_index: Some(block.index),
                };
            }

            // Verify Ed25519 digital signature
            let sig_valid = KeyAuthority::verify_signature_hex(
                &block.authority_pubkey,
                block.block_hash.as_bytes(),
                &block.signature,
            )
            .unwrap_or(false);

            if !sig_valid {
                return ChainVerificationResult {
                    is_valid: false,
                    total_blocks: self.blocks.len(),
                    verified_blocks: verified,
                    error_message: Some(format!(
                        "Cryptographic signature check failed on block {}",
                        block.index
                    )),
                    invalid_block_index: Some(block.index),
                };
            }

            verified += 1;
        }

        ChainVerificationResult {
            is_valid: true,
            total_blocks: self.blocks.len(),
            verified_blocks: verified,
            error_message: None,
            invalid_block_index: None,
        }
    }
}
