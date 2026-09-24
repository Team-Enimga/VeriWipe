//! Evidence Provenance Graph & Forensic Chain of Custody.
//! Maps each carved artifact back to exact source byte offsets, source disk hashes,
//! structural validation checks, and integrity confidence scores.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedArtifact {
    pub id: String,
    pub format: String,
    pub filename: String,
    pub start_offset: u64,
    pub end_offset: u64,
    pub length_bytes: usize,
    pub sha256_hash: String,
    pub confidence_score: u32,
    pub structural_status: String,
    pub extracted_path: Option<String>,
    pub provenance_notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceProvenanceGraph {
    pub case_id: String,
    pub source_target: String,
    pub source_sha256_before: String,
    pub source_sha256_after: String,
    pub source_size_bytes: u64,
    pub timestamp_utc: String,
    pub total_artifacts_recovered: usize,
    pub artifacts: Vec<CarvedArtifact>,
}

impl EvidenceProvenanceGraph {
    pub fn new(
        source_target: &str,
        source_sha256_before: &str,
        source_sha256_after: &str,
        source_size_bytes: u64,
        artifacts: Vec<CarvedArtifact>,
    ) -> Self {
        let case_id = format!("CASE-NTRO-{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase());
        let timestamp_utc = chrono::Utc::now().to_rfc3339();

        Self {
            case_id,
            source_target: source_target.to_string(),
            source_sha256_before: source_sha256_before.to_string(),
            source_sha256_after: source_sha256_after.to_string(),
            source_size_bytes,
            timestamp_utc,
            total_artifacts_recovered: artifacts.len(),
            artifacts,
        }
    }

    /// Save provenance graph manifest as JSON
    pub fn save(&self, output_dir: &Path) -> Result<PathBuf, String> {
        let _ = fs::create_dir_all(output_dir);
        let path = output_dir.join(format!("{}_provenance.json", self.case_id));
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(&path, json).map_err(|e| e.to_string())?;
        Ok(path)
    }
}
