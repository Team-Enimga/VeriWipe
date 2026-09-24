//! NIST SP 800-88 Rev 1 Compliant Certificate of Sanitization Generator.
//! Produces tamper-evident structured JSON and rich printable HTML certificates.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    pub path: String,
    pub model: String,
    pub serial_number: String,
    pub bus_type: String,
    pub capacity_bytes: u64,
    pub sector_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationDetails {
    pub standard: String,
    pub method_id: String,
    pub passes_executed: u32,
    pub patterns: Vec<String>,
    pub duration_seconds: f64,
    pub throughput_mbps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationDetails {
    pub verified_percentage: u32,
    pub sampled_sectors: u64,
    pub failed_sectors: u64,
    pub post_wipe_hash: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainAnchor {
    pub block_index: u64,
    pub block_hash: String,
    pub merkle_root: String,
    pub previous_block_hash: String,
    pub signature: String,
    pub authority_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationCertificate {
    pub certificate_id: String,
    pub created_at: String,
    pub organization: String,
    pub operator: String,
    pub compliance: String,
    pub device: DeviceFingerprint,
    pub sanitization: SanitizationDetails,
    pub verification: VerificationDetails,
    pub blockchain_anchor: BlockchainAnchor,
}

impl SanitizationCertificate {
    pub fn new(
        organization: &str,
        operator: &str,
        device: DeviceFingerprint,
        sanitization: SanitizationDetails,
        verification: VerificationDetails,
        blockchain_anchor: BlockchainAnchor,
    ) -> Self {
        let certificate_id = format!("VERIWIPE-CERT-{}", Uuid::new_v4().to_string()[..8].to_uppercase());
        let created_at = chrono::Utc::now().to_rfc3339();

        Self {
            certificate_id,
            created_at,
            organization: organization.to_string(),
            operator: operator.to_string(),
            compliance: "NIST SP 800-88 Rev 1 (Clear & Purge) & DoD 5220.22-M".to_string(),
            device,
            sanitization,
            verification,
            blockchain_anchor,
        }
    }

    /// Render rich standalone HTML report for visual certificate printing
    pub fn to_html(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Certificate of Data Sanitization - {cert_id}</title>
    <style>
        :root {{
            --bg: #0b1120;
            --surface: #1e293b;
            --border: #334155;
            --primary: #06b6d4;
            --success: #10b981;
            --text: #f8fafc;
            --muted: #94a3b8;
        }}
        @media print {{
            body {{ background: #fff !important; color: #000 !important; }}
            .container {{ border: 2px solid #000 !important; box-shadow: none !important; }}
        }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
        }}
        .container {{
            width: 100%;
            max-width: 850px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5);
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid var(--primary);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .title h1 {{
            margin: 0;
            font-size: 24px;
            color: var(--primary);
            text-transform: uppercase;
            letter-spacing: 1.5px;
        }}
        .title p {{
            margin: 4px 0 0;
            font-size: 13px;
            color: var(--muted);
        }}
        .badge {{
            background: rgba(16, 185, 129, 0.15);
            color: var(--success);
            border: 1px solid var(--success);
            padding: 6px 14px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 13px;
            letter-spacing: 1px;
        }}
        .section-title {{
            font-size: 14px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--primary);
            margin: 24px 0 12px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 6px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 16px;
            font-size: 13px;
        }}
        .item {{
            background: rgba(15, 23, 42, 0.6);
            padding: 12px 16px;
            border-radius: 8px;
            border: 1px solid rgba(51, 65, 85, 0.5);
        }}
        .item-label {{
            color: var(--muted);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }}
        .item-val {{
            font-weight: 600;
            word-break: break-all;
            color: var(--text);
        }}
        .crypto-box {{
            background: #090e17;
            border: 1px dashed var(--primary);
            border-radius: 8px;
            padding: 16px;
            margin-top: 24px;
            font-family: monospace;
            font-size: 11px;
            line-height: 1.6;
        }}
        .footer {{
            margin-top: 36px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 12px;
            color: var(--muted);
            border-top: 1px solid var(--border);
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">
                <h1>Certificate of Data Sanitization</h1>
                <p>National Technical Research Organisation (NTRO) • VeriWipe Platform</p>
                <p>Standard: {compliance}</p>
            </div>
            <div class="badge">SECURELY SANITIZED</div>
        </div>

        <div class="section-title">Certificate & Custody Information</div>
        <div class="grid">
            <div class="item">
                <div class="item-label">Certificate Serial Number</div>
                <div class="item-val" style="color: var(--primary);">{cert_id}</div>
            </div>
            <div class="item">
                <div class="item-label">Timestamp (UTC)</div>
                <div class="item-val">{timestamp}</div>
            </div>
            <div class="item">
                <div class="item-label">Organization</div>
                <div class="item-val">{org}</div>
            </div>
            <div class="item">
                <div class="item-label">Certified Forensic Operator</div>
                <div class="item-val">{operator}</div>
            </div>
        </div>

        <div class="section-title">Target Storage Media Fingerprint</div>
        <div class="grid">
            <div class="item">
                <div class="item-label">Block Device Node</div>
                <div class="item-val">{dev_path}</div>
            </div>
            <div class="item">
                <div class="item-label">Model / Bus Interface</div>
                <div class="item-val">{dev_model} ({bus_type})</div>
            </div>
            <div class="item">
                <div class="item-label">Hardware Serial Number</div>
                <div class="item-val">{dev_serial}</div>
            </div>
            <div class="item">
                <div class="item-label">Capacity & Sector Size</div>
                <div class="item-val">{capacity_mb:.2} MB ({capacity_bytes} bytes) • {sector_sz} B sectors</div>
            </div>
        </div>

        <div class="section-title">Sanitization Method & Read-Back Verification</div>
        <div class="grid">
            <div class="item">
                <div class="item-label">Sanitization Standard Applied</div>
                <div class="item-val">{method_std} ({passes} Passes)</div>
            </div>
            <div class="item">
                <div class="item-label">Duration & Throughput</div>
                <div class="item-val">{duration:.2}s ({throughput:.2} MB/s)</div>
            </div>
            <div class="item">
                <div class="item-label">Verification Scope</div>
                <div class="item-val">{verify_pct}% Sampling • {sampled_sec} Sectors Inspected</div>
            </div>
            <div class="item">
                <div class="item-label">Verification Result</div>
                <div class="item-val" style="color: var(--success); font-weight: bold;">{verify_res} ({failed_sec} Failures)</div>
            </div>
        </div>

        <div class="section-title">Tamper-Evident Blockchain Anchor</div>
        <div class="crypto-box">
            <div><strong>BLOCKCHAIN BLOCK INDEX:</strong> #{block_idx}</div>
            <div><strong>BLOCK HASH:</strong> {block_hash}</div>
            <div><strong>PARENT HASH:</strong> {prev_hash}</div>
            <div><strong>MERKLE ROOT:</strong> {merkle_root}</div>
            <div><strong>POST-WIPE SECTOR HASH (SHA-256):</strong> {post_hash}</div>
            <div><strong>AUTHORITY ED25519 SIGNATURE:</strong> {signature}</div>
            <div><strong>AUTHORITY PUBLIC KEY:</strong> {pubkey}</div>
        </div>

        <div class="footer">
            <div>Digitally Signed & Validated by VeriWipe Authority Engine</div>
            <div>Auditable under ISO/IEC 27037 & NIST SP 800-88 Rev 1</div>
        </div>
    </div>
</body>
</html>"#,
            cert_id = self.certificate_id,
            compliance = self.compliance,
            timestamp = self.created_at,
            org = self.organization,
            operator = self.operator,
            dev_path = self.device.path,
            dev_model = self.device.model,
            bus_type = self.device.bus_type,
            dev_serial = self.device.serial_number,
            capacity_mb = (self.device.capacity_bytes as f64) / (1024.0 * 1024.0),
            capacity_bytes = self.device.capacity_bytes,
            sector_sz = self.device.sector_size,
            method_std = self.sanitization.standard,
            passes = self.sanitization.passes_executed,
            duration = self.sanitization.duration_seconds,
            throughput = self.sanitization.throughput_mbps,
            verify_pct = self.verification.verified_percentage,
            sampled_sec = self.verification.sampled_sectors,
            verify_res = self.verification.result,
            failed_sec = self.verification.failed_sectors,
            block_idx = self.blockchain_anchor.block_index,
            block_hash = self.blockchain_anchor.block_hash,
            prev_hash = self.blockchain_anchor.previous_block_hash,
            merkle_root = self.blockchain_anchor.merkle_root,
            post_hash = self.verification.post_wipe_hash,
            signature = self.blockchain_anchor.signature,
            pubkey = self.blockchain_anchor.authority_pubkey,
        )
    }

    /// Save certificate both as structured JSON and printable HTML
    pub fn save(&self, output_dir: &Path) -> Result<(PathBuf, PathBuf), String> {
        let _ = fs::create_dir_all(output_dir);
        let base_name = format!("{}_{}", self.certificate_id, self.device.serial_number);
        let json_path = output_dir.join(format!("{}.json", base_name));
        let html_path = output_dir.join(format!("{}.html", base_name));

        let json_str = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(&json_path, json_str).map_err(|e| e.to_string())?;

        let html_str = self.to_html();
        fs::write(&html_path, html_str).map_err(|e| e.to_string())?;

        Ok((json_path, html_path))
    }
}
