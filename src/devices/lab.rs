//! Synthetic Forensic Test Lab Generator.
//! Creates virtual raw disk images pre-populated with partition tables and realistic
//! forensic test artifacts (PDF, JPEG, ZIP, PNG, text) for safe SIH demonstration.

use crate::blockchain::crypto::sha256_digest;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectedArtifact {
    pub name: String,
    pub format: String,
    pub offset_bytes: u64,
    pub length_bytes: usize,
    pub sha256_hash: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabDiskManifest {
    pub image_path: String,
    pub size_mb: u64,
    pub size_bytes: u64,
    pub created_at: String,
    pub artifacts: Vec<InjectedArtifact>,
}

/// Create a synthetic forensic test drive
pub fn create_synthetic_disk(
    output_dir: &Path,
    filename: &str,
    size_mb: u64,
) -> Result<LabDiskManifest, String> {
    let _ = fs::create_dir_all(output_dir);
    let image_path = output_dir.join(filename);
    let size_bytes = size_mb * 1024 * 1024;

    // Create sparse file and fill baseline
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&image_path)
        .map_err(|e| format!("Failed to create lab image: {}", e))?;

    file.set_len(size_bytes)
        .map_err(|e| format!("Failed to allocate disk image size: {}", e))?;

    // Fill first 2 MB with filesystem-like structures
    let mut mbr_sector = [0u8; 512];
    mbr_sector[0] = 0xEB; // JMP opcode
    mbr_sector[1] = 0x3C;
    mbr_sector[2] = 0x90; // NOP
    mbr_sector[3..11].copy_from_slice(b"VERIWIPE");
    mbr_sector[510] = 0x55; // MBR Signature
    mbr_sector[511] = 0xAA;

    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    file.write_all(&mbr_sector).map_err(|e| e.to_string())?;

    let mut artifacts = Vec::new();

    // 1. Injected Artifact: Valid PDF Document
    let pdf_content = create_synthetic_pdf();
    let pdf_offset = 65536; // 64 KB offset (sector 128)
    file.seek(SeekFrom::Start(pdf_offset))
        .map_err(|e| e.to_string())?;
    file.write_all(&pdf_content).map_err(|e| e.to_string())?;
    artifacts.push(InjectedArtifact {
        name: "ntro_classified_memo.pdf".to_string(),
        format: "PDF".to_string(),
        offset_bytes: pdf_offset,
        length_bytes: pdf_content.len(),
        sha256_hash: sha256_digest(&pdf_content),
        description: "National Technical Research Organisation internal security audit report".to_string(),
    });

    // 2. Injected Artifact: Valid JPEG Image
    let jpeg_content = create_synthetic_jpeg();
    let jpeg_offset = 262144; // 256 KB offset (sector 512)
    file.seek(SeekFrom::Start(jpeg_offset))
        .map_err(|e| e.to_string())?;
    file.write_all(&jpeg_content).map_err(|e| e.to_string())?;
    artifacts.push(InjectedArtifact {
        name: "satellite_recon_sample.jpg".to_string(),
        format: "JPEG".to_string(),
        offset_bytes: jpeg_offset,
        length_bytes: jpeg_content.len(),
        sha256_hash: sha256_digest(&jpeg_content),
        description: "High-resolution satellite telemetry visual capture".to_string(),
    });

    // 3. Injected Artifact: Valid ZIP Archive (Office Document format)
    let zip_content = create_synthetic_zip();
    let zip_offset = 524288; // 512 KB offset (sector 1024)
    file.seek(SeekFrom::Start(zip_offset))
        .map_err(|e| e.to_string())?;
    file.write_all(&zip_content).map_err(|e| e.to_string())?;
    artifacts.push(InjectedArtifact {
        name: "cryptographic_keys_manifest.zip".to_string(),
        format: "ZIP_OFFICE".to_string(),
        offset_bytes: zip_offset,
        length_bytes: zip_content.len(),
        sha256_hash: sha256_digest(&zip_content),
        description: "Archived cryptographic key schedules and asset ledger export".to_string(),
    });

    // 4. Injected Artifact: Valid PNG Image
    let png_content = create_synthetic_png();
    let png_offset = 1048576; // 1 MB offset (sector 2048)
    file.seek(SeekFrom::Start(png_offset))
        .map_err(|e| e.to_string())?;
    file.write_all(&png_content).map_err(|e| e.to_string())?;
    artifacts.push(InjectedArtifact {
        name: "radar_waveform_diagram.png".to_string(),
        format: "PNG".to_string(),
        offset_bytes: png_offset,
        length_bytes: png_content.len(),
        sha256_hash: sha256_digest(&png_content),
        description: "Electronic warfare signal frequency plot".to_string(),
    });

    file.flush().map_err(|e| e.to_string())?;

    let manifest = LabDiskManifest {
        image_path: image_path.to_string_lossy().to_string(),
        size_mb,
        size_bytes,
        created_at: chrono::Utc::now().to_rfc3339(),
        artifacts,
    };

    // Save manifest JSON alongside image
    let manifest_path = image_path.with_extension("manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
    let _ = fs::write(manifest_path, manifest_json);

    Ok(manifest)
}

/// List existing synthetic lab images
pub fn list_synthetic_disks(lab_dir: &Path) -> Vec<LabDiskManifest> {
    let mut results = Vec::new();
    if let Ok(entries) = fs::read_dir(lab_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json")
                && path.to_string_lossy().ends_with(".manifest.json")
            {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(manifest) = serde_json::from_str::<LabDiskManifest>(&content) {
                        if Path::new(&manifest.image_path).exists() {
                            results.push(manifest);
                        }
                    }
                }
            }
        }
    }
    results
}

/// Remove all lab test disks
pub fn cleanup_synthetic_disks(lab_dir: &Path) -> Result<usize, String> {
    let mut count = 0;
    if let Ok(entries) = fs::read_dir(lab_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("img")
                || path.to_string_lossy().ends_with(".manifest.json")
            {
                let _ = fs::remove_file(path);
                count += 1;
            }
        }
    }
    Ok(count)
}

// -------------------------------------------------------------
// Synthetic Artifact Generators
// -------------------------------------------------------------

fn create_synthetic_pdf() -> Vec<u8> {
    let text = "CONFIDENTIAL - NATIONAL TECHNICAL RESEARCH ORGANISATION (NTRO)\n\
                VERIWIPE FORENSIC VALIDATION CORPUS\n\
                Security Classification: RESTRICTED\n\
                Evidence Chain-of-Custody: Verified\n\
                This document serves as ground truth for forensic carver validation.\n";

    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");
    pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    pdf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n",
    );
    let stream_content = format!("BT /F1 12 Tf 72 712 Td ({}) Tj ET", text.replace('\n', " "));
    pdf.extend_from_slice(
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
            stream_content.len(),
            stream_content
        )
        .as_bytes(),
    );
    pdf.extend_from_slice(
        b"xref\n0 5\n0000000000 65535 f \n0000000018 00000 n \n0000000067 00000 n \n0000000125 00000 n \n0000000216 00000 n \n\
          trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n340\n%%EOF\n",
    );
    pdf
}

fn create_synthetic_jpeg() -> Vec<u8> {
    let mut jpeg = Vec::new();
    jpeg.extend_from_slice(&[0xFF, 0xD8]); // SOI marker

    // APP0 JFIF marker
    let jfif_data = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00";
    jpeg.extend_from_slice(&[0xFF, 0xE0]);
    let jfif_len = (jfif_data.len() + 2) as u16;
    jpeg.extend_from_slice(&jfif_len.to_be_bytes());
    jpeg.extend_from_slice(jfif_data);

    // COM (Comment) marker with NTRO provenance
    let comment = b"NTRO-VERIWIPE-GROUND-TRUTH-IMAGE-ID-26149";
    jpeg.extend_from_slice(&[0xFF, 0xFE]);
    let com_len = (comment.len() + 2) as u16;
    jpeg.extend_from_slice(&com_len.to_be_bytes());
    jpeg.extend_from_slice(comment);

    // SOF0 (Start of Frame)
    jpeg.extend_from_slice(&[
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x20, 0x00, 0x20, 0x01, 0x01, 0x11, 0x00,
    ]);

    // SOS (Start of Scan) + image payload
    jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
    for i in 0..128 {
        jpeg.push((i * 17 % 250) as u8);
    }

    jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI marker
    jpeg
}

fn create_synthetic_png() -> Vec<u8> {
    let mut png = Vec::new();
    // PNG 8-byte signature
    png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

    // IHDR Chunk: 16x16 px, 8-bit RGBA
    let ihdr_data = [
        0x00, 0x00, 0x00, 0x10, // width 16
        0x00, 0x00, 0x00, 0x10, // height 16
        0x08, // bit depth 8
        0x06, // color type RGBA
        0x00, // compression
        0x00, // filter
        0x00, // interlace
    ];
    write_png_chunk(&mut png, b"IHDR", &ihdr_data);

    // IDAT Chunk: raw compressed dummy pixel stream
    let dummy_idat = [0x78, 0x9C, 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01];
    write_png_chunk(&mut png, b"IDAT", &dummy_idat);

    // IEND Chunk
    write_png_chunk(&mut png, b"IEND", &[]);
    png
}

fn write_png_chunk(buf: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(chunk_type);
    buf.extend_from_slice(data);

    // CRC32 calculation
    let mut crc_buf = Vec::new();
    crc_buf.extend_from_slice(chunk_type);
    crc_buf.extend_from_slice(data);
    let crc = crc32_simple(&crc_buf);
    buf.extend_from_slice(&crc.to_be_bytes());
}

fn crc32_simple(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn create_synthetic_zip() -> Vec<u8> {
    let filename = b"secret_audit_records.txt";
    let filedata = b"TOP SECRET ENCRYPTED RECOVERY LOG\nOPERATION VERIWIPE COMPLETE\n";

    let mut zip = Vec::new();

    // Local file header: 0x04034b50
    zip.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
    zip.extend_from_slice(&[0x14, 0x00]); // version 2.0
    zip.extend_from_slice(&[0x00, 0x00]); // flags
    zip.extend_from_slice(&[0x00, 0x00]); // compression: none (stored)
    zip.extend_from_slice(&[0x21, 0x48, 0x65, 0x58]); // mod time & date
    let crc = crc32_simple(filedata);
    zip.extend_from_slice(&crc.to_le_bytes());
    zip.extend_from_slice(&(filedata.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(filedata.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(filename.len() as u16).to_le_bytes());
    zip.extend_from_slice(&[0x00, 0x00]); // extra field len
    zip.extend_from_slice(filename);
    zip.extend_from_slice(filedata);

    let central_dir_offset = zip.len() as u32;

    // Central directory header: 0x02014b50
    zip.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]);
    zip.extend_from_slice(&[0x14, 0x00]);
    zip.extend_from_slice(&[0x14, 0x00]);
    zip.extend_from_slice(&[0x00, 0x00]);
    zip.extend_from_slice(&[0x00, 0x00]);
    zip.extend_from_slice(&[0x21, 0x48, 0x65, 0x58]);
    zip.extend_from_slice(&crc.to_le_bytes());
    zip.extend_from_slice(&(filedata.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(filedata.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(filename.len() as u16).to_le_bytes());
    zip.extend_from_slice(&[0x00, 0x00]); // extra field len
    zip.extend_from_slice(&[0x00, 0x00]); // file comment len
    zip.extend_from_slice(&[0x00, 0x00]); // disk number start
    zip.extend_from_slice(&[0x00, 0x00]); // internal file attr
    zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // external file attr
    zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // relative offset of local header
    zip.extend_from_slice(filename);

    let central_dir_size = (zip.len() as u32) - central_dir_offset;

    // End of Central Directory record: 0x06054b50
    zip.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
    zip.extend_from_slice(&[0x00, 0x00]); // number of this disk
    zip.extend_from_slice(&[0x00, 0x00]); // number of disk with start of central dir
    zip.extend_from_slice(&[0x01, 0x00]); // total entries on this disk
    zip.extend_from_slice(&[0x01, 0x00]); // total entries in central dir
    zip.extend_from_slice(&central_dir_size.to_le_bytes());
    zip.extend_from_slice(&central_dir_offset.to_le_bytes());
    zip.extend_from_slice(&[0x00, 0x00]); // comment len

    zip
}
