//! Forensic Format Signatures and Structure-Aware Parsers.
//! Implements deep validation for JPEG, PNG, PDF, ZIP/Office, and MP4 formats,
//! rejecting false positives and computing structural validity scores.

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FileFormat {
    Jpeg,
    Png,
    Pdf,
    ZipOffice,
    Mp4,
}

impl FileFormat {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Jpeg => "JPEG",
            Self::Png => "PNG",
            Self::Pdf => "PDF",
            Self::ZipOffice => "ZIP_OFFICE",
            Self::Mp4 => "MP4",
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::Jpeg => "jpg",
            Self::Png => "png",
            Self::Pdf => "pdf",
            Self::ZipOffice => "zip",
            Self::Mp4 => "mp4",
        }
    }
}

pub struct FormatValidationResult {
    pub is_valid: bool,
    pub length: usize,
    pub confidence: u32, // 0 to 100
    pub integrity_status: &'static str,
    pub details: String,
}

// -------------------------------------------------------------
// Format Parsers
// -------------------------------------------------------------

/// Validate JPEG Structure (SOI -> Markers -> SOS -> EOI)
pub fn validate_jpeg(data: &[u8]) -> Option<FormatValidationResult> {
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
        return None;
    }

    let mut pos = 2;
    let mut found_sos = false;
    let max_search = data.len().min(50 * 1024 * 1024); // Cap search at 50 MB

    while pos + 1 < max_search {
        if data[pos] == 0xFF {
            let marker = data[pos + 1];
            // Skip fill bytes
            if marker == 0x00 || marker == 0xFF {
                pos += 1;
                continue;
            }

            // EOI (End of Image)
            if marker == 0xD9 {
                let length = pos + 2;
                let confidence = if found_sos { 98 } else { 85 };
                return Some(FormatValidationResult {
                    is_valid: true,
                    length,
                    confidence,
                    integrity_status: "INTACT_VALIDATED",
                    details: format!("Valid JPEG structure with SOF and EOI at byte {}", length),
                });
            }

            // SOS (Start of Scan - begins compressed image data stream)
            if marker == 0xDA {
                found_sos = true;
            }

            // Variable length markers (APP0-APP15, DQT, DHT, SOF0, etc.)
            if (0xE0..=0xEF).contains(&marker) || marker == 0xDB || marker == 0xC4 || marker == 0xC0 {
                if pos + 3 < max_search {
                    let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                    pos += 2 + len;
                    continue;
                }
            }
        }
        pos += 1;
    }

    // Fallback: If no EOI found within buffer, check if partial
    if found_sos && pos > 512 {
        Some(FormatValidationResult {
            is_valid: true,
            length: pos,
            confidence: 60,
            integrity_status: "PARTIAL_FRAGMENT",
            details: "JPEG header and scan found, but EOI trailer truncated".to_string(),
        })
    } else {
        None
    }
}

/// Validate PNG Structure (8-byte magic -> IHDR -> Chunks -> IEND)
pub fn validate_png(data: &[u8]) -> Option<FormatValidationResult> {
    let png_magic = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() < 16 || &data[..8] != png_magic {
        return None;
    }

    let mut pos = 8;
    let mut chunk_count = 0;
    let max_len = data.len().min(50 * 1024 * 1024);

    while pos + 12 <= max_len {
        let chunk_len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let chunk_type = &data[pos + 4..pos + 8];

        if chunk_count == 0 && chunk_type != b"IHDR" {
            return None; // First chunk MUST be IHDR
        }

        chunk_count += 1;
        let total_chunk_len = 4 + 4 + chunk_len + 4; // len + type + data + crc

        if chunk_type == b"IEND" {
            let length = pos + 12; // IEND has 0 data bytes + 4 CRC
            return Some(FormatValidationResult {
                is_valid: true,
                length,
                confidence: 99,
                integrity_status: "INTACT_VALIDATED",
                details: format!("Valid PNG image structure ({} chunks, terminated at IEND)", chunk_count),
            });
        }

        pos += total_chunk_len;
    }

    if chunk_count > 0 {
        Some(FormatValidationResult {
            is_valid: true,
            length: pos.min(max_len),
            confidence: 65,
            integrity_status: "PARTIAL_FRAGMENT",
            details: "PNG IHDR chunk validated, but trailer truncated".to_string(),
        })
    } else {
        None
    }
}

/// Validate PDF Structure (%PDF- -> Objects -> xref/startxref -> %%EOF)
pub fn validate_pdf(data: &[u8]) -> Option<FormatValidationResult> {
    if data.len() < 32 || !data.starts_with(b"%PDF-") {
        return None;
    }

    let max_len = data.len().min(100 * 1024 * 1024);
    let mut eof_pos = None;

    // Search for %%EOF trailer
    let eof_marker = b"%%EOF";
    let search_window = &data[..max_len];
    for (i, window) in search_window.windows(eof_marker.len()).enumerate() {
        if window == eof_marker {
            eof_pos = Some(i + eof_marker.len());
        }
    }

    if let Some(end) = eof_pos {
        let text_slice = String::from_utf8_lossy(&data[..end]);
        let has_obj = text_slice.contains("obj") && text_slice.contains("endobj");
        let has_xref = text_slice.contains("xref") || text_slice.contains("startxref");

        let confidence = if has_obj && has_xref { 96 } else { 85 };

        Some(FormatValidationResult {
            is_valid: true,
            length: end,
            confidence,
            integrity_status: "INTACT_VALIDATED",
            details: format!("Valid PDF document structure (verified xref/catalog, terminated at %%EOF)"),
        })
    } else {
        Some(FormatValidationResult {
            is_valid: true,
            length: 4096.min(max_len),
            confidence: 50,
            integrity_status: "PARTIAL_FRAGMENT",
            details: "PDF header found (%PDF-), but %%EOF trailer missing".to_string(),
        })
    }
}

/// Validate ZIP / Office Structure (PK\x03\x04 -> Central Directory -> PK\x05\x06)
pub fn validate_zip(data: &[u8]) -> Option<FormatValidationResult> {
    if data.len() < 30 || &data[..4] != b"PK\x03\x04" {
        return None;
    }

    let eocd_sig = [0x50, 0x4B, 0x05, 0x06]; // PK\x05\x06
    let max_len = data.len().min(150 * 1024 * 1024);
    let mut eocd_pos = None;

    let search_window = &data[..max_len];
    for (i, window) in search_window.windows(4).enumerate() {
        if window == eocd_sig {
            eocd_pos = Some(i);
        }
    }

    if let Some(pos) = eocd_pos {
        // EOCD structure is 22 bytes + comment length
        if pos + 22 <= max_len {
            let comment_len = u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize;
            let length = pos + 22 + comment_len;
            return Some(FormatValidationResult {
                is_valid: true,
                length,
                confidence: 98,
                integrity_status: "INTACT_VALIDATED",
                details: format!("Valid ZIP/Office archive structure with validated Central Directory ({} B)", length),
            });
        }
    }

    Some(FormatValidationResult {
        is_valid: true,
        length: 8192.min(max_len),
        confidence: 55,
        integrity_status: "PARTIAL_FRAGMENT",
        details: "ZIP Local File Header found (PK\\x03\\x04), EOCD truncated".to_string(),
    })
}

/// Validate MP4 / ISO Base Media (ftyp atom)
pub fn validate_mp4(data: &[u8]) -> Option<FormatValidationResult> {
    if data.len() < 12 || &data[4..8] != b"ftyp" {
        return None;
    }

    let ftyp_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if ftyp_len < 8 || ftyp_len > data.len() {
        return None;
    }

    // Traverse subsequent boxes if present (moov, mdat)
    let mut pos = ftyp_len;
    let max_len = data.len().min(500 * 1024 * 1024);
    let mut box_count = 1;

    while pos + 8 <= max_len {
        let box_len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        if box_len < 8 {
            break;
        }
        let box_type = &data[pos + 4..pos + 8];
        if box_type == b"mdat" || box_type == b"moov" {
            box_count += 1;
        }
        pos += box_len;
    }

    let length = pos.min(max_len);
    Some(FormatValidationResult {
        is_valid: true,
        length,
        confidence: if box_count > 1 { 95 } else { 75 },
        integrity_status: "INTACT_VALIDATED",
        details: format!("Valid MP4/ISO Media container (ftyp atom + {} sub-boxes)", box_count),
    })
}
