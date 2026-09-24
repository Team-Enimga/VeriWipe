use veriwipe::devices::lab::create_synthetic_disk;
use veriwipe::recovery::carver::carve_media;

#[test]
fn test_forensic_carver_validation() {
    let temp_dir = std::env::temp_dir().join(format!("veriwipe_test_carve_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);

    // 1. Create a 5MB synthetic test drive with injected artifacts
    let manifest = create_synthetic_disk(&temp_dir, "forensic_source.img", 5).expect("Failed to create test disk");
    assert_eq!(manifest.artifacts.len(), 4);

    let output_carve_dir = temp_dir.join("carved_out");

    // 2. Run Forensic Carver
    let carve_res = carve_media(
        std::path::Path::new(&manifest.image_path),
        &output_carve_dir,
        "ALL",
        true,
        None,
    ).expect("Carving failed");

    // 3. Verify exactly 4 valid artifacts were recovered
    assert_eq!(carve_res.provenance.total_artifacts_recovered, 4);
    assert!(carve_res.source_integrity_preserved, "Source media hash must remain untouched");

    // 4. Verify all extracted artifacts have high confidence and correct formats
    let formats: Vec<String> = carve_res.provenance.artifacts.iter().map(|a| a.format.clone()).collect();
    assert!(formats.contains(&"PDF".to_string()));
    assert!(formats.contains(&"JPEG".to_string()));
    assert!(formats.contains(&"ZIP_OFFICE".to_string()));
    assert!(formats.contains(&"PNG".to_string()));

    for art in &carve_res.provenance.artifacts {
        assert!(art.confidence_score >= 80, "Extracted candidate confidence should be >= 80%");
        assert_eq!(art.structural_status, "INTACT_VALIDATED");
        if let Some(ref path) = art.extracted_path {
            assert!(std::path::Path::new(path).exists());
        }
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}
