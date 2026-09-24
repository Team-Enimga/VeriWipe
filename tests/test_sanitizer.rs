use veriwipe::config::WipeMethod;
use veriwipe::devices::lab::create_synthetic_disk;
use veriwipe::sanitizer::*;

#[test]
fn test_secure_wipe_and_carver_crosscheck() {
    let temp_dir = std::env::temp_dir().join(format!("veriwipe_test_wipe_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);

    // 1. Create a 5MB synthetic test drive with injected artifacts
    let manifest = create_synthetic_disk(&temp_dir, "test_target.img", 5).expect("Failed to create test disk");
    assert_eq!(manifest.artifacts.len(), 4);

    // 2. Execute NIST 800-88 Purge wipe with 100% verification
    let wipe_res = execute_wipe(
        &manifest.image_path,
        WipeMethod::Nist800_88Purge,
        100,
        "Test_Forensic_Officer",
        "NTRO_Validation_Lab",
        None,
    ).expect("Wipe execution failed");

    // 3. Verify Sector Read-back status
    assert!(wipe_res.verification.is_cleared, "All sampled sectors must match expected pattern");
    assert_eq!(wipe_res.verification.failed_sectors, 0);

    // 4. Verify Forensic Carver found 0 remnants!
    assert_eq!(wipe_res.forensic_remnants_found, 0, "Carver must find 0 remnants on properly wiped drive");
    assert!(wipe_res.forensic_carver_verified_clean);

    // 5. Verify certificate generation
    assert!(std::path::Path::new(&wipe_res.certificate_json_path).exists());
    assert!(std::path::Path::new(&wipe_res.certificate_html_path).exists());

    let _ = std::fs::remove_dir_all(&temp_dir);
}
