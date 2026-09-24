use veriwipe::blockchain::*;

#[test]
fn test_blockchain_genesis_and_signing() {
    let temp_dir = std::env::temp_dir().join(format!("veriwipe_test_bc_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let privkey_path = temp_dir.join("authority.pk8");
    let pubkey_path = temp_dir.join("authority.pub");
    let ledger_path = temp_dir.join("test_chain.json");

    // 1. Generate Key Authority
    let authority = KeyAuthority::load_or_generate(&privkey_path, &pubkey_path).expect("Failed to create authority");
    assert_eq!(authority.public_key_hex().len(), 64);

    // 2. Initialize Ledger (creates Genesis block)
    let mut ledger = BlockchainLedger::load_or_create(&ledger_path, &authority).expect("Failed to init ledger");
    assert_eq!(ledger.blocks.len(), 1);
    assert_eq!(ledger.blocks[0].event_type, "GENESIS");

    // 3. Verify Chain
    let verify_res = ledger.verify_chain();
    assert!(verify_res.is_valid, "Genesis chain should be valid");
    assert_eq!(verify_res.verified_blocks, 1);

    // 4. Record new sanitization event
    let payload = serde_json::json!({
        "action": "SECURE_WIPE",
        "device": "/dev/sdb",
        "method": "NIST_SP_800_88_PURGE",
        "passes": 2,
        "sectors_verified": 1048576,
        "verification_result": "PASSED_ZERO_CONFIRMED"
    });

    let new_block = ledger.record_event(
        "WIPE_COMPLETED",
        "/dev/sdb",
        "Test_Officer_007",
        payload,
        &authority,
        Some(&ledger_path),
    ).expect("Failed to record block");

    assert_eq!(new_block.index, 1);
    assert_eq!(new_block.previous_hash, ledger.blocks[0].block_hash);

    // 5. Verify Chain with 2 blocks
    let verify_res2 = ledger.verify_chain();
    assert!(verify_res2.is_valid, "Chain with 2 blocks should be valid");
    assert_eq!(verify_res2.verified_blocks, 2);

    // 6. Test Tampering Detection: modify block 1 payload
    let mut tampered_ledger = ledger.clone();
    tampered_ledger.blocks[1].operator = "Malicious_Attacker".to_string();
    let tampered_res = tampered_ledger.verify_chain();
    assert!(!tampered_res.is_valid, "Tampered chain MUST be detected as invalid");
    assert_eq!(tampered_res.invalid_block_index, Some(1));

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_certificate_generation() {
    let temp_dir = std::env::temp_dir().join(format!("veriwipe_test_cert_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let cert = SanitizationCertificate::new(
        "National Technical Research Organisation (NTRO)",
        "Forensic_Examiner_42",
        DeviceFingerprint {
            path: "/dev/nvme0n1".to_string(),
            model: "Samsung SSD 980 PRO 1TB".to_string(),
            serial_number: "S5GXNF0R123456".to_string(),
            bus_type: "NVMe".to_string(),
            capacity_bytes: 1_000_204_886_016,
            sector_size: 512,
        },
        SanitizationDetails {
            standard: "NIST SP 800-88 Rev 1 (Purge)".to_string(),
            method_id: "NIST_800_88_PURGE".to_string(),
            passes_executed: 2,
            patterns: vec!["CRYPTOGRAPHIC_RANDOM".to_string(), "0x00_ZERO_FILL".to_string()],
            duration_seconds: 142.5,
            throughput_mbps: 450.2,
        },
        VerificationDetails {
            verified_percentage: 100,
            sampled_sectors: 1953525168,
            failed_sectors: 0,
            post_wipe_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            result: "VERIFIED_CLEARED_100_PERCENT".to_string(),
        },
        BlockchainAnchor {
            block_index: 42,
            block_hash: "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890".to_string(),
            merkle_root: "f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687".to_string(),
            previous_block_hash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            signature: "deadbeefcafebabe".repeat(4),
            authority_pubkey: "feedface01234567".repeat(4),
        },
    );

    let (json_path, html_path) = cert.save(&temp_dir).expect("Failed to save certificate");
    assert!(json_path.exists());
    assert!(html_path.exists());

    let html_content = std::fs::read_to_string(&html_path).unwrap();
    assert!(html_content.contains("Samsung SSD 980 PRO 1TB"));
    assert!(html_content.contains("S5GXNF0R123456"));
    assert!(html_content.contains("Certificate of Data Sanitization"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}
