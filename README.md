# VeriWipe 🛡️
### Integrated Secure Data Erasure & Advanced Forensic File Recovery Platform
**Smart India Hackathon (SIH 2026) | Problem Statement ID: 26149**  
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Team:** @Enigm@ (Team ID 132834)  

---

## 🌟 Executive Summary

VeriWipe is an enterprise & defense grade, offline-capable cyber-forensic platform built in **100% Pure Rust**. It unifies two critical operational requirements under an evidence-aware, self-checking architecture:

1. **Hardware & OEM-Aware Media Sanitization:** Permanent data destruction compliant with **NIST SP 800-88 Rev 1 (Clear & Purge)** and **DoD 5220.22-M**. Issues direct hardware controller commands (**NVMe Sanitize / Crypto Erase**, **ATA Secure Erase**, and Linux kernel `BLKDISCARD`/`BLKSECDISCARD`), followed by volatile hardware write-cache flushing (`BLKFLSBUF` + `fdatasync`).
2. **Autonomous "One-Shot" Bare-Metal Live USB Sanitizer:** An unattended/guarded live boot environment that auto-discovers all connected storage media, strictly isolates and protects the boot pendrive from being wiped, executes sanitization across all target drives, and logs signed certificates directly to the USB.
3. **Dual Verification Pipeline (Sector Check + Forensic Carver Cross-Check):** Does not naively assume completion. Verifies sector-level byte patterns (100% or statistical sampling) AND immediately runs our own advanced forensic carver to certify that **0 recoverable remnants exist**.
4. **Advanced Structure-Aware File Carving:** Deep raw-sector carving with structure-aware format parsers (JPEG, PNG, PDF, ZIP/DOCX/PPTX, MP4) and an **Evidence Provenance Graph** mapping extracted artifacts to source sectors, hashes, and calibrated confidence scores (0–100%).
5. **Tamper-Evident Hash-Chained Blockchain Ledger:** Ed25519-signed append-only Merkle ledger producing verifiable, court-admissible-ready Certificates of Sanitization (`.json` and printable `.html`).
6. **Dual User Interface:**
   - **In-OS Web Application:** High-fidelity interactive desktop GUI for file/disk erasure, carving, and blockchain verification.
   - **Bare-Metal Kiosk & Terminal TUI:** Autonomous kiosk GUI and curses-based console interface for headless or direct-boot deployment.
   - **Synthetic Forensic Test Lab:** Safe loopback drive generation for risk-free SIH live judging demonstrations on any laptop.

---

## 🏗️ Architecture (100% Pure Rust)

```
seceraserec/
├── Cargo.toml
├── src/
│   ├── main.rs                   # Unified CLI entry point & dispatcher
│   ├── config.rs                 # Standards definitions (NIST 800-88, DoD, paths)
│   ├── blockchain/
│   │   ├── crypto.rs             # SHA-256, Merkle root, Ed25519 signing & verification
│   │   ├── ledger.rs             # Append-only hash-chained block ledger & tampering detector
│   │   └── certificate.rs        # NIST 800-88 compliant JSON & HTML certificate generator
│   ├── devices/
│   │   ├── detector.rs           # /sys/block & lsblk drive enumerator, bus/serial/capacity
│   │   ├── safety.rs             # Strict boot-media isolation & rootfs protection locks
│   │   └── lab.rs                # Virtual forensic test lab (synthetic raw disks with files)
│   ├── sanitizer/
│   │   ├── algorithms.rs         # NIST Clear, Purge, DoD 3-Pass, Quick Zero patterns
│   │   ├── hardware.rs           # NVMe Sanitize, ATA Secure Erase, BLKDISCARD, cache flush
│   │   ├── drive.rs              # Streaming sector-level disk eraser with carver cross-check
│   │   ├── file.rs               # Secure file & directory shredder with metadata scrambling
│   │   └── verifier.rs           # Read-back verification engine (100% or statistical sampling)
│   ├── recovery/
│   │   ├── carver.rs             # Streaming sector scanner for raw disk images
│   │   ├── signatures.rs         # Structure-aware parsers (JPEG, PNG, PDF, ZIP/DOCX, MP4)
│   │   └── provenance.rs         # Evidence Provenance Graph (offsets, hashes, confidence)
│   ├── autonomous/
│   │   ├── autonuke.rs           # One-shot USB daemon with 15s abort timer & auto-commit
│   │   └── tui.rs                # Bare-metal terminal console interface (Crossterm)
│   └── web/
│       ├── server.rs             # Embedded Axum async HTTP & SSE progress server
│       └── embedded_ui.html      # High-fidelity cyber-forensic web dashboard
├── live_boot/
│   ├── grub.cfg                  # GRUB 2 boot menu (Autonomous vs Interactive vs Forensic RO)
│   ├── veriwipe-autowipe.service # Systemd live-boot unit
│   └── build_live_usb.sh         # Production bare-metal Live USB creation script
├── frontend/                     # Modern React web app (Dark Cyberpunk / Forensic UI)
├── tests/
│   ├── test_blockchain.rs        # Cryptographic ledger & certificate tests
│   ├── test_carver.rs            # Forensic carving & structure validation tests
│   └── test_sanitizer.rs         # NIST wipe & carver cross-check tests
└── DEMO_GUIDE.md                 # Step-by-step walkthrough for SIH judges
```

---

## 🚀 Quickstart & Usage

### 1. Build VeriWipe
```bash
cargo build --release
```

### 2. Device Discovery & Boot-Media Isolation Guard
```bash
# Enumerate storage devices and verify host rootfs is safely locked
cargo run -- devices
```

### 3. Safe Judge Demonstration (Synthetic Test Lab)
```bash
# Create a 20MB synthetic disk injected with confidential test files (PDF, JPEG, ZIP, PNG)
cargo run -- lab create --size-mb 20

# Carve and extract files with structure-aware validation
cargo run -- carve --source ./test_artifacts/forensic_demo.img --output ./test_artifacts/carved_output

# Securely sanitize the test disk (NIST Purge + OEM hardware commands + cache flush)
cargo run -- wipe --target ./test_artifacts/forensic_demo.img --method NIST_800_88_PURGE --force

# Verify with carver that 0 remnants remain on the wiped disk
cargo run -- carve --source ./test_artifacts/forensic_demo.img --output ./test_artifacts/carved_empty
```

### 4. Verify Cryptographic Blockchain Audit Ledger
```bash
cargo run -- blockchain verify
```

### 5. Launch the Cyber-Forensic Web GUI & USB Kiosk
```bash
cargo run -- serve --port 5000
```
Open **`http://localhost:5000`** in your browser.

### 6. Bare-Metal Autonomous Live USB Mode
```bash
# Test autonuke in safe dry-run simulation mode
cargo run -- autonuke --dry-run

# Run bare-metal terminal TUI
cargo run -- tui
```

---

## ⚖️ Standards & Compliance
- **NIST SP 800-88 Rev 1:** Guidelines for Media Sanitization (Clear & Purge)
- **DoD 5220.22-M:** National Industrial Security Program Operating Manual (NISPOM)
- **ISO/IEC 27037:** Guidelines for digital evidence preservation and source-integrity verification
- **FIPS 180-4:** Secure Hash Standard (SHA-256)
- **RFC 8032:** Edwards-Curve Digital Signature Algorithm (Ed25519)
