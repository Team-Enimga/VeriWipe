# VeriWipe 🛡️
### Integrated Secure Data Erasure & Advanced Forensic File Recovery Platform
**Smart India Hackathon (SIH 2026) | Problem Statement ID: 26149**  
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Team:** @Enigm@ (Team ID 132834)  

---

## 🌟 Executive Summary

VeriWipe is an enterprise & defense grade, offline-capable cyber-forensic platform bridging two complementary missions:
1. **Device-Aware Secure Sanitization:** Permanent data destruction compliant with **NIST SP 800-88 Rev 1 (Clear & Purge)** and **DoD 5220.22-M**, with cryptographically verified read-back checks.
2. **Autonomous "One-Shot" Bare-Metal USB Sanitizer:** Live bootable appliance that automatically discovers all connected storage media, strictly isolates and protects the boot media, sanitizes all internal disks, and commits an immutable cryptographic audit record.
3. **Advanced File Carving & Recovery:** Deep raw-sector carving with structure-aware parsers (JPEG, PNG, PDF, ZIP/DOCX/PPTX, MP4) and an **Evidence Provenance Graph** mapping extracted artifacts to source sectors and hashes.
4. **Tamper-Evident Hash-Chained Blockchain Ledger:** Ed25519-signed append-only Merkle ledger producing verifiable, court-admissible-ready Certificates of Sanitization.
5. **Dual Interface:**
   - **In-OS Web Application:** High-fidelity interactive desktop GUI for file/disk erasure, carving, and blockchain verification.
   - **Bare-Metal Kiosk & Terminal TUI:** Autonomous kiosk GUI and curses-based console interface for headless or direct-boot deployment.
   - **Virtual Test Lab Sandbox:** Safe loopback drive generation for risk-free SIH live judging demonstrations.

---

## 🏗️ Architecture

```
seceraserec/
├── veriwipe/
│   ├── blockchain/        # Hash-chained Merkle ledger & Ed25519 digital signing
│   ├── devices/           # Storage enumeration, safety interlocks, virtual test lab
│   ├── sanitizer/         # NIST 800-88 / DoD drive & file sanitization engines
│   ├── recovery/          # Structure-aware file carving & evidence provenance
│   ├── autonomous/        # One-shot bare-metal auto-wipe daemon & curses TUI
│   ├── live_boot/         # GRUB & systemd bare-metal live USB deployment files
│   └── api/               # FastAPI REST endpoints & SSE real-time event broadcaster
├── frontend/              # Modern React web app (Dark Cyberpunk / Forensic UI)
└── veriwipe_cli.py        # Unified CLI controller
```

---

## 🚀 Quickstart

### 1. Unified CLI
```bash
# Display system help and command options
python3 veriwipe_cli.py --help

# Create a safe 50MB virtual forensic test drive
python3 veriwipe_cli.py lab create --size 50

# Carve files from the forensic test image
python3 veriwipe_cli.py carve --source /tmp/veriwipe_lab/forensic_test.img

# Securely sanitize the test drive with NIST 800-88 Purge
python3 veriwipe_cli.py wipe --target /tmp/veriwipe_lab/forensic_test.img --method NIST_800_88_PURGE

# Verify blockchain ledger integrity
python3 veriwipe_cli.py blockchain verify

# Launch FastAPI backend & GUI server
python3 veriwipe_cli.py serve --port 5000
```

---

## ⚖️ Standards & Compliance
- **NIST SP 800-88 Rev 1:** Guidelines for Media Sanitization (Clear & Purge)
- **DoD 5220.22-M:** National Industrial Security Program Operating Manual (NISPOM)
- **ISO/IEC 27037:** Guidelines for identification, collection, acquisition, and preservation of digital evidence
- **FIPS 180-4:** Secure Hash Standard (SHA-256)
- **RFC 8032:** Edwards-Curve Digital Signature Algorithm (Ed25519)
