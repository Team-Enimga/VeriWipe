# VeriWipe 🛡️ — SIH 2026 Judge Demonstration Guide
### Problem Statement ID: 26149 (NTRO) | Theme: Blockchain & Cybersecurity
**Team:** @Enigm@ (Team ID 132834)  
**Product:** VeriWipe (100% Pure Rust Autonomous Cyber-Forensic Appliance)  

---

## 🎯 What to Tell the Judges (The 1-Minute Pitch)

> *"Good morning/afternoon, esteemed judges. We are Team @Enigm@, presenting **VeriWipe** for NTRO Problem Statement 26149.  
> Rather than viewing secure data erasure and forensic recovery as disconnected silos, VeriWipe unifies them under an **evidence-backed, self-checking operational pipeline**.  
> We do not naively overwrite zeroes and assume success. Instead, VeriWipe issues direct **OEM hardware-level commands**—such as NVMe Sanitize/Crypto Erase and ATA Secure Erase directly on the drive controllers—flushes volatile hardware write buffers with `BLKFLSBUF`, executes NIST SP 800-88 Purge overwriting, performs sector read-back verification, and then **cross-verifies by running our own advanced forensic carver** to prove 0 residual artifacts remain.  
> Every operation is cryptographically anchored to an **append-only, Ed25519-signed Merkle blockchain ledger**, producing verifiable Certificates of Sanitization.  
> For field operations, our signature capability is the **Autonomous Bare-Metal Live USB**: plug it into any target machine, boot it, and it automatically identifies and isolates the boot pendrive, prompts a 15-second safety abort countdown, sanitizes all internal drives, and records the signed certificates directly back to the USB ledger."*

---

## 🚀 Live Demonstration Walkthrough (5-Minute Script)

### Step 1: Hardware Enumeration & Boot-Media Isolation Guard
Show the judges how VeriWipe inspects physical disks and protects the host operating system:
```bash
cargo run -- devices
```
* **Judge Talking Point:** Point out how `/dev/nvme0n1` (or host disk) is automatically detected with bus type, model, serial number, and flagged as `STATUS: LOCKED 🔒 | REASON: HARD LOCK: Active root filesystem (/)`. VeriWipe’s kernel-level safety interlock makes accidental destruction of host or boot USB media mathematically impossible.

---

### Step 2: Synthetic Forensic Test Lab (100% Safe Demo)
Generate a synthetic 20MB raw disk pre-populated with partition tables and realistic confidential test files:
```bash
cargo run -- lab create --size-mb 20
```
* **Output:** Shows 4 ground-truth artifacts injected at physical sector offsets:
  1. `ntro_classified_memo.pdf` (Sector offset `0x00010000`, PDF catalog & cross-reference xref structure)
  2. `satellite_recon_sample.jpg` (Sector offset `0x00040000`, SOI/SOF0/EOI markers)
  3. `cryptographic_keys_manifest.zip` (Sector offset `0x00080000`, Central Directory structure)
  4. `radar_waveform_diagram.png` (Sector offset `0x00100000`, IHDR/IDAT/IEND chunks)

---

### Step 3: Advanced File Carving & Evidence Provenance Graph
Run the forensic carving engine to extract and validate the files:
```bash
cargo run -- carve --source ./test_artifacts/forensic_demo.img --output ./test_artifacts/carved_output
```
* **Judge Talking Point:**
  - Emphasize that VeriWipe is not just checking magic bytes; it parses internal format structures (`validate_pdf`, `validate_jpeg`, `validate_zip`).
  - Point out that **Source Media SHA-256 is checked before and after**, proving read-only forensic evidence preservation (ISO/IEC 27037).
  - Show the **Confidence Scores (96%–99%)** and the generated `EvidenceProvenanceGraph` JSON manifest linking physical sector offsets to extracted files.

---

### Step 4: Certified Media Sanitization & Carver Cross-Verification
Execute secure sanitization on the test drive:
```bash
cargo run -- wipe --target ./test_artifacts/forensic_demo.img --method NIST_800_88_PURGE --force
```
* **Judge Talking Point:**
  - Notice the **OEM Hardware Controller commands** executed.
  - Notice the **Cache Invalidation & Hardware Flush** (`flush_hardware_caches`).
  - Notice the **Sector Read-Back Verification** (100% sampled sectors confirmed zero).
  - Notice the **Forensic Carver Remnant Cross-Check**: VeriWipe runs its own carver on the wiped media and confirms `0 artifacts recovered (Clean: YES)`.
  - Notice the **NIST SP 800-88 Certificate of Sanitization** generated in both machine-readable JSON and printable HTML. Open the HTML certificate in a browser to show the official NTRO certificate seal!

---

### Step 5: Proof of Irrecoverability (Post-Wipe Carver Run)
Run the carver again on the wiped disk to prove to the judges that no files can be recovered:
```bash
cargo run -- carve --source ./test_artifacts/forensic_demo.img --output ./test_artifacts/carved_empty
```
* **Result:** `Total Artifacts Carved: 0`. Absolute forensic proof of irreversible destruction!

---

### Step 6: Blockchain Audit Ledger & Tampering Detection
Verify the cryptographic integrity of the blockchain audit ledger:
```bash
cargo run -- blockchain verify
```
* **Judge Talking Point:**
  - Traverses the entire hash chain from Genesis block `#0` to present.
  - Verifies parent hash continuity, SHA-256 block hashes, Merkle root, and Ed25519 digital signatures.
  - Proves that logs cannot be altered or retroactively manipulated by rogue operators.

---

### Step 7: Launch the Cyber-Forensic Web GUI & USB Kiosk
Start the embedded Axum HTTP server:
```bash
cargo run -- serve --port 5000
```
Open **`http://localhost:5000`** in any browser (or kiosk display on live USB) to explore the real-time interactive dashboard:
- Live Storage Discovery table
- Autonomous One-Shot Decommissioning console with countdown timer
- Real-time sector wipe progress bar & MB/s speedometer
- Forensic Carving studio with live provenance graph table
- Blockchain block explorer with digital signature verification badges
- One-click Test Lab generator

---

## 🏆 Key Differentiators to Emphasize to Judges

| Feature | Competitor / Legacy Tools | VeriWipe (Our Solution) |
|---|---|---|
| **Language & Architecture** | Python/Shell scripts with runtime dependencies | **100% Pure Rust**, single statically-linked binary, memory-safe, line-rate zero-copy I/O |
| **Sanitization Depth** | Naive `dd if=/dev/zero` | **OEM Hardware Controller Commands** (NVMe Sanitize / ATA Secure Erase) + NIST 800-88 Purge + Cache Flushing |
| **Verification Assurance** | Command exit code only | **Dual Assurance:** 100% sector read-back + active forensic carver cross-check |
| **Bare-Metal Live USB** | Manual setup, risk of wiping boot media | **One-Shot Autonuke Appliance** with bulletproof boot-media isolation & 15s abort timer |
| **Audit & Chain of Custody** | Plain text log files (easily editable) | **Append-Only Merkle Blockchain Ledger** signed with Ed25519 digital authority keys |
| **Judge Testing Safety** | Requires risking real drives or USBs | **Built-in Synthetic Forensic Test Lab** with ground-truth validation corpus |
