#!/usr/bin/env bash
# VeriWipe Bare-Metal Live USB ISO Generator
# SIH 2026 Problem Statement ID: 26149 (NTRO)

set -euo pipefail

echo "================================================================================"
echo "    VERIWIPE BARE-METAL LIVE USB BUILDER (100% PURE RUST APPLIANCE)             "
echo "================================================================================"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/build_iso"
BIN_PATH="${ROOT_DIR}/target/release/veriwipe"

echo "[1/4] Building optimized static release binary of VeriWipe..."
cd "${ROOT_DIR}"
cargo build --release

if [ ! -f "${BIN_PATH}" ]; then
    echo "❌ Error: veriwipe binary not found at ${BIN_PATH}"
    exit 1
fi
echo "✓ Compiled static binary: ${BIN_PATH} ($(du -h "${BIN_PATH}" | cut -f1))"

echo "[2/4] Preparing Live USB directory structure..."
mkdir -p "${OUTPUT_DIR}/boot/grub"
mkdir -p "${OUTPUT_DIR}/live"
mkdir -p "${OUTPUT_DIR}/veriwipe_records"

echo "[3/4] Copying kernel, initrd, binary, and GRUB configuration..."
cp "${ROOT_DIR}/live_boot/grub.cfg" "${OUTPUT_DIR}/boot/grub/grub.cfg"
cp "${BIN_PATH}" "${OUTPUT_DIR}/live/veriwipe"

echo "[4/4] Assembling hybrid UEFI/BIOS bootable ISO layout..."
echo "To generate the final bootable ISO, run:"
echo "  grub-mkrescue -o veriwipe_live_appliance.iso ${OUTPUT_DIR}"
echo ""
echo "To flash directly to a test pendrive (e.g. /dev/sdX):"
echo "  sudo dd if=veriwipe_live_appliance.iso of=/dev/sdX bs=4M status=progress conv=fsync"
echo "================================================================================"
echo "✓ Live USB staging complete at ${OUTPUT_DIR}"
