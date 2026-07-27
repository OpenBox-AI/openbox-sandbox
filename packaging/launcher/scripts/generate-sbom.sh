#!/usr/bin/env bash
set -euo pipefail

# Generate SPDX + CycloneDX SBOMs for a Rust binary using syft.
# Matches the dual-SBOM pattern from krnl-labs/kontrol-plane goreleaser config.
#
# Usage: ./generate-sbom.sh <binary-path> <output-dir>
#
# Outputs:
#   <output-dir>/<name>.spdx.json      — SPDX 2.3 SBOM
#   <output-dir>/<name>.cyclonedx.json — CycloneDX SBOM

SYFT_VERSION="${SYFT_VERSION:-v1.20.0}"

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <binary-path> <output-dir>" >&2
  exit 1
fi

BINARY="$1"
OUTPUT_DIR="$2"

if [[ ! -f "$BINARY" ]]; then
  echo "Error: binary not found at $BINARY" >&2
  exit 1
fi

# Install syft if not present or version mismatch
if ! command -v syft &>/dev/null; then
  echo "Installing syft $SYFT_VERSION..."
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sudo sh -s -- -b /usr/local/bin "$SYFT_VERSION"
fi

INSTALLED_VERSION="$(syft version 2>/dev/null | head -1 || true)"
echo "syft: $INSTALLED_VERSION"

mkdir -p "$OUTPUT_DIR"

BASENAME="$(basename "$BINARY")"
SPDX_OUT="$OUTPUT_DIR/${BASENAME}.spdx.json"
CDX_OUT="$OUTPUT_DIR/${BASENAME}.cyclonedx.json"

echo "Generating SBOMs for $BASENAME..."

syft "$BINARY" -o "spdx-json=$SPDX_OUT"
echo "  SPDX:   $SPDX_OUT"

syft "$BINARY" -o "cyclonedx-json=$CDX_OUT"
echo "  CycloneDX: $CDX_OUT"

# Print SHA-256 for evidence manifest
echo ""
echo "SHA-256 checksums:"
shasum -a 256 "$SPDX_OUT" "$CDX_OUT"
