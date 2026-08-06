#!/usr/bin/env bash
set -euo pipefail

# Generate SPDX + CycloneDX SBOMs for a launcher binary using Syft.
# The launcher has no third-party Cargo dependencies; this scans the final file
# and does not claim that external OpenShell artifacts are embedded.
#
# This script never downloads software or escalates privileges. Install the
# exact configured Syft version separately, or set SYFT_BIN to its executable.
#
# Usage: ./generate-sbom.sh <binary-path> <output-dir>
#
# Outputs:
#   <output-dir>/<name>.spdx.json      — SPDX 2.3 SBOM
#   <output-dir>/<name>.cyclonedx.json — CycloneDX SBOM

SYFT_VERSION="${SYFT_VERSION:-v1.20.0}"
SYFT_BIN="${SYFT_BIN:-syft}"

fail() {
  printf 'generate-sbom: %s\n' "$*" >&2
  exit 1
}

syft_guidance() {
  cat >&2 <<EOF
Install Syft ${SYFT_VERSION} from the reviewed upstream release:
  https://github.com/anchore/syft/releases/tag/${SYFT_VERSION}
Then ensure 'syft' is on PATH, or set:
  SYFT_BIN=/absolute/path/to/syft
This script does not download tools or invoke sudo.
EOF
}

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <binary-path> <output-dir>" >&2
  exit 1
fi

BINARY="$1"
OUTPUT_DIR="$2"

[[ -f "$BINARY" ]] || fail "binary not found at $BINARY"

if [[ "$SYFT_BIN" == */* ]]; then
  if [[ ! -x "$SYFT_BIN" ]]; then
    printf 'generate-sbom: configured SYFT_BIN is not executable: %s\n' "$SYFT_BIN" >&2
    syft_guidance
    exit 1
  fi
elif ! command -v "$SYFT_BIN" >/dev/null 2>&1; then
  printf "generate-sbom: Syft %s is required but '%s' was not found\n" \
    "$SYFT_VERSION" "$SYFT_BIN" >&2
  syft_guidance
  exit 1
fi

VERSION_OUTPUT="$("$SYFT_BIN" version 2>&1)" \
  || fail "could not query Syft version from $SYFT_BIN"
INSTALLED_VERSION="$(awk -F: '/^Version:[[:space:]]*/ { value=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value; exit }' <<<"$VERSION_OUTPUT")"
EXPECTED_VERSION="${SYFT_VERSION#v}"
if [[ -z "$INSTALLED_VERSION" || "$INSTALLED_VERSION" != "$EXPECTED_VERSION" ]]; then
  printf 'generate-sbom: Syft version mismatch: required %s, found %s\n' \
    "$SYFT_VERSION" "${INSTALLED_VERSION:-unrecognized}" >&2
  syft_guidance
  exit 1
fi
printf 'syft: %s (%s)\n' "$SYFT_VERSION" "$SYFT_BIN"

mkdir -p "$OUTPUT_DIR"

BASENAME="$(basename "$BINARY")"
SPDX_OUT="$OUTPUT_DIR/${BASENAME}.spdx.json"
CDX_OUT="$OUTPUT_DIR/${BASENAME}.cyclonedx.json"

echo "Generating SBOMs for $BASENAME..."

"$SYFT_BIN" "$BINARY" -o "spdx-json=$SPDX_OUT"
echo "  SPDX:   $SPDX_OUT"

"$SYFT_BIN" "$BINARY" -o "cyclonedx-json=$CDX_OUT"
echo "  CycloneDX: $CDX_OUT"

# Print SHA-256 for evidence manifest.
echo ""
echo "SHA-256 checksums:"
shasum -a 256 "$SPDX_OUT" "$CDX_OUT"
