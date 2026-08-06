#!/usr/bin/env bash
set -euo pipefail

# Verify an OpenBox Sandbox release artifact against its SHA256SUMS manifest.
#
# Usage: ./verify-release.sh <release-dir>
#        ./verify-release.sh --binary <binary-path> <sha256sums-path>
#
# The release directory should contain:
#   - SHA256SUMS
#   - One or more openbox-sandbox-* binaries
#   - Corresponding *.spdx.json and *.cyclonedx.json SBOM files
#   - Corresponding *.spdx.json.sbom.bundle.json cosign bundles
#
# Verification steps:
#   1. SHA-256 checksum verification
#   2. Required dual-format SBOM and signing-bundle presence
#   3. Cosign verification when cosign is installed

usage() {
  echo "Usage: $0 <release-dir>" >&2
  echo "       $0 --binary <binary-path> <sha256sums-path>" >&2
  exit 1
}

[[ $# -ge 1 ]] || usage
[[ $1 == "--binary" || $# -eq 1 ]] || usage

verify_checksums() {
  local dir="$1"
  local sums_file="$dir/SHA256SUMS"

  if [[ ! -f "$sums_file" ]]; then
    echo "ERROR: SHA256SUMS not found in $dir" >&2
    return 1
  fi

  echo "=== SHA-256 Checksum Verification ==="
  (cd "$dir" && shasum -a 256 -c SHA256SUMS)
  echo ""
}

verify_sbom_presence() {
  local dir="$1"

  echo "=== SBOM Presence Check ==="
  local missing=0 binaries=0
  for binary in "$dir"/openbox-sandbox-*; do
    [[ -f "$binary" ]] || continue
    # Skip SBOM files themselves
    [[ "$binary" == *.spdx.json ]] && continue
    [[ "$binary" == *.cyclonedx.json ]] && continue
    [[ "$binary" == *.sbom.bundle.json ]] && continue
    [[ "$binary" == SHA256SUMS ]] && continue
    [[ "$binary" == asset-manifest.json ]] && continue

    binaries=$((binaries + 1))
    local name
    name="$(basename "$binary")"
    local spdx="$dir/${name}.spdx.json"
    local cdx="$dir/${name}.cyclonedx.json"

    if [[ -f "$spdx" ]]; then
      echo "  $name: SPDX SBOM present"
    else
      echo "  $name: ERROR — SPDX SBOM missing" >&2
      missing=1
    fi

    if [[ -f "$cdx" ]]; then
      echo "  $name: CycloneDX SBOM present"
    else
      echo "  $name: ERROR — CycloneDX SBOM missing" >&2
      missing=1
    fi

    local bundle="$dir/${name}.spdx.json.sbom.bundle.json"
    if [[ -f "$bundle" ]]; then
      echo "  $name: cosign bundle present"
    else
      echo "  $name: ERROR — cosign bundle missing" >&2
      missing=1
    fi
  done
  if [[ $binaries -eq 0 ]]; then
    echo "  ERROR — no launcher binaries found" >&2
    missing=1
  fi
  echo ""
  return "$missing"
}

verify_cosign_bundles() {
  local dir="$1" binary name spdx bundle

  echo "=== Cosign Bundle Verification ==="
  if ! command -v cosign &>/dev/null; then
    echo "  cosign not installed — signatures present but cryptographic verification skipped"
    echo "  Install: https://docs.sigstore.dev/cosign/installation/"
    echo ""
    return 0
  fi

  for binary in "$dir"/openbox-sandbox-*; do
    [[ -f "$binary" ]] || continue
    [[ "$binary" == *.spdx.json || "$binary" == *.cyclonedx.json || "$binary" == *.sbom.bundle.json ]] && continue
    name="$(basename "$binary")"
    spdx="$dir/${name}.spdx.json"
    bundle="$dir/${name}.spdx.json.sbom.bundle.json"
    cosign verify-blob \
      --bundle "$bundle" \
      --certificate-identity-regexp 'https://github.com/OpenBox-AI/openbox-sandbox/.github/workflows/build.yml@refs/tags/.*' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "$spdx" >/dev/null
    echo "  $name: SPDX cosign signature verified"
  done
  echo ""
}

# Main
if [[ "$1" == "--binary" ]]; then
  if [[ $# -ne 3 ]]; then
    echo "Usage: $0 --binary <binary-path> <sha256sums-path>" >&2
    exit 1
  fi
  BINARY="$2"
  SUMS="$3"

  if [[ ! -f "$BINARY" ]]; then
    echo "ERROR: binary not found at $BINARY" >&2
    exit 1
  fi
  if [[ ! -f "$SUMS" ]]; then
    echo "ERROR: SHA256SUMS not found at $SUMS" >&2
    exit 1
  fi

  echo "=== Verifying $(basename "$BINARY") ==="
  echo ""
  EXPECTED="$(awk -v name="$(basename "$BINARY")" '$2 == name || $2 == "*" name { print $1 }' "$SUMS")"
  if [[ -z "$EXPECTED" ]]; then
    echo "ERROR: $(basename "$BINARY") not found in SHA256SUMS" >&2
    exit 1
  fi
  ACTUAL="$(shasum -a 256 "$BINARY" | awk '{print $1}')"
  if [[ "$EXPECTED" == "$ACTUAL" ]]; then
    echo "SHA-256: OK ($ACTUAL)"
  else
    echo "SHA-256: MISMATCH" >&2
    echo "  expected: $EXPECTED" >&2
    echo "  actual:   $ACTUAL" >&2
    exit 1
  fi
else
  RELEASE_DIR="$1"

  if [[ ! -d "$RELEASE_DIR" ]]; then
    echo "ERROR: release directory not found at $RELEASE_DIR" >&2
    exit 1
  fi

  echo "OpenBox Sandbox Release Verification"
  echo "====================================="
  echo "Directory: $RELEASE_DIR"
  echo ""

  verify_checksums "$RELEASE_DIR"
  verify_sbom_presence "$RELEASE_DIR"
  verify_cosign_bundles "$RELEASE_DIR"

  echo "=== Asset Manifest ==="
  if [[ -f "$RELEASE_DIR/asset-manifest.json" ]]; then
    echo "  Present — SHA-256 chain tracked"
    if command -v jq &>/dev/null; then
      echo ""
      jq -r '.supply_chain | to_entries[] | "  \(.key): \(.value | tostring | .[0:80])"' "$RELEASE_DIR/asset-manifest.json" 2>/dev/null || true
    fi
  else
    echo "  Not present (optional)"
  fi
  echo ""

  echo "Verification complete."
fi
