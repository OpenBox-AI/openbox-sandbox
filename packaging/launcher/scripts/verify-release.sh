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
#   - Corresponding *.spdx.json SBOM files
#   - Corresponding *.sbom.bundle.json cosign bundles
#
# Verification steps:
#   1. SHA-256 checksum verification
#   2. SBOM presence check
#   3. Cosign bundle presence check (informational — full verification requires cosign)

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <release-dir>" >&2
  echo "       $0 --binary <binary-path> <sha256sums-path>" >&2
  exit 1
fi

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
  local missing=0
  for binary in "$dir"/openbox-sandbox-*; do
    [[ -f "$binary" ]] || continue
    # Skip SBOM files themselves
    [[ "$binary" == *.spdx.json ]] && continue
    [[ "$binary" == *.cyclonedx.json ]] && continue
    [[ "$binary" == *.sbom.bundle.json ]] && continue
    [[ "$binary" == SHA256SUMS ]] && continue
    [[ "$binary" == asset-manifest.json ]] && continue

    local name
    name="$(basename "$binary")"
    local spdx="$dir/${name}.spdx.json"
    local cdx="$dir/${name}.cyclonedx.json"

    if [[ -f "$spdx" ]]; then
      echo "  $name: SPDX SBOM present"
    else
      echo "  $name: WARNING — SPDX SBOM missing"
      missing=1
    fi

    if [[ -f "$cdx" ]]; then
      echo "  $name: CycloneDX SBOM present"
    else
      echo "  $name: WARNING — CycloneDX SBOM missing"
    fi
  done
  echo ""
  return "$missing"
}

verify_cosign_bundles() {
  local dir="$1"

  echo "=== Cosign Bundle Check (informational) ==="
  if ! command -v cosign &>/dev/null; then
    echo "  cosign not installed — skipping bundle verification"
    echo "  Install: https://docs.sigstore.dev/cosign/installation/"
    echo ""
    return 0
  fi

  for bundle in "$dir"/*.sbom.bundle.json; do
    [[ -f "$bundle" ]] || continue
    local name
    name="$(basename "$bundle" .sbom.bundle.json)"
    echo "  $name: cosign bundle found ($(wc -c < "$bundle") bytes)"
    # Full verification requires the original SBOM file
    local spdx="$dir/${name}.spdx.json"
    if [[ -f "$spdx" ]]; then
      echo "    To verify: cosign verify-blob --bundle $bundle --certificate-identity-regexp 'https://github.com/OpenBox-AI/openbox-sandbox/.github/workflows/build.yml@refs/tags/.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com $spdx"
    fi
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
  EXPECTED="$(grep "$(basename "$BINARY")" "$SUMS" | awk '{print $1}')"
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
  verify_sbom_presence "$RELEASE_DIR" || true
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
