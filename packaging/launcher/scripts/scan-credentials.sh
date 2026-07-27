#!/usr/bin/env bash
set -euo pipefail

# Scan for credential files that must not be included in releases.
# Matches the pattern from openbox-sandbox-poc/package-gate3-service.sh.
#
# Usage: ./scan-credentials.sh <directory>
#
# Exits non-zero if any credential files are found.

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <directory>" >&2
  exit 1
fi

DIR="$1"

if [[ ! -d "$DIR" ]]; then
  echo "Error: directory not found at $DIR" >&2
  exit 1
fi

echo "Scanning $DIR for credential files..."

FOUND=0

# Private keys
while IFS= read -r -d '' file; do
  echo "  REJECT: private key: $file"
  FOUND=1
done < <(find "$DIR" -type f \( -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" -o -name "*.pkcs8" -o -name "*.ed25519" \) -print0 2>/dev/null)

# SSH keys
while IFS= read -r -d '' file; do
  echo "  REJECT: SSH key: $file"
  FOUND=1
done < <(find "$DIR" -type f \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "*.pub" \) -not -path "*/target/*" -print0 2>/dev/null)

# Cloud credentials
while IFS= read -r -d '' file; do
  echo "  REJECT: cloud credential: $file"
  FOUND=1
done < <(find "$DIR" -type f \( -name ".env" -o -name ".env.*" -o -name "credentials" -o -name "credentials.json" -o -name "service-account*.json" -o -name "*.credentials" \) -not -path "*/target/*" -print0 2>/dev/null)

# Certificate bundles (excluding CA certs and test fixtures)
while IFS= read -r -d '' file; do
  # Allow test fixtures in tests/ directories
  if [[ "$file" == */tests/* ]] || [[ "$file" == */test/* ]]; then
    continue
  fi
  echo "  REJECT: certificate bundle: $file"
  FOUND=1
done < <(find "$DIR" -type f \( -name "*.p12" -o -name "*.pfx" -o -name "ca-bundle.crt" -o -name "client.p12" \) -not -path "*/target/*" -print0 2>/dev/null)

if [[ "$FOUND" -eq 1 ]]; then
  echo ""
  echo "FAIL: credential files found in release candidate directory"
  exit 1
fi

echo "  OK: no credential files found"
