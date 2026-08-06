#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY="$SCRIPT_DIR/verify-release.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
RELEASE="$TMP/release"
mkdir -p "$RELEASE" "$TMP/bin"

# Keep the test independent of whether the host has cosign. Presence and
# command construction are under test here; cryptographic trust is exercised
# by real release verification with the installed cosign tool.
cat >"$TMP/bin/cosign" <<'EOF'
#!/usr/bin/env bash
[[ $1 == verify-blob ]]
EOF
chmod 0755 "$TMP/bin/cosign"

name='openbox-sandbox-linux-amd64'
printf 'launcher\n' >"$RELEASE/$name"
printf '{}\n' >"$RELEASE/$name.spdx.json"
printf '{}\n' >"$RELEASE/$name.cyclonedx.json"
printf '{}\n' >"$RELEASE/$name.spdx.json.sbom.bundle.json"
(
  cd "$RELEASE"
  shasum -a 256 openbox-sandbox-* >SHA256SUMS
)
PATH="$TMP/bin:$PATH" "$VERIFY" "$RELEASE" >"$TMP/valid.out"
grep -q 'SPDX cosign signature verified' "$TMP/valid.out"

rm "$RELEASE/$name.cyclonedx.json"
(
  cd "$RELEASE"
  shasum -a 256 openbox-sandbox-* >SHA256SUMS
)
if PATH="$TMP/bin:$PATH" "$VERIFY" "$RELEASE" >"$TMP/missing.out" 2>&1; then
  echo 'expected a missing CycloneDX SBOM to fail verification' >&2
  exit 1
fi
grep -q 'CycloneDX SBOM missing' "$TMP/missing.out"

printf 'release verifier tests passed\n'
