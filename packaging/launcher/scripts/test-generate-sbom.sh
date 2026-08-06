#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATE="$SCRIPT_DIR/generate-sbom.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

binary="$TMP/openbox-sandbox-linux-amd64"
printf 'launcher fixture\n' >"$binary"

# Missing tools fail with actionable, non-escalating guidance. Poisoned curl
# and sudo commands prove the generator never tries either fallback.
mkdir -p "$TMP/poison-bin"
for command in curl sudo; do
  cat >"$TMP/poison-bin/$command" <<EOF
#!/usr/bin/env bash
touch '$TMP/${command}-was-called'
exit 99
EOF
  chmod 0755 "$TMP/poison-bin/$command"
done
if PATH="$TMP/poison-bin:$PATH" SYFT_BIN="$TMP/missing-syft" \
  "$GENERATE" "$binary" "$TMP/missing-output" >"$TMP/stdout" 2>"$TMP/stderr"; then
  echo 'expected missing Syft to fail' >&2
  exit 1
fi
grep -q 'configured SYFT_BIN is not executable' "$TMP/stderr"
grep -q 'https://github.com/anchore/syft/releases/tag/v1.20.0' "$TMP/stderr"
grep -q 'This script does not download tools or invoke sudo' "$TMP/stderr"
test ! -e "$TMP/curl-was-called"
test ! -e "$TMP/sudo-was-called"
test ! -d "$TMP/missing-output"

make_fake_syft() {
  local path="$1" version="$2"
  cat >"$path" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ \${1:-} == version ]]; then
  cat <<VERSION
Application: syft
Version: ${version}
VERSION
  exit 0
fi
[[ \$# -eq 3 && \$2 == -o ]]
output="\${3#*=}"
format="\${3%%=*}"
printf '{"format":"%s","source":"%s"}\\n' "\$format" "\$1" >"\$output"
EOF
  chmod 0755 "$path"
}

make_fake_syft "$TMP/syft-mismatch" '1.19.0'
if SYFT_BIN="$TMP/syft-mismatch" "$GENERATE" "$binary" "$TMP/mismatch-output" \
  >"$TMP/stdout" 2>"$TMP/stderr"; then
  echo 'expected mismatched Syft to fail' >&2
  exit 1
fi
grep -q 'Syft version mismatch: required v1.20.0, found 1.19.0' "$TMP/stderr"
test ! -d "$TMP/mismatch-output"

make_fake_syft "$TMP/syft-match" '1.20.0'
SYFT_BIN="$TMP/syft-match" "$GENERATE" "$binary" "$TMP/output" \
  >"$TMP/stdout" 2>"$TMP/stderr"
spdx="$TMP/output/$(basename "$binary").spdx.json"
cyclonedx="$TMP/output/$(basename "$binary").cyclonedx.json"
test -f "$spdx"
test -f "$cyclonedx"
grep -q '"format":"spdx-json"' "$spdx"
grep -q '"format":"cyclonedx-json"' "$cyclonedx"
grep -q "syft: v1.20.0 ($TMP/syft-match)" "$TMP/stdout"
grep -q 'SHA-256 checksums:' "$TMP/stdout"

printf 'SBOM generator toolchain tests passed\n'
