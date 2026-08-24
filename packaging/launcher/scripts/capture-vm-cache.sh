#!/usr/bin/env bash
# Capture the prepared VM cache after a successful warm-up so it can ship as
# a release asset. The cache is arch-scoped and keyed by the pinned OpenShell
# version + image identity — the driver accepts it on any same-arch machine.
#
# Usage (builder machine, after `obs provision` warmed the cache):
#   ./capture-vm-cache.sh [output-dir]
# Publishing is maintainer-only and requires salamisandwich77's explicit token:
#   GH_TOKEN="$(gh auth token --user salamisandwich77)" gh release upload ...
set -Eeuo pipefail
if [[ -z "${BASH_VERSION:-}" ]]; then
  exec bash "$0" "$@"
fi

OUT="${1:-.}"
CACHE_DIR="${OPENBOX_VM_CACHE_DIR:-$HOME/.local/state/openshell-vm-driver-${USER:-user}-openshell/images}"
if [[ ! -d "$CACHE_DIR" ]]; then
  echo "error: no VM cache at $CACHE_DIR — provision + warm first" >&2
  exit 1
fi
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) NAME="prepared-vm-cache-darwin-arm64" ;;
  Linux-x86_64) NAME="prepared-vm-cache-linux-x86_64" ;;
  *) echo "error: unsupported platform"; exit 1 ;;
esac
mkdir -p "$OUT"
# The cache must carry its own image identity — the wizard reads this to set
# the sandbox image without touching any container runtime.
printf '%s' "$OPENBOX_SANDBOX_IMAGE" > "$CACHE_DIR/cache-image"
echo "capturing $CACHE_DIR -> $OUT/$NAME.tar.gz"
# Tar the CONTENTS of the images dir — extraction targets the driver's
# images dir directly, so no nested images/ prefix may exist in the tar.
tar -czf "$OUT/$NAME.tar.gz" -C "$CACHE_DIR" .
shasum -a 256 "$OUT/$NAME.tar.gz"
echo "done — upload with the explicit maintainer account:"
echo "  GH_TOKEN=\"\$(gh auth token --user salamisandwich77)\" gh release upload v0.1.0 $OUT/$NAME.tar.gz"
echo "  GH_TOKEN=\"\$(gh auth token --user salamisandwich77)\" gh release upload v0.1.0-dev $OUT/$NAME.tar.gz"
