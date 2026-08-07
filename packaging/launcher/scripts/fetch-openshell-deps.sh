#!/usr/bin/env bash
# Fetch the pinned OpenShell release into a bundle directory so the launcher can
# resolve it via $OPENBOX_BUNDLE_DIR. This is the supply-chain-safe alternative
# to `brew install openshell` (which tracks latest and can drift off the pin).
#
# Cross-platform: works on macOS (aarch64-apple-darwin) AND Linux/WSL2
# (aarch64|x86_64-unknown-linux-{gnu,musl}). The per-tarball sha256 is read from
# OpenShell's published checksum files rather than hardcoded per-platform, so the
# same script fetches the right artifact set on either host.
#
# What it does:
#   1. Detects OS/arch and maps to an OpenShell release target triple
#      (apple-darwin / unknown-linux-gnu / unknown-linux-musl).
#   2. Downloads the pinned OpenShell release tarballs for that triple.
#   3. Verifies each tarball's sha256 against OpenShell's published checksum file
#      for that release — a moved or compromised release cannot substitute.
#   4. Extracts into $OUT and points OPENBOX_BUNDLE_DIR at the result.
#
# These are *release-tarball* hashes. The launcher does NOT hash the extracted
# binaries at runtime (Homebrew re-signs mach-Os on install, so the on-disk hash
# is not stable); the tarball hash is the supply-chain guard, applied here.
#
# Usage:
#   ./fetch-openshell-deps.sh                       # default ./openbox-sandbox-bundle
#   OUT=/tmp/obs ./fetch-openshell-deps.sh
#   OPENBOX_OPENSHELL_VERSION=0.0.85 ./fetch-openshell-deps.sh
#   TARGET_TRIPLE=aarch64-unknown-linux-gnu ./fetch-openshell-deps.sh
#
# Then run the launcher against it:
#   OPENBOX_BUNDLE_DIR="$OUT" cargo run -- --dry-run

set -euo pipefail

OPENSHELL_VERSION="${OPENBOX_OPENSHELL_VERSION:-0.0.85}"
OUT="${OUT:-$(pwd)/openbox-sandbox-bundle}"
BASE="https://github.com/NVIDIA/OpenShell/releases/download/v${OPENSHELL_VERSION}"

# ── Detect OS/arch → OpenShell release target triple ─────────────────────────
detect_triple() {
  if [[ -n "${TARGET_TRIPLE:-}" ]]; then echo "$TARGET_TRIPLE"; return; fi
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"   # darwin | linux
  arch="$(uname -m)"                                # arm64 | aarch64 | x86_64
  # Normalize Apple's 'arm64' to the release triple's 'aarch64'.
  case "$arch" in arm64|aarch64) arch="aarch64";; esac
  case "$os" in
    darwin) echo "${arch}-apple-darwin";;
    linux)  echo "${arch}-unknown-linux-gnu";;
    *) echo "unsupported os: $os" >&2; exit 1;;
  esac
}

TRIPLE="$(detect_triple)"
# The CLI tarball uses -musl for linux (matches the formula convention); the
# gateway and driver-vm use -gnu. Allow overriding the suffix per artifact.
musl_triple="${TRIPLE%-gnu}-musl"

# ── Hosted-bin mode: fetch a prebuilt pinned bundle ─────────────────────────
# When OPENBOX_OPENSHELL_BUNDLE_URL is set, fetch the operator-hosted bundle
# (openbox-sandbox-bundle-<TRIPLE>.tar.gz + SHA256SUMS served from the
# "hosted bin" release server) instead of GitHub release tarballs. This is
# the toolchain-free flow: the tarball contains the source-built, pin-verified,
# supervisor-embedded binaries (bin/openshell, bin/openshell-gateway,
# libexec/openshell-driver-vm).
BUNDLE_URL="${OPENBOX_OPENSHELL_BUNDLE_URL:-}"
if [[ -n "$BUNDLE_URL" ]]; then
  # Private-release support: when GH_TOKEN is set (e.g. from `gh auth token`),
  # requests carry the bearer token; public releases need no auth. For
  # github.com bases the fetch goes through the API's octet-stream endpoint:
  # plain curl loses the Authorization header on the cross-host redirect and
  # the direct /releases/download/ URL now 404s even with a valid token.
  AUTH_HEADER=()
  if [[ -n "${GH_TOKEN:-}" ]]; then
    AUTH_HEADER=(-H "Authorization: Bearer $GH_TOKEN")
  fi
  BUNDLE_ARCHIVE="openbox-sandbox-bundle-${TRIPLE}.tar.gz"
  work="$(mktemp -d)"
  trap 'rm -rf "${work}"' EXIT
  echo "==> fetching hosted bundle ${BUNDLE_URL}/${BUNDLE_ARCHIVE}"
  mkdir -p "${OUT}/bin" "${OUT}/libexec"
  fetch_asset() {
    local name="$1" out="$2" id=""
    if [[ "$BUNDLE_URL" == https://github.com/* || "$BUNDLE_URL" == http://github.com/* ]] \
      && command -v python3 >/dev/null 2>&1; then
      local rel owner rest repo tag
      rel="${BUNDLE_URL#https://github.com/}"
      rel="${rel#http://github.com/}"
      owner="${rel%%/*}"
      rest="${rel#*/}"
      repo="${rest%%/*}"
      tag="${rest#*/}"
      tag="${tag#releases/download/}"
      tag="${tag%/}"
      # The "latest" alias has no tags/<tag> API endpoint; resolve it via
      # releases/latest instead.
      local api_path
      if [[ "$tag" == "latest" ]]; then
        api_path="releases/latest"
      else
        api_path="releases/tags/${tag}"
      fi
      id="$(curl -fsSL "${AUTH_HEADER[@]}" \
        "https://api.github.com/repos/${owner}/${repo}/${api_path}" \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print(next((a['id'] for a in d['assets'] if a['name']=='${name}'), ''))" 2>/dev/null || true)"
      if [[ -n "$id" ]]; then
        curl -fsSL "${AUTH_HEADER[@]}" -H "Accept: application/octet-stream" \
          "https://api.github.com/repos/${owner}/${repo}/releases/assets/${id}" -o "$out"
        return 0
      fi
    fi
    # Fallback: plain release-asset URL (public repos, or local hosted server).
    curl -fsSL "${AUTH_HEADER[@]}" "${BUNDLE_URL}/${name}" -o "$out"
  }
  fetch_asset "$BUNDLE_ARCHIVE" "${work}/${BUNDLE_ARCHIVE}"
  fetch_asset "SHA256SUMS" "${work}/SHA256SUMS"
  expected="$(awk -v a="$BUNDLE_ARCHIVE" '$2==a {print $1}' "${work}/SHA256SUMS")"
  [[ -n "$expected" ]] || { echo "error: SHA256SUMS missing entry for ${BUNDLE_ARCHIVE}" >&2; exit 1; }
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "${work}/${BUNDLE_ARCHIVE}" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    got="$(shasum -a 256 "${work}/${BUNDLE_ARCHIVE}" | awk '{print $1}')"
  else
    echo "error: neither sha256sum nor shasum is available" >&2; exit 1
  fi
  if [[ "$got" != "$expected" ]]; then
    echo "error: sha256 mismatch for ${BUNDLE_ARCHIVE}" >&2
    echo "  expected ${expected}" >&2
    echo "  found    ${got}" >&2
    exit 1
  fi
  echo "  sha256 verified (${expected:0:12}…)"
  tar -xzf "${work}/${BUNDLE_ARCHIVE}" -C "${work}"
  install -d "${OUT}/bin" "${OUT}/libexec"
  install -m 0755 "${work}/bin/openshell" "${OUT}/bin/openshell"
  install -m 0755 "${work}/bin/openshell-gateway" "${OUT}/bin/openshell-gateway"
  install -m 0755 "${work}/libexec/openshell-driver-vm" "${OUT}/libexec/openshell-driver-vm"
  echo "==> bundle ready: ${OUT}"
  echo "    gateway : ${OUT}/bin/openshell-gateway"
  echo "    driver  : ${OUT}/libexec/openshell-driver-vm"
  echo "    cli     : ${OUT}/bin/openshell"
  exit 0
fi

echo "==> fetching OpenShell v${OPENSHELL_VERSION} for ${TRIPLE} into ${OUT}"

mkdir -p "${OUT}/bin" "${OUT}/libexec"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# Fetch a published checksum file and resolve the hash for a given asset name.
# Falls back to the formula-pinned macOS darwin values if the checksum file is
# unavailable (keeps the macOS path working even offline-of-checksums).
checksum_for() {
  local asset="$1" cfile="$2" fallback="$3"
  local got
  got="$(curl -fsSL "${BASE}/${cfile}" 2>/dev/null | awk -v a="$asset" '$2==a {print $1}')"
  if [[ -z "$got" ]]; then
    if [[ -n "$fallback" ]]; then echo "$fallback"; return; fi
    echo "error: ${cfile} missing checksum for ${asset}" >&2; exit 1
  fi
  echo "$got"
}

verify_and_extract() {
  local asset="$1" cfile="$2" fallback_sha="${3:-}"
  local url="${BASE}/${asset}"
  local dst="${work}/${asset}"
  local expected
  expected="$(checksum_for "$asset" "$cfile" "$fallback_sha")"
  echo "  downloading ${asset}"
  command -v curl >/dev/null 2>&1 || { echo "error: curl is required" >&2; exit 1; }
  curl -fsSL "${url}" -o "${dst}"
  local got
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "${dst}" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    got="$(shasum -a 256 "${dst}" | awk '{print $1}')"
  else
    echo "error: neither sha256sum nor shasum is available" >&2; exit 1
  fi
  if [[ "${got}" != "${expected}" ]]; then
    echo "error: sha256 mismatch for ${asset}" >&2
    echo "  expected ${expected}" >&2
    echo "  found    ${got}" >&2
    echo "refusing to extract — the release tarball is not the pinned one." >&2
    exit 1
  fi
  echo "  sha256 verified (${expected:0:12}…)"
  tar -xzf "${dst}" -C "${work}"
}

# macOS darwin formula-pinned fallbacks (used only if the checksum file fetch
# fails). Linux has no formula, so it relies on the published checksum files.
darwin_fallback_gateway="5de3e08ad1bdb0cdd01373999f537edca3d8aca22ae1c29bc9926969fe401e45"
darwin_fallback_cli="522c963f9515c7325b978e89022de76227ac245eefe1371292af1424434e2067"
darwin_fallback_driver="c33a6f6ebd22c847fee764a0a15b1a577fb29f5624dfcc81c6a727f3eebc421b"

# Per-triple asset name convention:
#   gateway  : openshell-gateway-<TRIPLE>.tar.gz            (darwin / linux-gnu)
#   driver-vm: openshell-driver-vm-<TRIPLE>.tar.gz          (darwin / linux-gnu)
#   cli      : openshell-<TRIPLE>.tar.gz                   (darwin) / openshell-<musl_triple>.tar.gz (linux)
case "$TRIPLE" in
  *-apple-darwin)
    verify_and_extract "openshell-gateway-${TRIPLE}.tar.gz" "openshell-gateway-checksums-sha256.txt" "$darwin_fallback_gateway"
    verify_and_extract "openshell-driver-vm-${TRIPLE}.tar.gz" "openshell-checksums-sha256.txt" "$darwin_fallback_driver"
    verify_and_extract "openshell-${TRIPLE}.tar.gz" "openshell-checksums-sha256.txt" "$darwin_fallback_cli"
    ;;
  *-unknown-linux-gnu)
    # gateway + driver use the gnu triple; the CLI ships a musl triple for linux.
    verify_and_extract "openshell-gateway-${TRIPLE}.tar.gz" "openshell-gateway-checksums-sha256.txt" ""
    verify_and_extract "openshell-driver-vm-${TRIPLE}.tar.gz" "openshell-checksums-sha256.txt" ""
    verify_and_extract "openshell-${musl_triple}.tar.gz" "openshell-checksums-sha256.txt" ""
    ;;
  *-unknown-linux-musl)
    verify_and_extract "openshell-gateway-${TRIPLE}.tar.gz" "openshell-gateway-checksums-sha256.txt" ""
    verify_and_extract "openshell-driver-vm-${TRIPLE}.tar.gz" "openshell-checksums-sha256.txt" ""
    verify_and_extract "openshell-${TRIPLE}.tar.gz" "openshell-checksums-sha256.txt" ""
    ;;
  *) echo "unsupported triple: ${TRIPLE} (set TARGET_TRIPLE=)" >&2; exit 1;;
esac

# Locate the binaries in whatever layout the tarballs used and install them.
place() {
  local bin="$1" dest="$2"
  local src
  src="$(find "${work}" -type f -name "${bin}" -perm -u+x 2>/dev/null | head -1)"
  if [[ -z "${src}" ]]; then
    echo "warning: ${bin} not found in extracted tarballs; ${dest} will be absent" >&2
    return 0
  fi
  install -m 0755 "${src}" "${dest}"
  echo "  placed ${bin} -> ${dest}"
}

place openshell-gateway    "${OUT}/bin/openshell-gateway"
place openshell-driver-vm  "${OUT}/libexec/openshell-driver-vm"
place openshell             "${OUT}/bin/openshell"

echo
echo "==> bundle ready: ${OUT}"
echo "    gateway : ${OUT}/bin/openshell-gateway"
echo "    driver  : ${OUT}/libexec/openshell-driver-vm"
echo "    cli     : ${OUT}/bin/openshell"
echo
echo "Run the launcher against it:"
echo "  OPENBOX_BUNDLE_DIR=\"${OUT}\" cargo run -- --dry-run"
echo
echo "Notes:"
echo "  - macOS: extracted binaries are ad-hoc signed but do NOT carry the"
echo "    hypervisor entitlement. The gateway-start script re-signs the VM"
echo "    driver with com.apple.security.hypervisor at runtime."
echo "  - Linux/WSL2: the vm driver needs /dev/kvm; the container drivers"
echo "    (podman/docker) are preferred on Linux and give strict Landlock when the"
echo "    kernel has it."