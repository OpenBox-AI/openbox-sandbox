#!/usr/bin/env bash
if [[ -z "${BASH_VERSION:-}" ]]; then
  # Re-exec under bash when invoked from another interpreter (zsh, sh, ...).
  if command -v bash >/dev/null 2>&1; then
    exec bash "$0" "$@"
  fi
  echo "error: bash is required but not found on PATH" >&2
  exit 1
fi
# SPDX-License-Identifier: Apache-2.0
#
# provision-local-sandbox.sh — atomic local dogfood sandbox stack.
#
# Two reversible phases:
#
#   TEARDOWN (always runs first):
#     - stop the sandbox service this wizard started (pid file)
#     - stop the OpenShell gateway this wizard started (pid file)
#     - free the sandbox service port (17443) and gateway port (17670)
#     - kill any leak VM drivers our gateway spawned
#
#   STATE-CLEAN (only with --uninstall, or --clean-rerun):
#     - delete ~/.local/state/openbox-sandbox
#     - delete ~/.config/openbox-sandbox
#     - delete ~/.config/openshell/gateways/<name>     (gateway CLI metadata)
#     - delete /tmp/openshell-vm-driver-<user>-<name>  (VM driver state)
#     - delete ~/.local/state/openshell/tls            unless --keep-pki
#
#   PROVISION (skipped when --uninstall):
#     1. Codesign the VM driver with Hypervisor entitlement (macOS only).
#     2. Generate (or reuse) the local PKI via openshell-gateway generate-certs.
#     3. Start the mTLS VM gateway on https://127.0.0.1:17670
#        with the libkrun microVM compute driver.
#     4. Sign a runtime-caller mTLS leaf off the gateway CA, then compute the
#        sha256 fingerprint the sandbox service must authorize.
#     5. Write the sandbox service config (asset bundle, authorized caller,
#        runtime endpoint, mTLS dir) and start the service on 127.0.0.1:17443.
#     6. Emit ~/.config/openbox-sandbox/agent.env with the env contract the
#        OpenBox SDK agent consumes.
#
# Modes:
#   bash provision-local-sandbox.sh               Teardown -> Provision (default)
#   bash provision-local-sandbox.sh --clean-rerun Teardown -> State-clean -> Provision
#   bash provision-local-sandbox.sh --uninstall    Teardown -> State-clean -> exit 0
#   bash provision-local-sandbox.sh --keep-pki     (with --uninstall/--clean-rerun)
#                                                 Preserve ~/.local/state/openshell/tls
#
# Clean-state guarantee:
#   From a source checkout, `obs uninstall && obs provision` and
#   `obs provision --clean-rerun` both remove wizard-owned state before
#   provisioning. Fresh PKI and timestamps intentionally differ between runs.
#
# Env (see OPENBOX_SANDBOX_* / OPENSHELL_* defaults below).

set -Eeuo pipefail
# Name the failing line instead of dying silently under errexit.
trap 'echo "provision failed at line $LINENO (exit $?)" >&2' ERR
umask 077

die() { printf 'provision: %s\n' "$*" >&2; exit 1; }
# Portable sha256 (sha256sum on Linux, shasum on macOS).
sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "neither sha256sum nor shasum is available"
  fi
}
# Portable listen check (lsof preferred, /dev/tcp fallback).
port_listening() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  else
    (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1
  fi
}
resolve_runtime() {
  RUNTIME="${CONTAINER_RUNTIME:-}"
  if [[ -n "$RUNTIME" ]]; then
    command -v "$RUNTIME" >/dev/null 2>&1 && return 0
    return 1
  fi
  if command -v docker >/dev/null 2>&1 && docker ps >/dev/null 2>&1; then
    RUNTIME="docker"
    return 0
  fi
  if command -v podman >/dev/null 2>&1 && podman ps >/dev/null 2>&1; then
    RUNTIME="podman"
    return 0
  fi
  return 1
}

info() { printf '  ==> %s\n' "$*" >&2; }
ok()   { printf '  [ok] %s\n' "$*" >&2; }
err()  { printf '  [err] %s\n' "$*" >&2; }
warn() { printf '  [warn] %s\n' "$*" >&2; }

channel_tag() {
  case "$RELEASE_LINE" in
    dev) printf '%s\n' "v0.1.0-dev" ;;
    *)   printf '%s\n' "v0.1.0" ;;
  esac
}

resolve_sums_file() {
  local candidate tag
  for candidate in "$LAUNCHER_DIR/SHA256SUMS" "$(pwd)/SHA256SUMS"; do
    if [[ -f "$candidate" ]]; then
      SUMS_FILE="$candidate"
      return 0
    fi
  done
  SUMS_FILE=""
  command -v gh >/dev/null 2>&1 || return 1
  tag="$(channel_tag)"
  if gh release download "$tag" --repo OpenBox-AI/openbox-sandbox \
      --pattern SHA256SUMS --clobber >/dev/null 2>&1; then
    SUMS_FILE="$(pwd)/SHA256SUMS"
    return 0
  fi
  return 1
}

expect_sha() {
  local name="$1"
  resolve_sums_file >/dev/null 2>&1 || true
  [[ -n "$SUMS_FILE" && -f "$SUMS_FILE" ]] || return 0
  awk -v n="$name" '$2 == n { print $1; exit }' "$SUMS_FILE" 2>/dev/null || true
}

verify_asset() {
  local path="$1" name="$2" expected actual tag asset_dir downloaded_sha was_executable
  VERIFY_ASSET_ERROR=""
  if [[ -z "$path" || ! -f "$path" ]]; then
    VERIFY_ASSET_ERROR="$name is missing at ${path:-<empty path>}"
    return 1
  fi

  resolve_sums_file >/dev/null 2>&1 || true
  expected=""
  if [[ -n "$SUMS_FILE" && -f "$SUMS_FILE" ]]; then
    expected="$(awk -v n="$name" '$2 == n { print $1; exit }' "$SUMS_FILE" 2>/dev/null || true)"
  fi
  if [[ -z "$expected" ]]; then
    warn "no published checksum for $name — using local copy"
    return 0
  fi

  actual="$(sha256_hex "$path")"
  [[ "$actual" == "$expected" ]] && return 0

  VERIFY_ASSET_ERROR="sha256 mismatch for $name: expected $expected, got $actual"
  warn "$VERIFY_ASSET_ERROR — removing and re-downloading"
  was_executable=0
  [[ -x "$path" ]] && was_executable=1
  rm -f "$path"
  if ! command -v gh >/dev/null 2>&1; then
    VERIFY_ASSET_ERROR="$VERIFY_ASSET_ERROR; gh is unavailable for re-download"
    return 1
  fi

  tag="$(channel_tag)"
  asset_dir="$(cd "$(dirname "$path")" && pwd)"
  if ! gh release download "$tag" --repo OpenBox-AI/openbox-sandbox \
      --pattern "$name" --clobber --dir "$asset_dir" >/dev/null 2>&1; then
    VERIFY_ASSET_ERROR="$VERIFY_ASSET_ERROR; re-download from $tag failed"
    return 1
  fi
  if [[ ! -f "$path" && -f "$asset_dir/$name" ]]; then
    mv "$asset_dir/$name" "$path"
  fi
  if [[ ! -f "$path" ]]; then
    VERIFY_ASSET_ERROR="$VERIFY_ASSET_ERROR; re-download from $tag did not produce $path"
    return 1
  fi
  if [[ "$was_executable" == "1" ]]; then
    chmod +x "$path" 2>/dev/null || true
  fi

  downloaded_sha="$(sha256_hex "$path")"
  if [[ "$downloaded_sha" != "$expected" ]]; then
    warn "sha256 mismatch for re-downloaded $name: expected $expected, got $downloaded_sha"
    rm -f "$path"
    VERIFY_ASSET_ERROR="sha256 mismatch for re-downloaded $name: expected $expected, got $downloaded_sha"
    return 1
  fi
  ok "$name checksum verified after re-download ($expected)"
  return 0
}

# ─── Arg parsing (before binary checks; uninstall needs no bundle) ──────────
ARG_UNINSTALL=0
ARG_CLEAN_RERUN=0
ARG_KEEP_PKI=0
ARG_PURGE_CACHE="${OPENBOX_PURGE_CACHE:-0}"
VERIFY_PROVISION_ASSETS=1
for arg in "$@"; do
  case "$arg" in
    --uninstall)     ARG_UNINSTALL=1 ;;
    --clean-rerun)   ARG_CLEAN_RERUN=1 ;;
    --purge-cache)   ARG_PURGE_CACHE=1 ;;
    --keep-pki)      ARG_KEEP_PKI=1 ;;
    --help|-h)       sed -n '1,55p' "$0"; exit 0 ;;
    --)              break ;;
    *)               die "unsupported arg: $arg (use --uninstall|--clean-rerun|--keep-pki)" ;;
  esac
done
if [[ "$ARG_KEEP_PKI" == "1" && "$ARG_UNINSTALL" != "1" && "$ARG_CLEAN_RERUN" != "1" ]]; then
  die "--keep-pki requires --uninstall or --clean-rerun"
fi
if [[ "$ARG_PURGE_CACHE" == "1" && "$ARG_UNINSTALL" != "1" && "$ARG_CLEAN_RERUN" != "1" ]]; then
  die "--purge-cache requires --uninstall or --clean-rerun"
fi
if [[ "$ARG_UNINSTALL" == "1" || "${OPENBOX_TEARDOWN_ONLY:-0}" == "1" ]]; then
  VERIFY_PROVISION_ASSETS=0
fi

# ─── Defaults ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER_DIR="$SCRIPT_DIR"
RELEASE_LINE="${OPENBOX_RELEASE_LINE:-base}"
SUMS_FILE=""
VERIFY_ASSET_ERROR=""
info "release line: $RELEASE_LINE (the launcher passes the binary's channel; --dev/--base override)"
# Standalone (embedded-script) mode has no source checkout: operators must
# provide the policy path explicitly; PROJECT_ROOT then only supplies the
# checked-in defaults for source-tree runs.
PROJECT_ROOT="${OPENBOX_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"

if [[ -n "${OPENSHELL_BUNDLE_DIR:-}" && "${OPENSHELL_BUNDLE_DIR}" == /* ]]; then
  BUNDLE_DIR="$OPENSHELL_BUNDLE_DIR"
else
  # If OPENSHELL_BUNDLE_DIR is set but relative, resolve it against the
  # working directory before falling back to the repo-root defaults.
  if [[ -n "${OPENSHELL_BUNDLE_DIR:-}" ]]; then
    BUNDLE_DIR="$(cd "$OPENSHELL_BUNDLE_DIR" && pwd)"
  fi
  # Platform-aware: the bundle carries a per-platform directory
  # (darwin-arm64 on macOS, the flat layout elsewhere). Also try the
  # working-directory bundle (release binaries run from an empty cwd).
  OS_NAME="$(uname -s)"
  MACHINE="$(uname -m)"
  if [[ "$OS_NAME" == "Darwin" && "$MACHINE" == "arm64" ]]; then
    for base in "${BUNDLE_DIR:-}" "$PROJECT_ROOT/openbox-sandbox-bundle" "$(pwd)/openbox-sandbox-bundle"; do
      [[ -n "$base" && -d "$base/darwin-arm64" ]] || continue
      BUNDLE_DIR="$base/darwin-arm64"
      break
    done
  fi
  BUNDLE_DIR="${BUNDLE_DIR:-$PROJECT_ROOT/openbox-sandbox-bundle}"
fi
if [[ -n "${OPENBOX_SANDBOX_BIN:-}" && "${OPENBOX_SANDBOX_BIN}" == /* ]]; then
  SANDBOX_BIN="$OPENBOX_SANDBOX_BIN"
else
  SANDBOX_BIN="$PROJECT_ROOT/${OPENBOX_SANDBOX_BIN:-target/release/openbox-sandbox}"
  # The release bundle places the per-platform service binary directly in
  # the bundle dir; prefer it if it exists.
  for candidate in "$BUNDLE_DIR/openbox-sandbox-darwin-arm64" "$BUNDLE_DIR/openbox-sandbox"; do
    [[ -x "$candidate" ]] || continue
    SANDBOX_BIN="$candidate"
    break
  done
fi
if [[ "$VERIFY_PROVISION_ASSETS" == "1" ]] \
    && ! verify_asset "$SANDBOX_BIN" "$(basename "$SANDBOX_BIN")" \
    && [[ "$VERIFY_ASSET_ERROR" != *" is missing at "* ]]; then
  die "required service binary verification failed: $VERIFY_ASSET_ERROR"
fi
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) _dev_tar_default="openbox-sandbox-dev-darwin-arm64.tar.gz" ;;
  Linux-x86_64) _dev_tar_default="openbox-sandbox-dev-linux-x86_64.tar.gz" ;;
  Linux-aarch64|Linux-arm64) _dev_tar_default="openbox-sandbox-dev-linux-aarch64.tar.gz" ;;
  *) _dev_tar_default="openbox-sandbox-dev-darwin-arm64.tar.gz" ;;
esac
# Release line: explicit env/flag wins. The POLICY FILES are templates — the
# line selects the default template, never the other way around.

# Policy template resolution: an explicit policy file always wins; otherwise
# the channel selects the default template (dev -> allow, base -> deny).
# BOTH templates are downloaded by the launcher, so the choice is never
# blocked on which file happens to be present.
DEFAULT_POLICY_TEMPLATE="policy-deny-network-dev.yaml"
DEFAULT_POLICY_ID="openbox-deny-network-dev"
case "$RELEASE_LINE" in
  dev)  DEFAULT_POLICY_TEMPLATE="policy-allow-network-dev.yaml"
        DEFAULT_POLICY_ID="openbox-allow-network-dev" ;;
  *)    ;;
esac
POLICY_ID="${OPENBOX_POLICY_ID:-$DEFAULT_POLICY_ID}"
if [[ -n "${OPENBOX_POLICY_FILE:-}" && "${OPENBOX_POLICY_FILE}" == /* ]]; then
  POLICY_FILE="$OPENBOX_POLICY_FILE"
  case "$(basename "$POLICY_FILE")" in
    *allow*) POLICY_ID="${OPENBOX_POLICY_ID:-openbox-allow-network-dev}" ;;
  esac
else
  POLICY_FILE=""
  for _cand in "${OPENBOX_POLICY_FILE:-}" "$LAUNCHER_DIR/$DEFAULT_POLICY_TEMPLATE" "$(pwd)/$DEFAULT_POLICY_TEMPLATE" "$PROJECT_ROOT/deploy/policies/$DEFAULT_POLICY_TEMPLATE"; do
    [[ -n "$_cand" && -f "$_cand" ]] || continue
    POLICY_FILE="$(cd "$(dirname "$_cand")" && pwd)/$(basename "$_cand")"
    break
  done
  if [[ -z "$POLICY_FILE" ]]; then
    die "no policy template found for the $RELEASE_LINE line (checked launcher dir $LAUNCHER_DIR, cwd, and repo defaults) — set OPENBOX_POLICY_FILE"
  fi
  info "policy template: $POLICY_FILE (id $POLICY_ID)"
fi
if [[ "$VERIFY_PROVISION_ASSETS" == "1" ]]; then
  verify_asset "$POLICY_FILE" "$(basename "$POLICY_FILE")" \
    || die "required policy verification failed: $VERIFY_ASSET_ERROR"
fi
POLICY_VERSION="${OPENBOX_POLICY_VERSION:-1}"
COMPAT_ID="${OPENBOX_COMPAT_ID:-darwin-dev-1}"
SANDBOX_IMAGE="${OPENBOX_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e}"
# v0.1.0-dev releases ship the dev image tar next to obs — auto-detect it.
# STATE_ROOT/CONFIG_ROOT are hoisted here: the dev-image/runtime section
# below writes its logs under them, before the full defaults block runs.
STATE_ROOT="${OPENBOX_STATE_ROOT:-$HOME/.local/state/openbox-sandbox}"
CONFIG_ROOT="${OPENBOX_CONFIG_ROOT:-$HOME/.config/openbox-sandbox}"
USE_VM_CACHE="${OPENBOX_USE_VM_CACHE:-1}"

DEV_IMAGE_NAME="${OPENBOX_DEV_IMAGE_NAME:-openbox-sandboxes-dev}"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) _cache_default="prepared-vm-cache-darwin-arm64.tar.gz" ;;
  Linux-x86_64) _cache_default="prepared-vm-cache-linux-x86_64.tar.gz" ;;
  *)           _cache_default="" ;;
esac
VM_CACHE_TAR="${OPENBOX_VM_CACHE_TAR:-$_cache_default}"
if [[ -n "${OPENBOX_SANDBOX_DEV_TAR:-}" && "${OPENBOX_SANDBOX_DEV_TAR}" == /* ]]; then
  DEV_TAR="$OPENBOX_SANDBOX_DEV_TAR"
else
  DEV_TAR=""
  for _cand in "${OPENBOX_SANDBOX_DEV_TAR:-}" "$LAUNCHER_DIR/$_dev_tar_default" "$(pwd)/$_dev_tar_default"; do
    [[ -n "$_cand" && -f "$_cand" ]] || continue
    DEV_TAR="$(cd "$(dirname "$_cand")" && pwd)/$(basename "$_cand")"
    break
  done
fi
if [[ "$VERIFY_PROVISION_ASSETS" == "1" && -n "$DEV_TAR" ]]; then
  verify_asset "$DEV_TAR" "$(basename "$DEV_TAR")" \
    || die "required dev tar verification failed: $VERIFY_ASSET_ERROR"
fi
if [[ "$POLICY_ID" == *allow* && -z "$DEV_TAR" ]] \
   && ! docker image inspect openbox-sandboxes-dev:latest >/dev/null 2>&1; then
  die "dev policy selected ($POLICY_ID) but no dev image is available — download the dev image tar first: ./obs update --all"
fi
# Registry-mode assets: discover them NOW so the dev-tar fallback knows
# whether the registry mode will activate. The zot process itself starts
# after teardown (its lifetime spans the warm).
ZOT_BIN="${OPENBOX_ZOT_BIN:-}"
_oci_layout="${OPENBOX_OCI_LAYOUT:-}"
_oci_default=""
_zot_default=""
ZOT_CHECKSUM_NAME=""
ZOT_PID=""
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    _oci_default="openbox-sandbox-dev-darwin-arm64-oci.tar.gz"
    _zot_default="zot-darwin-arm64"
    ;;
  Linux-x86_64)
    _oci_default="openbox-sandbox-dev-linux-x86_64-oci.tar.gz"
    _zot_default="zot-linux-x86_64"
    ;;
esac
if [[ "$USE_VM_CACHE" == "1" && ( -z "$ZOT_BIN" || -z "$_oci_layout" ) ]]; then
  if [[ -z "$_oci_layout" ]]; then
    for _c in "$LAUNCHER_DIR/$_oci_default" "$(pwd)/$_oci_default"; do
      [[ -f "$_c" ]] && _oci_layout="$_c" && break
    done
  fi
  if [[ -z "$ZOT_BIN" ]]; then
    for _z in "$LAUNCHER_DIR/$_zot_default" "$(pwd)/$_zot_default" \
      "$LAUNCHER_DIR/zot" "$(pwd)/zot"; do
      # Release assets download without the exec bit — accept any regular
      # file and fix the mode. Bare "zot" remains a compatibility fallback.
      if [[ -f "$_z" ]]; then
        ZOT_BIN="$_z"
        break
      fi
    done
  fi
fi
if [[ "$VERIFY_PROVISION_ASSETS" == "1" && -n "$_oci_layout" ]]; then
  if ! verify_asset "$_oci_layout" "$(basename "$_oci_layout")"; then
    warn "OCI layout verification failed ($VERIFY_ASSET_ERROR) — falling back to the container runtime path"
    _oci_layout=""
  fi
fi
if [[ "$VERIFY_PROVISION_ASSETS" == "1" && -n "$ZOT_BIN" ]]; then
  ZOT_CHECKSUM_NAME="$(basename "$ZOT_BIN")"
  if [[ -z "$(expect_sha "$ZOT_CHECKSUM_NAME")" && -n "$_zot_default" \
      && "$ZOT_CHECKSUM_NAME" != "$_zot_default" && -n "$(expect_sha "$_zot_default")" ]]; then
    ZOT_CHECKSUM_NAME="$_zot_default"
  fi
  if ! verify_asset "$ZOT_BIN" "$ZOT_CHECKSUM_NAME"; then
    warn "zot verification failed ($VERIFY_ASSET_ERROR) — falling back to the container runtime path"
    ZOT_BIN=""
  fi
fi
if [[ -n "$ZOT_BIN" ]]; then
  chmod +x "$ZOT_BIN" 2>/dev/null || true
fi

if [[ -n "$DEV_TAR" ]] && [[ -z "$ZOT_BIN" || -z "$_oci_layout" ]] && [[ -z "${OPENBOX_SANDBOX_IMAGE:-}" ]]; then
  info "dev release detected ($DEV_TAR) — loading the dev sandbox image so the driver can resolve it locally (registry mode unavailable)"
  if ! resolve_runtime; then
    die "the dev image ref is host-less — the VM driver resolves it through a container runtime or a local registry. Install Docker/Podman, or ship the OCI layout + zot assets"
  fi
  # Container runtime selection (the VM driver speaks the Docker-compatible
  # API: Docker first, then rootless Podman — researched from driver.rs
  # connect_local_container_engine). Explicit CONTAINER_RUNTIME wins.
  if ! resolve_runtime; then
    if command -v brew >/dev/null 2>&1 && [[ "$(uname -s)" == "Darwin" ]]; then
      RUNTIME_LOG="${STATE_ROOT}/brew-podman.log"
      mkdir -p "$STATE_ROOT"
      info "no usable container runtime — installing Podman via Homebrew (log: $RUNTIME_LOG)"
      brew install podman >"$RUNTIME_LOG" 2>&1 \
        || { tail -n 15 "$RUNTIME_LOG" >&2 || true; die "podman install failed — see $RUNTIME_LOG"; }
      info "initializing the Podman machine (first start may take a few minutes)"
      podman machine init >/dev/null 2>&1 || true
      podman machine start >/dev/null 2>&1 \
        || die "podman machine start failed — run 'podman machine init && podman machine start' manually"
      ok "podman installed and running"
      RUNTIME="podman"
    else
      die "no container runtime available — install Docker or Podman and re-run"
    fi
  fi
  info "container runtime: $RUNTIME"
  LOAD_OUTPUT="$(gunzip -c "$DEV_TAR" | "$RUNTIME" load 2>&1)" || {
    err "dev image load failed — runtime output:"
    printf '%s\n' "$LOAD_OUTPUT" >&2
    die "dev image load failed"
  }
  # The digest comes from the tar itself via docker load's reported image ID —
  # never from the mutable ':latest' tag, which can drift across machines.
  DEV_DIGEST="$(printf '%s\n' "$LOAD_OUTPUT" | sed -n 's/.*Loaded image ID: sha256:\([a-f0-9]\+\).*/sha256:\1/p' | head -1)"
  if [[ -z "$DEV_DIGEST" ]]; then
    DEV_DIGEST="$(printf '%s\n' "$LOAD_OUTPUT" | sed -n "s/.*Loaded image: ${DEV_IMAGE_NAME}@sha256:\\([a-f0-9]\\+\\).*/sha256:\\1/p" | head -1)"
  fi
  if [[ -z "$DEV_DIGEST" ]]; then
    DEV_DIGEST="$("$RUNTIME" image inspect "$DEV_IMAGE_NAME:latest" --format '{{.Id}}' 2>/dev/null || true)"
  fi
  if [[ -z "$DEV_DIGEST" ]]; then
    DEV_DIGEST="$("$RUNTIME" images --no-trunc --format '{{.ID}}' "$DEV_IMAGE_NAME:latest" 2>/dev/null | head -1 || true)"
  fi
  if [[ -z "$DEV_DIGEST" ]]; then
    err "could not determine the loaded dev image digest — runtime output:"
    printf '%s\n' "$LOAD_OUTPUT" >&2
    die "the image tar may be malformed or the runtime refused the load"
  fi
  info "dev image digest: $DEV_DIGEST"
  # A docker-save archive has no RepoDigest, so inspecting name@image-ID fails
  # and makes the VM driver fall back to Docker Hub. Resolve the loaded image
  # by its local tag; the driver still keys the prepared cache by its image ID.
  SANDBOX_IMAGE="$DEV_IMAGE_NAME:latest"
fi
PORT="${OPENSHELL_SERVER_PORT:-17670}"
GATEWAY_NAME="${OPENSHELL_GATEWAY_NAME:-openshell}"
SANDBOX_PORT="${OPENBOX_SANDBOX_PORT:-17443}"
LOG_LEVEL="${OPENSHELL_LOG_LEVEL:-info}"
NO_START="${NO_START:-0}"
TEARDOWN_ONLY="${OPENBOX_TEARDOWN_ONLY:-0}"

# Everything else is configurable too — every path, port, size, timeout, and
# identity below has an env override with the shipped default.
CERT_DAYS="${OPENBOX_CERT_DAYS:-825}"
RSA_BITS="${OPENBOX_RSA_BITS:-2048}"
JWT_TTL_SECS="${OPENBOX_JWT_TTL_SECS:-3600}"
GATEWAY_READY_POLLS="${OPENBOX_GATEWAY_READY_POLLS:-60}"
GATEWAY_READY_INTERVAL="${OPENBOX_GATEWAY_READY_INTERVAL:-0.5}"
SERVICE_READY_POLLS="${OPENBOX_SERVICE_READY_POLLS:-40}"
SERVICE_READY_INTERVAL="${OPENBOX_SERVICE_READY_INTERVAL:-0.25}"
VM_CACHE_HIT_TIMEOUT="${OPENBOX_VM_CACHE_HIT_TIMEOUT:-30}"
WARM_POLL_COUNT="${OPENBOX_WARM_POLL_COUNT:-240}"
WARM_POLL_INTERVAL="${OPENBOX_WARM_POLL_INTERVAL:-5}"
RUNTIME_CONNECT_TIMEOUT_MS="${OPENBOX_RUNTIME_CONNECT_TIMEOUT_MS:-10000}"
RUNTIME_POLL_INTERVAL_MS="${OPENBOX_RUNTIME_POLL_INTERVAL_MS:-500}"
RECONCILE_DELETE_DEADLINE_MS="${OPENBOX_RECONCILE_DELETE_DEADLINE_MS:-60000}"
RECONCILE_WAIT_DEADLINE_MS="${OPENBOX_RECONCILE_WAIT_DEADLINE_MS:-60000}"
MAX_CONNECTIONS="${OPENBOX_MAX_CONNECTIONS:-64}"
GATEWAY_LOG_LEVEL="${OPENBOX_GATEWAY_LOG_LEVEL:-info}"
KRUN_LOG_LEVEL="${OPENBOX_KRUN_LOG_LEVEL:-1}"
DRIVER_RUST_LOG="${OPENBOX_DRIVER_RUST_LOG:-}"
DRAIN_TIMEOUT_MS="${OPENBOX_DRAIN_TIMEOUT_MS:-30000}"
ALLOW_DEGRADED_LANDLOCK="${OPENBOX_ALLOW_DEGRADED_LANDLOCK:-true}"
CALLER_SUBJ="${OPENBOX_CALLER_SUBJ:-/CN=openbox-sandbox-runtime-caller}"
RUNTIME_MTLS_DIR="${OPENBOX_RUNTIME_MTLS_DIR:-$CONFIG_ROOT/runtime-mtls}"
OPENSHELL_META_DIR="${OPENBOX_OPENSHELL_META_DIR:-$HOME/.config/openshell}"
OPENSHELL_SOURCE_PIN="f169084923503a02a94425857b938de2841cab0c"
OPENSHELL_SOURCE_MARKER="f1690849"
# Locked released OpenShell version for the hosted-bin flow (no source build).
# Accepted together with the source marker; the live verify test proves the
# wire contract either way.
OPENSHELL_LOCKED_VERSION="${OPENBOX_OPENSHELL_LOCKED_VERSION:-0.0.88}"

# Binary resolution priority (the sandbox protocol is pinned to exact OpenShell
# source commit f1690849; the 0.0.85 release is older and is rejected here):
#   $OPENSHELL_BIN_OVERRIDE/<symlinks>  — explicit directory
#   $OPENSHELL_BUNDLE_DIR (release bundle, prefers ${bin}/${libexec})
#   A flat source-build directory selected through OPENSHELL_BIN_OVERRIDE.
OPENSHELL_BIN_OVERRIDE="${OPENSHELL_BIN_OVERRIDE:-}"
GATEWAY_BIN="${OPENBOX_GATEWAY_BIN:-}"
CLI_BIN="${OPENBOX_CLI_BIN:-}"
DRIVER_BIN="${OPENBOX_DRIVER_BIN:-}"
for _cand in "${GATEWAY_BIN:-}" "$LAUNCHER_DIR/bin/openshell-gateway" "$(pwd)/bin/openshell-gateway" "$(pwd)/openshell-gateway"; do
  [[ -n "$_cand" && -x "$_cand" ]] || continue
  GATEWAY_BIN="$_cand"
  break
done
for _cand in "${CLI_BIN:-}" "$LAUNCHER_DIR/bin/openshell" "$(pwd)/bin/openshell" "$(pwd)/openshell"; do
  [[ -n "$_cand" && -x "$_cand" ]] || continue
  CLI_BIN="$_cand"
  break
done
for _cand in "${DRIVER_BIN:-}" "$LAUNCHER_DIR/libexec/openshell-driver-vm" "$(pwd)/libexec/openshell-driver-vm" "$(pwd)/openshell-driver-vm"; do
  [[ -n "$_cand" && -x "$_cand" ]] || continue
  DRIVER_BIN="$_cand"
  break
done
if [[ -z "$GATEWAY_BIN" || -z "$CLI_BIN" || -z "$DRIVER_BIN" ]] \
   && [[ -n "${OPENSHELL_BIN_OVERRIDE:-}" && -d "${OPENSHELL_BIN_OVERRIDE}" ]]; then
  for layout in "release" "flat"; do
    case "$layout" in
      release)
        g="${OPENSHELL_BIN_OVERRIDE}/bin/openshell-gateway"
        c="${OPENSHELL_BIN_OVERRIDE}/bin/openshell"
        d="${OPENSHELL_BIN_OVERRIDE}/libexec/openshell-driver-vm" ;;
      flat)
        g="${OPENSHELL_BIN_OVERRIDE}/openshell-gateway"
        c="${OPENSHELL_BIN_OVERRIDE}/openshell"
        d="${OPENSHELL_BIN_OVERRIDE}/openshell-driver-vm" ;;
    esac
    if [[ -x "$g" && -x "$c" && -x "$d" ]]; then
      GATEWAY_BIN="$g"; CLI_BIN="$c"; DRIVER_BIN="$d"; break
    fi
  done
fi
# Fall back to the bundle dir for ANY still-missing binary — finding only the
# gateway in the cwd must not leave the CLI/driver empty.
if [[ -z "$GATEWAY_BIN" || -z "$CLI_BIN" || -z "$DRIVER_BIN" ]]; then
  GATEWAY_BIN="${GATEWAY_BIN:-$BUNDLE_DIR/bin/openshell-gateway}"
  CLI_BIN="${CLI_BIN:-$BUNDLE_DIR/bin/openshell}"
  DRIVER_BIN="${DRIVER_BIN:-$BUNDLE_DIR/libexec/openshell-driver-vm}"
fi
for _bin in "$GATEWAY_BIN" "$CLI_BIN" "$DRIVER_BIN"; do
  if [[ ! -x "$_bin" ]]; then
    die "OpenShell binary missing: $_bin — re-run so the launcher can fetch the bundle"
  fi
done

VM_DRIVER_STATE_DIR="${OPENSHELL_VM_DRIVER_STATE_DIR:-$HOME/.local/state/openshell-vm-driver-${USER:-user}-${GATEWAY_NAME}}"
TLS_DIR="${OPENSHELL_LOCAL_TLS_DIR:-$HOME/.local/state/openshell/tls}"

GATEWAY_STATE_DIR="$STATE_ROOT/gateway"
GATEWAY_META_DIR="$HOME/.config/openshell/gateways/$GATEWAY_NAME"
GATEWAY_MTLS_DIR="$GATEWAY_META_DIR/mtls"
SANDBOX_TLS_DIR="$CONFIG_ROOT/tls"
SANDBOX_STATE_DIR="$STATE_ROOT/cleanup"
SERVICE_CONFIG="$CONFIG_ROOT/service.json"
SERVICE_LOG="$STATE_ROOT/sandbox-service.log"
GATEWAY_PID_FILE="$GATEWAY_STATE_DIR/gateway.pid"
GATEWAY_LOG="$GATEWAY_STATE_DIR/gateway.log"
GATEWAY_CONFIG="$GATEWAY_STATE_DIR/gateway.toml"
SANDBOX_PID_FILE="$STATE_ROOT/sandbox-service.pid"
AGENT_ENV="$CONFIG_ROOT/agent.env"

VM_HOST_GATEWAY="host.containers.internal"
GRPC_ENDPOINT="https://${VM_HOST_GATEWAY}:${PORT}"

echo "openbox-sandbox local stack" >&2
info "state:  $STATE_ROOT"
info "config: $CONFIG_ROOT"
[[ "$ARG_UNINSTALL" == "1" ]] && info "mode:   --uninstall"
[[ "$ARG_CLEAN_RERUN" == "1" ]] && info "mode:   --clean-rerun"
echo "" >&2

# Provisioning must reject an incompatible runtime before mutating local state.
# The root adapter is compiled against this source protocol, which is stricter
# than the launcher's separate 0.0.85 artifact/version pin.
if [[ "$ARG_UNINSTALL" != "1" && "$TEARDOWN_ONLY" != "1" ]]; then
  [[ -x "$GATEWAY_BIN" ]] || die "openshell-gateway not found at $GATEWAY_BIN"
  [[ -x "$CLI_BIN" ]] || die "openshell CLI not found at $CLI_BIN"
  [[ -x "$DRIVER_BIN" ]] || die "openshell-driver-vm not found at $DRIVER_BIN"

  require_source_marker() {
    local binary="$1" label="$2" version
    version="$("$binary" --version 2>&1)" \
      || die "$label --version failed: $version"
    if [[ ! "$version" =~ (^|[^[:xdigit:]])g?${OPENSHELL_SOURCE_MARKER}([^[:xdigit:]]|$) \
      && "$version" != *"$OPENSHELL_LOCKED_VERSION"* ]]; then
      cat >&2 <<EOF
provision: incompatible $label: '$version'
provision: required OpenShell source marker $OPENSHELL_SOURCE_MARKER
provision: or locked released version $OPENSHELL_LOCKED_VERSION
provision: (the wire contract is proven by the live verify test).
EOF
      exit 1
    fi
    ok "$label verified ($OPENSHELL_SOURCE_MARKER | $OPENSHELL_LOCKED_VERSION)"
  }

  require_source_marker "$GATEWAY_BIN" "openshell-gateway"
  require_source_marker "$CLI_BIN" "openshell"
  require_source_marker "$DRIVER_BIN" "openshell-driver-vm"
  [[ -x "$SANDBOX_BIN" ]] \
    || die "openbox-sandbox service not found at $SANDBOX_BIN (set OPENBOX_SANDBOX_BIN to the downloaded release binary)"
  [[ -f "$POLICY_FILE" ]] || die "policy file not found at $POLICY_FILE"
fi

# ─── TEARDOWN (always) ───────────────────────────────────────────────────────
process_command() {
  ps -ww -p "$1" -o command= 2>/dev/null | awk 'NF { sub(/^[[:space:]]+/, ""); print; exit }'
}

process_alive() {
  local state
  state="$(ps -p "$1" -o stat= 2>/dev/null | awk 'NF { print; exit }' || true)"
  [[ -n "$state" && "$state" != Z* ]]
}

process_matches() {
  local pid="$1" expected_binary="$2" required_marker="${3:-}" identity_mode="${4:-exact}" command_line executable
  command_line="$(process_command "$pid")"
  [[ -n "$command_line" ]] || return 1
  if [[ "$identity_mode" == "gateway-config" ]]; then
    executable="${command_line%% *}"
    [[ "${executable##*/}" == "openshell-gateway" ]] || return 1
    [[ "$command_line" == *" --config $required_marker" \
      || "$command_line" == *" --config $required_marker "* ]]
  elif [[ "$identity_mode" == "binary-name" ]]; then
    executable="${command_line%% *}"
    [[ "${executable##*/}" == "$expected_binary" ]] || return 1
  else
    [[ "$command_line" == "$expected_binary" || "$command_line" == "$expected_binary "* ]] \
      || return 1
    [[ -z "$required_marker" || "$command_line" == *"$required_marker"* ]]
  fi
}

stop_pid_file() {
  local f="$1" label="$2" expected_binary="$3" required_marker="${4:-}" identity_mode="${5:-exact}" pid expected_description
  [[ -f "$f" ]] || return 0
  pid="$(cat "$f" 2>/dev/null || true)"
  if [[ ! "$pid" =~ ^[1-9][0-9]*$ ]]; then
    die "$label PID file is malformed at $f; refusing teardown"
  fi
  if ! process_alive "$pid"; then
    warn "$label PID file is stale (pid=$pid); removing it"
    rm -f "$f"
    return 0
  fi
  if ! process_matches "$pid" "$expected_binary" "$required_marker" "$identity_mode"; then
    if [[ "$identity_mode" == "gateway-config" ]]; then
      expected_description="openshell-gateway with exact wizard config $required_marker"
    else
      expected_description="$expected_binary${required_marker:+ ... $required_marker}"
    fi
    die "$label PID $pid does not match wizard command '$expected_description'; refusing to signal it"
  fi

  info "stopping validated $label pid=$pid"
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    process_alive "$pid" || break
    sleep "$SERVICE_READY_INTERVAL"
  done
  if process_alive "$pid"; then
    process_matches "$pid" "$expected_binary" "$required_marker" "$identity_mode" \
      || die "$label PID $pid changed identity while stopping; refusing SIGKILL"
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$f"
}

sweep_matching_listeners() {
  local port="$1" expected_binary="$2" pids pid command_line executable
  if ! command -v lsof >/dev/null 2>&1; then
    return 0
  fi
  pids="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)"
  [[ -n "$pids" ]] || return 0
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    command_line="$(process_command "$pid")"
    executable="${command_line%% *}"
    if [[ "${executable##*/}" == "$expected_binary" ]]; then
      warn "killing stale $expected_binary listener pid=$pid (port $port)"
      kill -9 "$pid" 2>/dev/null || true
    fi
  done <<<"$pids"
}

# Portable timeout: run "$@" for at most $1 seconds. macOS lacks the GNU
# `timeout` binary; a wedged gateway must never hang the wizard silently.
run_with_timeout() {
  local secs="$1"; shift
  "$@" &
  local pid=$!
  ( sleep "$secs"; kill -9 "$pid" 2>/dev/null ) &
  local killer=$!
  wait "$pid" 2>/dev/null
  local rc=$?
  kill "$killer" 2>/dev/null
  wait "$killer" 2>/dev/null
  return "$rc"
}

assert_port_free() {
  local port="$1" label="$2" pids pid command_line
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)"
    [[ -z "$pids" ]] && return 0
    warn "$label port $port is still occupied; no unowned listener will be signalled"
    while IFS= read -r pid; do
      [[ -n "$pid" ]] || continue
      command_line="$(process_command "$pid")"
      warn "listener pid=$pid command=${command_line:-unknown}"
      case "$command_line" in
        *homebrew*openshell*|*"brew"*)
          err "a Homebrew openshell is serving this port — stop it first:"
          err "  brew services stop openshell   # or: kill $pid"
          ;;
        *) err "stop the process above and re-run" ;;
      esac
    done <<<"$pids"
    die "$label port $port remains occupied after validated PID teardown"
  fi
  if (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1; then
    die "$label port $port is occupied and lsof is unavailable; refusing unowned teardown"
  fi
}

stop_scoped_vm_drivers() {
  local pid command_line
  local -a scoped_pids=()
  command -v pgrep >/dev/null 2>&1 || return 0
  while IFS= read -r pid; do
    [[ -n "$pid" && "$pid" != "$$" ]] || continue
    command_line="$(process_command "$pid")"
    if [[ "$command_line" == *"openshell-driver-vm"* \
      && "$command_line" == *"--internal-run-vm"* \
      && "$command_line" == *"$VM_DRIVER_STATE_DIR"* ]]; then
      info "stopping wizard-scoped VM driver pid=$pid state=$VM_DRIVER_STATE_DIR"
      kill "$pid" 2>/dev/null || true
      scoped_pids+=("$pid")
    else
      warn "leaving unrelated VM driver pid=$pid command=${command_line:-unknown}"
    fi
  done < <(pgrep -f "openshell-driver-vm --internal-run-vm" 2>/dev/null || true)
  [[ ${#scoped_pids[@]} -eq 0 ]] && return 0
  sleep 1
  for pid in "${scoped_pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      command_line="$(process_command "$pid")"
      die "wizard-scoped VM driver pid=$pid did not stop; refusing state deletion (command=${command_line:-unknown})"
    fi
  done
}

# Stop a wizard-started local image registry (zot) if one is running.
if [[ -f "$STATE_ROOT/zot/zot.pid" ]]; then
  _zot_pid="$(cat "$STATE_ROOT/zot/zot.pid" 2>/dev/null || true)"
  if [[ -n "$_zot_pid" ]] && kill -0 "$_zot_pid" 2>/dev/null; then
    kill "$_zot_pid" 2>/dev/null || true
    info "stopped local image registry (zot pid=$_zot_pid)"
  fi
  rm -f "$STATE_ROOT/zot/zot.pid"
fi
info "Teardown (always)"
stop_pid_file "$SANDBOX_PID_FILE" "sandbox service" "$(basename "$SANDBOX_BIN")" "" "binary-name"
sweep_matching_listeners "$SANDBOX_PORT" "$(basename "$SANDBOX_BIN")"
stop_pid_file "$GATEWAY_PID_FILE" "gateway" "$GATEWAY_BIN" "$GATEWAY_CONFIG" "gateway-config"
assert_port_free "$SANDBOX_PORT" "sandbox service"
assert_port_free "$PORT" "gateway"
stop_scoped_vm_drivers
ok "teardown complete"
echo "" >&2

# ─── Error trap for the provision phase ──────────────────────────────────────
# If anything below (gateway start, mTLS, service start, agent.env) fails, tear
# down ONLY the wizard-owned processes started this run, using the same
# validated-ownership checks as the initial teardown. Never signals unowned
# processes; the validated stops refuse on identity mismatch (fail closed).
provision_error_cleanup() {
  local rc=$?
  trap - EXIT  # disarm first: a validated-stop refusal may die() inside cleanup
  trap - ERR   # teardown steps may legitimately probe dead pids; no trap noise
  if [[ "$rc" != "0" ]]; then
    warn "provision failed (exit $rc); tearing down wizard-owned processes started this run"
    stop_pid_file "$SANDBOX_PID_FILE" "sandbox service" "$(basename "$SANDBOX_BIN")" "" "binary-name"
    stop_pid_file "$GATEWAY_PID_FILE" "gateway" "$GATEWAY_BIN" "$GATEWAY_CONFIG" "gateway-config"
    stop_scoped_vm_drivers
    if [[ -n "${ZOT_PID:-}" ]] && kill -0 "$ZOT_PID" 2>/dev/null; then
      kill "$ZOT_PID" 2>/dev/null || true
      rm -f "$STATE_ROOT/zot/zot.pid"
    fi
  fi
}
if [[ "$TEARDOWN_ONLY" == "1" ]]; then
  ok "stack teardown complete"
  exit 0
fi

if [[ "$ARG_UNINSTALL" != "1" ]]; then
  trap provision_error_cleanup EXIT
fi

# ─── STATE-CLEAN (uninstall or clean-rerun) ──────────────────────────────────
state_clean() {
  info "Removing wizard state"
  rm -rf -- "$STATE_ROOT"
  rm -rf -- "$CONFIG_ROOT"
  rm -rf -- "$GATEWAY_META_DIR"
  if [[ "$ARG_UNINSTALL" == "1" || "$ARG_PURGE_CACHE" == "1" ]]; then
    # Uninstall and explicit --purge-cache remove prepared images too.
    rm -rf -- "$VM_DRIVER_STATE_DIR"
  else
    # A normal --clean-rerun preserves the prepared image cache; the driver's
    # identity check ignores stale entries.
    find "$VM_DRIVER_STATE_DIR" -mindepth 1 -maxdepth 1 ! -name images -exec rm -rf {} + 2>/dev/null || true
  fi
  if [[ "$ARG_KEEP_PKI" == "1" ]]; then
    info "--keep-pki: preserving $TLS_DIR"
  else
    rm -rf -- "$TLS_DIR"
  fi
  # active_gateway pointer (only ours) — leave the empty dir/sibling alone.
  if [[ -f "$HOME/.config/openshell/active_gateway" ]] && \
     [[ "$(cat "$HOME/.config/openshell/active_gateway" 2>/dev/null)" == "$GATEWAY_NAME" ]]; then
    rm -f "$HOME/.config/openshell/active_gateway"
  fi
  ok "state cleaned"
  echo "" >&2
}

if [[ "$ARG_UNINSTALL" == "1" || "$ARG_CLEAN_RERUN" == "1" ]]; then
  state_clean
fi

if [[ "$ARG_UNINSTALL" == "1" ]]; then
  ok "uninstall complete — host equivalent to 'before provision'"
  exit 0
fi

# ─── 1. Platform pre-flight ─────────────────────────────────────────────────
if [[ "$(uname -s)" == "Linux" ]]; then
  # KVM: the driver opens /dev/kvm directly (runtime.rs check_kvm_access).
  if [[ ! -r /dev/kvm ]]; then
    die "/dev/kvm is not accessible — KVM is required for microVMs on Linux. Fix: usermod -aG kvm $USER, log out and back in, or check your udev rules"
  fi
  # glibc: the release binaries are glibc-built (docs reject musl/Alpine).
  # Amazon Linux identifies it as "GNU libc" in ldd output, so prefer the
  # portable getconf query and retain ldd as a fallback.
  if ! getconf GNU_LIBC_VERSION 2>/dev/null | grep -qi '^glibc ' \
     && ! ldd --version 2>/dev/null | grep -Eqi 'glibc|GNU libc'; then
    die "glibc 2.28+ is required — this system appears to be musl-based (Alpine or similar), which the release binaries do not support"
  fi
  info "Linux pre-flight ok (/dev/kvm readable, glibc present)"
fi

# ─── 1. Codesign VM driver (macOS) ──────────────────────────────────────────
if [[ "$(uname -s)" == "Darwin" ]]; then
  if ! command -v codesign >/dev/null 2>&1; then
    die "codesign not found — install Xcode Command Line Tools: xcode-select --install"
  fi
  if ! DevToolsSecurity -status 2>/dev/null | grep -q enabled; then
    die "developer mode is disabled — run: sudo DevToolsSecurity -enable"
  fi
  info "Codesigning openshell-driver-vm with Hypervisor entitlement"
  ENTITLEMENTS="$STATE_ROOT/driver-vm.entitlements.plist"
  mkdir -p "$STATE_ROOT"
  cat >"$ENTITLEMENTS" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.hypervisor</key>
    <true/>
</dict>
</plist>
EOF
  if codesign --entitlements "$ENTITLEMENTS" --force -s - "$DRIVER_BIN" 2>&1; then
    ok "driver-vm codesigned"
  else
    err "codesign failed (see above) — the Hypervisor entitlement requires Xcode Command Line Tools and developer mode"
    info "run: xcode-select --install"
    info "then: DevToolsSecurity -enable"
    die "cannot sign the VM driver without developer tools"
  fi
  ok "driver signed"
fi

# ─── 2. Generate local PKI ──────────────────────────────────────────────────
# Resolve strategy for the dev image, in order of preference:
#   1. REGISTRY MODE (runtime-agnostic): a bundled zot serves the shipped OCI
#      layout at 127.0.0.1; the driver resolves through its registry path.
#      No Docker, no Podman, no installs.
#   2. Container-engine load: the dev tar is loaded into docker/podman so the
#      driver's local-engine resolve succeeds. Fallback only.
# (Asset discovery already happened in the defaults — the start happens here.)
if [[ -n "$_oci_layout" && -n "$ZOT_BIN" ]]; then
  ZOT_DIR="$STATE_ROOT/zot"
  ZOT_PORT="${OPENBOX_ZOT_PORT:-15000}"
  mkdir -p "$ZOT_DIR/layout" "$ZOT_DIR/tls"
  info "runtime-agnostic image registry: serving the shipped OCI layout via zot on 127.0.0.1:$ZOT_PORT (HTTPS)"
  tar -xzf "$_oci_layout" -C "$ZOT_DIR/layout" \
    || die "failed to extract the OCI layout ($_oci_layout)"
  # The VM driver's registry client speaks HTTPS only — generate a local CA
  # and trust it into the user keychain so its TLS verification passes.
  openssl req -x509 -newkey rsa:2048 \
    -keyout "$ZOT_DIR/tls/key.pem" -out "$ZOT_DIR/tls/cert.pem" \
    -days 825 -nodes -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" >/dev/null 2>&1 \
    || die "failed to generate the registry TLS certificate"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    # Trust the wizard CA so the driver's TLS verification passes. Order:
    #   1. login keychain (silent; works in GUI sessions)
    #   2. system keychain via sudo — INTERACTIVE prompt (the wizard runs in
    #      the user's terminal, so sudo can ask for the password; SSH sessions
    #      with a locked login keychain land here)
    #   3. explicit die with the exact one-time command
    _trusted=0
    if security verify-cert -c "$ZOT_DIR/tls/cert.pem" -p ssl >/dev/null 2>&1 \
       || security add-trusted-cert -d -r trustRoot \
          -k "$HOME/Library/Keychains/login.keychain-db" "$ZOT_DIR/tls/cert.pem" >/dev/null 2>&1; then
      _trusted=1
    fi
    if [[ "$_trusted" != "1" ]]; then
      info "registry CA needs system trust — prompting for sudo (this unlocks the local image registry)"
      if sudo -p "sudo password required to trust the local image registry CA: " \
          security add-trusted-cert -d -r trustRoot \
          -k /Library/Keychains/System.keychain "$ZOT_DIR/tls/cert.pem" >/dev/null 2>&1; then
        info "registry CA trusted via the system keychain"
        _trusted=1
      fi
    fi
    if [[ "$_trusted" != "1" ]]; then
      err "the registry CA could not be trusted"
      err "run once, then re-provision:"
      err "  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $ZOT_DIR/tls/cert.pem"
      err "or unlock the login keychain: security unlock-keychain"
      kill "$ZOT_PID" 2>/dev/null || true
      die "local image registry certificate is untrusted"
    fi
  else
    mkdir -p "$STATE_ROOT/certs"
    cp "$ZOT_DIR/tls/cert.pem" "$STATE_ROOT/certs/openbox-registry-ca.crt"
    sudo -n cp "$ZOT_DIR/tls/cert.pem" /usr/local/share/ca-certificates/openbox-registry-ca.crt >/dev/null 2>&1 \
      && sudo -n update-ca-certificates >/dev/null 2>&1 \
      || warn "could not install the registry CA system-wide (sudo required) — the driver may reject the registry certificate"
  fi
  cat > "$ZOT_DIR/zot-config.json" <<ZOTEOF
{
  "storage": { "rootDirectory": "$ZOT_DIR/layout" },
  "http": {
    "address": "127.0.0.1",
    "port": "$ZOT_PORT",
    "tls": { "cert": "$ZOT_DIR/tls/cert.pem", "key": "$ZOT_DIR/tls/key.pem" }
  },
  "log": { "level": "error" }
}
ZOTEOF
  "$ZOT_BIN" serve "$ZOT_DIR/zot-config.json" > "$ZOT_DIR/zot.log" 2>&1 &
  ZOT_PID=$!
  echo "$ZOT_PID" > "$ZOT_DIR/zot.pid"
  for _i in $(seq 1 20); do
    curl -skf "https://127.0.0.1:$ZOT_PORT/v2/" >/dev/null 2>&1 && break
    sleep 0.5
  done
  if ! curl -skf "https://127.0.0.1:$ZOT_PORT/v2/" >/dev/null 2>&1; then
    err "zot did not come up (log: $ZOT_DIR/zot.log)"
    kill "$ZOT_PID" 2>/dev/null || true
    die "local image registry failed to start"
  fi
  # Pin the registry ref to the manifest digest — the sandbox service's
  # immutability validation requires a @sha256 template.
  _manifest_digest="$(curl -skI \
    -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" \
    "https://127.0.0.1:$ZOT_PORT/v2/openbox-sandboxes-dev/manifests/latest" \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest" {print $2}' | head -1)"
  if [[ -z "$_manifest_digest" ]]; then
    err "could not read the manifest digest from the local registry"
    kill "$ZOT_PID" 2>/dev/null || true
    die "local image registry has no manifest digest"
  fi
  SANDBOX_IMAGE="127.0.0.1:$ZOT_PORT/openbox-sandboxes-dev@$_manifest_digest"
  info "dev image resolves via the local registry ($SANDBOX_IMAGE) — no container runtime"
fi
info "Generating local PKI into $TLS_DIR"
mkdir -p "$TLS_DIR"
"$GATEWAY_BIN" generate-certs \
  --output-dir "$TLS_DIR" \
  --server-san "127.0.0.1" \
  --server-san "localhost" \
  --server-san "host.openshell.internal" \
  --server-san "host.containers.internal" \
  --server-san "host.docker.internal" >/dev/null 2>&1 || die "generate-certs failed"

# Harden the CA for strict TLS consumers: openshell-gateway generate-certs
# omits the keyUsage extension, and OpenSSL 3.5+ rejects an issuer whose CA
# certificate lacks keyCertSign ("CA cert does not include key usage
# extension"). Re-sign the CA with the same key/subject plus the required
# extensions so leaves issued below remain verifiable end-to-end.
CA_SUBJ="$(openssl x509 -in "$TLS_DIR/ca.crt" -noout -subject -nameopt RFC2253 \
  | sed 's/^subject=//' \
  | awk -F, '{for (i = NF; i >= 1; i--) printf "/%s", $i}')"
cat > "$TLS_DIR/ca.ext" <<'EOF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl req -new -key "$TLS_DIR/ca.key" -subj "$CA_SUBJ" \
  -out "$TLS_DIR/ca.csr.tmp" 2>/dev/null || die "CA re-key CSR failed"
openssl x509 -req -in "$TLS_DIR/ca.csr.tmp" -signkey "$TLS_DIR/ca.key" \
  -out "$TLS_DIR/ca.crt.tmp" -days "$CERT_DAYS" -extfile "$TLS_DIR/ca.ext" 2>/dev/null \
  || die "CA re-sign failed"
mv "$TLS_DIR/ca.crt.tmp" "$TLS_DIR/ca.crt"
rm -f "$TLS_DIR/ca.csr.tmp" "$TLS_DIR/ca.ext"
openssl verify -CAfile "$TLS_DIR/ca.crt" "$TLS_DIR/ca.crt" >/dev/null 2>&1 \
  || die "hardened CA failed self-verify"

mkdir -p "$GATEWAY_MTLS_DIR"
chmod 700 "$GATEWAY_META_DIR" "$GATEWAY_MTLS_DIR" 2>/dev/null || true
cp "$TLS_DIR/ca.crt"            "$GATEWAY_MTLS_DIR/ca.crt"
cp "$TLS_DIR/client/tls.crt"   "$GATEWAY_MTLS_DIR/tls.crt"
cp "$TLS_DIR/client/tls.key"    "$GATEWAY_MTLS_DIR/tls.key"
chmod 644 "$GATEWAY_MTLS_DIR/ca.crt" "$GATEWAY_MTLS_DIR/tls.crt"
chmod 600 "$GATEWAY_MTLS_DIR/tls.key"
ok "PKI ready (CA at $TLS_DIR/ca.crt)"

# ─── 3. Start the gateway ────────────────────────────────────────────────────
mkdir -p "$GATEWAY_STATE_DIR" "$VM_DRIVER_STATE_DIR"
chmod 700 "$VM_DRIVER_STATE_DIR"

cat >"$GATEWAY_CONFIG" <<EOF
[openshell]
version = 1

[openshell.gateway]
compute_drivers = ["vm"]
disable_tls = false
log_level = "${GATEWAY_LOG_LEVEL}"

[openshell.gateway.auth]
allow_unauthenticated_users = false

[openshell.gateway.mtls_auth]
enabled = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${TLS_DIR}/jwt/signing.pem"
public_key_path = "${TLS_DIR}/jwt/public.pem"
kid_path = "${TLS_DIR}/jwt/kid"
gateway_id = "${GATEWAY_NAME}"
ttl_secs = ${JWT_TTL_SECS}

[openshell.drivers.vm]
default_image = "${SANDBOX_IMAGE}"
krun_log_level = ${KRUN_LOG_LEVEL}
grpc_endpoint = "${GRPC_ENDPOINT}"
driver_dir = "$(dirname "$DRIVER_BIN")"
state_dir = "${VM_DRIVER_STATE_DIR}"
guest_tls_ca = "${TLS_DIR}/ca.crt"
guest_tls_cert = "${TLS_DIR}/client/tls.crt"
guest_tls_key = "${TLS_DIR}/client/tls.key"
EOF

mkdir -p "$GATEWAY_META_DIR"
cat >"$GATEWAY_META_DIR/metadata.json" <<EOF
{
  "name": "${GATEWAY_NAME}",
  "gateway_endpoint": "https://127.0.0.1:${PORT}",
  "is_remote": false,
  "gateway_port": ${PORT},
  "auth_mode": "mtls",
  "vm_driver_state_dir": "${VM_DRIVER_STATE_DIR}"
}
EOF
chmod 600 "$GATEWAY_META_DIR/metadata.json"
mkdir -p "$OPENSHELL_META_DIR"
printf '%s' "$GATEWAY_NAME" >"$OPENSHELL_META_DIR/active_gateway"

if [[ "$NO_START" == "1" ]]; then
  info "NO_START=1 — gateway config written, not started"
else
  info "Starting gateway on https://127.0.0.1:${PORT}"
  # No-image workaround: the script keeps its strict global `umask 077` for all
  # wizard-owned host state, but launches ONLY the gateway child under
  # `umask 022` in a subshell. `exec` preserves the PID (subshell -> nohup ->
  # gateway are the same process), so PID capture, nohup semantics, ownership,
  # and teardown identity are unchanged. Purpose: the unmodified guest's
  # OverlayFS upperdir must be traversable for the imageless guest to boot.
  # Scope of the relaxation: files this provisioning shell writes itself keep
  # umask 077 / their explicit chmod modes; only the gateway/VM-driver
  # descendants inherit 022. So driver-created cache subdirectories may land at
  # 0755, but they stay unreachable to other users behind the explicitly 0700
  # $VM_DRIVER_STATE_DIR parent created above. The log redirect stays OUTSIDE
  # the subshell so gateway.log is opened by the parent shell under umask 077
  # (0600), not by the relaxed child.
  ( umask 022; export RUST_LOG="${DRIVER_RUST_LOG:-${RUST_LOG:-}}"; exec nohup "$GATEWAY_BIN" \
    --config "$GATEWAY_CONFIG" \
    --port "$PORT" \
    --log-level "$LOG_LEVEL" \
    --drivers vm \
    --db-url "sqlite:${GATEWAY_STATE_DIR}/gateway.db?mode=rwc" \
    --tls-cert "$TLS_DIR/server/tls.crt" \
    --tls-key "$TLS_DIR/server/tls.key" \
    --tls-client-ca "$TLS_DIR/ca.crt" \
    --enable-mtls-auth true ) >"$GATEWAY_LOG" 2>&1 &
  echo $! >"$GATEWAY_PID_FILE"
  gateway_ready=0
  for _ in $(seq 1 "$GATEWAY_READY_POLLS"); do
    if (echo >/dev/tcp/127.0.0.1/"$PORT") >/dev/null 2>&1; then
      ok "gateway up (pid=$(cat "$GATEWAY_PID_FILE"))"
      gateway_ready=1
      break
    fi
    sleep "$GATEWAY_READY_INTERVAL"
  done
  if [[ "$gateway_ready" != "1" ]]; then
    err "gateway failed to become ready after ${GATEWAY_READY_POLLS} polls; log content ($GATEWAY_LOG):"
    tail -n 20 "$GATEWAY_LOG" 2>/dev/null >&2 || true
    if ! process_alive "$(cat "$GATEWAY_PID_FILE" 2>/dev/null || echo 0)"; then
      err "the gateway process is no longer alive — it exited during startup"
    fi
    die "gateway failed to become ready"
  fi
fi

# ─── 4. Runtime-caller mTLS pair (signed by gateway CA) ─────────────────────
info "Generating runtime-caller mTLS pair"
mkdir -p "$SANDBOX_TLS_DIR"
chmod 700 "$SANDBOX_TLS_DIR"

openssl genrsa -out "$SANDBOX_TLS_DIR/client.key" "$RSA_BITS" >/dev/null 2>&1
openssl req -new -key "$SANDBOX_TLS_DIR/client.key" -subj "$CALLER_SUBJ" \
  -out "$SANDBOX_TLS_DIR/client.csr" >/dev/null 2>&1
cat >"$SANDBOX_TLS_DIR/client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -sha256 -days "$CERT_DAYS" \
  -in "$SANDBOX_TLS_DIR/client.csr" \
  -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
  -extfile "$SANDBOX_TLS_DIR/client.ext" \
  -out "$SANDBOX_TLS_DIR/client.crt" >/dev/null 2>&1 || die "caller cert sign failed"
cp "$TLS_DIR/ca.crt" "$SANDBOX_TLS_DIR/ca.crt"
chmod 600 "$SANDBOX_TLS_DIR/client.key"
chmod 644 "$SANDBOX_TLS_DIR/client.crt" "$SANDBOX_TLS_DIR/ca.crt"
rm -f "$SANDBOX_TLS_DIR/client.csr"

# Server identity for the sandbox service itself.
openssl genrsa -out "$SANDBOX_TLS_DIR/server.key" "$RSA_BITS" >/dev/null 2>&1
cat >"$SANDBOX_TLS_DIR/server.cnf.tmp" <<'EOF'
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no
[dn]
CN = localhost
[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF
openssl req -new -key "$SANDBOX_TLS_DIR/server.key" -config "$SANDBOX_TLS_DIR/server.cnf.tmp" \
  -out "$SANDBOX_TLS_DIR/server.csr" >/dev/null 2>&1
openssl x509 -req -sha256 -days "$CERT_DAYS" \
  -in "$SANDBOX_TLS_DIR/server.csr" \
  -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
  -extfile "$SANDBOX_TLS_DIR/server.cnf.tmp" -extensions v3_req \
  -out "$SANDBOX_TLS_DIR/server.crt" >/dev/null 2>&1 || die "server cert sign failed"
chmod 600 "$SANDBOX_TLS_DIR/server.key"
chmod 644 "$SANDBOX_TLS_DIR/server.crt"
rm -f "$SANDBOX_TLS_DIR/server.csr" "$SANDBOX_TLS_DIR/server.cnf.tmp"

# Runtime-mTLS credentials (sandbox service -> gateway).
RUNTIME_MTLS_DIR="$RUNTIME_MTLS_DIR"
mkdir -p "$RUNTIME_MTLS_DIR"
chmod 700 "$RUNTIME_MTLS_DIR"
cp "$TLS_DIR/ca.crt"            "$RUNTIME_MTLS_DIR/ca.crt"
cp "$TLS_DIR/client/tls.crt"   "$RUNTIME_MTLS_DIR/tls.crt"
cp "$TLS_DIR/client/tls.key"    "$RUNTIME_MTLS_DIR/tls.key"
chmod 600 "$RUNTIME_MTLS_DIR"/*

CALLER_FP="$(openssl x509 -in "$SANDBOX_TLS_DIR/client.crt" -outform DER | sha256_hex /dev/stdin)"
ADAPTER_SHA="$(sha256_hex "$SANDBOX_BIN")"
POLICY_SHA="$(sha256_hex "$POLICY_FILE")"
ok "caller fingerprint: $CALLER_FP"
ok "adapter sha:        $ADAPTER_SHA"
ok "policy sha:         $POLICY_SHA"

# ─── 5. Write the sandbox service config ────────────────────────────────────
info "Writing sandbox service config -> $SERVICE_CONFIG"
mkdir -p "$SANDBOX_STATE_DIR"
chmod 700 "$SANDBOX_STATE_DIR"
mkdir -p "$CONFIG_ROOT"
cat >"$SERVICE_CONFIG" <<EOF
{
  "bind_address": "127.0.0.1:${SANDBOX_PORT}",
  "server_certificate_path": "${SANDBOX_TLS_DIR}/server.crt",
  "server_private_key_path": "${SANDBOX_TLS_DIR}/server.key",
  "client_ca_path": "${SANDBOX_TLS_DIR}/ca.crt",
  "authorized_callers": [
    {"certificate_sha256": "${CALLER_FP}", "role": "runtime"}
  ],
  "state_directory": "${SANDBOX_STATE_DIR}",
  "asset_bundle": {
    "runtime_contract_version": 1,
    "adapter_build_sha256": "${ADAPTER_SHA}",
    "template": "${SANDBOX_IMAGE}",
    "policy": {"id": "${POLICY_ID}", "version": ${POLICY_VERSION}, "sha256": "${POLICY_SHA}"},
    "compatibility_id": "${COMPAT_ID}"
  },
  "runtime_endpoint": "https://127.0.0.1:${PORT}",
  "runtime_mtls_directory": "${RUNTIME_MTLS_DIR}",
  "runtime_connect_timeout_ms": ${RUNTIME_CONNECT_TIMEOUT_MS},
  "runtime_poll_interval_ms": ${RUNTIME_POLL_INTERVAL_MS},
  "reconcile_delete_deadline_ms": ${RECONCILE_DELETE_DEADLINE_MS},
  "reconcile_wait_deadline_ms": ${RECONCILE_WAIT_DEADLINE_MS},
  "maximum_connections": ${MAX_CONNECTIONS},
  "drain_timeout_ms": ${DRAIN_TIMEOUT_MS},
  "allow_degraded_landlock": ${ALLOW_DEGRADED_LANDLOCK}
}
EOF
chmod 600 "$SERVICE_CONFIG"
ok "service config written"

# ─── 6. Start (or restart) the sandbox service ──────────────────────────────
if [[ "$NO_START" == "1" ]]; then
  info "NO_START=1 — service not started"
else
  info "Starting sandbox service on 127.0.0.1:${SANDBOX_PORT}"
  OPENBOX_SANDBOX_CONFIG="$SERVICE_CONFIG" nohup "$SANDBOX_BIN" >"$SERVICE_LOG" 2>&1 &
  echo $! >"$SANDBOX_PID_FILE"
  service_ready=0
  for _ in $(seq 1 "$SERVICE_READY_POLLS"); do
    if port_listening "$SANDBOX_PORT"; then
      ok "service up (pid=$(cat "$SANDBOX_PID_FILE"))"
      service_ready=1
      break
    fi
    sleep "$SERVICE_READY_INTERVAL"
  done
  if [[ "$service_ready" != "1" ]]; then
    err "sandbox service failed to become ready after ${SERVICE_READY_POLLS} polls; log content ($SERVICE_LOG):"
    tail -n 20 "$SERVICE_LOG" 2>/dev/null >&2 || true
    die "sandbox service failed to become ready"
  fi
  OPENBOX_SANDBOX_CONFIG="$SERVICE_CONFIG" "$SANDBOX_BIN" --check-config >/dev/null 2>&1 || \
    die "running service rejected --check-config"
  ok "running service validates --check-config"
fi

# ─── 7. Emit agent.env ─────────────────────────────────────────────────────
info "Emitting agent env -> $AGENT_ENV"
cat >"$AGENT_ENV" <<EOF
# OpenBox SDK agent environment. Source this file (or copy the values) into
# your agent's runtime — these are the credentials and parameters the SDK
# needs to drive the local sandbox service over mutual TLS.
#
#   set -a; source ${AGENT_ENV}; set +a
#
# Generated by provision-local-sandbox.sh at $(date -u +%Y-%m-%dT%H:%M:%SZ).
# A clean-state rerun reproduces this schema; fresh PKI and timestamps differ.

# Sandbox service boundary (mTLS, loopback).
OPENBOX_SANDBOX_ENDPOINT=127.0.0.1:${SANDBOX_PORT}
OPENBOX_SANDBOX_SERVER_NAME=localhost
OPENBOX_SANDBOX_CA=${SANDBOX_TLS_DIR}/ca.crt
OPENBOX_SANDBOX_CERT=${SANDBOX_TLS_DIR}/client.crt
OPENBOX_SANDBOX_KEY=${SANDBOX_TLS_DIR}/client.key

# Service artifact and asset bundle identity. obs verify hashes this exact
# binary before running the live lifecycle, preventing stale-source proof.
OPENBOX_SANDBOX_BINARY=${SANDBOX_BIN}
OPENBOX_SANDBOX_ADAPTER_SHA=${ADAPTER_SHA}
OPENBOX_SANDBOX_TEMPLATE=${SANDBOX_IMAGE}
OPENBOX_SANDBOX_POLICY_FILE=${POLICY_FILE}
OPENBOX_SANDBOX_POLICY_ID=${POLICY_ID}
OPENBOX_SANDBOX_POLICY_VERSION=${POLICY_VERSION}
OPENBOX_SANDBOX_POLICY_SHA256=${POLICY_SHA}
OPENBOX_SANDBOX_COMPAT_ID=${COMPAT_ID}

# Discovery anchors.
OPENBOX_SANDBOX_CONFIG_PATH=${SERVICE_CONFIG}
OPENBOX_GATEWAY_ENDPOINT=https://127.0.0.1:${PORT}
EOF
chmod 600 "$AGENT_ENV"
ok "agent.env written"

# ─── 7.5 Warm the VM driver image cache ─────────────────────────────────────
# First sandbox create on a cold cache pulls + converts the sandbox image
# (minutes), which exceeds the live test's wait_ready deadline. Pre-warm with
# one create -> ready -> delete cycle so the first real request is fast.
# Skip with OPENBOX_WARM_CACHE=0 (or implicitly when NO_START=1).
# Try the shipped prepared-cache first (zero runtime deps): extract, warm,
# expect a fast cache-hit ready. Only when that misses do we fall back to the
# container-runtime path (docker/podman, optional) to build the cache locally.
try_shipped_vm_cache() {
  [[ "$USE_VM_CACHE" == "1" && -n "$VM_CACHE_TAR" ]] || return 1
  for _cand in "$LAUNCHER_DIR/$VM_CACHE_TAR" "$(pwd)/$VM_CACHE_TAR"; do
    [[ -f "$_cand" ]] || continue
    VM_CACHE_TAR="$_cand"
    break
  done
  [[ -f "$VM_CACHE_TAR" ]] || return 1

  # Verify through the same channel-locked path as every other release asset.
  # A mismatch is removed and re-downloaded; any failure takes the runtime path.
  if ! verify_asset "$VM_CACHE_TAR" "$(basename "$VM_CACHE_TAR")"; then
    warn "prepared cache verification failed ($VERIFY_ASSET_ERROR) — falling back to the runtime path"
    return 1
  fi

  info "prepared VM cache found ($VM_CACHE_TAR) — extracting into $VM_DRIVER_STATE_DIR/images"
  mkdir -p "$VM_DRIVER_STATE_DIR/images"
  tar -xzf "$VM_CACHE_TAR" -C "$VM_DRIVER_STATE_DIR/images" \
    || { warn "prepared cache extraction failed — falling back to the runtime path"; return 1; }
  return 0
}

if [[ "${OPENBOX_WARM_CACHE:-1}" == "0" ]]; then
  info "cache warm skipped (OPENBOX_WARM_CACHE=0)"
elif [[ "$NO_START" == "1" ]]; then
  info "cache warm skipped (NO_START=1; stack not started)"
elif [[ -x "$CLI_BIN" ]]; then
  cache_prepared=0
  try_shipped_vm_cache && cache_prepared=1
  # The runtime is ONLY needed when the shipped cache is absent/missed —
  # it is no longer a required dependency of the happy path.
  if [[ "$cache_prepared" != "1" ]]; then
    if ! resolve_runtime; then
      die "no prepared VM cache and no container runtime available — install Docker or Podman (or re-run once the cache asset is present) and re-run"
    fi
  fi
  # The VM driver builds the ext4 rootfs with mkfs.ext4 AND fixes ownership
  # with debugfs (both from e2fsprogs) — checked against the pinned driver's
  # own candidate paths. Fail fast BEFORE the multi-minute image pull.
  # Declared at top level so the static audit sees them bound before use;
  # find_e2fs_tools fills them.
  MKFS=""
  DEBUGFS=""
  find_e2fs_tools() {
    MKFS=""
    DEBUGFS=""
    for _tool in mkfs.ext4 mke2fs debugfs; do
      _cand="$(command -v "$_tool" 2>/dev/null || true)"
      if [[ -z "$_cand" ]]; then
        for _root in /opt/homebrew/opt/e2fsprogs /usr/local/opt/e2fsprogs; do
          for _sub in sbin bin; do
            [[ -x "$_root/$_sub/$_tool" ]] || continue
            _cand="$_root/$_sub/$_tool"
            break 2
          done
        done
      fi
      [[ -n "$_cand" ]] || continue
      [[ "$_tool" != "debugfs" ]] && MKFS="$_cand"
      [[ "$_tool" == "debugfs" ]] && DEBUGFS="$_cand"
    done
  }
  find_e2fs_tools
  if [[ -z "$MKFS" || -z "$DEBUGFS" ]]; then
    if command -v brew >/dev/null 2>&1; then
      BREW_LOG="${STATE_ROOT}/brew-e2fsprogs.log"
      mkdir -p "$STATE_ROOT"
      info "installing e2fsprogs via Homebrew (may take a few minutes; log: $BREW_LOG)"
      if ! brew install e2fsprogs >"$BREW_LOG" 2>&1; then
        err "brew install failed — log tail ($BREW_LOG):"
        tail -n 15 "$BREW_LOG" 2>/dev/null >&2 || true
        die "brew install e2fsprogs failed — install it manually and re-run"
      fi
      ok "e2fsprogs installed (full log: $BREW_LOG)"
      find_e2fs_tools
    fi
    if [[ -z "$MKFS" || -z "$DEBUGFS" ]]; then
      die "e2fsprogs (mkfs.ext4 + debugfs) is required by the VM driver — install it manually: brew install e2fsprogs"
    fi
    ok "e2fsprogs ready (mkfs=$MKFS debugfs=$DEBUGFS)"
  fi
  info "warming VM driver image cache ($SANDBOX_IMAGE)..."
  if [[ "$SANDBOX_IMAGE" == ghcr.io/* ]]; then
    warn "no dev image tar detected — the driver will PULL FROM ghcr.io on first warm"
    warn "if the pull fails (offline/slow network), download the dev image: ./obs update --all"
  fi
  # Rotate previous warm logs — only the current run's log is kept.
  find "$STATE_ROOT" -maxdepth 1 -name 'warm-*.log' -type f ! -newermt '-1 minute' -delete 2>/dev/null || true
  warm_name="w$(date +%s)"
  warm_log="${STATE_ROOT}/warm-${warm_name}.log"
  warm_start="$(date +%s)"

  # One full warm attempt: create + poll to ready/terminal. Returns 0 when
  # the sandbox reached ready, 1 otherwise. Reused by the runtime fallback
  # retry so a failed first attempt (e.g. registry rejected) actually gets
  # re-driven through the container-engine path instead of just printed.
  warm_attempt() {
    local attempt_name="$1" attempt_log="$2"
    run_with_timeout "${OPENBOX_WARM_CREATE_TIMEOUT:-300}" \
      "$CLI_BIN" sandbox create --name "$attempt_name" -- /bin/true >"$attempt_log" 2>&1 \
      || warn "warm sandbox create exited non-zero (CLI timeout or validation failure); see $attempt_log — polling by name"
    tail -n +1 -f "$attempt_log" >&2 &
    local tail_pid=$!
    local saw_once=0
    local attempts=0
    local phase=""
    local last_phase=""
    local heartbeat=0
    for _ in $(seq 1 "$WARM_POLL_COUNT"); do
      elapsed=$(( $(date +%s) - warm_start ))
      local status
      status="$(run_with_timeout "${OPENBOX_WARM_GET_TIMEOUT:-10}" "$CLI_BIN" sandbox get "$attempt_name" 2>/dev/null)" || {
        if [[ "$saw_once" == "1" ]]; then
          info "warm sandbox $attempt_name completed and reaped (elapsed ${elapsed}s)"
          kill "$tail_pid" 2>/dev/null || true
          return 0
        fi
        status=""
      }
      if [[ -n "$status" ]]; then
        saw_once=1
        phase="$(printf '%s\n' "$status" | grep -oiE 'provisioning|pulling|booting|starting|creating|ready|running|deleting|error' | head -1 || true)"
        if [[ -n "$phase" && "$phase" != "$last_phase" ]]; then
          info "warm progress: phase=$phase elapsed=${elapsed}s"
          last_phase="$phase"
          heartbeat=0
        fi
      fi
      heartbeat=$((heartbeat + 1))
      if (( heartbeat % 6 == 0 )); then
        info "still warming… elapsed=${elapsed}s phase=${last_phase:-waiting-for-gateway}"
      fi
      if printf '%s\n' "$status" | grep -qiE 'ready|running|deleting'; then
        kill "$tail_pid" 2>/dev/null || true
        return 0
      fi
      if printf '%s\n' "$status" | grep -qiE 'error|failed'; then
        err "warm sandbox entered a terminal error state; log content ($attempt_log):"
        tail -n 20 "$attempt_log" 2>/dev/null >&2 || true
        kill "$tail_pid" 2>/dev/null || true
        return 1
      fi
      sleep "$WARM_POLL_INTERVAL"
    done
    kill "$tail_pid" 2>/dev/null || true
    return 1
  }
  warm_attempt "$warm_name" "$warm_log" && warmed=1 || warmed=0
  if [[ "$warmed" == "1" ]]; then
    if [[ "$cache_prepared" == "1" ]]; then
      ok "prepared VM cache hit — warm completed in ${elapsed}s (no image pull or build)"
    else
      ok "cache warmed: $warm_name"
    fi
  else
    if [[ "$cache_prepared" == "1" ]]; then
      err "prepared VM cache MISS — the driver rejected or failed it; falling back to the runtime path (the extracted cache is left in place — remove it manually if you want it gone)"
      cache_prepared=0
    fi
    if [[ "$cache_prepared" != "1" ]] && resolve_runtime; then
      # Real retry: ensure the image resolves through the engine, then run a
      # second full warm attempt. The first failure's sandbox is reaped.
      info "first warm attempt failed — retrying via the container runtime ($RUNTIME)"
      if [[ -n "$DEV_TAR" ]]; then
        LOAD_OUTPUT2="$(gunzip -c "$DEV_TAR" | "$RUNTIME" load 2>&1)" \
          || warn "dev image load failed during the fallback retry — the driver may still resolve it if already loaded"
      fi
      retry_name="w$(date +%s)r"
      retry_log="${STATE_ROOT}/warm-${retry_name}.log"
      if warm_attempt "$retry_name" "$retry_log"; then
        warmed=1
        warm_name="$retry_name"
        warm_log="$retry_log"
        ok "cache warmed via the runtime fallback: $warm_name"
      else
        warn "runtime-fallback warm also failed (log: $retry_log); first request may be slow"
      fi
    elif [[ ! -s "$warm_log" ]] && [[ "$(grep -ciE 'error|failed|validation' "$warm_log" 2>/dev/null || true)" -eq 0 ]]; then
      warn "warm sandbox did not reach ready in ${elapsed}s; first request may be slow"
    fi
  fi
  # (The warm_attempt function kills its own log-tailer.)
  run_with_timeout "${OPENBOX_WARM_DELETE_TIMEOUT:-30}" "$CLI_BIN" sandbox delete "$warm_name" >/dev/null 2>&1 \
    || warn "warm sandbox $warm_name delete failed (gateway will reap it)"
else
  warn "cache warm skipped (no CLI at $CLI_BIN)"
fi

trap - EXIT  # provision succeeded — keep the wizard processes running

echo "" >&2
ok "provision complete"
info "gateway:   https://127.0.0.1:${PORT}   (pid file: $GATEWAY_PID_FILE)"
info "service:   127.0.0.1:${SANDBOX_PORT}        (pid file: $SANDBOX_PID_FILE)"
info "agent env: $AGENT_ENV"
info "verify:    obs verify"