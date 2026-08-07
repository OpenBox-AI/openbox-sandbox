#!/usr/bin/env bash
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
info() { printf '  ==> %s\n' "$*" >&2; }
ok()   { printf '  [ok] %s\n' "$*" >&2; }
warn() { printf '  [warn] %s\n' "$*" >&2; }

# ─── Arg parsing (before binary checks; uninstall needs no bundle) ──────────
ARG_UNINSTALL=0
ARG_CLEAN_RERUN=0
ARG_KEEP_PKI=0
for arg in "$@"; do
  case "$arg" in
    --uninstall)     ARG_UNINSTALL=1 ;;
    --clean-rerun)   ARG_CLEAN_RERUN=1 ;;
    --keep-pki)      ARG_KEEP_PKI=1 ;;
    --help|-h)       sed -n '1,55p' "$0"; exit 0 ;;
    --)              break ;;
    *)               die "unsupported arg: $arg (use --uninstall|--clean-rerun|--keep-pki)" ;;
  esac
done
if [[ "$ARG_KEEP_PKI" == "1" && "$ARG_UNINSTALL" != "1" && "$ARG_CLEAN_RERUN" != "1" ]]; then
  die "--keep-pki requires --uninstall or --clean-rerun"
fi

# ─── Defaults ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Standalone (embedded-script) mode has no source checkout: operators must
# provide the policy path explicitly; PROJECT_ROOT then only supplies the
# checked-in defaults for source-tree runs.
PROJECT_ROOT="${OPENBOX_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"

if [[ -n "${OPENSHELL_BUNDLE_DIR:-}" && "${OPENSHELL_BUNDLE_DIR}" == /* ]]; then
  BUNDLE_DIR="$OPENSHELL_BUNDLE_DIR"
else
  BUNDLE_DIR="$PROJECT_ROOT/${OPENSHELL_BUNDLE_DIR:-openbox-sandbox-bundle}"
fi
if [[ -n "${OPENBOX_SANDBOX_BIN:-}" && "${OPENBOX_SANDBOX_BIN}" == /* ]]; then
  SANDBOX_BIN="$OPENBOX_SANDBOX_BIN"
else
  SANDBOX_BIN="$PROJECT_ROOT/${OPENBOX_SANDBOX_BIN:-target/release/openbox-sandbox}"
fi
if [[ -n "${OPENBOX_POLICY_FILE:-}" && "${OPENBOX_POLICY_FILE}" == /* ]]; then
  POLICY_FILE="$OPENBOX_POLICY_FILE"
else
  POLICY_FILE="$(cd "$PROJECT_ROOT" && pwd)/${OPENBOX_POLICY_FILE:-deploy/policies/policy-deny-network-dev.yaml}"
fi
POLICY_ID="${OPENBOX_POLICY_ID:-openbox-deny-network-dev}"
POLICY_VERSION="${OPENBOX_POLICY_VERSION:-1}"
COMPAT_ID="${OPENBOX_COMPAT_ID:-darwin-dev-1}"
SANDBOX_IMAGE="${OPENBOX_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e}"
PORT="${OPENSHELL_SERVER_PORT:-17670}"
GATEWAY_NAME="${OPENSHELL_GATEWAY_NAME:-openshell}"
STATE_ROOT="${OPENBOX_STATE_ROOT:-$HOME/.local/state/openbox-sandbox}"
CONFIG_ROOT="${OPENBOX_CONFIG_ROOT:-$HOME/.config/openbox-sandbox}"
SANDBOX_PORT="${OPENBOX_SANDBOX_PORT:-17443}"
LOG_LEVEL="${OPENSHELL_LOG_LEVEL:-info}"
NO_START="${NO_START:-0}"
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
GATEWAY_BIN=""
CLI_BIN=""
DRIVER_BIN=""
if [[ -n "${OPENSHELL_BIN_OVERRIDE:-}" && -d "${OPENSHELL_BIN_OVERRIDE}" ]]; then
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
if [[ -z "$GATEWAY_BIN" ]]; then
  GATEWAY_BIN="$BUNDLE_DIR/bin/openshell-gateway"
  CLI_BIN="$BUNDLE_DIR/bin/openshell"
  DRIVER_BIN="$BUNDLE_DIR/libexec/openshell-driver-vm"
fi

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
if [[ "$ARG_UNINSTALL" != "1" ]]; then
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
  state="$(ps -p "$1" -o stat= 2>/dev/null | awk 'NF { print; exit }')"
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
    sleep 0.25
  done
  if process_alive "$pid"; then
    process_matches "$pid" "$expected_binary" "$required_marker" "$identity_mode" \
      || die "$label PID $pid changed identity while stopping; refusing SIGKILL"
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$f"
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

info "Teardown (always)"
stop_pid_file "$SANDBOX_PID_FILE" "sandbox service" "$SANDBOX_BIN"
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
  if [[ "$rc" != "0" ]]; then
    warn "provision failed (exit $rc); tearing down wizard-owned processes started this run"
    stop_pid_file "$SANDBOX_PID_FILE" "sandbox service" "$SANDBOX_BIN"
    stop_pid_file "$GATEWAY_PID_FILE" "gateway" "$GATEWAY_BIN" "$GATEWAY_CONFIG" "gateway-config"
    stop_scoped_vm_drivers
  fi
}
if [[ "$ARG_UNINSTALL" != "1" ]]; then
  trap provision_error_cleanup EXIT
fi

# ─── STATE-CLEAN (uninstall or clean-rerun) ──────────────────────────────────
state_clean() {
  info "Removing wizard state"
  rm -rf -- "$STATE_ROOT"
  rm -rf -- "$CONFIG_ROOT"
  rm -rf -- "$GATEWAY_META_DIR"
  rm -rf -- "$VM_DRIVER_STATE_DIR"
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

# ─── 1. Codesign VM driver (macOS) ──────────────────────────────────────────
if [[ "$(uname -s)" == "Darwin" ]]; then
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
  codesign --entitlements "$ENTITLEMENTS" --force -s - "$DRIVER_BIN" >/dev/null 2>&1 || \
    die "codesign failed (Hypervisor framework entitlement requires developer mode)"
  ok "driver signed"
fi

# ─── 2. Generate local PKI ──────────────────────────────────────────────────
info "Generating local PKI into $TLS_DIR"
mkdir -p "$TLS_DIR"
"$GATEWAY_BIN" generate-certs \
  --output-dir "$TLS_DIR" \
  --server-san "127.0.0.1" \
  --server-san "localhost" \
  --server-san "host.openshell.internal" \
  --server-san "host.containers.internal" \
  --server-san "host.docker.internal" >/dev/null 2>&1 || die "generate-certs failed"

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

[openshell.gateway.auth]
allow_unauthenticated_users = false

[openshell.gateway.mtls_auth]
enabled = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${TLS_DIR}/jwt/signing.pem"
public_key_path = "${TLS_DIR}/jwt/public.pem"
kid_path = "${TLS_DIR}/jwt/kid"
gateway_id = "${GATEWAY_NAME}"
ttl_secs = 3600

[openshell.drivers.vm]
default_image = "${SANDBOX_IMAGE}"
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
mkdir -p "$HOME/.config/openshell"
printf '%s' "$GATEWAY_NAME" >"$HOME/.config/openshell/active_gateway"

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
  ( umask 022; exec nohup "$GATEWAY_BIN" \
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
  for _ in $(seq 1 60); do
    if (echo >/dev/tcp/127.0.0.1/"$PORT") >/dev/null 2>&1; then
      ok "gateway up (pid=$(cat "$GATEWAY_PID_FILE"))"
      gateway_ready=1
      break
    fi
    sleep 0.5
  done
  [[ "$gateway_ready" == "1" ]] || die "gateway failed to become ready; see $GATEWAY_LOG"
fi

# ─── 4. Runtime-caller mTLS pair (signed by gateway CA) ─────────────────────
info "Generating runtime-caller mTLS pair"
mkdir -p "$SANDBOX_TLS_DIR"
chmod 700 "$SANDBOX_TLS_DIR"

CALLER_SUBJ="/CN=openbox-sandbox-runtime-caller"
openssl genrsa -out "$SANDBOX_TLS_DIR/client.key" 2048 >/dev/null 2>&1
openssl req -new -key "$SANDBOX_TLS_DIR/client.key" -subj "$CALLER_SUBJ" \
  -out "$SANDBOX_TLS_DIR/client.csr" >/dev/null 2>&1
cat >"$SANDBOX_TLS_DIR/client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -sha256 -days 825 \
  -in "$SANDBOX_TLS_DIR/client.csr" \
  -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
  -extfile "$SANDBOX_TLS_DIR/client.ext" \
  -out "$SANDBOX_TLS_DIR/client.crt" >/dev/null 2>&1 || die "caller cert sign failed"
cp "$TLS_DIR/ca.crt" "$SANDBOX_TLS_DIR/ca.crt"
chmod 600 "$SANDBOX_TLS_DIR/client.key"
chmod 644 "$SANDBOX_TLS_DIR/client.crt" "$SANDBOX_TLS_DIR/ca.crt"
rm -f "$SANDBOX_TLS_DIR/client.csr"

# Server identity for the sandbox service itself.
openssl genrsa -out "$SANDBOX_TLS_DIR/server.key" 2048 >/dev/null 2>&1
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
openssl x509 -req -sha256 -days 825 \
  -in "$SANDBOX_TLS_DIR/server.csr" \
  -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
  -extfile "$SANDBOX_TLS_DIR/server.cnf.tmp" -extensions v3_req \
  -out "$SANDBOX_TLS_DIR/server.crt" >/dev/null 2>&1 || die "server cert sign failed"
chmod 600 "$SANDBOX_TLS_DIR/server.key"
chmod 644 "$SANDBOX_TLS_DIR/server.crt"
rm -f "$SANDBOX_TLS_DIR/server.csr" "$SANDBOX_TLS_DIR/server.cnf.tmp"

# Runtime-mTLS credentials (sandbox service -> gateway).
RUNTIME_MTLS_DIR="$CONFIG_ROOT/runtime-mtls"
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
  "runtime_connect_timeout_ms": 10000,
  "runtime_poll_interval_ms": 500,
  "reconcile_delete_deadline_ms": 60000,
  "reconcile_wait_deadline_ms": 60000,
  "maximum_connections": 64,
  "drain_timeout_ms": 30000,
  "allow_degraded_landlock": true
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
  for _ in $(seq 1 40); do
    if port_listening "$SANDBOX_PORT"; then
      ok "service up (pid=$(cat "$SANDBOX_PID_FILE"))"
      service_ready=1
      break
    fi
    sleep 0.25
  done
  [[ "$service_ready" == "1" ]] || die "sandbox service failed to become ready; see $SERVICE_LOG"
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
if [[ "${OPENBOX_WARM_CACHE:-1}" == "0" ]]; then
  info "cache warm skipped (OPENBOX_WARM_CACHE=0)"
elif [[ "$NO_START" == "1" ]]; then
  info "cache warm skipped (NO_START=1; stack not started)"
elif [[ -x "$CLI_BIN" ]]; then
  info "warming VM driver image cache ($SANDBOX_IMAGE)..."
  warm_name="w$(date +%s)"
  if "$CLI_BIN" sandbox create --name "$warm_name" -- /bin/true >/dev/null 2>&1; then
    warmed=0
    # Cold-cache create can take ~5-6 min (image pull/extract + microVM boot
    # on small hosts); poll up to 10 min before warning.
    for _ in $(seq 1 120); do
      if "$CLI_BIN" sandbox get "$warm_name" 2>/dev/null \
        | grep -qiE 'ready|running'; then
        warmed=1
        break
      fi
      sleep 5
    done
    if [[ "$warmed" == "1" ]]; then
      ok "cache warmed: $warm_name"
    else
      warn "warm sandbox did not reach ready in time; first request may be slow"
    fi
    "$CLI_BIN" sandbox delete "$warm_name" >/dev/null 2>&1 \
      || warn "warm sandbox $warm_name delete failed (gateway will reap it)"
  else
    die "cache warm failed: sandbox create rejected by gateway; see $GATEWAY_LOG"
  fi
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