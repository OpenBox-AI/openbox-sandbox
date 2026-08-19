#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "native srt provision failed at line $LINENO (exit $?)" >&2' ERR
umask 077

die() { printf 'provision: %s\n' "$*" >&2; exit 1; }
info() { printf '  ==> %s\n' "$*" >&2; }
ok() { printf '  [ok] %s\n' "$*" >&2; }
sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
port_listening() {
  if command -v lsof >/dev/null 2>&1; then lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  else (echo >/dev/tcp/127.0.0.1/"$1") >/dev/null 2>&1; fi
}

ARG_UNINSTALL=0; ARG_CLEAN_RERUN=0; ARG_KEEP_PKI=0
for arg in "$@"; do
  case "$arg" in
    --uninstall) ARG_UNINSTALL=1 ;;
    --clean-rerun) ARG_CLEAN_RERUN=1 ;;
    --keep-pki) ARG_KEEP_PKI=1 ;;
    --purge-cache) : ;; # no cache exists on the native provider
    --help|-h) echo 'native srt provision: --clean-rerun | --uninstall | --keep-pki'; exit 0 ;;
    *) die "unsupported arg: $arg" ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${OPENBOX_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
STATE_ROOT="${OPENBOX_STATE_ROOT:-$HOME/.local/state/openbox-sandbox}"
CONFIG_ROOT="${OPENBOX_CONFIG_ROOT:-$HOME/.config/openbox-sandbox}"
# The service rejects symlink path components. Resolve macOS /tmp -> /private/tmp
# and any operator-provided physical roots before writing pinned absolute paths.
mkdir -p "$STATE_ROOT" "$CONFIG_ROOT"
STATE_ROOT="$(cd "$STATE_ROOT" && pwd -P)"
CONFIG_ROOT="$(cd "$CONFIG_ROOT" && pwd -P)"
SANDBOX_PORT="${OPENBOX_SANDBOX_PORT:-17443}"
SERVICE_CONFIG="$CONFIG_ROOT/service.json"
SERVICE_LOG="$STATE_ROOT/sandbox-service.log"
SERVICE_PID_FILE="$STATE_ROOT/sandbox-service.pid"
SANDBOX_TLS_DIR="$CONFIG_ROOT/tls"
SANDBOX_STATE_DIR="$STATE_ROOT/cleanup"
SRT_WORKSPACE_ROOT="${OPENBOX_SRT_WORKSPACE_ROOT:-/private/tmp/openbox-sandbox-${UID}/workspaces}"
SRT_PROFILE="$STATE_ROOT/srt/policy.$([[ "$(uname -s)" == Darwin ]] && echo sb || echo json)"
AGENT_ENV="$CONFIG_ROOT/agent.env"
NO_START="${NO_START:-0}"
SERVICE_READY_POLLS="${OPENBOX_SERVICE_READY_POLLS:-40}"
SERVICE_READY_INTERVAL="${OPENBOX_SERVICE_READY_INTERVAL:-0.25}"
RECONCILE_DELETE_DEADLINE_MS="${OPENBOX_RECONCILE_DELETE_DEADLINE_MS:-60000}"
RECONCILE_WAIT_DEADLINE_MS="${OPENBOX_RECONCILE_WAIT_DEADLINE_MS:-60000}"
MAX_CONNECTIONS="${OPENBOX_MAX_CONNECTIONS:-64}"
DRAIN_TIMEOUT_MS="${OPENBOX_DRAIN_TIMEOUT_MS:-30000}"
CERT_DAYS="${OPENBOX_CERT_DAYS:-825}"
RSA_BITS="${OPENBOX_RSA_BITS:-2048}"
CALLER_SUBJ="${OPENBOX_CALLER_SUBJ:-/CN=openbox-sandbox-runtime-caller}"
POLICY_VERSION="${OPENBOX_POLICY_VERSION:-1}"
COMPAT_ID="${OPENBOX_COMPAT_ID:-native-srt-v1}"

if [[ -n "${OPENBOX_SANDBOX_BIN:-}" ]]; then SANDBOX_BIN="$OPENBOX_SANDBOX_BIN"
elif [[ "$(uname -s)-$(uname -m)" == Darwin-arm64 && -x "$(pwd)/openbox-sandbox-darwin-arm64" ]]; then SANDBOX_BIN="$(pwd)/openbox-sandbox-darwin-arm64"
elif [[ "$(uname -s)-$(uname -m)" == Linux-x86_64 && -x "$(pwd)/openbox-sandbox-linux-x86_64" ]]; then SANDBOX_BIN="$(pwd)/openbox-sandbox-linux-x86_64"
else SANDBOX_BIN="$PROJECT_ROOT/target/release/openbox-sandbox"; fi
if [[ "${OPENBOX_RELEASE_LINE:-base}" == dev ]]; then
  DEFAULT_POLICY_TEMPLATE="policy-allow-network-dev.yaml"
  DEFAULT_POLICY_ID="openbox-allow-network-dev"
else
  DEFAULT_POLICY_TEMPLATE="policy-deny-network-dev.yaml"
  DEFAULT_POLICY_ID="openbox-deny-network-dev"
fi
if [[ -n "${OPENBOX_POLICY_FILE:-}" ]]; then
  POLICY_FILE="$OPENBOX_POLICY_FILE"
elif [[ -f "$(pwd)/$DEFAULT_POLICY_TEMPLATE" ]]; then
  POLICY_FILE="$(pwd)/$DEFAULT_POLICY_TEMPLATE"
else
  POLICY_FILE="$PROJECT_ROOT/deploy/policies/$DEFAULT_POLICY_TEMPLATE"
fi
POLICY_ID="${OPENBOX_POLICY_ID:-$DEFAULT_POLICY_ID}"
case "$(basename "$POLICY_FILE")" in
  *allow*) POLICY_ID="${OPENBOX_POLICY_ID:-openbox-allow-network-dev}" ;;
esac

stop_service() {
  [[ -f "$SERVICE_PID_FILE" ]] || return 0
  local pid command
  pid="$(cat "$SERVICE_PID_FILE" 2>/dev/null || true)"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || die "malformed service PID file"
  if kill -0 "$pid" 2>/dev/null; then
    command="$(ps -ww -p "$pid" -o command= 2>/dev/null || true)"
    [[ "${command%% *}" == *"$(basename "$SANDBOX_BIN")" ]] || die "service PID identity mismatch; refusing to signal"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep "$SERVICE_READY_INTERVAL"; done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$SERVICE_PID_FILE"
}

info "native srt teardown"
stop_service
if port_listening "$SANDBOX_PORT"; then die "sandbox service port $SANDBOX_PORT remains occupied"; fi
ok "teardown complete"

if [[ "$ARG_UNINSTALL" == 1 || "$ARG_CLEAN_RERUN" == 1 ]]; then
  rm -rf -- "$STATE_ROOT" "$CONFIG_ROOT" "$(dirname "$SRT_WORKSPACE_ROOT")"
  ok "state cleaned"
fi
if [[ "$ARG_UNINSTALL" == 1 || "${OPENBOX_TEARDOWN_ONLY:-0}" == 1 ]]; then ok "native srt teardown/uninstall complete"; exit 0; fi

[[ -x "$SANDBOX_BIN" ]] || die "openbox-sandbox service not found at $SANDBOX_BIN"
[[ -f "$POLICY_FILE" ]] || die "channel policy not found at $POLICY_FILE"
if [[ "$(uname -s)" == Darwin ]] && [[ ! -x /usr/bin/sandbox-exec ]]; then
  die "/usr/bin/sandbox-exec is required for the native srt provider on macOS (it ships with macOS; contact Apple support if missing)"
fi
if [[ "$(uname -s)" == Linux ]] && ! command -v bwrap >/dev/null 2>&1; then
  die "bubblewrap is required for the native srt provider (install package: bubblewrap)"
fi
command -v openssl >/dev/null 2>&1 || die "openssl is required"

mkdir -p "$STATE_ROOT/srt" "$SRT_WORKSPACE_ROOT" "$SANDBOX_STATE_DIR" "$CONFIG_ROOT" "$SANDBOX_TLS_DIR"
SRT_WORKSPACE_ROOT="$(cd "$SRT_WORKSPACE_ROOT" && pwd -P)"
chmod 700 "$(dirname "$SRT_WORKSPACE_ROOT")" "$STATE_ROOT" "$STATE_ROOT/srt" "$SRT_WORKSPACE_ROOT" "$SANDBOX_STATE_DIR" "$CONFIG_ROOT" "$SANDBOX_TLS_DIR"
info "compiling deployment-pinned native policy"
SRT_PROFILE_SHA="$($SANDBOX_BIN --compile-srt-policy "$POLICY_FILE" "$SRT_PROFILE" "$SRT_WORKSPACE_ROOT")" \
  || die "native policy compilation failed"
chmod 600 "$SRT_PROFILE"
[[ "$(sha256_hex "$SRT_PROFILE")" == "$SRT_PROFILE_SHA" ]] || die "compiled native profile hash mismatch"
ok "profile pinned: $SRT_PROFILE_SHA"

# Local boundary PKI only. No gateway CA, keychain, or sudo path exists here.
CA_KEY="$SANDBOX_TLS_DIR/ca.key"; CA_CERT="$SANDBOX_TLS_DIR/ca.crt"
openssl req -x509 -newkey rsa:"$RSA_BITS" -nodes -sha256 -days "$CERT_DAYS" \
  -subj '/CN=OpenBox Native SRT Local CA' -keyout "$CA_KEY" -out "$CA_CERT" \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl genrsa -out "$SANDBOX_TLS_DIR/client.key" "$RSA_BITS" >/dev/null 2>&1
openssl req -new -key "$SANDBOX_TLS_DIR/client.key" -subj "$CALLER_SUBJ" -out "$SANDBOX_TLS_DIR/client.csr" >/dev/null 2>&1
cat >"$SANDBOX_TLS_DIR/client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -sha256 -days "$CERT_DAYS" -in "$SANDBOX_TLS_DIR/client.csr" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -extfile "$SANDBOX_TLS_DIR/client.ext" \
  -out "$SANDBOX_TLS_DIR/client.crt" >/dev/null 2>&1
openssl genrsa -out "$SANDBOX_TLS_DIR/server.key" "$RSA_BITS" >/dev/null 2>&1
cat >"$SANDBOX_TLS_DIR/server.cnf" <<'EOF'
[req]
distinguished_name=dn
req_extensions=v3_req
prompt=no
[dn]
CN=localhost
[v3_req]
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt
[alt]
DNS.1=localhost
IP.1=127.0.0.1
EOF
openssl req -new -key "$SANDBOX_TLS_DIR/server.key" -config "$SANDBOX_TLS_DIR/server.cnf" -out "$SANDBOX_TLS_DIR/server.csr" >/dev/null 2>&1
openssl x509 -req -sha256 -days "$CERT_DAYS" -in "$SANDBOX_TLS_DIR/server.csr" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -extfile "$SANDBOX_TLS_DIR/server.cnf" -extensions v3_req \
  -out "$SANDBOX_TLS_DIR/server.crt" >/dev/null 2>&1
chmod 600 "$CA_KEY" "$SANDBOX_TLS_DIR/client.key" "$SANDBOX_TLS_DIR/server.key"
chmod 644 "$CA_CERT" "$SANDBOX_TLS_DIR/client.crt" "$SANDBOX_TLS_DIR/server.crt"
rm -f "$SANDBOX_TLS_DIR"/*.csr "$SANDBOX_TLS_DIR"/*.ext "$SANDBOX_TLS_DIR/server.cnf"

CALLER_FP="$(openssl x509 -in "$SANDBOX_TLS_DIR/client.crt" -outform DER | sha256_hex /dev/stdin)"
ADAPTER_SHA="$(sha256_hex "$SANDBOX_BIN")"
POLICY_SHA="$(sha256_hex "$POLICY_FILE")"
cat >"$SERVICE_CONFIG" <<EOF
{
  "bind_address": "127.0.0.1:${SANDBOX_PORT}",
  "server_certificate_path": "${SANDBOX_TLS_DIR}/server.crt",
  "server_private_key_path": "${SANDBOX_TLS_DIR}/server.key",
  "client_ca_path": "${CA_CERT}",
  "authorized_callers": [{"certificate_sha256":"${CALLER_FP}","role":"runtime"}],
  "state_directory": "${SANDBOX_STATE_DIR}",
  "provider": "srt",
  "provider_capability": "enforced-locally",
  "srt_profile_path": "${SRT_PROFILE}",
  "srt_profile_sha256": "${SRT_PROFILE_SHA}",
  "srt_workspace_root": "${SRT_WORKSPACE_ROOT}",
  "asset_bundle": {
    "runtime_contract_version": 1,
    "adapter_build_sha256": "${ADAPTER_SHA}",
    "template": "native://srt",
    "policy": {"id":"${POLICY_ID}","version":${POLICY_VERSION},"sha256":"${POLICY_SHA}"},
    "compatibility_id": "${COMPAT_ID}"
  },
  "reconcile_delete_deadline_ms": ${RECONCILE_DELETE_DEADLINE_MS},
  "reconcile_wait_deadline_ms": ${RECONCILE_WAIT_DEADLINE_MS},
  "maximum_connections": ${MAX_CONNECTIONS},
  "drain_timeout_ms": ${DRAIN_TIMEOUT_MS}
}
EOF
chmod 600 "$SERVICE_CONFIG"
OPENBOX_SANDBOX_CONFIG="$SERVICE_CONFIG" "$SANDBOX_BIN" --check-config >/dev/null || die "service rejected native srt config"
ok "service config validated (provider=srt, capability=enforced-locally)"

if [[ "$NO_START" != 1 ]]; then
  OPENBOX_SANDBOX_CONFIG="$SERVICE_CONFIG" nohup "$SANDBOX_BIN" >"$SERVICE_LOG" 2>&1 &
  echo $! >"$SERVICE_PID_FILE"
  ready=0
  for _ in $(seq 1 "$SERVICE_READY_POLLS"); do port_listening "$SANDBOX_PORT" && ready=1 && break; sleep "$SERVICE_READY_INTERVAL"; done
  if [[ "$ready" != 1 ]]; then tail -n 30 "$SERVICE_LOG" >&2 || true; die "sandbox service failed to start"; fi
  ok "service up (provider=srt pid=$(cat "$SERVICE_PID_FILE"))"
fi

cat >"$AGENT_ENV" <<EOF
# OpenBox SDK agent environment. Provider-neutral boundary values.
OPENBOX_SANDBOX_ENDPOINT=127.0.0.1:${SANDBOX_PORT}
OPENBOX_SANDBOX_SERVER_NAME=localhost
OPENBOX_SANDBOX_CA=${CA_CERT}
OPENBOX_SANDBOX_CERT=${SANDBOX_TLS_DIR}/client.crt
OPENBOX_SANDBOX_KEY=${SANDBOX_TLS_DIR}/client.key
OPENBOX_SANDBOX_BINARY=${SANDBOX_BIN}
OPENBOX_SANDBOX_ADAPTER_SHA=${ADAPTER_SHA}
OPENBOX_SANDBOX_TEMPLATE=native://srt
OPENBOX_SANDBOX_POLICY_FILE=${POLICY_FILE}
OPENBOX_SANDBOX_POLICY_ID=${POLICY_ID}
OPENBOX_SANDBOX_POLICY_VERSION=${POLICY_VERSION}
OPENBOX_SANDBOX_POLICY_SHA256=${POLICY_SHA}
OPENBOX_SANDBOX_COMPAT_ID=${COMPAT_ID}
OPENBOX_SANDBOX_CONFIG_PATH=${SERVICE_CONFIG}
OPENBOX_PROVIDER=srt
EOF
chmod 600 "$AGENT_ENV"

if [[ "$NO_START" != 1 ]]; then
  info "native runner smoke: /bin/true"
  if [[ "$(uname -s)" == Darwin ]]; then
    (cd "$SRT_WORKSPACE_ROOT" && /usr/bin/sandbox-exec \
      -D "WORKSPACE_ROOT=$SRT_WORKSPACE_ROOT" -D "WORKSPACE=$SRT_WORKSPACE_ROOT" \
      -f "$SRT_PROFILE" -- /usr/bin/true) || die "native Seatbelt smoke failed"
  else
    bwrap_args=(--die-with-parent --new-session --unshare-all --unshare-net --proc /proc --dev /dev)
    for path in /usr /bin /sbin /lib /lib64 /etc; do
      [[ -e "$path" ]] && bwrap_args+=(--ro-bind "$path" "$path")
    done
    bwrap_args+=(--bind "$SRT_WORKSPACE_ROOT" /sandbox --chdir /sandbox -- /bin/true)
    bwrap "${bwrap_args[@]}" || die "native bwrap smoke failed"
  fi
  ok "native sandbox smoke ready"
fi
ok "native srt provision complete"
info "service: 127.0.0.1:${SANDBOX_PORT}"
info "agent env: $AGENT_ENV"
