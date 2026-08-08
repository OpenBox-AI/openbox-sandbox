#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVISION="$SCRIPT_DIR/provision-local-sandbox.sh"
TMP="$(mktemp -d)"
PIDS=()
cleanup() {
  local pid
  # ${arr[@]+...} guard keeps bash 3.2 (macOS) happy with empty arrays.
  for pid in "${PIDS[@]+"${PIDS[@]}"}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

free_tcp_port() {
  python3 - <<'PY'
import socket

sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
}

make_bundle() {
  local version="$1" bin
  rm -rf "${TMP:?}/bin"
  mkdir -p "$TMP/bin"
  for bin in openshell-gateway openshell openshell-driver-vm; do
    cat >"$TMP/bin/$bin" <<EOF
#!/usr/bin/env bash
printf '%s\\n' '$bin $version'
EOF
    chmod 0755 "$TMP/bin/$bin"
  done
}

run_provision() {
  HOME="$TMP/home" \
  OPENBOX_STATE_ROOT="$TMP/state" \
  OPENBOX_CONFIG_ROOT="$TMP/config" \
  OPENSHELL_BIN_OVERRIDE="$TMP/bin" \
  OPENBOX_SANDBOX_BIN="$TMP/missing-openbox-sandbox" \
    bash "$PROVISION" >"$TMP/stdout" 2>"$TMP/stderr"
}

mkdir -p "$TMP/home" "$TMP/state"
printf 'preserve-before-compatibility-check\n' >"$TMP/state/sentinel"
grep -Fq "OPENBOX_SANDBOX_BINARY=\${SANDBOX_BIN}" "$PROVISION"
grep -Fq 'fresh PKI and timestamps differ' "$PROVISION"

# ── No-image umask workaround: strict global umask, gateway-child-only relax ──
# The wizard must keep a strict global `umask 077` so every bit of host state it
# writes stays private, and relax to `umask 022` ONLY for the gateway child so
# the gateway -> VM driver -> guest PID1 chain inherits it for the imageless
# guest. These static assertions fail if the global umask is weakened, the
# child-only scoping is removed, or the PID/launch structure is broken.
grep -Eq '^umask 077$' "$PROVISION" \
  || { echo 'expected the global umask 077 to be preserved' >&2; exit 1; }
if grep -Eq '^[[:space:]]*umask 022[[:space:]]*$' "$PROVISION"; then
  echo 'expected umask 022 to be scoped to the gateway child, not a global statement' >&2
  exit 1
fi
# shellcheck disable=SC2016  # literal $GATEWAY_BIN in the launch construct
grep -Eq '\([[:space:]]*umask 022;[[:space:]]*exec nohup "\$GATEWAY_BIN"' "$PROVISION" \
  || { echo 'expected the gateway child to launch under ( umask 022; exec nohup ... )' >&2; exit 1; }
# The log redirect must be OUTSIDE the umask 022 subshell so gateway.log is
# opened by the parent shell under umask 077 (0600), not the relaxed child
# (which produced a 0644 log). Require the outside-redirection structure...
# shellcheck disable=SC2016  # literal redirect/backgrounding text in the script
grep -Fq -- '--enable-mtls-auth true ) >"$GATEWAY_LOG" 2>&1 &' "$PROVISION" \
  || { echo 'expected the gateway subshell to close before the log redirect (redirect outside umask 022)' >&2; exit 1; }
# ...and reject the prior inside-subshell redirection that created a 0644 log.
# shellcheck disable=SC2016  # literal inside-subshell redirect text
if grep -Fq -- '--enable-mtls-auth true >"$GATEWAY_LOG" 2>&1 ) &' "$PROVISION"; then
  echo 'gateway log redirect must not be inside the umask 022 subshell' >&2
  exit 1
fi
# shellcheck disable=SC2016  # literal $! / $GATEWAY_PID_FILE in the script
grep -Fq -- 'echo $! >"$GATEWAY_PID_FILE"' "$PROVISION" \
  || { echo 'expected the gateway PID capture to be preserved' >&2; exit 1; }

if bash "$PROVISION" --keep-pki >"$TMP/stdout" 2>"$TMP/stderr"; then
  echo 'expected standalone --keep-pki to be rejected' >&2
  exit 1
fi
grep -q -- '--keep-pki requires --uninstall or --clean-rerun' "$TMP/stderr"

make_bundle '0.0.85'
if run_provision; then
  echo 'expected the 0.0.85 release bundle to be rejected' >&2
  exit 1
fi
grep -q 'required OpenShell source marker f1690849' "$TMP/stderr"
grep -q 'or locked released version 0.0.88' "$TMP/stderr"
test -f "$TMP/state/sentinel"

make_bundle '0.0.0-gf16908490'
if run_provision; then
  echo 'expected a longer, non-exact source marker to be rejected' >&2
  exit 1
fi
grep -q 'required OpenShell source marker f1690849' "$TMP/stderr"

make_bundle '0.0.0-gf1690849'
if run_provision; then
  echo 'expected the missing root service binary to stop the test run' >&2
  exit 1
fi
grep -q 'openshell-gateway verified (f1690849 | 0.0.88)' "$TMP/stderr"
grep -q 'openshell verified (f1690849 | 0.0.88)' "$TMP/stderr"
grep -q 'openshell-driver-vm verified (f1690849 | 0.0.88)' "$TMP/stderr"
grep -q 'openbox-sandbox service not found' "$TMP/stderr"

# Demo down can invoke teardown without deleting provisioned state or requiring
# the runtime bundle to still be installed.
mkdir -p "$TMP/teardown-state" "$TMP/teardown-config"
printf 'keep-state\n' >"$TMP/teardown-state/sentinel"
printf 'keep-config\n' >"$TMP/teardown-config/sentinel"
HOME="$TMP/home" OPENBOX_STATE_ROOT="$TMP/teardown-state" \
  OPENBOX_CONFIG_ROOT="$TMP/teardown-config" OPENBOX_SANDBOX_PORT="$(free_tcp_port)" \
  OPENSHELL_SERVER_PORT="$(free_tcp_port)" OPENBOX_TEARDOWN_ONLY=1 \
  bash "$PROVISION" >"$TMP/stdout" 2>"$TMP/stderr"
test -f "$TMP/teardown-state/sentinel"
test -f "$TMP/teardown-config/sentinel"
grep -q 'stack teardown complete' "$TMP/stderr"

# An unrelated listener on a configured port must survive teardown. The wizard
# reports the owner and fails instead of signalling it.
port_file="$TMP/listener.port"
python3 - "$port_file" <<'PY' &
import socket
import sys
import time

listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen()
with open(sys.argv[1], "w", encoding="utf-8") as output:
    output.write(str(listener.getsockname()[1]))
while True:
    time.sleep(1)
PY
listener_pid=$!
PIDS+=("$listener_pid")
for _ in $(seq 1 50); do
  [[ -s "$port_file" ]] && break
  sleep 0.1
done
listener_port="$(cat "$port_file")"
listener_gateway_port="$(free_tcp_port)"
if HOME="$TMP/home" OPENBOX_STATE_ROOT="$TMP/listener-state" \
  OPENBOX_CONFIG_ROOT="$TMP/listener-config" OPENBOX_SANDBOX_PORT="$listener_port" \
  OPENSHELL_SERVER_PORT="$listener_gateway_port" bash "$PROVISION" --uninstall \
  >"$TMP/stdout" 2>"$TMP/stderr"; then
  echo 'expected teardown to reject an unrelated port listener' >&2
  exit 1
fi
kill -0 "$listener_pid"
grep -q 'no unowned listener will be signalled' "$TMP/stderr"
grep -q "listener pid=$listener_pid" "$TMP/stderr"
kill "$listener_pid"
wait "$listener_pid" 2>/dev/null || true

# A reused/mismatched PID file must not authorize signalling another process.
sleep 30 &
unrelated_pid=$!
PIDS+=("$unrelated_pid")
mkdir -p "$TMP/pid-state"
printf '%s\n' "$unrelated_pid" >"$TMP/pid-state/sandbox-service.pid"
if HOME="$TMP/home" OPENBOX_STATE_ROOT="$TMP/pid-state" \
  OPENBOX_CONFIG_ROOT="$TMP/pid-config" OPENBOX_SANDBOX_PORT="$(free_tcp_port)" \
  OPENSHELL_SERVER_PORT="$(free_tcp_port)" bash "$PROVISION" --uninstall \
  >"$TMP/stdout" 2>"$TMP/stderr"; then
  echo 'expected teardown to reject a mismatched PID file' >&2
  exit 1
fi
kill -0 "$unrelated_pid"
grep -q 'does not match wizard command' "$TMP/stderr"
kill "$unrelated_pid"
wait "$unrelated_pid" 2>/dev/null || true

# Gateway ownership is stable across invocation paths: uninstall resolves the
# default bundle, but may stop an override-path gateway only when its command
# carries this wizard's exact gateway config marker.
mkdir -p "$TMP/override-bin" "$TMP/override-state/gateway"
cat >"$TMP/override-bin/gateway.c" <<'EOF'
#include <signal.h>
#include <unistd.h>
static volatile sig_atomic_t stopped = 0;
static void stop(int signal_number) {
  (void)signal_number;
  stopped = 1;
}
int main(void) {
  signal(SIGTERM, stop);
  while (!stopped) pause();
  return 0;
}
EOF
cc -o "$TMP/override-bin/openshell-gateway" "$TMP/override-bin/gateway.c"
override_gateway_config="$TMP/override-state/gateway/gateway.toml"
printf '[openshell]\nversion = 1\n' >"$override_gateway_config"
"$TMP/override-bin/openshell-gateway" --config "$override_gateway_config" &
override_gateway_pid=$!
PIDS+=("$override_gateway_pid")
printf '%s\n' "$override_gateway_pid" >"$TMP/override-state/gateway/gateway.pid"
sleep 0.2
env -u OPENSHELL_BIN_OVERRIDE HOME="$TMP/home" OPENBOX_STATE_ROOT="$TMP/override-state" \
  OPENBOX_CONFIG_ROOT="$TMP/override-config" OPENBOX_SANDBOX_PORT="$(free_tcp_port)" \
  OPENSHELL_SERVER_PORT="$(free_tcp_port)" bash "$PROVISION" --uninstall \
  >"$TMP/stdout" 2>"$TMP/stderr"
if kill -0 "$override_gateway_pid" 2>/dev/null; then
  echo 'expected config-marked override gateway to stop' >&2
  exit 1
fi
wait "$override_gateway_pid" 2>/dev/null || true
grep -q "stopping validated gateway pid=$override_gateway_pid" "$TMP/stderr"

# The same process name without the exact wizard config marker is not owned,
# even when a gateway PID file points at it.
mkdir -p "$TMP/unmarked-state/gateway"
unmarked_gateway_config="$TMP/unmarked-state/gateway/gateway.toml"
printf '[openshell]\nversion = 1\n' >"$unmarked_gateway_config"
"$TMP/override-bin/openshell-gateway" --config "${unmarked_gateway_config}.other" &
unmarked_gateway_pid=$!
PIDS+=("$unmarked_gateway_pid")
printf '%s\n' "$unmarked_gateway_pid" >"$TMP/unmarked-state/gateway/gateway.pid"
sleep 0.2
if env -u OPENSHELL_BIN_OVERRIDE HOME="$TMP/home" OPENBOX_STATE_ROOT="$TMP/unmarked-state" \
  OPENBOX_CONFIG_ROOT="$TMP/unmarked-config" OPENBOX_SANDBOX_PORT="$(free_tcp_port)" \
  OPENSHELL_SERVER_PORT="$(free_tcp_port)" bash "$PROVISION" --uninstall \
  >"$TMP/stdout" 2>"$TMP/stderr"; then
  echo 'expected unmarked same-name gateway to be rejected' >&2
  exit 1
fi
kill -0 "$unmarked_gateway_pid"
grep -q "exact wizard config $unmarked_gateway_config" "$TMP/stderr"
kill "$unmarked_gateway_pid"
wait "$unmarked_gateway_pid" 2>/dev/null || true

# Driver cleanup is scoped by this wizard's exact VM state directory. A driver
# command associated with another state directory is reported and left alive.
cat >"$TMP/openshell-driver-vm" <<'EOF'
#!/usr/bin/env bash
child=''
cleanup_child() {
  [[ -z "$child" ]] || kill "$child" 2>/dev/null || true
  [[ -z "$child" ]] || wait "$child" 2>/dev/null || true
  exit 0
}
trap cleanup_child TERM INT
sleep 30 &
child=$!
wait "$child"
EOF
chmod 0755 "$TMP/openshell-driver-vm"
"$TMP/openshell-driver-vm" --internal-run-vm --state-dir "$TMP/unrelated-driver-state" &
unrelated_driver_pid=$!
PIDS+=("$unrelated_driver_pid")
sleep 0.2
driver_sandbox_port="$(free_tcp_port)"
driver_gateway_port="$(free_tcp_port)"
HOME="$TMP/home" OPENBOX_STATE_ROOT="$TMP/driver-state" \
  OPENBOX_CONFIG_ROOT="$TMP/driver-config" OPENBOX_SANDBOX_PORT="$driver_sandbox_port" \
  OPENSHELL_SERVER_PORT="$driver_gateway_port" OPENSHELL_VM_DRIVER_STATE_DIR="$TMP/our-driver-state" \
  bash "$PROVISION" --uninstall >"$TMP/stdout" 2>"$TMP/stderr"
kill -0 "$unrelated_driver_pid"
grep -q "leaving unrelated VM driver pid=$unrelated_driver_pid" "$TMP/stderr"
kill "$unrelated_driver_pid"
wait "$unrelated_driver_pid" 2>/dev/null || true

our_driver_state="$TMP/scoped-driver-state"
"$TMP/openshell-driver-vm" --internal-run-vm --state-dir "$our_driver_state" &
scoped_driver_pid=$!
PIDS+=("$scoped_driver_pid")
sleep 0.2
HOME="$TMP/home" OPENBOX_STATE_ROOT="$TMP/scoped-state" \
  OPENBOX_CONFIG_ROOT="$TMP/scoped-config" OPENBOX_SANDBOX_PORT="$(free_tcp_port)" \
  OPENSHELL_SERVER_PORT="$(free_tcp_port)" OPENSHELL_VM_DRIVER_STATE_DIR="$our_driver_state" \
  bash "$PROVISION" --uninstall >"$TMP/stdout" 2>"$TMP/stderr"
if kill -0 "$scoped_driver_pid" 2>/dev/null; then
  echo 'expected the wizard-scoped VM driver to stop' >&2
  exit 1
fi
wait "$scoped_driver_pid" 2>/dev/null || true
grep -q "stopping wizard-scoped VM driver pid=$scoped_driver_pid" "$TMP/stderr"

printf 'provision source-marker and teardown-ownership tests passed\n'
