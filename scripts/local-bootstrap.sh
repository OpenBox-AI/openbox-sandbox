#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly OPENSHELL_SOURCE_PIN="f169084923503a02a94425857b938de2841cab0c"
readonly OPENSHELL_VERSION_MARKER="gf1690849"
readonly RUSTUP_VERSION="1.28.2"
readonly RUST_TOOLCHAIN="1.95.0"
readonly LOCAL_IMAGE="ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"

fail() {
  printf 'openbox-sandbox local bootstrap: %s\n' "$1" >&2
  exit 1
}

ask_yes_no() {
  local prompt=$1 answer
  [[ -r /dev/tty && -w /dev/tty ]] || return 1
  printf '%s [y/N] ' "$prompt" >/dev/tty
  IFS= read -r answer </dev/tty || return 1
  [[ $answer == y || $answer == Y || $answer == yes || $answer == YES ]]
}

DEPENDENCY_MODE=ask
NO_START=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --install-dependencies) DEPENDENCY_MODE=yes ;;
    --no-install-dependencies) DEPENDENCY_MODE=no ;;
    --no-start) NO_START=1 ;;
    *) fail "unsupported local bootstrap option: $1" ;;
  esac
  shift
done

[[ $EUID -ne 0 ]] || fail "run as an ordinary user; privileged installation is requested only after preparation"
[[ $OSTYPE == linux* ]] || fail "local bootstrap currently supports Debian-family Linux hosts"
command -v apt-get >/dev/null 2>&1 || fail "local bootstrap currently requires apt-get; use a published release bundle on this host"
command -v sudo >/dev/null 2>&1 || fail "sudo is required to install local build and service prerequisites"

script_source=${BASH_SOURCE[0]}
[[ $script_source == /* ]] || script_source="$PWD/$script_source"
script_parent=${script_source%/*}
ROOT=$(CDPATH='' cd -P -- "$script_parent/.." && pwd -P) || fail "cannot resolve source root"
readonly ROOT
[[ -f $ROOT/Cargo.toml && -f $ROOT/Cargo.lock && -x $ROOT/install.sh ]] \
  || fail "local bootstrap must run from a complete source checkout"

printf '%s\n' \
  "This mode builds a complete LOCAL, NON-PRODUCTION installation from the locked source." \
  "It downloads exact source/toolchain dependencies, generates local-only mTLS identities," \
  "and installs the pinned OpenShell gateway plus OpenBox Sandbox." >&2
if [[ $DEPENDENCY_MODE == no ]]; then
  INSTALL_BUILD_DEPENDENCIES=0
elif [[ $DEPENDENCY_MODE == yes ]] \
  || ask_yes_no "Install missing local build prerequisites with apt-get?"; then
  INSTALL_BUILD_DEPENDENCIES=1
else
  fail "local bootstrap requires approved build prerequisites"
fi

readonly -a BUILD_PACKAGES=(
  autoconf automake build-essential ca-certificates clang cmake curl dpkg-dev
  fuse-overlayfs git libclang-dev libtool libz3-dev openssl pkg-config podman
  slirp4netns systemd uidmap
)
missing_packages=()
for package in "${BUILD_PACKAGES[@]}"; do
  dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'ok installed' \
    || missing_packages+=("$package")
done
if [[ ${#missing_packages[@]} -gt 0 ]]; then
  [[ $INSTALL_BUILD_DEPENDENCIES -eq 1 ]] \
    || fail "missing local build packages: ${missing_packages[*]}"
  sudo apt-get update
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    "${missing_packages[@]}"
fi

for command in curl dpkg-deb git openssl sha256sum; do
  command -v "$command" >/dev/null 2>&1 || fail "required command unavailable: $command"
done

export CARGO_HOME="$HOME/.cargo"
export RUSTUP_HOME="$HOME/.rustup"

install_rustup() {
  local target checksum temporary_directory temporary expected
  case $(uname -m) in
    x86_64|amd64)
      target=x86_64-unknown-linux-gnu
      expected=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
      ;;
    aarch64|arm64)
      target=aarch64-unknown-linux-gnu
      expected=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c
      ;;
    *) fail "unsupported local Rust architecture: $(uname -m)" ;;
  esac
  temporary_directory=$(mktemp -d /tmp/openbox-rustup.XXXXXXXX)
  temporary="$temporary_directory/rustup-init"
  trap 'rm -rf -- "$temporary_directory"' RETURN
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
    "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${target}/rustup-init" \
    --output "$temporary"
  checksum=$(sha256sum "$temporary" | awk '{print $1}')
  [[ $checksum == "$expected" ]] || fail "rustup-init checksum mismatch"
  chmod 0700 "$temporary"
  "$temporary" -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN" --no-modify-path
  rm -rf -- "$temporary_directory"
  trap - RETURN
}

if [[ ! -x $HOME/.cargo/bin/rustup ]]; then
  install_rustup
fi
export PATH="$CARGO_HOME/bin:$PATH"
rustup set auto-self-update disable
rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
rustup override unset --path "$ROOT" >/dev/null 2>&1 || true
[[ $(rustc +"$RUST_TOOLCHAIN" --version) == "rustc ${RUST_TOOLCHAIN} "* ]] \
  || fail "required Rust toolchain is unavailable"

LOCAL_ROOT="$ROOT/.openbox-local"
[[ ! -L $LOCAL_ROOT ]] || fail "local build directory cannot be a symbolic link"
install -d -m 0700 "$LOCAL_ROOT" "$LOCAL_ROOT/build" "$LOCAL_ROOT/clients" "$LOCAL_ROOT/pki"
OPENBOX_TARGET="$LOCAL_ROOT/build/openbox-target"
OPENSHELL_CHECKOUT="$LOCAL_ROOT/build/openshell-source"
OPENSHELL_TARGET="$LOCAL_ROOT/build/openshell-target"
RELEASE="$LOCAL_ROOT/release"

if [[ -e $OPENSHELL_CHECKOUT ]]; then
  if [[ ! -d $OPENSHELL_CHECKOUT || -L $OPENSHELL_CHECKOUT ]] \
    || [[ $(git -C "$OPENSHELL_CHECKOUT" rev-parse HEAD 2>/dev/null || true) != "$OPENSHELL_SOURCE_PIN" ]] \
    || [[ -n $(git -C "$OPENSHELL_CHECKOUT" status --porcelain 2>/dev/null || true) ]]; then
    rm -rf -- "$OPENSHELL_CHECKOUT"
  fi
fi
if [[ ! -d $OPENSHELL_CHECKOUT ]]; then
  git clone --filter=blob:none --no-checkout https://github.com/NVIDIA/OpenShell.git "$OPENSHELL_CHECKOUT"
  git -C "$OPENSHELL_CHECKOUT" fetch --depth=128 origin "$OPENSHELL_SOURCE_PIN"
  git -C "$OPENSHELL_CHECKOUT" checkout --detach "$OPENSHELL_SOURCE_PIN"
fi
[[ $(git -C "$OPENSHELL_CHECKOUT" rev-parse HEAD) == "$OPENSHELL_SOURCE_PIN" ]] \
  || fail "OpenShell source pin mismatch"
[[ -z $(git -C "$OPENSHELL_CHECKOUT" status --porcelain) ]] \
  || fail "OpenShell source checkout is not clean"

printf 'Building OpenBox Sandbox from locked sources...\n' >&2
CARGO_TARGET_DIR="$OPENBOX_TARGET" cargo +"$RUST_TOOLCHAIN" build \
  --manifest-path "$ROOT/Cargo.toml" --release --locked --bin openbox-sandbox
OPENBOX_BINARY="$OPENBOX_TARGET/release/openbox-sandbox"

printf 'Building pinned OpenShell package...\n' >&2
CARGO_TARGET_DIR="$OPENSHELL_TARGET" cargo +"$RUST_TOOLCHAIN" build \
  --manifest-path "$OPENSHELL_CHECKOUT/Cargo.toml" --release --locked \
  -p openshell-cli -p openshell-server -p openshell-driver-vm
"$OPENSHELL_TARGET/release/openshell" --version | grep -q "$OPENSHELL_VERSION_MARKER" \
  || fail "built OpenShell CLI does not identify the approved source pin"
"$OPENSHELL_TARGET/release/openshell-gateway" --version | grep -q "$OPENSHELL_VERSION_MARKER" \
  || fail "built OpenShell gateway does not identify the approved source pin"

PACKAGE_OUTPUT="$LOCAL_ROOT/build/openshell-package"
rm -rf -- "$PACKAGE_OUTPUT"
install -d -m 0700 "$PACKAGE_OUTPUT"
(
  umask 022
  OPENSHELL_CLI_BINARY="$OPENSHELL_TARGET/release/openshell" \
  OPENSHELL_GATEWAY_BINARY="$OPENSHELL_TARGET/release/openshell-gateway" \
  OPENSHELL_DRIVER_VM_BINARY="$OPENSHELL_TARGET/release/openshell-driver-vm" \
  OPENSHELL_DEB_VERSION="0.0.0~openboxlocal.gf1690849" \
  OPENSHELL_OUTPUT_DIR="$PACKAGE_OUTPUT" \
    "$OPENSHELL_CHECKOUT/tasks/scripts/package-deb.sh" >/dev/null
)
mapfile -t openshell_packages < <(find "$PACKAGE_OUTPUT" -maxdepth 1 -type f -name '*.deb' -print)
[[ ${#openshell_packages[@]} -eq 1 ]] || fail "local OpenShell package assembly failed"

rm -rf -- "$RELEASE" "$LOCAL_ROOT/clients" "$LOCAL_ROOT/pki"
install -d -m 0700 "$RELEASE/tls" "$RELEASE/runtime-mtls" "$RELEASE/openshell" \
  "$LOCAL_ROOT/clients/runtime" "$LOCAL_ROOT/clients/administrator" "$LOCAL_ROOT/pki"
PKI="$LOCAL_ROOT/pki"
openssl req -x509 -newkey rsa:3072 -sha256 -days 30 -nodes \
  -subj '/CN=OpenBox Local Development CA' -keyout "$PKI/ca.key" -out "$PKI/ca.crt" >/dev/null 2>&1
chmod 0600 "$PKI/ca.key"
cat >"$PKI/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1
EOF
openssl req -new -newkey rsa:3072 -nodes -subj '/CN=127.0.0.1' \
  -keyout "$PKI/server.key" -out "$PKI/server.csr" >/dev/null 2>&1
openssl x509 -req -sha256 -days 30 -in "$PKI/server.csr" -CA "$PKI/ca.crt" \
  -CAkey "$PKI/ca.key" -CAcreateserial -extfile "$PKI/server.ext" \
  -out "$PKI/server.crt" >/dev/null 2>&1

make_client() {
  local name=$1 role=$2 directory="$LOCAL_ROOT/clients/$1"
  cat >"$PKI/${name}.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
  openssl req -new -newkey rsa:3072 -nodes -subj "/CN=OpenBox Local ${role}" \
    -keyout "$directory/tls.key" -out "$PKI/${name}.csr" >/dev/null 2>&1
  openssl x509 -req -sha256 -days 30 -in "$PKI/${name}.csr" -CA "$PKI/ca.crt" \
    -CAkey "$PKI/ca.key" -CAcreateserial -extfile "$PKI/${name}.ext" \
    -out "$directory/tls.crt" >/dev/null 2>&1
  cp "$PKI/ca.crt" "$directory/ca.crt"
  chmod 0600 "$directory"/*
}
make_client runtime Runtime
make_client administrator Administrator

certificate_fingerprint() {
  openssl x509 -in "$1" -outform DER | sha256sum | awk '{print $1}'
}
runtime_fingerprint=$(certificate_fingerprint "$LOCAL_ROOT/clients/runtime/tls.crt")
admin_fingerprint=$(certificate_fingerprint "$LOCAL_ROOT/clients/administrator/tls.crt")
adapter_sha=$(sha256sum "$OPENBOX_BINARY" | awk '{print $1}')
policy_sha=$(sha256sum "$ROOT/deploy/policies/policy-deny-network.yaml" | awk '{print $1}')

cp "$OPENBOX_BINARY" "$RELEASE/openbox-sandbox"
cp "$PKI/ca.crt" "$RELEASE/tls/client-ca.crt"
cp "$PKI/server.crt" "$RELEASE/tls/server.crt"
cp "$PKI/server.key" "$RELEASE/tls/server.key"
cp "$LOCAL_ROOT/clients/runtime/ca.crt" "$RELEASE/runtime-mtls/ca.crt"
cp "$LOCAL_ROOT/clients/runtime/tls.crt" "$RELEASE/runtime-mtls/tls.crt"
cp "$LOCAL_ROOT/clients/runtime/tls.key" "$RELEASE/runtime-mtls/tls.key"
cp "${openshell_packages[0]}" "$RELEASE/openshell/"
printf '%s\n' "$OPENSHELL_SOURCE_PIN" >"$RELEASE/openshell/source-commit"
cat >"$RELEASE/service.json" <<EOF
{
  "bind_address": "127.0.0.1:17443",
  "server_certificate_path": "/etc/openbox-sandbox/tls/server.crt",
  "server_private_key_path": "/etc/openbox-sandbox/tls/server.key",
  "client_ca_path": "/etc/openbox-sandbox/tls/client-ca.crt",
  "authorized_callers": [
    {"certificate_sha256": "$runtime_fingerprint", "role": "runtime"},
    {"certificate_sha256": "$admin_fingerprint", "role": "administrator"}
  ],
  "state_directory": "/var/lib/openbox-sandbox/cleanup",
  "asset_bundle": {
    "runtime_contract_version": 1,
    "adapter_build_sha256": "$adapter_sha",
    "template": "$LOCAL_IMAGE",
    "policy": {"id": "openbox-deny-network-local", "version": 1, "sha256": "$policy_sha"},
    "compatibility_id": "local-development-f1690849-contract-1"
  },
  "runtime_endpoint": "https://127.0.0.1:17670",
  "runtime_mtls_directory": "/etc/openbox-sandbox/runtime-mtls",
  "runtime_connect_timeout_ms": 10000,
  "runtime_poll_interval_ms": 250,
  "reconcile_delete_deadline_ms": 60000,
  "reconcile_wait_deadline_ms": 60000,
  "maximum_connections": 64,
  "drain_timeout_ms": 30000
}
EOF
chmod 0755 "$RELEASE/openbox-sandbox"
find "$RELEASE" -type f ! -name SHA256SUMS -exec chmod 0600 {} +
(
  cd "$RELEASE"
  mapfile -t files < <(find . -type f ! -name SHA256SUMS -print | sed 's#^./##' | LC_ALL=C sort)
  sha256sum "${files[@]}" >SHA256SUMS
)

target_uid=$(id -u)
target_user=$(id -un)
sudo loginctl enable-linger "$target_user"
sudo systemctl start "user@${target_uid}.service"
XDG_RUNTIME_DIR="/run/user/${target_uid}" \
DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${target_uid}/bus" \
  systemctl --user enable --now podman.socket
XDG_RUNTIME_DIR="/run/user/${target_uid}" \
DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${target_uid}/bus" \
  systemctl --user is-active --quiet podman.socket \
  || fail "rootless Podman socket did not become active"

install_args=()
[[ $DEPENDENCY_MODE == yes ]] && install_args+=(--install-dependencies)
[[ $DEPENDENCY_MODE == no ]] && install_args+=(--no-install-dependencies)
[[ $NO_START -eq 1 ]] && install_args+=(--no-start)
"$ROOT/install.sh" "${install_args[@]}" "$RELEASE"

printf '%s\n' \
  "Local non-production installation complete." \
  "Runtime caller credentials: $LOCAL_ROOT/clients/runtime" \
  "Administrator caller credentials: $LOCAL_ROOT/clients/administrator" \
  "Pinned policy: $ROOT/deploy/policies/policy-deny-network.yaml" \
  "Local artifacts and private keys remain under $LOCAL_ROOT (mode 0700)."
