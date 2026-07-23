#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly SERVICE_NAME="openbox-sandbox.service"
readonly SERVICE_USER="openbox-sandbox"
readonly SERVICE_GROUP="openbox-sandbox"
readonly BINARY_DESTINATION="/opt/openbox/bin/openbox-sandbox"
readonly CONFIG_DESTINATION="/etc/openbox-sandbox/service.json"
readonly TLS_DESTINATION="/etc/openbox-sandbox/tls"
readonly RUNTIME_MTLS_DESTINATION="/etc/openbox-sandbox/runtime-mtls"
readonly STATE_DESTINATION="/var/lib/openbox-sandbox/cleanup"
readonly UNIT_DESTINATION="/etc/systemd/system/${SERVICE_NAME}"
readonly OPENSHELL_SOURCE_PIN="f169084923503a02a94425857b938de2841cab0c"
readonly OPENSHELL_VERSION_MARKER="gf1690849"

usage() {
  cat <<'EOF'
Usage: ./install.sh [OPTIONS] [/absolute/path/to/release]

In a published installation bundle, the installer uses the adjacent ./release
payload. In a fresh source checkout without that payload, it automatically runs
the clearly non-production local bootstrap. It performs non-root preparation
before requesting administrator authorization for system changes.

Options:
  --local                     Force the fresh-source local bootstrap.
  --install-dependencies      Install missing host/build prerequisites without asking.
  --no-install-dependencies   Never install host prerequisites.
  --no-start                  Install and validate without starting openbox-sandbox.
  -h, --help                  Show this help.

The release directory must contain exactly:
  SHA256SUMS
  openbox-sandbox
  service.json
  tls/client-ca.crt
  tls/server.crt
  tls/server.key
  runtime-mtls/ca.crt
  runtime-mtls/tls.crt
  runtime-mtls/tls.key

Unless the exact pinned OpenShell build is already installed, the release must also contain:
  openshell/source-commit
  openshell/*.deb                         (Debian family)
  openshell/openshell-*.rpm               (RPM family)
  openshell/openshell-gateway-*.rpm       (RPM family)

SHA256SUMS must cover every other file. Missing host prerequisites require
interactive approval or --install-dependencies. Required OpenShell packages are
installed only from the checksummed local payload and must identify the pinned
source commit; the installer never substitutes a latest release.
EOF
}

fail() {
  printf 'openbox-sandbox installer: %s\n' "$1" >&2
  exit 1
}

script_source=${BASH_SOURCE[0]}
if [[ $script_source != /* ]]; then
  script_source="$PWD/$script_source"
fi
script_parent=${script_source%/*}
script_name=${script_source##*/}
SCRIPT_DIRECTORY=$(CDPATH='' cd -P -- "$script_parent" && pwd -P) \
  || fail "cannot resolve installer directory"
readonly SCRIPT_DIRECTORY
readonly SCRIPT_PATH="${SCRIPT_DIRECTORY}/${script_name}"
readonly DEFAULT_RELEASE_DIRECTORY="${SCRIPT_DIRECTORY}/release"
[[ -f $SCRIPT_PATH && ! -L $SCRIPT_PATH ]] || fail "installer must be a regular, non-symbolic-link file"

basic_release_preflight() {
  local release_directory=$1 relative_path
  [[ $release_directory == /* ]] || fail "release path must be absolute"
  [[ -d $release_directory && ! -L $release_directory ]] \
    || fail "release path must be a real directory"
  for relative_path in \
    SHA256SUMS \
    openbox-sandbox \
    service.json \
    tls/client-ca.crt \
    tls/server.crt \
    tls/server.key \
    runtime-mtls/ca.crt \
    runtime-mtls/tls.crt \
    runtime-mtls/tls.key; do
    [[ -f $release_directory/$relative_path && ! -L $release_directory/$relative_path ]] \
      || fail "release preflight rejected required file: ${relative_path}"
  done
  [[ -f $SCRIPT_DIRECTORY/deploy/$SERVICE_NAME \
    && ! -L $SCRIPT_DIRECTORY/deploy/$SERVICE_NAME ]] \
    || fail "trusted systemd unit is unavailable"
}

ask_yes_no() {
  local prompt=$1 answer
  [[ -r /dev/tty && -w /dev/tty ]] || return 1
  printf '%s [y/N] ' "$prompt" >/dev/tty
  IFS= read -r answer </dev/tty || return 1
  [[ $answer == "y" || $answer == "Y" || $answer == "yes" || $answer == "YES" ]]
}

approved() {
  local mode=$1 prompt=$2
  case "$mode" in
    yes) return 0 ;;
    no) return 1 ;;
    ask) ask_yes_no "$prompt" ;;
    *) fail "internal approval mode is invalid" ;;
  esac
}

PRIVILEGED_PHASE=0
if [[ ${1:-} == --_openbox-privileged-phase ]]; then
  [[ $EUID -eq 0 ]] || fail "internal privileged phase requires administrator authorization"
  PRIVILEGED_PHASE=1
  shift
fi
readonly PRIVILEGED_PHASE
readonly -a ORIGINAL_ARGUMENTS=("$@")

NO_START=0
LOCAL_MODE=0
DEPENDENCY_MODE=ask
while [[ $# -gt 0 ]]; do
  case $1 in
    --local) LOCAL_MODE=1 ;;
    --install-dependencies) DEPENDENCY_MODE=yes ;;
    --no-install-dependencies) DEPENDENCY_MODE=no ;;
    --no-start) NO_START=1 ;;
    --help|-h)
      usage
      exit 0
      ;;
    --*)
      usage >&2
      exit 2
      ;;
    *) break ;;
  esac
  shift
done
[[ $# -le 1 ]] || { usage >&2; exit 2; }
if [[ $# -eq 0 ]]; then
  RELEASE_INPUT=$DEFAULT_RELEASE_DIRECTORY
else
  RELEASE_INPUT=$1
fi

if [[ $LOCAL_MODE -eq 1 || ($# -eq 0 && ! -d $RELEASE_INPUT) ]]; then
  [[ $PRIVILEGED_PHASE -eq 0 && $EUID -ne 0 ]] \
    || fail "local bootstrap must begin as an ordinary user"
  [[ $# -eq 0 ]] || fail "--local does not accept a release path"
  LOCAL_BOOTSTRAP="$SCRIPT_DIRECTORY/scripts/local-bootstrap.sh"
  [[ -f $LOCAL_BOOTSTRAP && ! -L $LOCAL_BOOTSTRAP && -x $LOCAL_BOOTSTRAP ]] \
    || fail "fresh source checkout has no trusted local bootstrap"
  bootstrap_arguments=()
  [[ $DEPENDENCY_MODE == yes ]] && bootstrap_arguments+=(--install-dependencies)
  [[ $DEPENDENCY_MODE == no ]] && bootstrap_arguments+=(--no-install-dependencies)
  [[ $NO_START -eq 1 ]] && bootstrap_arguments+=(--no-start)
  exec "$LOCAL_BOOTSTRAP" "${bootstrap_arguments[@]}"
fi

if [[ $EUID -ne 0 ]]; then
  [[ $PRIVILEGED_PHASE -eq 0 ]] || fail "internal privilege state is invalid"
  [[ $OSTYPE == linux* ]] || fail "requires Linux and systemd"
  basic_release_preflight "$RELEASE_INPUT"
  if [[ -x /usr/bin/sudo ]]; then
    SUDO_COMMAND=/usr/bin/sudo
  elif [[ -x /bin/sudo ]]; then
    SUDO_COMMAND=/bin/sudo
  else
    fail "system installation requires sudo; install it or ask an administrator to run this installer"
  fi
  printf '%s\n' \
    "Release structure preflight passed." \
    "Administrator authorization is now required to install the verified pinned OpenShell dependency," \
    "any approved missing host prerequisites, the locked service account, protected configuration," \
    "credentials, and the systemd service." >&2
  exec "$SUDO_COMMAND" -- "$SCRIPT_PATH" --_openbox-privileged-phase "${ORIGINAL_ARGUMENTS[@]}"
fi
if [[ $PRIVILEGED_PHASE -eq 1 ]]; then
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  export PATH
  unset BASH_ENV CDPATH ENV
fi
[[ $(uname -s) == "Linux" ]] || fail "requires Linux and systemd"
basic_release_preflight "$RELEASE_INPUT"

if command -v apt-get >/dev/null 2>&1; then
  PACKAGE_FAMILY=deb
elif command -v dnf >/dev/null 2>&1; then
  PACKAGE_FAMILY=rpm
  RPM_INSTALLER=dnf
elif command -v yum >/dev/null 2>&1; then
  PACKAGE_FAMILY=rpm
  RPM_INSTALLER=yum
else
  fail "requires apt-get, dnf, or yum"
fi

readonly -a REQUIRED_COMMANDS=(
  awk basename chmod chown cp curl diff dirname env find getent groupadd id install
  loginctl mktemp mv readlink rm runuser sed sha256sum sleep sort systemctl uname useradd
)
missing_commands=()
for command in "${REQUIRED_COMMANDS[@]}"; do
  command -v "$command" >/dev/null 2>&1 || missing_commands+=("$command")
done
if [[ ${#missing_commands[@]} -gt 0 ]]; then
  if ! approved "$DEPENDENCY_MODE" "Install missing host prerequisites (${missing_commands[*]})?"; then
    fail "missing host prerequisites: ${missing_commands[*]}"
  fi
  case $PACKAGE_FAMILY in
    deb)
      apt-get update
      env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates coreutils curl diffutils findutils gawk libc-bin passwd sed systemd util-linux
      ;;
    rpm)
      "$RPM_INSTALLER" install -y \
        ca-certificates coreutils curl diffutils findutils gawk glibc-common shadow-utils sed systemd util-linux
      ;;
  esac
fi
for command in "${REQUIRED_COMMANDS[@]}"; do
  command -v "$command" >/dev/null 2>&1 || fail "required command unavailable after prerequisite handling: ${command}"
done

[[ $RELEASE_INPUT == /* ]] || fail "release path must be absolute"
[[ -d $RELEASE_INPUT && ! -L $RELEASE_INPUT ]] || fail "release path must be a real directory"
RELEASE_DIRECTORY=$(readlink -f -- "$RELEASE_INPUT")
[[ $RELEASE_DIRECTORY == "$RELEASE_INPUT" ]] || fail "release path must be canonical"

UNIT_SOURCE="${SCRIPT_DIRECTORY}/deploy/${SERVICE_NAME}"
[[ -f $UNIT_SOURCE && ! -L $UNIT_SOURCE ]] || fail "trusted systemd unit is unavailable"

RELEASE_FILES=(
  "openbox-sandbox"
  "runtime-mtls/ca.crt"
  "runtime-mtls/tls.crt"
  "runtime-mtls/tls.key"
  "service.json"
  "tls/client-ca.crt"
  "tls/server.crt"
  "tls/server.key"
)
OPENSHELL_PACKAGE_FILES=()
OPENSHELL_PAYLOAD=0
if [[ -d $RELEASE_DIRECTORY/openshell && ! -L $RELEASE_DIRECTORY/openshell ]]; then
  [[ -f $RELEASE_DIRECTORY/openshell/source-commit ]] \
    || fail "OpenShell payload is missing source-commit"
  case $PACKAGE_FAMILY in
    deb)
      mapfile -t OPENSHELL_PACKAGE_FILES < <(
        find "$RELEASE_DIRECTORY/openshell" -maxdepth 1 -type f -name '*.deb' -print | LC_ALL=C sort
      )
      [[ ${#OPENSHELL_PACKAGE_FILES[@]} -eq 1 ]] \
        || fail "Debian OpenShell payload must contain exactly one .deb"
      ;;
    rpm)
      mapfile -t OPENSHELL_PACKAGE_FILES < <(
        find "$RELEASE_DIRECTORY/openshell" -maxdepth 1 -type f -name '*.rpm' -print | LC_ALL=C sort
      )
      [[ ${#OPENSHELL_PACKAGE_FILES[@]} -eq 2 ]] \
        || fail "RPM OpenShell payload must contain exactly two .rpm files"
      gateway_packages=0
      cli_packages=0
      for package_path in "${OPENSHELL_PACKAGE_FILES[@]}"; do
        package_name=$(basename -- "$package_path")
        if [[ $package_name == openshell-gateway-*.rpm ]]; then
          ((gateway_packages += 1))
        elif [[ $package_name == openshell-*.rpm ]]; then
          ((cli_packages += 1))
        fi
      done
      [[ $gateway_packages -eq 1 && $cli_packages -eq 1 ]] \
        || fail "RPM OpenShell payload requires one CLI and one gateway package"
      ;;
  esac
  RELEASE_FILES+=("openshell/source-commit")
  for package_path in "${OPENSHELL_PACKAGE_FILES[@]}"; do
    RELEASE_FILES+=("openshell/$(basename -- "$package_path")")
  done
  OPENSHELL_PAYLOAD=1
fi
ALL_RELEASE_FILES=("${RELEASE_FILES[@]}" "SHA256SUMS")

SNAPSHOT_DIRECTORY=$(mktemp -d /tmp/openbox-sandbox-install.XXXXXXXX)
BACKUP_DIRECTORY=$(mktemp -d /tmp/openbox-sandbox-backup.XXXXXXXX)
cleanup() {
  rm -rf -- "$SNAPSHOT_DIRECTORY" "$BACKUP_DIRECTORY"
}
trap cleanup EXIT

mapfile -t actual_files < <(
  cd -- "$RELEASE_DIRECTORY"
  find . -type f -print | sed 's#^\./##' | LC_ALL=C sort
)
mapfile -t expected_files < <(printf '%s\n' "${ALL_RELEASE_FILES[@]}" | LC_ALL=C sort)
[[ ${#actual_files[@]} -eq ${#expected_files[@]} ]] || fail "release contains missing or unexpected files"
diff -u <(printf '%s\n' "${expected_files[@]}") <(printf '%s\n' "${actual_files[@]}") >/dev/null \
  || fail "release contains missing or unexpected files"
[[ -z $(find "$RELEASE_DIRECTORY" -type l -print -quit) ]] || fail "release contains a symbolic link"
[[ -z $(find "$RELEASE_DIRECTORY" ! -type f ! -type d -print -quit) ]] || fail "release contains a special file"

install -d -o root -g root -m 0700 "$SNAPSHOT_DIRECTORY/release"
for relative_path in "${ALL_RELEASE_FILES[@]}"; do
  source_path="${RELEASE_DIRECTORY}/${relative_path}"
  [[ -f $source_path && ! -L $source_path ]] || fail "release file rejected: ${relative_path}"
  install -d -o root -g root -m 0700 "$SNAPSHOT_DIRECTORY/release/$(dirname -- "$relative_path")"
  snapshot_path="$SNAPSHOT_DIRECTORY/release/$relative_path"
  cp --no-dereference -- "$source_path" "$snapshot_path"
  [[ -f $snapshot_path && ! -L $snapshot_path ]] \
    || fail "release file changed during the privileged snapshot: ${relative_path}"
  chown root:root "$snapshot_path"
  chmod 0600 "$snapshot_path"
done
cp --no-dereference -- "$UNIT_SOURCE" "$SNAPSHOT_DIRECTORY/${SERVICE_NAME}"
[[ -f $SNAPSHOT_DIRECTORY/$SERVICE_NAME && ! -L $SNAPSHOT_DIRECTORY/$SERVICE_NAME ]] \
  || fail "systemd unit changed during the privileged snapshot"
chown root:root "$SNAPSHOT_DIRECTORY/${SERVICE_NAME}"
chmod 0600 "$SNAPSHOT_DIRECTORY/${SERVICE_NAME}"

if ! awk '
  NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ { exit 2 }
  {
    name=$2
    sub(/^\*/, "", name)
    if (name ~ /^\// || name ~ /(^|\/)\.\.($|\/)/ || seen[name]++) { exit 2 }
    print name
  }
' "$SNAPSHOT_DIRECTORY/release/SHA256SUMS" >"$SNAPSHOT_DIRECTORY/manifest-files"; then
  fail "SHA256SUMS is malformed"
fi
LC_ALL=C sort -o "$SNAPSHOT_DIRECTORY/manifest-files" "$SNAPSHOT_DIRECTORY/manifest-files"
mapfile -t manifest_files <"$SNAPSHOT_DIRECTORY/manifest-files"
mapfile -t expected_manifest_files < <(printf '%s\n' "${RELEASE_FILES[@]}" | LC_ALL=C sort)
diff -u <(printf '%s\n' "${expected_manifest_files[@]}") <(printf '%s\n' "${manifest_files[@]}") >/dev/null \
  || fail "SHA256SUMS does not cover the exact release"
(
  cd -- "$SNAPSHOT_DIRECTORY/release"
  sha256sum --check --strict SHA256SUMS >/dev/null
) || fail "release checksum verification failed"
if [[ $OPENSHELL_PAYLOAD -eq 1 ]]; then
  [[ $(<"$SNAPSHOT_DIRECTORY/release/openshell/source-commit") == "$OPENSHELL_SOURCE_PIN" ]] \
    || fail "OpenShell payload does not attest the required source commit"
fi

openshell_matches_pin() {
  local cli gateway cli_version gateway_version
  cli=$(command -v openshell 2>/dev/null || true)
  gateway=$(command -v openshell-gateway 2>/dev/null || true)
  [[ -n $cli && -n $gateway && -x $cli && -x $gateway ]] || return 1
  cli_version=$($cli --version 2>/dev/null || true)
  gateway_version=$($gateway --version 2>/dev/null || true)
  [[ $cli_version == *"$OPENSHELL_VERSION_MARKER"* \
    && $gateway_version == *"$OPENSHELL_VERSION_MARKER"* ]]
}

install_pinned_openshell() {
  local package_path relative_path
  [[ $OPENSHELL_PAYLOAD -eq 1 ]] \
    || fail "the verified release does not include a pinned OpenShell package"
  snapshot_packages=()
  for package_path in "${OPENSHELL_PACKAGE_FILES[@]}"; do
    relative_path="openshell/$(basename -- "$package_path")"
    snapshot_packages+=("$SNAPSHOT_DIRECTORY/release/$relative_path")
  done
  case $PACKAGE_FAMILY in
    deb)
      env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confnew \
        "${snapshot_packages[@]}"
      ;;
    rpm)
      "$RPM_INSTALLER" install -y "${snapshot_packages[@]}"
      ;;
  esac
  openshell_matches_pin \
    || fail "installed OpenShell binaries do not identify source pin ${OPENSHELL_SOURCE_PIN}"
}

snapshot_openshell_mtls() {
  local target_user target_uid target_home target_runtime source_directory elapsed
  target_user=${SUDO_USER:-root}
  id "$target_user" >/dev/null 2>&1 || fail "cannot resolve OpenShell service user: ${target_user}"
  target_uid=$(id -u "$target_user")
  target_home=$(getent passwd "$target_user" | awk -F: '{ print $6 }')
  [[ -n $target_home && $target_home == /* ]] || fail "cannot resolve OpenShell service home"
  target_runtime="/run/user/${target_uid}"
  loginctl enable-linger "$target_user"
  systemctl start "user@${target_uid}.service"

  as_openshell_user() {
    runuser -u "$target_user" -- env \
      HOME="$target_home" \
      XDG_RUNTIME_DIR="$target_runtime" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=${target_runtime}/bus" \
      "$@"
  }

  as_openshell_user systemctl --user daemon-reload
  as_openshell_user systemctl --user enable openshell-gateway.service
  if [[ ${OPENSHELL_INSTALLED_NOW:-0} -eq 1 ]]; then
    as_openshell_user systemctl --user restart openshell-gateway.service
  elif ! as_openshell_user systemctl --user is-active --quiet openshell-gateway.service; then
    as_openshell_user systemctl --user start openshell-gateway.service
  fi

  source_directory="$target_home/.config/openshell/gateways/openshell/mtls"
  elapsed=0
  while [[ $elapsed -lt 30 ]]; do
    if [[ -f $source_directory/ca.crt \
      && -f $source_directory/tls.crt \
      && -f $source_directory/tls.key ]] \
      && curl --silent --show-error --max-time 2 \
        --cacert "$source_directory/ca.crt" \
        --cert "$source_directory/tls.crt" \
        --key "$source_directory/tls.key" \
        --output /dev/null https://127.0.0.1:17670/; then
      break
    fi
    sleep 1
    ((elapsed += 1))
  done
  [[ $elapsed -lt 30 ]] || fail "pinned OpenShell gateway did not become ready"

  install -d -o root -g root -m 0700 "$SNAPSHOT_DIRECTORY/openshell-mtls"
  for credential in ca.crt tls.crt tls.key; do
    [[ ! -L $source_directory/$credential ]] \
      || fail "OpenShell generated a symbolic-link credential"
    cp --no-dereference -- "$source_directory/$credential" \
      "$SNAPSHOT_DIRECTORY/openshell-mtls/$credential"
    chown root:root "$SNAPSHOT_DIRECTORY/openshell-mtls/$credential"
    chmod 0600 "$SNAPSHOT_DIRECTORY/openshell-mtls/$credential"
  done
  RUNTIME_MTLS_SOURCE="$SNAPSHOT_DIRECTORY/openshell-mtls"
}

RUNTIME_MTLS_SOURCE="$SNAPSHOT_DIRECTORY/release/runtime-mtls"
OPENSHELL_INSTALLED_NOW=0
if ! openshell_matches_pin; then
  [[ $OPENSHELL_PAYLOAD -eq 1 ]] \
    || fail "required pinned OpenShell is not installed and the release has no usable package"
  install_pinned_openshell
  OPENSHELL_INSTALLED_NOW=1
fi
snapshot_openshell_mtls

for destination in \
  "$BINARY_DESTINATION" \
  "$CONFIG_DESTINATION" \
  "$TLS_DESTINATION/client-ca.crt" \
  "$TLS_DESTINATION/server.crt" \
  "$TLS_DESTINATION/server.key" \
  "$RUNTIME_MTLS_DESTINATION/ca.crt" \
  "$RUNTIME_MTLS_DESTINATION/tls.crt" \
  "$RUNTIME_MTLS_DESTINATION/tls.key" \
  "$UNIT_DESTINATION"; do
  [[ ! -L $destination ]] || fail "installation destination contains a symbolic link: ${destination}"
done
for directory in /opt/openbox /opt/openbox/bin /etc/openbox-sandbox "$TLS_DESTINATION" \
  "$RUNTIME_MTLS_DESTINATION" /var/lib/openbox-sandbox "$STATE_DESTINATION"; do
  [[ ! -L $directory ]] || fail "installation directory contains a symbolic link: ${directory}"
done

NOLOGIN_SHELL=$(command -v nologin) || fail "nologin shell is unavailable"
if ! getent group "$SERVICE_GROUP" >/dev/null; then
  groupadd --system "$SERVICE_GROUP"
fi
if id "$SERVICE_USER" >/dev/null 2>&1; then
  [[ $(id -gn "$SERVICE_USER") == "$SERVICE_GROUP" ]] || fail "existing service user has the wrong primary group"
else
  useradd --system --gid "$SERVICE_GROUP" --home-dir /var/lib/openbox-sandbox \
    --no-create-home --shell "$NOLOGIN_SHELL" "$SERVICE_USER"
fi

readonly -a DESTINATIONS=(
  "$BINARY_DESTINATION"
  "$CONFIG_DESTINATION"
  "$TLS_DESTINATION/client-ca.crt"
  "$TLS_DESTINATION/server.crt"
  "$TLS_DESTINATION/server.key"
  "$RUNTIME_MTLS_DESTINATION/ca.crt"
  "$RUNTIME_MTLS_DESTINATION/tls.crt"
  "$RUNTIME_MTLS_DESTINATION/tls.key"
  "$UNIT_DESTINATION"
)
MUTATED=0
WAS_ACTIVE=0
WAS_ENABLED=0
systemctl is-active --quiet "$SERVICE_NAME" && WAS_ACTIVE=1 || true
systemctl is-enabled --quiet "$SERVICE_NAME" && WAS_ENABLED=1 || true
for index in "${!DESTINATIONS[@]}"; do
  destination=${DESTINATIONS[$index]}
  if [[ -e $destination ]]; then
    cp -a --no-dereference -- "$destination" "$BACKUP_DIRECTORY/$index"
  else
    : >"$BACKUP_DIRECTORY/$index.absent"
  fi
done

rollback() {
  local status=$?
  trap - ERR
  if [[ $MUTATED -eq 1 ]]; then
    for index in "${!DESTINATIONS[@]}"; do
      destination=${DESTINATIONS[$index]}
      if [[ -e $BACKUP_DIRECTORY/$index ]]; then
        rm -f -- "$destination"
        cp -a --no-dereference -- "$BACKUP_DIRECTORY/$index" "$destination"
      else
        rm -f -- "$destination"
      fi
    done
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [[ $WAS_ENABLED -eq 0 ]]; then
      systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    if [[ $WAS_ACTIVE -eq 1 ]]; then
      systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
    else
      systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
  fi
  printf 'openbox-sandbox installer: installation rolled back\n' >&2
  exit "$status"
}
trap rollback ERR

install_atomic() {
  local source=$1 destination=$2 owner=$3 group=$4 mode=$5 temporary
  temporary="${destination}.install.$$"
  rm -f -- "$temporary"
  install -o "$owner" -g "$group" -m "$mode" -- "$source" "$temporary"
  mv -f -- "$temporary" "$destination"
}

install -d -o root -g root -m 0755 /opt/openbox /opt/openbox/bin
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 \
  /etc/openbox-sandbox "$TLS_DESTINATION" "$RUNTIME_MTLS_DESTINATION" \
  /var/lib/openbox-sandbox "$STATE_DESTINATION"
MUTATED=1
install_atomic "$SNAPSHOT_DIRECTORY/release/openbox-sandbox" "$BINARY_DESTINATION" root root 0755
install_atomic "$SNAPSHOT_DIRECTORY/release/service.json" "$CONFIG_DESTINATION" "$SERVICE_USER" "$SERVICE_GROUP" 0600
install_atomic "$SNAPSHOT_DIRECTORY/release/tls/client-ca.crt" "$TLS_DESTINATION/client-ca.crt" "$SERVICE_USER" "$SERVICE_GROUP" 0600
install_atomic "$SNAPSHOT_DIRECTORY/release/tls/server.crt" "$TLS_DESTINATION/server.crt" "$SERVICE_USER" "$SERVICE_GROUP" 0600
install_atomic "$SNAPSHOT_DIRECTORY/release/tls/server.key" "$TLS_DESTINATION/server.key" "$SERVICE_USER" "$SERVICE_GROUP" 0600
install_atomic "$RUNTIME_MTLS_SOURCE/ca.crt" "$RUNTIME_MTLS_DESTINATION/ca.crt" "$SERVICE_USER" "$SERVICE_GROUP" 0600
install_atomic "$RUNTIME_MTLS_SOURCE/tls.crt" "$RUNTIME_MTLS_DESTINATION/tls.crt" "$SERVICE_USER" "$SERVICE_GROUP" 0600
install_atomic "$RUNTIME_MTLS_SOURCE/tls.key" "$RUNTIME_MTLS_DESTINATION/tls.key" "$SERVICE_USER" "$SERVICE_GROUP" 0600
install_atomic "$SNAPSHOT_DIRECTORY/${SERVICE_NAME}" "$UNIT_DESTINATION" root root 0644

runuser -u "$SERVICE_USER" -- env OPENBOX_SANDBOX_CONFIG="$CONFIG_DESTINATION" \
  "$BINARY_DESTINATION" --check-config
systemctl daemon-reload
if [[ $NO_START -eq 0 ]]; then
  systemctl enable "$SERVICE_NAME"
  if [[ $WAS_ACTIVE -eq 1 ]]; then
    systemctl restart "$SERVICE_NAME"
  else
    systemctl start "$SERVICE_NAME"
  fi
  systemctl is-active --quiet "$SERVICE_NAME"
fi

trap - ERR
printf 'openbox-sandbox installed from verified local release: %s\n' "$RELEASE_DIRECTORY"
if [[ $NO_START -eq 1 ]]; then
  printf 'service not started (--no-start)\n'
fi
