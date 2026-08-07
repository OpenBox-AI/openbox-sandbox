# Linux host E2E journey — OpenShell on the `openshell` EC2 VM

**Goal:** determine what a Linux host needs to run OpenShell, test our installer
(`install.sh`) on it, and prove the E2E flow (client → mTLS root service →
external OpenShell gateway → sandbox create/exec/delete) on a Linux host.

**Host under test:** EC2 `i-0f48b03bbf673b454` (`openshell`), c7i.large,
Amazon Linux 2023, ap-southeast-1, reachable only via AWS SSM (no public IP).
Managed by this Mac via `aws ssm` (profile `ssm`).

**Date:** 2026-08-03. **Driver:** pi session + worker subagents.

---

## Part 1 — What a Linux host needs to run OpenShell (study)

Sources: repo docs (`docs/installation.md`, `packaging/launcher/README.md`,
`scripts/local-bootstrap.sh`, `install.sh`), NVIDIA OpenShell docs
(`sandbox-compute-drivers`, VM driver README).

### Host OS / kernel requirements

- Linux kernel (OpenBox enforces isolation with **Landlock, namespaces,
  cgroups, seccomp** — no macOS/Windows equivalent).
- `systemd` with user-session support: the gateway runs as a **per-user
  systemd service** (`openshell-gateway.service`), requiring `loginctl
  enable-linger` and a D-Bus user session (`DBUS_SESSION_BUS_ADDRESS`).
- cgroups v2 for rootless Podman.

### Package manager

- Installer (`install.sh`) supports exactly two families:
  - **Debian family** — `apt-get`; OpenShell payload = exactly **one `.deb`**.
  - **RPM family** — `dnf`/`yum`; OpenShell payload = exactly **two `.rpm`**
    files: `openshell-*.rpm` (CLI) + `openshell-gateway-*.rpm` (gateway).
- Local bootstrap (`--local`) currently supports **Debian-family only**
  (hard-requires `apt-get`; exits otherwise).

### OpenShell runtime (pinned, external)

- Service installer pins OpenShell source commit
  `f169084923503a02a94425857b938de2841cab0c`, marker **`gf1690849`** in
  `--version` output of both `openshell` and `openshell-gateway`.
- The 0.0.85 release bundle (tarballs, debs, rpms) is **older than the pin**:
  `obs provision` rejects 0.0.85 and requires source-built binaries at the
  exact pin. The installer likewise rejects binaries whose version lacks the
  marker → 0.0.85 RPMs are expected to FAIL the installer marker check
  (to be verified empirically in Part 2).
- Getting a pinned build therefore requires a **Rust toolchain build from
  source** at the pinned commit (rustup 1.28.2, Rust 1.95.0 per local
  bootstrap).

### Sandbox compute driver (runtime for sandboxes)

- One of: **Docker**, **Podman** (rootless 5.x, cgroups v2, active user
  socket), **Kubernetes**, or **VM** (libkrun microVM; KVM on Linux).
- The gateway auto-detects Kubernetes → Podman → Docker. VM driver is opt-in.
- Local bootstrap provisions **rootless Podman** on Debian.
- VM driver additionally needs `/dev/kvm` (nested virtualization on EC2).

### Network egress

- Gateway/sandboxes pull images (default
  `ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:...`) and the
  gateway API talks to OpenShell infra → outbound HTTPS required.

### Tooling for the E2E proof

- `openbox-sandbox` root service binary built from this repo
  (`cargo build --release --locked`), plus the `obs` launcher
  (`packaging/launcher`), plus all three OpenShell binaries at the pin
  (`openshell`, `openshell-gateway`, `openshell-sandbox`).
- Live proof needs a sandbox **image** and a **policy YAML** meeting the
  policy floor (`tests/live_openshell.rs`).

### Amazon Linux 2023 specifics (this host)

- dnf family → RPM payload path.
- SELinux enforcing by default (containers/sandboxes interaction TBD).
- No `apt-get` → `install.sh` local mode hard-fails by design.
- c7i.large = 2 vCPU / 4 GiB RAM → Rust builds likely need swap and patience.

---

## Part 2 — Journey log (append-only)

| # | Step | Result | Notes |
|---|------|--------|-------|
| 1 | Baseline host | PASS | Kernel 6.18.38 AL2023; SELinux **Permissive**; /dev/kvm present; cgroup v2; 2 vCPU / 3.7 GiB; 50 GB disk; no swap; docker 25.0.16 installed (inactive); podman absent; sshd active; ec2-user sudoless; ssm-user uid 1001 |
| 2 | Transfer repo | PASS | git archive → 137 KB .tar.gz; sha256 ffeb96178…; SCP via SSM port-forward tunnel; sha256 verified on host; extracted to /home/ec2-user/obs |
| 3a | install.sh (no args) | FAIL (expected) | As ec2-user: "local bootstrap currently requires apt-get"; exit 1 |
| 3b | install.sh --local --install-dependencies | FAIL (expected) | Same error; exit 1 — AL2023 has dnf not apt-get |
| 3c | 0.0.85 RPM pin check | FINDING | openshell: `0.0.85`, gateway: `0.0.85`; neither contains `gf1690849` marker → installer rejects both; gateway RPM needs podman dep not in AL2023 repos (installed CLI-only via --skip-broken + rpm2cpio for gateway version extraction); RPMs kept in /tmp |
| 4a | dnf deps (git/gcc/make/rpm-build/python3) | PASS | git 2.50.1, gcc 11.5.0, python 3.9.25; curl skipped (curl-8.17.0 already present, conflicts with curl-minimal) |
| 4b | Podman availability | FINDING | Not in AL2023 `amazonlinux` repo; `dnf search podman` → no matches; openshell-gateway 0.0.85 RPM lists podman as RPM dependency; docker 25.0.16 is available and in ec2-user's docker group → gateway can use docker at runtime |
| 4c | Docker rootful verify | PASS | systemctl start docker; docker info: overlay2, cgroup v2, server 25.0.16; ec2-user access confirmed |
| 4d | Swap creation | PASS | 8 GiB /swapfile; swapon; /etc/fstab updated |
| 4e | Rust toolchain | PASS | rustup 1.29.0 (FINDING: bootstrap pins 1.28.2; installer now ships 1.29.0); rustc/cargo 1.95.0 ✓; rust-toolchain.toml correctly applied |
| 4f | loginctl enable-linger + user session | PASS | loginctl enable-linger ec2-user; user@1000.service active; systemctl --user works via XDG_RUNTIME_DIR=/run/user/1000 |
| 4g | KVM | PASS | /dev/kvm crw-rw-rw- (world-writable); VM driver usable |
| 4h | SELinux under docker | PASS | Permissive; docker runs fine; container-selinux-2.245.0 installed |

---

## Part 3 — Phase 1 detail log

### 3.0 Auth check

```
$ aws sts get-caller-identity --profile ssm
Arn: arn:aws:sts::345594574230:assumed-role/AWSReservedSSO_ec2instanceaccess_e2ea75ccb4910470/kittinan
```
Result: PASS — SSO token valid.

---

### 3.1 Baseline host

**Command set A** (uname, os-release, selinux, kvm, cgroup, memory, disk, nproc, which tools, sshd, ssh config, user ids, swap):

```
Linux ip-10-1-61-103.ap-southeast-1.compute.internal 6.18.38-73.137.amzn2023.x86_64
  #2 SMP PREEMPT_DYNAMIC Mon Jul 13 22:27:08 UTC 2026 x86_64 GNU/Linux

NAME="Amazon Linux" VERSION="2023" VERSION_ID="2023"
PRETTY_NAME="Amazon Linux 2023.12.20260724"
ID_LIKE="fedora" SUPPORT_END="2029-06-30"

SELinux: Permissive

/dev/kvm: crw-rw-rw-. 1 root kvm 10, 232 Jul 27 06:58 /dev/kvm  ← KVM present!

cgroup: cgroup2fs  (cgroups v2 ✓)

Memory: 3.7 GiB total, 205 MiB used; Swap: 0B
Disk /: 50G total, 2.4G used, 48G free
nproc: 2

which results:
  - podman: NOT FOUND
  - docker: /usr/bin/docker
  - openshell: NOT FOUND
  - openshell-gateway: NOT FOUND
```

**Command set B** (rpm, sshd, sshd_config, user ids, docker version):

```
rpm -q podman: package podman is not installed
systemctl is-active sshd: active
PasswordAuthentication no

id ec2-user: uid=1000(ec2-user) gid=1000(ec2-user)
  groups: adm, wheel, systemd-journal, docker
id ssm-user: uid=1001(ssm-user) gid=1001(ssm-user)

sudo -u ec2-user -n true: ec2-user-sudo-ok (passwordless sudo)

rpm -q docker: docker-25.0.16-1.amzn2023.0.3.x86_64
Docker version: 25.0.14, build 0bab007  (pre-installed, systemctl status: inactive)
swapon --show: (empty — no swap)
```

**Findings:**
- SELinux is **Permissive** (the study doc predicted Enforcing — actually Permissive on this AMI).
- `/dev/kvm` is present and world-writable → VM driver option available.
- Docker pre-installed but inactive; ec2-user is in `docker` group.
- Podman absent from host.
- ssm-user account exists (uid 1001); ec2-user has passwordless sudo.

---

### 3.2 Transfer repo

**Mac:**
```
$ cd /Users/z/orca/projects/openbox-sandbox
$ git archive --format=tar.gz -o /tmp/obs-src.tar.gz HEAD
$ ls -lh /tmp/obs-src.tar.gz
-rw-r--r-- 1 z wheel 137K Aug 3 17:42 /tmp/obs-src.tar.gz
$ sha256sum /tmp/obs-src.tar.gz
ffeb96178a0606a4ff325ab4166ce552abc63e1bb20cf8c5211bc5c7ec5e2c4c  /tmp/obs-src.tar.gz
```

**SSH key injection (SendCommand as root):**
```bash
# Keygen on Mac:
ssh-keygen -t ed25519 -N "" -f /tmp/obs-transfer-key
# Public key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJCe7XfUQSM...

# Inject via SendCommand:
install -d -m 700 /home/ec2-user/.ssh
echo '<PUBKEY>' >> /home/ec2-user/.ssh/authorized_keys
chmod 600 /home/ec2-user/.ssh/authorized_keys
chown -R ec2-user:ec2-user /home/ec2-user/.ssh
# Result: key-injected; 1 line in authorized_keys
```

**Port-forward tunnel:**
```bash
nohup aws ssm start-session --profile ssm --target i-0f48b03bbf673b454 \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["22"],"localPortNumber":["2222"]}' \
  >/tmp/ssm-tunnel.log 2>&1 &
# Log: "Port 2222 opened for sessionId kittinan-lzonbtztd8jef5ivezql9nue6y"
```

**SCP:**
```
scp -P 2222 -i /tmp/obs-transfer-key -o StrictHostKeyChecking=no \
    /tmp/obs-src.tar.gz ec2-user@127.0.0.1:/tmp/obs-src.tar.gz
# scp exit: 0
```

**Verify + extract on host (SendCommand):**
```
sha256sum /tmp/obs-src.tar.gz
→ ffeb96178a0606a4ff325ab4166ce552abc63e1bb20cf8c5211bc5c7ec5e2c4c  ✓ MATCHES

mkdir -p /home/ec2-user/obs && tar xzf /tmp/obs-src.tar.gz -C /home/ec2-user/obs
ls /home/ec2-user/obs:
  Cargo.lock  Cargo.toml  README.md  build.rs  deny.toml  deploy
  docs  install.sh  packaging  rust-toolchain.toml  scripts  src  tests
→ extract-ok
```

Tunnel killed post-transfer. Ephemeral SSH key cleared from authorized_keys at end of session.

---

### 3.3a install.sh (no args)

```bash
sudo -u ec2-user bash -c 'cd /home/ec2-user/obs && bash install.sh 2>&1' | tail -40

output:
  openbox-sandbox local bootstrap: local bootstrap currently requires apt-get;
  use a published release bundle on this host
exit-code: 1
```

Root cause: `install.sh` detects no `apt-get` → exits. AL2023 is dnf/rpm family; local bootstrap only supports Debian. **Expected failure.**

---

### 3.3b install.sh --local --install-dependencies

```bash
sudo -u ec2-user bash -c 'cd /home/ec2-user/obs && bash install.sh --local --install-dependencies 2>&1' | tail -40

output:
  openbox-sandbox local bootstrap: local bootstrap currently requires apt-get;
  use a published release bundle on this host
exit-code: 1
```

Same result. `--install-dependencies` flag does not change the apt-get guard. **Expected failure.**

---

### 3.3c RPM marker / pin check

**Download:**
```
curl -L -o /tmp/openshell.rpm https://github.com/NVIDIA/OpenShell/releases/download/v0.0.85/openshell-0.0.85-1.fc44.x86_64.rpm
→ 12M, sha256: 929096c0d27b1e2e149151671a35ee9b192e9af52363239f1228d0c8f291f8ce

curl -L -o /tmp/openshell-gateway.rpm https://github.com/NVIDIA/OpenShell/releases/download/v0.0.85/openshell-gateway-0.0.85-1.fc44.x86_64.rpm
→ 17M, sha256: b3547e6947ae0a32e3bf0d3ff53f5be99060ed1589b4e5e844080ec6e55d2ab8
```

**Install attempt (first pass):**
```
dnf install -y /tmp/openshell.rpm /tmp/openshell-gateway.rpm
Error: Problem: conflicting requests
  - nothing provides podman needed by openshell-gateway-0.0.85-1.fc44.x86_64
```

Podman not in AL2023 repos. Gateway RPM's RPM dep on `podman` cannot be satisfied.

**Install openshell (CLI only):**
```
dnf install -y /tmp/openshell.rpm  → Installed: openshell-0.0.85-1.fc44.x86_64
openshell --version → "openshell 0.0.85"
```

**Gateway version via rpm2cpio (without installing):**
```
rpm2cpio /tmp/openshell-gateway.rpm | cpio -idm  → 116822 blocks
/tmp/usr/bin/openshell-gateway --version → "openshell-gateway 0.0.85"
```

**CRITICAL FINDING — Version marker absent:**
```
openshell     → "openshell 0.0.85"          ← does NOT contain "gf1690849"
openshell-gateway → "openshell-gateway 0.0.85" ← does NOT contain "gf1690849"
```

**Pin marker logic from install.sh (lines 353–365):**
```bash
readonly OPENSHELL_VERSION_MARKER="gf1690849"   # line 15

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
```

`openshell_matches_pin` would return 1 (fail) for 0.0.85 binaries → installer would
reject them with: `installed OpenShell binaries do not identify source pin f169084923503a02a94425857b938de2841cab0c`.

**Cleanup:** `dnf remove -y openshell`; extracted gateway files removed from /tmp. RPMs kept at `/tmp/openshell.rpm` and `/tmp/openshell-gateway.rpm` for Phase 2 reference.

---

### 3.4a Dev prerequisites

```
dnf install -y git gcc gcc-c++ make rpm-build python3
  (curl skipped — curl-8.17.0 already installed; conflicts with curl-minimal)
→ Complete!

git --version    → git version 2.50.1
gcc --version    → gcc (GCC) 11.5.0 20240719 (Red Hat 11.5.0-5)
python3 --version → Python 3.9.25
```

---

### 3.4b Podman investigation

```
dnf search podman → No matches found.
dnf repolist:
  amazonlinux   Amazon Linux 2023 repository
  kernel-livepatch  Amazon Linux 2023 Kernel Livepatch repository

rpm -qa | grep container:
  containerd-2.2.5-1.amzn2023.0.1.x86_64
  container-selinux-2.245.0-1.amzn2023.noarch
```

**Conclusion:** Podman is absent from the `amazonlinux` repo (the only package feed available).
Docker 25.0.16 is installed, active (after `systemctl start docker`), and accessible to
`ec2-user` (via the `docker` group). The openshell-gateway auto-detection order is
Kubernetes → Podman → Docker; gateway will fall back to Docker at runtime.

The openshell-gateway RPM's `podman` RPM dependency is a packaging artifact that
prevents a clean `dnf install`; the binary itself works against Docker.
**Phase 2 option:** install gateway RPM with `rpm --nodeps` or build from source.

---

### 3.4c Docker verify (rootful, accessible to ec2-user)

```
systemctl start docker → active
docker info:
  Server Version: 25.0.16
  Storage Driver: overlay2
  Cgroup Driver: systemd
  Cgroup Version: 2
  Running: 0
sudo -u ec2-user docker info → docker-ec2user-ok
```

---

### 3.4d Swap

```
# Pre-existing state: no swap
dd if=/dev/zero of=/swapfile bs=1M count=8192  → 8.6 GB written, 143 MB/s
chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab

swapon --show:
  NAME      TYPE SIZE USED PRIO
  /swapfile file   8G   0B   -2

free -h:
  Mem:  3.7Gi  265Mi  124Mi
  Swap: 8.0Gi    0B   8.0Gi
```

---

### 3.4e Rust toolchain

```bash
sudo -u ec2-user bash -c 'curl --proto=https --tlsv1.2 -sSf https://sh.rustup.rs | \
  sh -s -- -y --default-toolchain 1.95.0 2>&1'

Result:
  1.95.0-x86_64-unknown-linux-gnu installed - rustc 1.95.0 (59807616e 2026-04-14)
  Rust is installed now.

sudo -u ec2-user bash -c 'source /home/ec2-user/.cargo/env && rustup --version'
→ rustup 1.29.0 (28d1352db 2026-03-05)

cargo --version → cargo 1.95.0 (f2d3ce0bd 2026-03-21)
rustc --version → rustc 1.95.0 (59807616e 2026-04-14)
```

**FINDING — rustup version divergence:**
`scripts/local-bootstrap.sh` line 7: `readonly RUSTUP_VERSION="1.28.2"` — pins rustup to
1.28.2 and downloads the exact binary from `static.rust-lang.org/rustup/archive/1.28.2/...`
with checksum validation. The standard `sh.rustup.rs` installer now ships rustup **1.29.0**.
The installed rustup is 1.29.0 — not 1.28.2.

Impact: for Phase 2, this is non-blocking because the Rust toolchain version (1.95.0) is
what matters for compilation reproducibility, not the rustup wrapper version. The bootstrap
script's checksum-pinned approach is more reproducible; the standard installer approach
provides a slightly newer rustup but the same Rust toolchain.

**rust-toolchain.toml verification:**
```
cat /home/ec2-user/obs/rust-toolchain.toml:
  [toolchain]
  channel = "1.95.0"
  components = ["clippy", "rust-analyzer", "rust-src", "rustfmt"]

rustup show active-toolchain (from obs dir):
  1.95.0-x86_64-unknown-linux-gnu (overridden by '/home/ec2-user/obs/rust-toolchain.toml')
```

---

### 3.4f User systemd session (linger)

```
loginctl enable-linger ec2-user  → Linger=yes
systemctl start user@1000.service → active

sudo -u ec2-user XDG_RUNTIME_DIR=/run/user/1000 systemctl --user list-units
→ units listed (device units, etc.)
→ user-session-ok
```

ec2-user has a working systemd user session — required for `openshell-gateway.service`.

---

### 3.4g /dev/kvm

```
ls -l /dev/kvm
→ crw-rw-rw-. 1 root kvm 10, 232 Jul 27 06:58 /dev/kvm
```

KVM character device present and **world-writable** — ec2-user can use it without being in
the `kvm` group. EC2 c7i.large instance supports nested virtualisation. VM driver available
for Phase 2 if podman/docker prove insufficient.

---

### 3.4h SELinux + container interaction

```
getenforce → Permissive
sestatus:
  SELinux status: enabled
  Loaded policy name: targeted
  Current mode: permissive
  Max kernel policy version: 35

docker context: system_u:object_r:container_runtime_exec_t:s0
container-selinux-2.245.0 installed
```

SELinux is enabled but in **Permissive mode** — policies log violations but do not block.
Docker and containers run without SELinux denials. Rootless podman (if later installed)
would also work in permissive mode.

---

### 3.5 Final host state (end of Phase 1)

| Component | State |
|-----------|-------|
| Kernel | 6.18.38-73.137.amzn2023.x86_64 |
| OS | Amazon Linux 2023.12.20260724 |
| SELinux | Permissive (enabled, targeted) |
| cgroups | v2 (cgroup2fs) |
| /dev/kvm | present, crw-rw-rw- |
| Docker | 25.0.16, active, overlay2, cgroup v2 |
| Podman | absent (not in AL2023 repo) |
| Swap | 8 GiB /swapfile, active |
| Disk / | 50 GB, ~13 GB used, 38 GB free |
| Rust | 1.95.0 (rustup 1.29.0) |
| Git | 2.50.1 |
| GCC | 11.5.0 |
| Python | 3.9.25 |
| Linger | ec2-user enabled |
| user@1000 | active |
| OBS repo | /home/ec2-user/obs (HEAD d935cc9) |

---

## Part 2 (continued) — Phase 2 journey log

| # | Step | Result | Notes |
|---|------|--------|-------|
| 5 | Additional system deps | PASS | protobuf-compiler 3.19.6, openssl-devel 3.5.5, perl-Digest-SHA, clang-devel 15.0.7 (provides libclang.so), z3-devel 4.8.17 + z3-libs. z3.h symlink needed: `/usr/include/z3.h → /usr/include/z3/z3.h` |
| 6 | openbox-sandbox service build | PASS | `cargo build --release --locked --bin openbox-sandbox`; **6m 09s**; 7.7 MB binary. Cloned openshell-core + openshell-policy from git as build deps |
| 7 | obs launcher build | PASS (with fix) | First attempt with `--locked` failed (Cargo.lock not in git archive); dropped `--locked` per README; **1.46s**; 595 KB binary at `packaging/launcher/target/release/osb` (renamed from `obs` in recent commit) |
| 8 | OpenShell clone at pin | PASS | `git clone --filter=blob:none --no-checkout` + `fetch --depth=128` + checkout at f169084923503a02a94425857b938de2841cab0c |
| 9 | OpenShell binary build | PASS | `-p openshell-cli -p openshell-server -p openshell-driver-vm`; **10m 24s**; required `LIBCLANG_PATH=/usr/lib64` (bindgen) + `z3.h` symlink fix; all three binaries report `0.0.88-dev.11+gf1690849` ✓ |
| 10 | obs provision | PASS | `osb provision` exit 0 (12:50:15 UTC); gateway pid=401784, service pid=401840; agent.env at ~/.config/openbox-sandbox/agent.env |
| 11 | obs verify | FAIL | `cargo test --lib live_service_create_exec_delete` exit 101 (21.75s); sandbox sbx-d17713684e7449b created→ProvisioningFailed; root cause: ENOSPC on tmpfs /tmp (1.9 GB); VM driver `--state-dir /tmp/...` routes OCI image cache to tmpfs; layers 01-03 extract OK, layer 04 (sha256:fbd7d054…) runs out of space mid-tar at `usr/lib/gcc/x86_64-linux-gnu/13/include/pconfigintrin.h`; Rust tar::unpack() reports last file at ENOSPC; two attempts hit different files confirming variable-point ENOSPC, not a fixed symlink issue |
| 12 | obs uninstall | PASS | `osb uninstall` exit 0; pids 401840+401784 stopped; state cleaned; no openshell/openbox processes or ports after teardown |
| 13 | re-provision with fix | PASS | Added `OPENSHELL_BIN_OVERRIDE=/home/ec2-user/openshell/target/release` + `OPENSHELL_VM_DRIVER_STATE_DIR=/home/ec2-user/.local/state/openshell-vm-driver`; exit 0; gateway pid=422854, driver pid=422865 with `--state-dir` on EBS (33 GB free), service pid=422910 |
| 14 | re-verify (fix 1 applied) | FAIL (new error) | Image layers pulled from ghcr.io in **98s** to EBS (ENOSPC fixed ✓); rootfs preparation failed: `sandbox supervisor not embedded` — driver built without `OPENSHELL_VM_RUNTIME_COMPRESSED_DIR`; needs `mise run vm:setup && mise run vm:supervisor` pre-build; halting per one-attempt rule |
| 15 | re-uninstall | PASS | `osb uninstall` (with OPENSHELL_VM_DRIVER_STATE_DIR set); pids 422910+422854+422865 stopped; state cleaned; 0 processes/ports |
| 16 | vm:setup (download runtime) | PASS | **18s**; bypassed gh CLI with direct curl; downloaded vm-runtime-linux-x86_64.tar.zst (21M) from public GitHub Release; extracted libkrun.so (5.3M), libkrunfw.so.5 (21M), gvproxy (13M), umoci (7.6M); downloaded umoci v0.6.0 amd64; compressed all with zstd -19 → vm-runtime-compressed/ (4 .zst files, totalling ~15M) |
| 17 | vm:supervisor (build supervisor bundle) | PASS | **7m 00s**; ran build-supervisor-bundle.sh directly (no mise needed); cargo build -p openshell-sandbox --target x86_64-unknown-linux-gnu; binary 23M → compressed 6.3M at vm-runtime-compressed/openshell-sandbox.zst |
| 18 | driver rebuild with embedding | PASS | **3m 14s**; OPENSHELL_VM_RUNTIME_COMPRESSED_DIR=/home/ec2-user/openshell/target/vm-runtime-compressed; embedded: libkrun 1.8M + libkrunfw 6.3M + gvproxy 3.9M + supervisor 6.3M + umoci 2.5M; binary grew 18M → **38M** |
| 19 | re-provision (driver with supervisor) | PASS | exit 0; gateway pid=434201, driver pid=434212, service pid=434258; all marker checks PASS |
| 20 | verify attempt 1 (cache miss) | FAIL (Deadline) | 120s timeout hit; image pull+ext4 conversion took **2:41** (cache miss on new embedded driver); VM DID boot (launcher at 14:10:54Z, supervisor connected 14:10:56Z — 44s after deadline); overlay setup succeeded, policy loaded, tail launched; no upperdir issue observed |
| 21 | verify attempt 2 (cache hit) | **PASS** | **3.09s**; full lifecycle create→ready→exec(`uname -a`)→delete→wait_deleted; `stdout="Linux sbx-abbfbe0ead1c452 6.12.76 #1 SMP ... x86_64 GNU/Linux"` exit_code=0 |
| 22 | final teardown | PASS | `osb uninstall` exit 0; pids 434258+434201 stopped; state cleaned; disk 19G used 31G free; 0 processes/ports |

---

## Part 4 — Phase 2 detail log

### 4.1 Additional system dependencies

Discovered iteratively during the OpenShell build (each failure revealed the next missing dep).

```
dnf install -y protobuf-compiler openssl-devel perl-Digest-SHA
→ protobuf-compiler-3.19.6-1.amzn2023.0.3.x86_64  (protoc at /usr/bin/protoc)
→ openssl-devel-1:3.5.5-1.amzn2023.0.5.x86_64
→ perl-Digest-SHA-1:6.04-522.amzn2023.0.2.x86_64

dnf install -y clang clang-devel
→ clang-devel-15.0.7-3.amzn2023.0.4.x86_64  (/usr/lib64/libclang.so)
  (also pulled: llvm-15.0.7, llvm-libs, libomp-devel, compiler-rt, libatomic)

dnf install -y z3-devel z3-libs
→ z3-devel-4.8.17-1.amzn2023.0.2.x86_64
→ z3-libs-4.8.17-1.amzn2023.0.2.x86_64
→ z3.h is at /usr/include/z3/z3.h; bindgen expects <z3.h>
   Fix: ln -sf /usr/include/z3/z3.h /usr/include/z3.h
```

**Build environment additions required (not in base AL2023):**
- `LIBCLANG_PATH=/usr/lib64` — bindgen can't find libclang.so without this
- `/usr/include/z3.h` symlink — z3-sys crate's `wrapper.h` includes `<z3.h>`
  but AL2023's z3-devel puts it at `z3/z3.h`

---

### 4.2 openbox-sandbox service build

```bash
# obs directory was owned by root from the Phase 1 tar extraction (SendCommand runs as root)
chown -R ec2-user:ec2-user /home/ec2-user/obs

# Build script (via base64 injection to avoid heredoc quoting issues):
cd /home/ec2-user/obs
cargo build --release --locked --bin openbox-sandbox
```

Timeline:
```
[Mon Aug  3 11:14:56 UTC 2026] Starting openbox-sandbox service build
→ Downloaded and compiled all deps (rustls, tonic, tokio, axum, prost, ring, …)
→ Compiled openshell-core and openshell-policy from git (pin f1690849)
    Finished `release` profile [optimized] target(s) in 6m 09s
[Mon Aug  3 11:21:05 UTC 2026] Service build exit: 0

$ ls -lh /home/ec2-user/obs/target/release/openbox-sandbox
-rwxr-xr-x. 2 ec2-user ec2-user 7.7M Aug  3 11:21 openbox-sandbox
```

**Note:** The openbox-sandbox build itself clones openshell-core and openshell-policy
at the pin as Cargo git deps — this is separate from the OpenShell binary build.
No extra system deps needed; openssl-devel provides rustls-native-certs backing.

---

### 4.3 obs launcher build

**Attempt 1 (failed):** `cargo build --release --locked --manifest-path packaging/launcher/Cargo.toml`
```
error: cannot create the lock file /home/ec2-user/obs/packaging/launcher/Cargo.lock
  because --locked was passed to prevent this
```
`packaging/launcher/Cargo.lock` is not tracked in the git repo (not in `git archive HEAD`
output). The README dogfood section does NOT use `--locked` for the launcher.

**Attempt 2 (success):** `cargo build --release --manifest-path packaging/launcher/Cargo.toml`
```
   Compiling openbox-sandbox-launcher v0.0.0 (/home/ec2-user/obs/packaging/launcher)
    Finished `release` profile [optimized] target(s) in 1.46s
```
Launcher has zero third-party crate deps — builds in 1.46s from scratch.

**Binary naming note:** The binary is named `osb` (not `obs`). The `aa1ec59` commit
"feat(launcher): rename binary to osb" changed the name; the README's dogfood section
still uses `obs` in prose. Binary is at:
```
/home/ec2-user/obs/packaging/launcher/target/release/osb  (595 KB)
```

Verification:
```
$ /home/ec2-user/obs/packaging/launcher/target/release/osb --help
openbox-sandbox — thin client / launcher
USAGE:
  openbox-sandbox setup [OPTIONS]     Run first-time setup.
  openbox-sandbox [OPTIONS]           Start the sandbox service.
…
```

---

### 4.4 OpenShell clone at pin f1690849

```bash
git clone --filter=blob:none --no-checkout \
  https://github.com/NVIDIA/OpenShell.git /home/ec2-user/openshell
git -C /home/ec2-user/openshell fetch --depth=128 origin \
  f169084923503a02a94425857b938de2841cab0c
git -C /home/ec2-user/openshell checkout --detach \
  f169084923503a02a94425857b938de2841cab0c
```

Clone succeeded. HEAD confirmed at pin. Ownership fixed: `chown -R ec2-user:ec2-user /home/ec2-user/openshell`.

---

### 4.5 OpenShell binary build

```bash
export LIBCLANG_PATH=/usr/lib64
cd /home/ec2-user/openshell
cargo +1.95.0 build --release --locked \
  -p openshell-cli -p openshell-server -p openshell-driver-vm
```

**Build failures and fixes (chronological):**
1. `bindgen-0.72.1`: "Unable to find libclang" → fix: `LIBCLANG_PATH=/usr/lib64`
2. `z3-sys-0.10.9`: "fatal error: 'z3.h' file not found" → fix: `dnf install -y z3-devel z3-libs`
   then `ln -sf /usr/include/z3/z3.h /usr/include/z3.h`

**Successful run:**
```
[Mon Aug  3 11:37:10 UTC 2026] Starting OpenShell build at pin f169084923503a02a94425857b938de2841cab0c
   Compiling z3-sys v0.10.9          ← bindgen + libclang + z3.h all working
   … (openshell-gateway-interceptors, openshell-prover, sqlx, aws-config, …)
    Finished `release` profile [optimized] target(s) in 10m 24s
[Mon Aug  3 11:47:37 UTC 2026] OpenShell build done: 0
```

**Marker verification:**
```
$ /home/ec2-user/openshell/target/release/openshell --version
openshell 0.0.88-dev.11+gf1690849

$ /home/ec2-user/openshell/target/release/openshell-gateway --version
openshell-gateway 0.0.88-dev.11+gf1690849

$ /home/ec2-user/openshell/target/release/openshell-driver-vm --version
openshell-driver-vm 0.0.88-dev.11+gf1690849
```

All three contain `gf1690849` → `openshell_matches_pin` / `require_source_marker` PASS ✓

**Binary sizes:**
- openshell (CLI): 22 MB
- openshell-gateway: 49 MB
- openshell-driver-vm: 18 MB

---

### 4.6 obs provision

```bash
/home/ec2-user/obs/packaging/launcher/target/release/osb provision
```

Output:
```
▸ PROVISION
  ==> Teardown (always)
  [ok] teardown complete
  ==> Generating local PKI into /home/ec2-user/.local/state/openshell/tls
  [ok] PKI ready (CA at /home/ec2-user/.local/state/openshell/tls/ca.crt)
  ==> Starting gateway on https://127.0.0.1:17670
  [ok] gateway up (pid=401784)
  ==> Generating runtime-caller mTLS pair
  [ok] caller fingerprint: 4457464ba177bd833ffd19773bbe00539fa00335938da10fc894a6a4813ca26b
  [ok] adapter sha:        7f3a1d6f73583c19ec71bf122c0a506bfbfa25247e95d66c962f9cf5796f3e27
  [ok] policy sha:         9e6ea9b48c8c121a065ae212490f8250fe86000340fd42c170355776ca6bfbd8
  ==> Starting sandbox service on 127.0.0.1:17443
  [ok] service up (pid=401840)
  ==> Emitting agent env -> /home/ec2-user/.config/openbox-sandbox/agent.env
  [ok] agent.env written
  [ok] provision complete

[Mon Aug  3 12:50:15 UTC 2026] provision exit: 0
```

Process table post-provision:
```
ec2-user 401784  openshell-gateway --port 17670 --drivers vm --tls-cert ... --enable-mtls-auth true
ec2-user 401795  openshell-driver-vm --state-dir /tmp/openshell-vm-driver-ec2-user-openshell ...
ec2-user 401840  openbox-sandbox (service, port 17443, mTLS)
```

Ports:
```
LISTEN 127.0.0.1:17443  openbox-sandbox
LISTEN 127.0.0.1:17670  openshell-gateway
```

---

### 4.7 agent.env discovery

```
find /home/ec2-user -name agent.env
→ /home/ec2-user/.config/openbox-sandbox/agent.env
```

Contents (keys, no secret values):
```
OPENBOX_SANDBOX_ENDPOINT=127.0.0.1:17443
OPENBOX_SANDBOX_SERVER_NAME=localhost
OPENBOX_SANDBOX_CA=/home/ec2-user/.config/openbox-sandbox/tls/ca.crt
OPENBOX_SANDBOX_CERT=/home/ec2-user/.config/openbox-sandbox/tls/client.crt
OPENBOX_SANDBOX_KEY=/home/ec2-user/.config/openbox-sandbox/tls/client.key
OPENBOX_SANDBOX_BINARY=/home/ec2-user/obs/target/release/openbox-sandbox
OPENBOX_SANDBOX_ADAPTER_SHA=7f3a1d6f73583c19ec71bf122c0a506bfbfa25247e95d66c962f9cf5796f3e27
OPENBOX_SANDBOX_TEMPLATE=ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63...
OPENBOX_SANDBOX_POLICY_FILE=/home/ec2-user/obs/deploy/policies/policy-deny-network-dev.yaml
OPENBOX_SANDBOX_POLICY_ID=openbox-deny-network-dev
OPENBOX_SANDBOX_POLICY_VERSION=1
OPENBOX_SANDBOX_POLICY_SHA256=9e6ea9b48c8c121a065ae212490f8250fe86000340fd42c170355776ca6bfbd8
OPENBOX_SANDBOX_COMPAT_ID=darwin-dev-1
OPENBOX_SANDBOX_CONFIG_PATH=/home/ec2-user/.config/openbox-sandbox/service.json
OPENBOX_GATEWAY_ENDPOINT=https://127.0.0.1:17670
```

Generated by `provision-local-sandbox.sh` at 2026-08-03T12:50:15Z.

**Note:** `OPENBOX_SANDBOX_COMPAT_ID=darwin-dev-1` — the provision script used the macOS
compat-id string on this Linux host; this value is embedded in the provisioned PKI and
agent.env and is not known to cause runtime failures (the verify test reads it but treats
it as an opaque string matching the policy YAML value).

---

### 4.8 verify run

**Command (equivalent to what `osb verify` / dogfood.rs `run_verify()` runs):**
```bash
source /home/ec2-user/.cargo/env
cd /home/ec2-user/obs
set -a
. /home/ec2-user/.config/openbox-sandbox/agent.env
set +a
cargo +1.95.0 test --lib live_service_create_exec_delete \
  -- --nocapture --test-threads=1 > /tmp/verify.log 2>&1
```

**Test output (from /tmp/verify.log):**
```
   Finished `test` profile [unoptimized + debuginfo] target(s) in 1.07s
    Running unittests src/lib.rs (target/debug/deps/openbox_sandbox-3122abde366fec5d)

running 1 test
test integration_tests::live_service::live_service_create_exec_delete ...
live_service: endpoint=127.0.0.1:17443 server_name=localhost
live_service: template=ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63...
live_service: policy=.../policy-deny-network-dev.yaml sha256=9e6ea9b4...
live_service: adapter_sha=7f3a1d6f...
live_service: compat_id=darwin-dev-1 cmd="uname -a"
live_service: connected to service boundary; creating sandbox ...
live_service: request_id=sbx-d17713684e7449b (len=19)
live_service: created by service; waiting ready ...

thread panicked at src/integration_tests/live_service.rs:166:10:
real service wait_ready must succeed: ReadinessFailure {
  cleanup_target: CleanupTarget { request_id: RequestOwnedId("sbx-d17713684e7449b") },
  code: WorkloadError,
  detail: "<redacted>"
}

FAILED  test result: FAILED. 0 passed; 1 failed  finished in 21.75s
EXIT_CODE=101
```

**Result: FAIL (exit 101)**

**Gateway log — root cause:**
```
2026-08-03T13:09:15Z WARN openshell_driver_vm::driver:
  vm driver: sandbox provisioning failed sandbox_id=a97b3605... sandbox_name=sbx-d17713684e7449b
  error: failed to extract layer 'sha256:fbd7d0054f4036ea2bc139c57538964370108cf3f955e49569d865c3289c86dc'
  for vm sandbox image 'ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63...':
  extract layer into .../images/...staging-1785762528895-1/layers/04-sha256-fbd7d054...root:
  failed to unpack `.../layers/04-sha256-fbd7d054...root/usr/lib/gcc/x86_64-linux-gnu/13/include/pconfigintrin.h`
```

**Root cause analysis — ENOSPC on tmpfs:**

The VM driver locates its image cache under `--state-dir /tmp/openshell-vm-driver-ec2-user-openshell`,
which is on the host's `/tmp` **tmpfs** (1.9 GB = 50% of 3.7 GB RAM, EC2 default for Amazon Linux 2023).

Layer extraction flow (`extract_layer_blob_to_dir` in `openshell-driver-vm/src/driver.rs:3795`):
```rust
fn extract_tar_reader_to_dir(reader: impl Read, dest: &Path) -> Result<(), String> {
    let mut archive = tar::Archive::new(reader);
    archive.unpack(dest).map_err(|err|
        format!("extract layer into {}: {err}", dest.display()))
}
```
The Rust `tar` crate's `unpack()` returns `"failed to unpack {path}"` when `io::Error` (ENOSPC)
hits during extraction. The path reported is the last file being written at the moment of failure.

**Evidence that the cause is ENOSPC, not a fixed structural issue:**
- **Prior attempt** (sbx-31a87514, run by previous worker at 12:57 UTC) failed at:
  `usr/include/node/openssl/archs/BSD-x86/asm_avx2/include/openssl/comp.h`
- **This attempt** (sbx-d17713684e7449b, 13:08 UTC) failed at:
  `usr/lib/gcc/x86_64-linux-gnu/13/include/pconfigintrin.h`

Different files in layer 04 across two independent runs: consistent with ENOSPC hitting at
different points depending on tmpfs utilization at extraction time. A fixed structural error
(e.g., symlink traversal protection in tar) would always fail at the same entry.

Layers 01-03 extracted successfully both times. Layer 04 contains large Node.js and GCC
header trees; their combined uncompressed size exceeds the remaining tmpfs headroom once
layers 01-03 are staged.

**The upperdir fix (from prior memory) is NOT the issue:** that fix addresses microVM boot
(`chmod 0755 /overlay/upper`), which is reached only after successful image extraction.
The failure here is pre-boot, in the image-pull stage.

---

### 4.9 teardown

```bash
/home/ec2-user/obs/packaging/launcher/target/release/osb uninstall
```

Output:
```
▸ UNINSTALL
  • teardown -> delete state root / config root / gateway metadata / PKI
  ==> Teardown (always)
  ==> stopping validated sandbox service pid=401840
  ==> stopping validated gateway pid=401784
  [ok] teardown complete
  ==> Removing wizard state
  [ok] state cleaned
  [ok] uninstall complete — host equivalent to 'before provision'
```

Exit code: 0

Post-teardown verification:
```
ps aux | grep -E "openshell|openbox" | grep -v grep → (empty)
ss -tlnp | grep -E "17670|17443"               → (empty)
```

All processes gone; ports 17670 and 17443 no longer listening.

---

## Part 5 — Phase 2 Conclusions (snapshot, superseded by Part 7)

### (a) What a Linux host needs to run OpenShell (empirical additions to Part 1 theory)

| Requirement | Status | Notes |
|-------------|--------|-------|
| Rust 1.95.0 toolchain | Needed, not pre-installed | `curl -sSf https://sh.rustup.rs \| sh -s -- -y --default-toolchain 1.95.0` |
| protobuf-compiler, openssl-devel, clang-devel | Needed | Not in base AL2023; dnf-installable |
| z3-devel + z3.h symlink | Needed for OpenShell build | AL2023 z3-devel puts header at `z3/z3.h`; need `ln -sf /usr/include/z3/z3.h /usr/include/z3.h` |
| LIBCLANG_PATH=/usr/lib64 | Needed for bindgen | Not set by default |
| Docker (rootful) | Needed if no podman | Podman absent from AL2023 repos; gateway falls back to Docker |
| Persistent (non-tmpfs) state dir for VM driver | **CRITICAL GAP** | Default `--state-dir /tmp/...` uses tmpfs; on EC2 instances with ≤4 GB RAM, tmpfs is too small to extract sandbox base image layers; must redirect to persistent disk |
| loginctl enable-linger + user@1000 | Needed | For systemd user session (gateway depends on this) |
| /dev/kvm | Needed for VM driver | Present on c7i.large EC2; world-writable |
| Swap | Needed for Rust builds | 8 GB /swapfile created; build used swap |
| Disk space | ~13 GB for full build | repos cloned, all binaries built |

### (b) E2E result on AL2023

| Phase | Result |
|-------|--------|
| install.sh (local bootstrap) | FAIL (expected) — requires apt-get, not available on AL2023 |
| 0.0.85 RPM pin check | FAIL (expected) — marker gf1690849 absent from release builds |
| openbox-sandbox service build | PASS |
| obs launcher build (as `osb`) | PASS (without --locked) |
| OpenShell source build at pin gf1690849 | PASS |
| obs provision | PASS — gateway, driver, service all up |
| obs verify (sandbox create→ready→exec→delete) | **FAIL** — OCI image layer extraction fails with ENOSPC on tmpfs |
| obs uninstall | PASS — full teardown, clean state |

**Overall E2E verdict: PARTIAL.** The stack provisions and uninstalls cleanly on AL2023.
The verify (sandbox lifecycle) fails because the VM driver stores image cache in `/tmp`
(tmpfs, 1.9 GB on this instance), which is too small for the base sandbox image.
No sandbox microVM was ever booted on this host.

### (c) Gaps and open items

1. **VM driver state-dir on persistent disk (blocker for VM driver on EC2/Linux).**
   `provision-local-sandbox.sh` sets `--state-dir /tmp/openshell-vm-driver-{user}-openshell`.
   On Linux with small RAM (≤4 GB), tmpfs exhaustion prevents any sandbox from being created.
   Fix: route the driver state dir to `/home/ec2-user/.local/state/openshell-driver-vm` or
   any persistent filesystem. The 50 GB EBS volume has ~37 GB free.

2. **obs setup / fetch-openshell-deps.sh never tested on Linux.**
   The full `obs setup` flow (which would fetch pre-built OpenShell binaries) was bypassed;
   we built from source manually. The convenience setup path remains untested on Linux.

3. **RPM install track (install.sh, published bundle).**
   Confirmed 0.0.85 RPMs fail the pin marker check. A correctly-pinned RPM bundle
   (version `0.0.88-dev.11+gf1690849`) does not exist yet as a published release.
   The `install.sh` RPM track is structurally correct but has no valid bundle to test against.

4. **The upperdir fix (prior memory `upperdir-fix-release-evidence-audit`) is not yet upstream.**
   Once the ENOSPC issue is fixed (item 1), the VM driver will proceed to microVM boot.
   The upperdir fix (`chmod 0755 /overlay/upper`) will then be needed for the sandbox
   exec step to succeed. Both issues must be resolved for a full PASS.

5. **Error detail redacted in test output.**
   `ReadinessFailure { detail: "<redacted>" }` — the underlying ENOSPC error is
   visible in the gateway log (`--log-level info`) but not surfaced in the Rust test output.
   Increasing `--log-level debug` on the driver would add more context.

6. **`OPENBOX_SANDBOX_COMPAT_ID=darwin-dev-1`** embedded in provisioned state.
   The provision script emits this value on Linux without substituting a Linux-appropriate
   id. Not a runtime blocker (the test passes it through as an opaque string), but worth
   noting for a proper Linux release.

---

## Part 6 — Phase 3 detail log (ENOSPC fix + re-verify)

### 5.1 Re-provision with fix

**Problem identified in Phase 2:** `osb provision` defaults `--state-dir` to
`/tmp/openshell-vm-driver-{user}-openshell` (tmpfs, 1.9 GB on this EC2 instance), which
is too small to extract the sandbox base image OCI layers (3 layers + layer 4 together
exceed tmpfs capacity).

**Fix applied:** Set `OPENSHELL_VM_DRIVER_STATE_DIR` before calling `osb provision`,
redirecting the VM driver state to persistent EBS storage (~33 GB free).

Also needed: `OPENSHELL_BIN_OVERRIDE` was required (but missing from the Phase 2 provision
because the previous worker had set it differently). Without it, the script looks for
binaries at `$PROJECT_ROOT/openbox-sandbox-bundle/bin/` which doesn't exist.

```bash
export OPENSHELL_BIN_OVERRIDE=/home/ec2-user/openshell/target/release
export OPENSHELL_VM_DRIVER_STATE_DIR=/home/ec2-user/.local/state/openshell-vm-driver
/home/ec2-user/obs/packaging/launcher/target/release/osb provision
```

Output (exit 0):
```
▸ PROVISION
  [ok] openshell-gateway source marker f1690849 verified
  [ok] openshell source marker f1690849 verified
  [ok] openshell-driver-vm source marker f1690849 verified
  [ok] gateway up (pid=422854)
  [ok] service up (pid=422910)
  [ok] agent.env written
  [ok] provision complete
```

VM driver process confirmed with persistent state dir:
```
/home/ec2-user/openshell/target/release/openshell-driver-vm \
  --state-dir /home/ec2-user/.local/state/openshell-vm-driver \
  ...  (pid=422865)
```

Disk verification:
```
/dev/nvme0n1p1  50G  18G  33G  35%  /
/tmp (tmpfs)    1.9G  29M  1.9G   2%  /tmp
```

### 5.2 Re-verify (sandbox sbx-9037565dd82e402)

**Command (same as Phase 2 verify):**
```bash
source /home/ec2-user/.cargo/env
cd /home/ec2-user/obs
set -a; . /home/ec2-user/.config/openbox-sandbox/agent.env; set +a
cargo +1.95.0 test --lib live_service_create_exec_delete \
  -- --nocapture --test-threads=1 > /tmp/verify2.log 2>&1
```

**Test output:**
```
   Finished `test` profile [unoptimized + debuginfo] target(s) in 0.11s  (cached)
    Running unittests src/lib.rs
running 1 test
live_service: request_id=sbx-9037565dd82e402
live_service: created by service; waiting ready ...

thread panicked at src/integration_tests/live_service.rs:166:10:
real service wait_ready must succeed: ReadinessFailure {
  code: WorkloadError, detail: "<redacted>"
}
FAILED.  finished in 99.56s
EXIT_CODE=101
```

**Result: FAIL (exit 101)**

**Gateway log — new root cause:**

Timeline for sbx-9037565dd82e402 (sandbox_id=de23bc49...):
```
13:33:28Z  create_sandbox received; resolved image ref; preparing disks
13:33:28Z  ensuring cached root disk image (registry) — cache miss; build lock acquired
13:33:29Z  pulling registry image layers → staging dir on EBS
           staging: .local/state/openshell-vm-driver/images/
             sandbox-bootstrap-rootfs-ext4-v3-...-aeef1c63....staging-1785764009276-0
13:35:07Z  image layers pulled, preparing rootfs image  [← ~98s for download+extraction]
13:35:07Z  WARN: rootfs preparation failed
           error: "vm sandbox image '...base@sha256:aeef1c63...' is not base-compatible:
           sandbox supervisor not embedded.
           Build openshell-driver-vm with OPENSHELL_VM_RUNTIME_COMPRESSED_DIR set
           and run `mise run vm:setup && mise run vm:supervisor` first"
13:35:07Z  Sandbox phase changed: Provisioning → Error
```

**ENOSPC fix confirmed working:** The image download + OCI layer extraction completed
successfully in **98 seconds** on EBS. The staging directory was created and populated
on the persistent filesystem. ENOSPC is no longer the failure mode.

**New blocker: embedded supervisor not present in driver binary.**

The `openshell-driver-vm` binary needs the sandbox supervisor embedded at **build time**.
From the driver README:
> The runtime (libkrun + libkrunfw + gvproxy), guest OCI unpacker, and sandbox supervisor
> are embedded directly in the binary.

The build process for the driver requires:
1. `OPENSHELL_VM_RUNTIME_COMPRESSED_DIR` env var pointing to pre-built VM runtime
2. `mise run vm:setup` — downloads/builds libkrun runtime deps
3. `mise run vm:supervisor` — builds the guest supervisor binary

The Phase 2 build step 9 (`cargo build --release --locked -p openshell-driver-vm`) ran
without these prerequisites, producing a functional binary that can authenticate and
extract image layers but **cannot prepare the ext4 rootfs** because the guest init
program is missing from the binary.

This blocker requires a full driver rebuild with the correct build-time env. Per task
constraint (one fix attempt), stopping here and reporting back.

### 5.3 Re-teardown

```bash
export OPENSHELL_BIN_OVERRIDE=/home/ec2-user/openshell/target/release
export OPENSHELL_VM_DRIVER_STATE_DIR=/home/ec2-user/.local/state/openshell-vm-driver
/home/ec2-user/obs/packaging/launcher/target/release/osb uninstall
```

Output:
```
▸ UNINSTALL
  ==> stopping validated sandbox service pid=422910
  ==> stopping validated gateway pid=422854
  [ok] teardown complete
  [ok] state cleaned
  [ok] uninstall complete — host equivalent to 'before provision'
```
Exit 0. Post-teardown: 0 processes, 0 ports.

---

---

## Part 7 — Phase 4 detail log (embedded supervisor + re-verify)

### 7.1 Understanding vm:setup and vm:supervisor

**Sources read on host:**
```
/home/ec2-user/openshell/tasks/vm.toml                            ← task definitions
/home/ec2-user/openshell/tasks/scripts/vm/vm-setup.sh            ← vm:setup body
/home/ec2-user/openshell/tasks/scripts/vm/download-kernel-runtime.sh  ← download logic
/home/ec2-user/openshell/tasks/scripts/vm/build-supervisor-bundle.sh  ← vm:supervisor body
/home/ec2-user/openshell/tasks/scripts/vm/_lib.sh                ← shared helpers
/home/ec2-user/openshell/crates/openshell-driver-vm/runtime/pins.env  ← version pins
```

**What vm:setup does:**
1. Calls `download-kernel-runtime.sh` (default mode) — requires `gh` CLI.
2. Downloads `vm-runtime-${PLATFORM}.tar.zst` from the `vm-runtime` GitHub Release
   in `NVIDIA/OpenShell`.
3. Extracts to `target/vm-runtime-extracted/` (libkrun.so, libkrunfw.so.5,
   libkrunfw.so.5.3.0, gvproxy; downloads umoci v0.6.0 if not in tarball).
4. Compresses each file with `zstd -19 -T0` to `target/vm-runtime-compressed/`
   (adds `.zst` suffix).

**Expected output (linux-x86_64):**
```
target/vm-runtime-compressed/
  libkrun.so.zst          1.8M
  libkrunfw.so.5.zst      6.3M
  libkrunfw.so.5.3.0.zst  6.3M  ← versioned name also compressed
  gvproxy.zst             3.9M
  umoci.zst               2.5M
```

**What vm:supervisor does:**
1. Calls `build-supervisor-bundle.sh`.
2. Detects architecture (x86_64 → target `x86_64-unknown-linux-gnu`).
3. Tries `cargo zigbuild` (preferred for cross-compile); falls back to `cargo build`.
4. Builds `-p openshell-sandbox --target x86_64-unknown-linux-gnu`.
5. Compresses the binary with `zstd -19` to
   `${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR}/openshell-sandbox.zst`.

**Dependencies:**
- `gh` CLI (GitHub CLI) — for `vm-setup.sh` download mode. **Not in AL2023
  repos.** Bypassed by downloading `vm-runtime-linux-x86_64.tar.zst` directly
  via `curl -L` (public GitHub Release, no auth needed).
- `zstd` — present on host at `/usr/bin/zstd`.
- Rust 1.95.0 — already installed.
- `cargo-zigbuild` — not installed; build-supervisor-bundle.sh falls back to
  `cargo build` automatically.
- x86_64-unknown-linux-gnu target — pre-installed (default host target).

**mise installation:** NOT required. Both scripts can be run directly without
the `mise` task runner. mise was absent from the host (`which mise → NO-MISE`);
invoking the scripts directly avoided the dependency entirely.

---

### 7.2 vm:setup (direct curl approach)

`gh` CLI is absent and not in AL2023 repos. However, `vm-runtime-linux-x86_64.tar.zst`
is publicly accessible without authentication:
```bash
curl -sI "https://github.com/NVIDIA/OpenShell/releases/download/vm-runtime/vm-runtime-linux-x86_64.tar.zst"
# HTTP/2 302 → redirect to release-assets.githubusercontent.com
```

Custom download script (`/tmp/vm-setup-direct.sh`) replicated the logic of
`download-kernel-runtime.sh` using only `curl` and the already-present `zstd`:

```bash
curl -L -o "$TARBALL" \
  "https://github.com/NVIDIA/OpenShell/releases/download/vm-runtime/vm-runtime-linux-x86_64.tar.zst"
zstd -d "$TARBALL" --stdout | tar -xf - -C "$EXTRACT_DIR"
# download umoci v0.6.0 amd64 (not in tarball):
curl -fsSL -o "${EXTRACT_DIR}/umoci" \
  "https://github.com/opencontainers/umoci/releases/download/v0.6.0/umoci.linux.amd64"
# compress all files:
for file in "$EXTRACT_DIR"/*; do zstd -19 -f -q -T0 -o "${OUTPUT_DIR}/${name}.zst" "$file"; done
```

Result (18 seconds, 13:47:34Z → 13:47:52Z):
```
gvproxy:         13M → 3.9M
libkrun.so:      5.3M → 1.8M
libkrunfw.so.5:  21M → 6.3M
libkrunfw.so.5.3.0: 21M → 6.3M
umoci:           7.6M → 2.5M
VALIDATE: PASS — all 4 required artifacts present
```

Output dir: `/home/ec2-user/openshell/target/vm-runtime-compressed/`

---

### 7.3 vm:supervisor build

```bash
export LIBCLANG_PATH=/usr/lib64
export OPENSHELL_VM_RUNTIME_COMPRESSED_DIR=/home/ec2-user/openshell/target/vm-runtime-compressed
nohup bash /home/ec2-user/openshell/tasks/scripts/vm/build-supervisor-bundle.sh > /tmp/vm-supervisor.log 2>&1
```

Build log:
```
==> Building openshell-sandbox supervisor bundle
    Guest arch: x86_64
    Rust target: x86_64-unknown-linux-gnu
    Output: /home/ec2-user/openshell/target/vm-runtime-compressed/openshell-sandbox.zst
    cargo-zigbuild not found, falling back to cargo build...
   Compiling openshell-supervisor-network v0.0.0 (...)
   Compiling openshell-supervisor-middleware-builtins v0.0.0 (...)
   Compiling openshell-sandbox v0.0.0 (...)
    Finished `release` profile [optimized] target(s) in 7m 00s
    Binary: 23M
    Compressed: 6.3M
```

Elapsed: **7 minutes** (13:48 → 13:55 UTC).

Final output: `target/vm-runtime-compressed/openshell-sandbox.zst` (6.3M)

Note: cargo-zigbuild is not installed; the script auto-detected this and used
plain `cargo build`. On Linux with native target, this is equivalent.

---

### 7.4 Driver rebuild with embedded supervisor

Before rebuild:
```
/home/ec2-user/openshell/target/release/openshell-driver-vm: 18M
```

Rebuild command:
```bash
export LIBCLANG_PATH=/usr/lib64
export OPENSHELL_VM_RUNTIME_COMPRESSED_DIR=/home/ec2-user/openshell/target/vm-runtime-compressed
cargo +1.95.0 build --release --locked -p openshell-driver-vm \
  --manifest-path /home/ec2-user/openshell/Cargo.toml
```

Build log (embedding messages emitted by driver's build.rs):
```
warning: openshell-driver-vm@0.0.0: Embedded libkrun.so.zst: 1850760 bytes
warning: openshell-driver-vm@0.0.0: Embedded libkrunfw.so.5.zst: 6548031 bytes
warning: openshell-driver-vm@0.0.0: Embedded gvproxy.zst: 4042363 bytes
warning: openshell-driver-vm@0.0.0: Embedded openshell-sandbox.zst: 6573269 bytes
warning: openshell-driver-vm@0.0.0: Embedded umoci.zst: 2610930 bytes
   Finished `release` profile [optimized] target(s) in 3m 14s
```

After rebuild:
```
/home/ec2-user/openshell/target/release/openshell-driver-vm: 38M
```

**Binary size delta: 18M → 38M (+20M).** The increase matches the total of embedded
compressed artifacts (1.8 + 6.3 + 3.9 + 6.3 + 2.5 ≈ 20.8M). The supervisor is
now embedded.

Elapsed: **3 minutes 14 seconds** (14:02 UTC finish).

---

### 7.5 Re-provision

```bash
export OPENSHELL_BIN_OVERRIDE=/home/ec2-user/openshell/target/release
export OPENSHELL_VM_DRIVER_STATE_DIR=/home/ec2-user/.local/state/openshell-vm-driver
/home/ec2-user/obs/packaging/launcher/target/release/osb provision
```

Output (exit 0, 14:05:08Z):
```
[ok] openshell-gateway source marker f1690849 verified
[ok] openshell source marker f1690849 verified
[ok] openshell-driver-vm source marker f1690849 verified
[ok] gateway up (pid=434201)
[ok] service up (pid=434258)
[ok] agent.env written
[ok] provision complete
```

VM driver process (with persistent state dir):
```
/home/ec2-user/openshell/target/release/openshell-driver-vm \
  --bind-socket /home/ec2-user/.local/state/openshell-vm-driver/run/compute-driver.sock \
  --state-dir /home/ec2-user/.local/state/openshell-vm-driver ...
```

---

### 7.6 Verify attempt 1 — cache miss (Deadline)

**Command:**
```bash
cd /home/ec2-user/obs
source /home/ec2-user/.cargo/env
set -a; . /home/ec2-user/.config/openbox-sandbox/agent.env; set +a
cargo +1.95.0 test --lib live_service_create_exec_delete -- --nocapture --test-threads=1
```

**Result: FAIL (code: Deadline, 120.08s)**

Sandbox: `sbx-9d276ccb653a4af` (sandbox_id=`73ca52bd-02dc-4b7b-b295-23391684e5ce`)

**Gateway log timeline:**
```
14:08:12.856Z  CreateSandbox received
14:08:13.686Z  cache miss → acquiring build lock → pulling OCI layers from registry
14:10:54.005Z  root disk image committed to cache ← 2m40s image pull + ext4 conversion
14:10:54.781Z  spawning VM launcher (pid=434646)
14:10:55.789Z  GetSandboxConfig served (supervisor started inside VM)
14:10:56.212Z  ReportPolicyStatus: policy loaded
14:10:56.224Z  ConnectSupervisor: accepted — supervisor session established
```

**Test deadline:** 120s from create (14:08:12Z) = 14:10:12Z.
**Supervisor connected at:** 14:10:56Z = **44 seconds AFTER the deadline.**

**Root cause:** Image cache miss on first run with the embedded-supervisor binary.
The driver's image identity includes the driver version string:
`sandbox-bootstrap-rootfs-ext4-v3:openshell-0.0.88-dev.11+gf1690849:sha256:aeef1c63...`
The previous cache entry (from the Phase 3 abort at the supervisor-not-embedded error)
was abandoned staging data. A full image pull + OCI-to-ext4 conversion was needed.

**Critical finding — upperdir not an issue:**
From the VM console log (`rootfs-console.log`):
```
[0.006s] setting up writable overlay root   ← SUCCEEDED, no error
[0.105s] prepared /sandbox ownership (998:998)
[0.228s] starting openshell-sandbox supervisor
2026-08-03T14:10:56.068Z OCSF LIFECYCLE:INSTALL [INFO] OpenShell Sandbox Supervisor success
2026-08-03T14:10:56.075Z OCSF PROC:LAUNCH [INFO] tail(568)
```
The overlay upperdir setup succeeded without the fix from memory
`upperdir-fix-release-evidence-audit`. The current pin (f169084923503a02a94425857b938de2841cab0c)
does NOT require the upperdir chmod fix on this host.

**The sandbox VM was fully alive and running when the test gave up.** The supervisor
continued making periodic GetSandboxConfig and GetInferenceBundle requests until
the old sandbox VM was cleaned up (at teardown).

---

### 7.7 Verify attempt 2 — cache hit (PASS)

With rootfs.ext4 committed to cache at `/home/ec2-user/.local/state/openshell-vm-driver/images/...`,
the second verify run skips image pull entirely.

**Command:** (same as attempt 1)

**Result: PASS (3.09s)**

```
test integration_tests::live_service::live_service_create_exec_delete ...
live_service: endpoint=127.0.0.1:17443 server_name=localhost
live_service: template=ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63...
live_service: policy=.../policy-deny-network-dev.yaml sha256=9e6ea9b4...
live_service: adapter_sha=7f3a1d6f...
live_service: compat_id=darwin-dev-1 cmd="uname -a"
live_service: connected to service boundary; creating sandbox ...
live_service: request_id=sbx-abbfbe0ead1c452 (len=19)
live_service: created by service; waiting ready ...
live_service: ready; exec: uname -a
live_service: stdout="Linux sbx-abbfbe0ead1c452 6.12.76 #1 SMP PREEMPT_DYNAMIC
             Tue Mar 10 13:28:56 CET 2026 x86_64 x86_64 x86_64 GNU/Linux\n"
live_service: exit_code=ObservedExitCode(0) stdout_bytes=117 stderr_bytes=0
live_service: complete lifecycle (create->wait_ready->exec->delete->wait_deleted) SUCCEEDED
ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 68 filtered out; finished in 3.09s
```

**Evidence:**
- Sandbox guest kernel: Linux 6.12.76 (libkrun guest kernel, embedded at build time)
- `uname -a` exit code: 0 ✓
- Full lifecycle verified: create → wait_ready → exec → delete → wait_deleted
- Test duration: 3.09s (cache hit; VM launched in seconds)

---

### 7.8 Final teardown

```bash
export OPENSHELL_BIN_OVERRIDE=/home/ec2-user/openshell/target/release
export OPENSHELL_VM_DRIVER_STATE_DIR=/home/ec2-user/.local/state/openshell-vm-driver
/home/ec2-user/obs/packaging/launcher/target/release/osb uninstall
```

Output (exit 0, 14:19:19Z):
```
==> stopping validated sandbox service pid=434258
==> stopping validated gateway pid=434201
[ok] teardown complete
[ok] state cleaned
[ok] uninstall complete — host equivalent to 'before provision'
```

Post-teardown:
```
ps aux | grep -E "openshell|openbox" → 0 processes
ss -tlnp | grep -E "17670|17443"   → 0 ports
df -h /                            → 50G total, 19G used, 31G free
free -h                            → 3.7Gi total, 340Mi used, 2.7Gi free
```

Clean state confirmed.

---

## Part 8 — Conclusions (FINAL — PASS)

### E2E Result Summary

| Verify attempt | Fix applied | Result | Duration | Root cause / note |
|----------------|-------------|--------|----------|-------------------|
| Attempt 1 (previous worker, 12:57 UTC) | none | FAIL | 21.75s | ENOSPC: tmpfs /tmp (1.9 GB) too small for OCI layer extraction |
| Attempt 2 (13:08 UTC, Phase 2 worker) | none | FAIL | 21.75s | ENOSPC (same) |
| Attempt 3 (13:33 UTC, Phase 3 fix) | OPENSHELL_VM_DRIVER_STATE_DIR on EBS | FAIL | 99.56s | Embedded supervisor missing from driver binary |
| Attempt 4 (14:08 UTC, Phase 4) | Embedded supervisor + EBS state dir | FAIL (Deadline) | 120.08s | Image cache miss; VM DID boot; test deadline (120s) < image pull time (2:41) |
| Attempt 5 (14:17 UTC, cache hit) | Same | **PASS** | **3.09s** | Cache hit; full lifecycle completed |

**Final status: PASS — `live_service_create_exec_delete` SUCCEEDED on Amazon Linux 2023 with KVM VM driver.**

### PASS evidence

```
live_service: complete lifecycle (create->wait_ready->exec->delete->wait_deleted) SUCCEEDED
test result: ok. 1 passed; 0 failed; finished in 3.09s

VM guest uname output:
  Linux sbx-abbfbe0ead1c452 6.12.76 #1 SMP PREEMPT_DYNAMIC
  Tue Mar 10 13:28:56 CET 2026 x86_64 x86_64 x86_64 GNU/Linux
  (exit code 0)

Teardown: exit 0, 0 processes, 0 ports, disk 19G/50G used.
```

### Blocker chain (fully resolved)

1. **ENOSPC on tmpfs (FIXED in Phase 3)** — set `OPENSHELL_VM_DRIVER_STATE_DIR` to
   persistent EBS. Image layers pull and extract in ~98s on EBS.

2. **Missing embedded supervisor (FIXED in Phase 4)** — `openshell-driver-vm` rebuilt with
   `OPENSHELL_VM_RUNTIME_COMPRESSED_DIR` pointing to pre-built runtime artifacts.
   - Download: `vm-runtime-linux-x86_64.tar.zst` via `curl -L` (no `gh` CLI needed;
     release is publicly accessible without auth).
   - Build supervisor: `build-supervisor-bundle.sh` run directly (no `mise` needed);
     falls back to `cargo build` when `cargo-zigbuild` absent. 7 minutes.
   - Rebuild driver: binary grew 18M → 38M (supervisor + runtime embedded). 3m14s.

3. **Upperdir chmod (NOT required at this pin)** — the upperdir fix from memory
   `upperdir-fix-release-evidence-audit` was NOT needed at pin f1690849 on this host.
   VM console log shows `[0.006s] setting up writable overlay root` succeeded without
   error. The prior memory's fix was for a different worktree (pin 596d729e).

4. **Test deadline vs first-run image pull (not a bug, working as designed)** — The
   image cache is populated on first sandbox creation. With cold cache, image pull +
   ext4 conversion takes ~2:41; the 120s `wait_ready` deadline expires. On warm cache,
   all subsequent creates complete in seconds. Production deployments should warm the
   cache before running time-sensitive test suites.

### What a Linux host needs (empirical, complete)

| Requirement | Status | Detail |
|-------------|--------|--------|
| Rust 1.95.0 | Must install | `curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.95.0` |
| protobuf-compiler, openssl-devel, clang-devel | Must install | `dnf install -y protobuf-compiler openssl-devel clang clang-devel` |
| z3-devel + z3.h symlink | Must install | `dnf install -y z3-devel z3-libs && ln -sf /usr/include/z3/z3.h /usr/include/z3.h` |
| LIBCLANG_PATH=/usr/lib64 | Must set | For bindgen during OpenShell build |
| Docker (rootful) | Must install/activate | Podman absent from AL2023; Docker 25.0.16 sufficient |
| Persistent state dir for VM driver | Critical | `OPENSHELL_VM_DRIVER_STATE_DIR=/home/ec2-user/.local/state/openshell-vm-driver` (not tmpfs) |
| loginctl enable-linger + user@1000 | Required | For systemd user session |
| /dev/kvm | Required for VM driver | Present on c7i.large; world-writable |
| Swap (≥8 GB) | Needed for Rust builds | `dd if=/dev/zero of=/swapfile bs=1M count=8192 && mkswap /swapfile && swapon` |
| vm-runtime-compressed/ dir | Must prepare | Download vm-runtime tarball via curl + zstd-compress; 18s |
| openshell-sandbox supervisor | Must build | Run `build-supervisor-bundle.sh` (7m) then rebuild driver with OPENSHELL_VM_RUNTIME_COMPRESSED_DIR |
| OPENSHELL_BIN_OVERRIDE | Must set for provision/uninstall | Points to source-built binary directory |
| Disk (≥20 GB) | Required | Build artifacts ~10 GB; image cache (rootfs.ext4) ~3 GB; swap 8 GB |
| Time budget for first sandbox create | Expected | First creation ~3 min (cold cache); subsequent creates = seconds |

### Documentation gaps identified

1. **VM driver build not documented for self-hosting.** The `vm-setup.sh` + `build-supervisor-bundle.sh`
   step is undocumented in openbox-sandbox README and local-bootstrap.sh. The standard
   `cargo build -p openshell-driver-vm` silently produces a non-functional binary (passes
   the pin marker check but cannot boot microVMs).

2. **`mise` is not required.** The scripts in `tasks/scripts/vm/` can be run directly;
   `mise` is the task runner wrapper, not a dependency.

3. **`gh` CLI is not required.** The vm-runtime tarball is publicly downloadable via `curl`;
   installing `gh` (not in AL2023 repos) is unnecessary for this step.

4. **First sandbox creation latency not documented.** The test's 120s `wait_ready` timeout
   is insufficient for a first run on a cold state dir. Production setups should pre-warm
   the image cache (run one create/delete cycle) before time-sensitive tests.

---

## Part 9 — Hosted-bin (toolchain-free) flow — PREPARED AND TESTED (PASS)

**Date:** 2026-08-06. **Goal:** the real workflow must be `curl → verify (sha256 + SBOM/syft) → run obs setup/provision/verify/uninstall` — no building, no toolchain, no manual OpenShell install. `obs` is the only interface; setup pre-warms the cold cache; uninstall cleans up.

### Repo changes (this journey, all in packaging/launcher/)

| File | Change |
|------|--------|
| `scripts/fetch-openshell-deps.sh` | NEW `OPENBOX_OPENSHELL_BUNDLE_URL` mode: fetch `openbox-sandbox-bundle-<triple>.tar.gz` + `SHA256SUMS` from a hosted release server, verify sha256 (sha256sum or shasum), extract into the bundle dir (bin/ + libexec/ layout). `obs setup` inherits the env → setup is the only acquisition path. |
| `scripts/provision-local-sandbox.sh` | NEW warm-cache step (section 7.5): after agent.env, `openshell sandbox create --name w<epoch> -- /bin/true` → poll `sandbox get` for ready (up to 10 min, 120×5s — cold boot on small hosts takes ~5-6 min) → `sandbox delete`. `OPENBOX_WARM_CACHE=0` skips. VM driver state dir default changed from `/tmp/...` (tmpfs ENOSPC footgun) to `$HOME/.local/state/openshell-vm-driver-...`. |
| `src/dogfood.rs` | `obs verify` honors `OPENBOX_VERIFY_BIN=<prebuilt harness>`: runs the compiled `live_service_create_exec_delete` test binary with agent.env instead of invoking cargo. |
| `README.md` | Hosted-bin flow documented; uninstall must be called with the same `OPENBOX_SANDBOX_BIN`/`OPENSHELL_BUNDLE_DIR` env as provision (wizard teardown refuses to signal a service whose command line doesn't match the resolved binary path). |

`mise` and `gh` CLI: confirmed NOT required (no real references in our scripts; the upstream error text mentions mise, the OpenShell `tasks/scripts/vm/*` scripts run directly).

### Release assembly (on the host, /home/ec2-user/release/)

| Artifact | Size | Notes |
|----------|------|-------|
| obs / openbox-sandbox-linux-amd64 | 641 KB | rebuilt launcher (new code) |
| openbox-sandbox | 8.0 MB | root service binary |
| openbox-sandbox-verify | 9.4 MB | prebuilt lib test harness (cargo test --release --lib --no-run → renamed) |
| openbox-sandbox-bundle-x86_64-unknown-linux-gnu.tar.gz | 57.5 MB | bin/openshell + bin/openshell-gateway + libexec/openshell-driver-vm (pinned 0.0.88-dev.11+gf1690849, supervisor-embedded 38 MB driver) |
| SHA256SUMS | 1.9 KB | sha256sum format, covers every file incl. SBOMs |
| *.spdx.json + *.cyclonedx.json × 6 | ~1 KB each | Syft v1.20.0 scans (Rust static binaries → no package graph, small SBOMs — expected) |

Served: `python3 -m http.server 8080 --bind 127.0.0.1 --directory /home/ec2-user/release` (still running; future: GitHub releases).

Copied into the repo: `openbox-sandbox-bundle/` now holds the full Linux release (182 MB, gitignored, checksums re-verified on the Mac).

### Clean-user test (user `obsclient` — no cargo, no sources, no toolchain)

| Step | Result | Evidence |
|------|--------|----------|
| curl artifacts from http://127.0.0.1:8080 | PASS | obs/openbox-sandbox/openbox-sandbox-verify/tarball/SHA256SUMS downloaded |
| sha256sum -c SHA256SUMS | PASS | all files OK |
| syft scan (client-side) | PASS | scans run clean on host + Mac (no package graph in static Rust bins) |
| `obs setup` with OPENBOX_OPENSHELL_BUNDLE_URL=... | PASS | fetched + sha256-verified hosted bundle into ./openbox-sandbox-bundle; pin verify OK (marker gf1690849) |
| `obs provision` (OPENSHELL_BUNDLE_DIR=...bundle, OPENBOX_SANDBOX_BIN=~/bin/openbox-sandbox) | PASS (exit 0) | gateway 17670 + driver (state under ~/.local/state) + service 17443 + agent.env; **warm step ran**: image pull + ext4 prep completed (~3.5 GB cache built), sandbox didn't reach ready within poll on this slow-booting host (warned, not fatal) |
| `obs verify` with OPENBOX_VERIFY_BIN | **PASS** | `live_service_create_exec_delete ... ok` — 69 passed / 0 failed in **2.97 s** (warm cache; guest kernel 6.12.76, uname exit 0) |
| `obs uninstall` (same env as provision) | PASS (exit 0) | "uninstall complete — host equivalent to before provision"; 0 processes left |

### Mac-side client test (the "real workflow" from a different machine)

SSM port-forward (18080 → host 8080) → curl all artifacts → `shasum -a 256 -c SHA256SUMS` fully OK → syft v1.20.0 scans run clean. The client never touches cargo/build tooling.

### Findings / gotchas

1. **Env var names differ by prefix in the wizard**: `OPENSHELL_BUNDLE_DIR` (bundle) vs `OPENBOX_SANDBOX_BIN` (service bin). Using `OPENBOX_BUNDLE_DIR` silently falls back to the repo-relative default.
2. **Uninstall needs the same env as provision** (safety check compares running service cmdline vs resolved binary path) — now documented in README.
3. **Warm CLI syntax** (empirically corrected during test): `sandbox create --name <short-name> -- /bin/true`, `sandbox get <name>` (status output), `sandbox delete <name>`. Sandbox names are ≤19 chars (MAX_ROUTABLE_NAME_LEN).
4. **Warm poll window**: 300 s was too short (cold image prep + boot ≈ 5-6 min on 2 vCPU); bumped to 600 s.
5. **Cache warm works**: after the warm step, verify passed in 2.97 s vs 120 s deadline fail on cold cache.
6. **State dir default**: wizard now defaults the VM driver state to persistent disk (`~/.local/state/...`) — the tmpfs ENOSPC failure mode (Part 7) is fixed in the default path, not just via env override.

---

## Part 10 — Single-bin standalone obs + GitHub Release prep (PASS)

**Date:** 2026-08-06. **Goal:** obs must be ONE artifact — no source tree, no sibling scripts on the client; release published to the (private, later public) GitHub repo via `gh`; client flow = curl → verify → obs setup/provision/verify/uninstall, nothing else.

### Repo changes

| File | Change |
|------|--------|
| `packaging/launcher/src/scripts.rs` (NEW) | Embeds `fetch-openshell-deps.sh` + `provision-local-sandbox.sh` via `include_str!`. Resolution chain: OPENBOX_SOURCE_ROOT → repo walk from cwd → scripts/ next to the executable → **materialized embedded copy** at `~/.local/share/openbox-sandbox/scripts/` (mode 0700, byte-diff resync, idempotent). Unit test added (8/8 pass). |
| `src/setup.rs`, `src/dogfood.rs`, `src/main.rs` | Wire `scripts::resolve` for fetch + wizard (provision/uninstall/status). |
| `scripts/provision-local-sandbox.sh` | Standalone-safe: `OPENBOX_PROJECT_ROOT` override; `OPENBOX_POLICY_FILE` accepts absolute paths (policy ships as a release asset — the client has no repo to source it from). |
| `src/pin.rs` | **Bug found by the standalone test:** `version_satisfies` was exact-match `== 0.0.85`, rejecting the pinned source build (`0.0.88-dev.11+gf1690849`) in `obs setup`'s pin verify (provision's marker check accepted it). Now accepts the exact release OR the root-protocol marker `gf1690849` (const `ROOT_PROTOCOL_MARKER`). |
| `scripts/publish-release.sh` (NEW) | `gh`-based publish: verify SHA256SUMS → replace floating tag (default `hosted-bin`) → `gh release create` with all assets → list published assets. As-if-public: stable download URLs `https://github.com/OpenBox-AI/openbox-sandbox/releases/download/<tag>/<asset>`. |
| `packaging/launcher/Cargo.toml` | `[[bin]] name = "obs"` (working tree; git HEAD still has the `osb` typo — needs a commit). |

### Release layout (20 files + bundle binaries, 182 MB in repo `openbox-sandbox-bundle/`)

obs · openbox-sandbox · openbox-sandbox-verify (9.4 MB lib-test harness) · openbox-sandbox-bundle-x86_64-unknown-linux-gnu.tar.gz (57 MB, bin/ + libexec/) · **policy-deny-network-dev.yaml (NEW — standalone clients need it)** · SHA256SUMS (clean, no `./` prefixes — first regeneration attempt with `find -printf %P` produced an EMPTY manifest because `%P` has no newline; fixed with a `while read` loop) · 12 Syft v1.20.0 SBOMs (spdx + cyclonedx × 6 binaries).

### gh CLI (dev-only, on the build host)

Not in AL2023 repos (`dnf install gh` → "No match"); installed **gh 2.74.0** from the official RPM (`github.com/cli/cli/releases/download/v2.74.0/gh_2.74.0_linux_amd64.rpm`).
**User auth (interactive, do once):** `gh auth login` → GitHub.com → HTTPS → browser flow.

### Standalone retest (user `obsclient`, NO source tree, NO OPENBOX_SOURCE_ROOT)

| Step | Result | Evidence |
|------|--------|----------|
| curl assets + checksums | PASS | binaries vs manifest diff = match; `sha256sum -c` all OK |
| `obs setup --skip-service` (OPENBOX_OPENSHELL_BUNDLE_URL) | **PASS (exit 0)** | **embedded fetch script** materialized (`~/.local/share/openbox-sandbox/scripts/fetch-openshell-deps.sh`), bundle downloaded + sha256 verified, pin verify passed after the pin.rs fix |
| `obs provision` (OPENSHELL_BUNDLE_DIR + OPENBOX_SANDBOX_BIN + OPENBOX_POLICY_FILE, all absolute) | **PASS (exit 0)** | gateway + service + agent.env; **warm step: `cache warmed: w1785992156`** (the 600 s poll window fixed the Part-9 timeout) |
| `obs verify` (OPENBOX_VERIFY_BIN) | **PASS** | 69 passed / 0 failed in **3.02 s**, `live_service_create_exec_delete ... ok` |
| `obs uninstall` (same env) | **PASS (exit 0)** | "host equivalent to before provision"; **0 processes** (only empty `~/.config/openshell`, `~/.local/state/openshell` CLI-metadata dirs remain — minor, gateway CLI artifact) |

### Findings

1. The standalone test caught a real pin-verify bug (setup rejected the pinned build) — fixed in pin.rs.
2. Warm step now completes (600 s poll); first provision cold ≈ 8-10 min, verify then 3 s.
3. `find -printf %P` without `\n` silently empties a manifest via `$(...)` — use `while read` loops for checksum generation.
4. obsclient's client-side flow needs NO toolchain, NO scripts, NO repo — one binary + the bundle + policy + harness.

### Part 10 addendum — no new scripts: publish folded into obs

- `scripts/publish-release.sh` deleted (both copies). The publish flow is now
  the native `obs publish <release-dir> [tag]` command (`src/publish.rs`):
  preflight (gh present + authenticated) → `sha256sum -c` → replace floating
  tag (`hosted-bin` default) → `gh release create` with all assets → asset
  list. Shells out to `gh`/`sha256sum` only (launcher stays dependency-free).
- `gh` authenticated on the build host as `salamisandwich77` (device flow,
  scopes gist/read:org/repo); private repo `OpenBox-AI/openbox-sandbox` visible.
- Release dir regenerated (obs with publish), manifest 20 entries verified;
  repo `openbox-sandbox-bundle/` re-synced + verified.
- Remaining shell files are dev-side only: generate-sbom.sh, verify-release.sh,
  scan-credentials.sh (publish/sbom tooling); the two runtime scripts are
  embedded in obs and never shipped.

### Part 11 — Lean (no dup) + first real GitHub Release (PUBLISHED)

**Lean changes (all compiled, 8/8 tests):**
- **Removed the `obs setup` service-unit step entirely** (`src/service.rs` deleted, 219 lines): it duplicated provision's per-user gateway management and the repo's own advisory called it not-release-ready. `obs setup` is now exactly one job: deps check → fetch bundle → verify pin. Flags `--skip-service`/`--no-start` removed (usage, parser, README).
- **`obs provision` auto-fetches the bundle**: when `OPENBOX_OPENSHELL_BUNDLE_URL` is set and the target bundle is missing, provision runs the embedded fetch logic (OUT = OPENSHELL_BUNDLE_DIR or ./openbox-sandbox-bundle) and pins OPENSHELL_BUNDLE_DIR to the fetched location. A fresh machine needs only `obs provision`.
- **`obs publish <dir> [tag]` fixed**: `gh release create` infers the repo from local git — the release dir isn't a git repo, so all gh calls now take explicit `--repo OpenBox-AI/openbox-sandbox` (as-if-public design).

**First real publish (private repo — safe to exercise):**
- `obs publish /home/ec2-user/release hosted-bin` → **18 assets** (obs, openbox-sandbox, openbox-sandbox-verify, 57 MB bundle tarball, policy, SHA256SUMS, 12 Syft SBOMs) at `https://github.com/OpenBox-AI/openbox-sandbox/releases/download/hosted-bin/`.
- Republish exercised the replace path: `replacing existing release 'hosted-bin'` → 18 assets again. Delete + recreate = no git-history trail (release assets are outside git history).

### Part 12 — REAL flow from the private GitHub release (FULL PASS)

**The complete workflow, exactly as a consumer would run it:**

| Step | Result |
|------|--------|
| `gh release download hosted-bin` (18 assets) | PASS |
| checksum verify (manifest vs downloaded binaries) | PASS |
| `obs provision` DIRECTLY (no setup!) with `OPENBOX_OPENSHELL_BUNDLE_URL=<github release base>` + `GH_TOKEN` + `OPENBOX_SANDBOX_BIN` + `OPENBOX_POLICY_FILE` | **PASS (exit 0)** — auto-fetched the bundle **from the private GitHub release**, sha256 verified, markers verified, gateway + service up, **`cache warmed: w1785995673`** |
| `obs verify` (harness) | **PASS** — 69/69 in **2.51 s** |
| `obs uninstall` (same env) | **PASS** — clean, 0 processes |

**Bugs found + fixed during this test round:**
1. GitHub now 404s direct `releases/download/<tag>/<asset>` URLs **even with a valid token** (0 redirects) — the fetch now goes through the API octet-stream endpoint (`Accept: application/octet-stream`, follows the pre-signed redirect) when the base is github.com, with `GH_TOKEN` bearer auth for private repos; plain-URL fallback retained for public/local bases.
2. Bash `set -u` gotcha: `local a=... b=$a` in one statement → "unbound variable" — locals declared first, assigned after.
3. URL parse bug: `owner/repo/releases/download/tag` needs the `releases/download/` segment stripped before `tag` — fixed + locally verified before rebuild this time.
4. Client-binary staleness: obs re-downloaded right after a republish can race GitHub's asset CDN — resolved by copying from the release dir for the test (the publish itself was verified correct).

**Housekeeping:** local HTTP release server stopped (GitHub release is now the channel); `obsclient` user + its downloads left in place for the next test round; repo `openbox-sandbox-bundle/` re-synced + checksum-verified.

### Part 13 — CI becomes the builder; Mac + AWS are test clients

**Decision (user):** nothing is built manually anymore. GitHub Actions builds the
entire pinned release (linux x86_64 + aarch64 on ARM runners + darwin arm64 on
macOS runners): root service, verify harness, obs launcher, source-pinned
OpenShell with the embedded supervisor (via OpenShell's `tasks/scripts/vm/`
directly — no mise, no gh), syft SBOMs, **keyless cosign signing** (OIDC
`--bundle` format), and the floating `hosted-bin` tag replace+publish.

- `.github/workflows/hosted-bin.yml` — manual dispatch or push to main
  (launcher/src/lockfile/workflow paths). The manual darwin build on the Mac
  was interrupted and abandoned; the interrupted state lives only in /tmp.
- Mac and the EC2 `openshell` VM are now pure consumers: download from the
  CI-published release, verify, `obs provision/verify/uninstall`.
- History: 13 atomic commits pushed to main (force-pushed once after a
  fixup-squash; `workflow` scope added to the dev token for workflow-file
  pushes; the YAML validation failure (`--notes` multiline string) was found
  with actionlint and fixed).

### Part 14 — LOCKED RELEASED OpenShell 0.0.88; source build removed (FINAL)

**Decision (user):** never compile OpenShell. Lock a released version; CI
downloads NVIDIA's prebuilt tarballs (sha256-verified against their published
checksums); the released VM driver already ships with the supervisor + runtime
embedded (39.7 MB vs 18 MB unembedded — proven by the size gate).

**Changes (commit `launcher: lock released OpenShell 0.0.88 and drop the
source build`):**
- `pin.rs`: version gate accepts the locked release `0.0.88` (or the source
  marker) — `LOCKED_RELEASE_VERSION` const.
- wizard `require_source_marker`: accepts `0.0.88` or the marker;
  `OPENSHELL_LOCKED_VERSION` env-overridable.
- `install.sh` + `docs/installation.md`: same relaxed gate; the wire contract
  is proven by the live verify test instead of the marker.
- `hosted-bin.yml`: the OpenShell clone/build/supervisor/vm-runtime steps are
  replaced by one download step (`fetch-openshell-deps.sh` with
  `OPENBOX_OPENSHELL_VERSION=0.0.88` + `TARGET_TRIPLE`); driver size gate
  (>30 MB) retained; cache now covers only our crates.
- fetch script: portable `sha256sum` fallback (containers have no `shasum`).

**Result (run 31114215514): all 4 jobs GREEN in ~10 min** (darwin + both
linux + publish, 41 assets). AWS consumer flow from the CI release:
download → checksums → `obs provision` (auto-fetch; gate logs
`verified (f1690849 | 0.0.88)`) → warm → **verify: 69/69 in 2.50 s**
(the released 0.0.88 wire contract is compatible — the empirical proof the
gate always wanted) → uninstall clean.

**CI runs are now fast:** only our three crates compile (cached); the
OpenShell compile is gone entirely. The version is locked; nothing about
OpenShell changes unless the lock is bumped deliberately.

### Part 15 — AUDIT (2026-08-06)

**Repository**
- Working tree clean; local HEAD == remote main (9da63d4).
- 36 commits, single author (salamisandwich77), no secrets in tracked files
  (only gitignored .dogfood dev keys, untracked).

**Release v0.1.0**
- 41 assets, formal name, not draft/prerelease, published 16:47Z.
- Integrity: sha256 verified (only bundle-subdir entries live inside the
  verified tarball).
- Provenance: 9 binaries x (SPDX + CycloneDX + keyless cosign bundle) =
  COMPLETE; cosign verify-blob -> "Verified OK" (OIDC identity = workflow).
- Binaries: OpenShell 0.0.88 on all three; driver 39.4 MB (supervisor
  embedded, gate >30 MB); obs embedded scripts present; glibc-clean on AL2023.

**Credentials/host**
- gh token (workflow scope) 0600; cosign key 0600; cosign password 0600.
- 0 leftover runtime processes; build trees + swap expected (dev host).

**Findings**
- HIGH: injected test SSH key still in ec2-user authorized_keys; private key
  at /tmp/obs-transfer-key on the Mac -> REMOVED in this audit.
- MEDIUM: test user obsclient still present -> REMOVED.
- MEDIUM: /tmp litter (210 host / 61 Mac test files) -> CLEANED.
- MEDIUM (open): CI supply chain pins: dtolnay/rust-toolchain@master,
  actions/*@v4 major tags, amazonlinux:2023 container (floating tag) -> pin
  to SHAs/digests for hardened posture.
- LOW (open): dev-host cosign keypair is redundant (CI uses keyless OIDC);
  consider removing it.
- LOW (open): hosted-bin workflow auto-runs on push; consider tag/manual
  gating for production publishes.
- NOTE: legacy build.yml launcher-release track still publishes per-push;
  separate from hosted-bin; confirm intent.
- NOTE: cargo-deny + trivy gates green on recent runs.

### Part 16 — Hardening + legacy removal (user-directed)

- hosted-bin.yml: workflow_dispatch ONLY (manual publish); all actions pinned
  to commit SHAs (checkout/cache/upload/download-artifact, rust-toolchain,
  trivy-action); containers digest-pinned (amazonlinux:2023@sha256 per arch);
  new `scan` job (Trivy fs HIGH,CRITICAL + credential scan) folded in.
- build.yml (legacy per-push launcher release track) DELETED — hosted-bin is
  the single release pipeline.
- Dev-host cosign keypair + password + cosign binary removed (CI signs
  keyless via OIDC; the pair was redundant).
- Audit remediation from Part 15 already applied (SSH key, obsclient, /tmp).

### Part 17 — Hardened pipeline validated green (ALL jobs)

- cargo-deny now gates the ROOT crate (was launcher-only): licenses + advisories
  + sources — green on push. GHSA-gfxp-f68g-8x78 (libyml <=0.0.5, via the
  locked openshell-policy/serde_yml chain) has NO patched release; allowed
  with justification in deny.toml + .trivyignore (operator-controlled policy
  YAML only; revisit on OpenShell lock bump).
- hosted-bin run 31137516994: security scan + 3 builds + publish ALL SUCCESS —
  the fully pinned pipeline (SHA-pinned actions, digest-pinned containers,
  manual dispatch, formal name + v0.1.0 tag) is validated end-to-end in CI.
- v0.1.0 re-published by CI with the formal notes.

### Part 18 — Consumer re-validation vs v0.1.0 + darwin test (BOTH PASS)

**1. AWS consumer flow vs the final release (v0.1.0):** download -> checksums ->
`obs provision` (auto-fetch, gates verified 0.0.88) -> warm -> `obs verify`
69/69 in 2.54s -> uninstall clean, 0 processes. One transient ghcr.io layer
download error on the first attempt (network, retried fine).

**2. Mac darwin consumer test (the last untested claim):** darwin arm64 assets
from v0.1.0 -> checksums (Mach-O arm64) -> `obs provision` on macOS: wizard
codesign path OK, gateway + service up (port 17671 — the user's Homebrew
gateway occupies 17670; `OPENSHELL_SERVER_PORT` override works) -> `obs verify`
**69/69 in 1.79s** -> uninstall clean. Pre-existing brew gateway untouched.

**Bugs found + fixed:**
- auto-fetch second-run bug: when the bundle already exists, auto-fetch
  skipped WITHOUT pinning OPENSHELL_BUNDLE_DIR, so the wizard fell back to the
  project-root default and died. Fixed in dogfood.rs (commit 429a847); released
  obs predates the fix, so explicit OPENSHELL_BUNDLE_DIR remains the documented
  primary flow.
- The darwin warm step warns "did not reach ready in time" on the Mac (cold
  Hypervisor VM boot vs the 10-min poll); the image cache is still warmed
  (verify ran in 1.79s), so the warning is cosmetic on darwin. The ready-grep
  may not match the darwin CLI status format.

### Part 19 — Systematic line-by-line audit (2,662 lines) + fix-all pass

**Fixed (committed 453569f + fadbd6f):**
- HIGH: `obs publish`/CI deleted the old release before uploading -> atomic
  replace via DRAFT staging tag + retag + publish; a failed upload leaves the
  current release untouched and staging can never flash as "latest".
- publish.rs metadata formalized (title OpenBox Sandbox <version>; notes for
  the locked-0.0.88 era) — previously stale "hosted bin"/"source pin" text.
- Wizard portability: hardcoded shasum -> sha256_hex() (sha256sum|shasum);
  hardcoded lsof in the service-ready loop -> port_listening() with /dev/tcp
  fallback; stale cargo error message -> OPENBOX_SANDBOX_BIN.
- Warm step lifecycle-aware: a reaped warm sandbox (fast hosts) counts as
  success; Deleting phase accepted; only stuck Provisioning/Error is a miss.
  (Root cause of the darwin warning: sandbox already ran /bin/true and was
  reaped before the poll's first get.)
- Release now ships BOTH policies (strict + dev): bundle.rs requires both
  names, exposed by --verify-runtime on the released bundle.
- obs verify hints at OPENBOX_VERIFY_BIN when cargo is absent.
- Stale docs aligned (setup removed, version gate wording).

**Verified clean:** teardown ownership/fail-closed logic, agent.env parsing +
service-binary hash gate, scripts.rs materialization, pin gate, fetch-script
URL/API/latest handling, main.rs parsing. All 8 launcher tests green.

### Part 20 — Fix-all pass completion (FULLY GREEN run 31145623942)

The remaining audit items, all closed:
- Warm step: lifecycle-aware (a reaped warm sandbox = success; Deleting
  accepted; only stuck Provisioning/Error is a miss). Root cause of the
  darwin warning: the sandbox ran /bin/true and was reaped before the poll.
- obs status + --verify-runtime exercised: status reports gracefully;
  --verify-runtime exposed that the release lacked the STRICT policy ->
  release now ships BOTH policies (42 assets).
- Atomic publish validated in CI: draft staging -> resolve id via the
  releases LIST endpoint (tags lookup hides drafts — the 404) -> delete old
  release only after the new upload (the 422 — tag still held by the old
  release) -> retag -> publish. The draft-staging race is closed (drafts are
  never "latest").
- A failed run's partial state left duplicate-tag drafts; cleaned manually
  and the workflow now self-cleans stale drafts before publishing.
- obs verify hints at OPENBOX_VERIFY_BIN when cargo is absent.
- Final state: v0.1.0 published, 42 assets, both policies, sole release;
  all 5 pipeline jobs green (scan incl. MEDIUM gate, 3 builds, publish).

### Part 21 — Small-things pass complete (push gate green)

- obs status reads gateway/service ports from wizard metadata (port overrides
  now reported correctly).
- deny.yml gains a `launcher-tests` job (the repo's own test scripts run on
  every push — the wizard regression gate). gcc installed for the C fixture;
  bash -x tracing kept for instant diagnosis.
- cargo-deny made version-portable: `--config` dropped (auto-discovery) and
  the legacy `[graph]` section removed — both CLI generations now pass.
- CI run 31148379785: cargo deny -> success, launcher tests -> success.
- Host lean-out: swap, Docker, Rust toolchain removed (3.8 GB used). Mac
  .dogfood removed. Release deferred per user (no dispatch since the last
  green publish; the pipeline remains dispatch-only).

### Part 22 — Darwin warm warning: FIXED + validated on macOS

The lifecycle-aware warm fix (reaped warm sandbox = success; Deleting
accepted) was re-validated on the Mac with the current-code obs:
- provision on port 17671 (brew gateway holds 17670): gates verified,
  gateway + service up, warm -> **"[ok] cache warmed: w1786082895"** (the old
  "did not reach ready in time" warning is gone).
- verify: 69/69 in 3.84s; uninstall clean, port free.
The same code is staged for the next release bump (0.1.1).

### Part 23 — Current-code testing round (4 uncovered paths)

All tests used CI-artifact/current-code binaries (the release predates several
fixes; release binaries are NOT representative of current behavior):

1. **Auto-fetch second-run fix — VALIDATED (host, linux):** run 1 with only
   OPENBOX_OPENSHELL_BUNDLE_URL fetched once -> bundle ready -> warm ->
   complete. Run 2 (same env, bundle present, cwd correct): **0 fetch
   attempts**, gates verified, warm, complete. The pin-on-skip fix works.
   (First run-2 attempt failed only because the test script forgot `cd` — the
   auto-fetch default is cwd-relative, correctly.)
2. **obs status port reporting — VALIDATED (macOS, current obs):** NO_START=1
   provision on 17777/17778, then `obs status` reports
   "not listening on 17777/17778" (metadata-read) instead of the defaults.
3. **obs publish (Rust) draft-staging flow — VALIDATED (host):** throwaway
   tag v0.1.2-test: staging upload (7 assets) -> retag -> published
   (draft=false) -> deleted. The atomic flow works outside CI's bash version.
4. **NO_START=1 — VALIDATED:** config written, no processes, warm skipped,
   uninstall clean.

Cleanup: obsclient removed, test artifacts gone, throwaway release deleted,
tunnel stopped. Note: CI artifacts from run 31145623942 predate the status
fix — tests must use current-code binaries (local build or a fresh dispatch).

## Part 11 — Canonical native-integration Temporal shape (PASS)

The temporal CONSTRAIN proof was reshaped to the released SDK's canonical
integration pattern (measured against `OpenBox-AI/openbox-temporal-sdk-python`
v1.4.0 and `poc-temporal-agent`): a standard Temporal `Worker` composed with
`OpenBoxPlugin` instead of the `create_openbox_worker` wrapper route.

```python
worker = Worker(
    client, task_queue=...,
    workflows=[GovernedBatchPocWorkflow], activities=[],
    plugins=[OpenBoxPlugin(openbox_url=..., openbox_api_key=...,
                           sandbox=TemporalSandboxConfig(...))],
)
```

- The workflow is plain Temporal (`workflow.execute_activity`); the governed
  command is evaluated with Core at activity time inside the plugin's
  interceptor chain, and the verdict branches execution: CONSTRAIN runs in a
  sandbox under the verdict-named policy (registry-resolved by id, pinned by
  sha), ALLOW runs on the host under a controlled minimal environment.
- The application agent still evaluates with Core before starting the workflow
  (governance precedes start); evidence records both the pre-workflow decision
  and the activity-time evaluation.
- The governed span joins the workflow's W3C trace via the task-header
  `_tracer-data` payload (the SDK's governed branch decodes it with the default
  payload converter); the run-time tracing interceptor is a passive component.
- Matrix green: behavioral CONSTRAIN sandbox, ALLOW host, gpt-4o CONSTRAIN
  sandbox, external Temporal dev server sandbox; POC 204 + SDK 1086 +
  dispatcher 49 tests passing.

## Part 12 — Released-surface alignment (PASS)

The local SDK fork was aligned to the released v1.4.0 surface and behavior:

- The five released modules (core_adapter, governance_state, multi_agent, patch,
  patch_coordinator) are restored and WIRED, not just importable: the workflow
  interceptor is the released version (patch markers + coordinator +
  Continue-As-New), BLOCK-with-patch raises a restart request, the plugin and
  wrapper carry `max_patch_restarts`, and the base SDK gained the strict patch
  envelope (Patch/PatchDirective/handle_patch + JS-safe new_input validation).
  The upstream patch/multi-agent/replay test suites are ported and green —
  the CAN replay test proves a BLOCK-with-patch at workflow start restarts the
  run with the patched input.
- Workflow-level governance events (WorkflowStarted/Completed) now flow
  end-to-end (no skip_workflow_types) and the runner replays with the SDK's
  GovernanceInterceptor so the versioned markers replay cleanly.
- Single-client convergence: the governed command is evaluated at activity time
  by the plugin's governance client (one shared Core runtime transport); the
  dispatcher executes the verdict without a second client.
- Matrix green: behavioral sandbox, ALLOW host, gpt-4o, external Temporal.
  Suites: temporal SDK 1186, base 454, POC 204, dispatcher 49.
