# OpenBox Sandbox

The default provider is `native`: an OpenBox-owned native OS sandbox that invokes
argv directly under macOS Seatbelt (`sandbox-exec`) or Linux bubblewrap. It is
conceptually similar to Anthropic's sandbox-runtime, but implemented natively
without adopting Anthropic's Node/npm CLI.
Profiles are compiled only during provisioning, pinned by SHA-256 in the
service config, and verified before every execution. OpenShell remains an
explicit alternative with `obs provision --provider openshell`.

OpenBox Sandbox is the standalone, production-intent, framework-neutral sandbox runtime for running client-owned commands through OpenShell.

## Native provider network and violation evidence

For a pinned policy with network endpoints, the native runtime starts an
execution-scoped HTTP proxy on an ephemeral loopback port and clears the
command environment before setting `HTTP_PROXY`, `HTTPS_PROXY`, and equivalent
lowercase variables. The proxy supports HTTPS `CONNECT` and plain HTTP proxy
requests, resolves DNS outside the sandbox, and compares the normalized
requested `host:port` with endpoints extracted from the compiled, SHA-256-pinned
policy. Refused hosts and IP-literal bypass targets receive HTTP 403. On macOS,
the Seatbelt profile permits only that exact `localhost:<port>`; direct sockets
and a stopped proxy have no fallback egress path.

Terminal results retain typed `sandbox_evidence`: each observed proxy request
records its allowed/denied decision, host, and port. On macOS, the runtime also
queries the unified log store for the exact sandbox process under
`com.apple.sandbox.reporting:violation`, reports the count and stable denial
categories, and mirrors each record to the service log. Empirical testing found
that `log stream` does not deliver kernel-originated violation records to a
redirected pipe on current macOS, while `log show` exposes them immediately;
the runtime therefore uses the latter after process observation. Linux
bubblewrap has no equivalent unprivileged deny-event stream, so violation
evidence is absent there.

Linux bubblewrap cannot filter a shared network namespace by destination
address. The Linux native path routes proxy-aware HTTP(S) clients through the
same policy proxy, but it cannot make the macOS direct-socket guarantee without
an additional kernel network control. Deny-network policies remain fully
isolated with a private network namespace; use the deny profile (or OpenShell)
where bypass-resistant Linux egress enforcement is required.

## Platform

The host that runs OpenShell and this service must run on a Linux kernel, and Linux is the preferred and supported platform for production. Isolation is enforced by Linux kernel features — Landlock, namespaces, cgroups, and seccomp — that have no macOS or Windows equivalent, and the runtime installs as a rootless-Podman, systemd-managed deployment. The sandboxes it runs are Podman containers created on that Linux host. macOS and Windows cannot host it natively; use a Linux VM to provide the kernel, which is also the recommended path for local development on those hosts.

## Repository and binary boundary

Integration PoC/showcase material belongs exclusively to the separate `OpenBox-AI/openbox-sandbox-poc` repository and is not a dependency.

This repository has three deliberately separate modules:

- root `openbox-sandbox`: the production-intent mTLS sandbox service;
- `packaging/launcher` / `obs`: a dependency-free operator/developer launcher;
- OpenShell: the external gateway/driver runtime, pinned but not maintained here.

The existing cross-platform download names `openbox-sandbox-<platform>` contain
the `obs` launcher for compatibility. They are not the Linux service installer
payload. See [`packaging/launcher/README.md`](packaging/launcher/README.md).

## Linux sandbox-service install

From the repository or an OpenBox release bundle, run:

```sh
./install.sh
```

That is the complete installation command. Do **not** build OpenBox or install OpenShell first.

The installer chooses the correct mode automatically:

| What is beside `install.sh` | What happens |
|---|---|
| A verified `release/` directory | Installs the prebuilt release without compiling anything. |
| No `release/` directory | Builds and installs a clearly labelled local-development deployment from the locked sources. |

The local-development path currently supports Debian-family Linux. It may ask permission to install missing packages, then asks for `sudo` only when system files and services must be changed. It also provisions the pinned OpenShell dependency and rootless Podman.

Useful options:

```text
--no-start                  Install without starting the service
--install-dependencies      Install missing packages without prompting
--no-install-dependencies   Fail instead of installing missing packages
--local                     Force local-development mode
```

For the deployment-specific Linux service payload layout, security checks,
generated local credentials, rollback behavior, and automation options, see
[Installation details](docs/installation.md). This `release/` payload is distinct
from cross-platform `obs` launcher release assets.

## What it does

`openbox-sandbox` provides:

- a loopback-only TLS 1.3 mTLS service;
- exact caller-certificate authorization;
- strict, versioned request and response framing;
- durable sandbox lifecycle ownership and restart reconciliation;
- `create → ready → exec → delete → terminal absence`;
- bounded output, cancellation, draining, and conservative failure handling; and
- a direct adapter for the pinned OpenShell gateway.

The `openbox-sandbox` service binary does **not** call governance services, interpret verdicts, or execute commands on the host. The library's `GovernedDispatcher` is the separate client-side enforcement boundary: it privately owns governance, host, and sandbox capabilities, and routes each immutable command at most once. The sandbox service remains provider-only.

## Build without installing

Installation does not require this step. Contributors who only want to compile the binary can run:

```sh
cargo build --release --locked --bin openbox-sandbox
```

Cargo fetches the exact approved OpenShell source revision from `Cargo.lock`; no separate OpenShell checkout is needed.

## Policy boundary

`deploy/policies/policy-deny-network.yaml` is the default security-floor candidate. Network-enabled policies are accepted only when their exact identity, version, body, and SHA-256 match the configured release identity and they meet the filesystem, Landlock, process, and middleware security floor.

Writable paths are exactly `[/sandbox]`. Every non-empty network policy must also declare `/tmp` exactly once as read-only, with no conflicting path declarations and no network middleware. This pins the provider proxy baseline so it cannot enrich `/tmp` as writable, preserving the exact loaded-policy readiness attestation.

## Developer checks

```sh
./scripts/check-language.sh
./scripts/test-check-language.sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test
cargo doc --all-features --no-deps
cargo deny check
bash -n install.sh scripts/check-language.sh scripts/local-bootstrap.sh scripts/test-check-language.sh \
  packaging/launcher/scripts/*.sh
shellcheck -x install.sh scripts/check-language.sh scripts/local-bootstrap.sh scripts/test-check-language.sh \
  packaging/launcher/scripts/*.sh
cargo fmt --manifest-path packaging/launcher/Cargo.toml -- --check
cargo clippy --manifest-path packaging/launcher/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path packaging/launcher/Cargo.toml
packaging/launcher/scripts/test-provision-local-sandbox.sh
packaging/launcher/scripts/test-generate-sbom.sh
packaging/launcher/scripts/test-verify-release.sh
```
