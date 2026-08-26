# OpenBox Sandbox

OpenBox Sandbox runs one authorized command in an isolated sandbox. A client
reaches it over mutual TLS on the loopback interface only.

The service does one job. It never calls a governance service. It never reads a
verdict. It never runs a command on the host.

---

## Quick start

These steps are for macOS on Apple Silicon. On Linux x86_64, install the
`bubblewrap` package first, then download `obs-linux-x86_64` instead.

**1. Download the launcher and the manifest.**

```bash
curl -fL -O https://github.com/OpenBox-AI/openbox-sandbox/releases/download/v0.1.0-dev/obs-darwin-arm64
curl -fL -O https://github.com/OpenBox-AI/openbox-sandbox/releases/download/v0.1.0-dev/SHA256SUMS
```

**2. Check the file, then rename it.**

Check the file before you rename it. The manifest lists the release filename.
The check fails after you rename the file.

```bash
shasum -a 256 -c SHA256SUMS 2>/dev/null | grep obs-darwin-arm64
chmod +x obs-darwin-arm64
mv obs-darwin-arm64 obs
```

The command shows one line, because you downloaded one file. Every other asset
in the manifest reports `FAILED open or read`. Ignore those lines.

This check finds a corrupt download. It also finds assets that came from two
different releases. It does not prove who built the file, because the manifest
comes from the same release.

**3. Provision the stack.**

```bash
./obs provision
```

## Commands

| Command | Result |
|---|---|
| `obs provision` | Compiles the policy, starts the service, writes `agent.env` |
| `obs status` | Reports what is ready |
| `obs verify` | Proves a live create, exec, and delete over mutual TLS |
| `obs uninstall` | Removes everything the launcher created |
| `obs update` | Replaces `obs` from a release |

## How the service runs

The service runs in your terminal. Press Ctrl-C to stop it. The service first
drains the work in flight, then exits.

Two flags change this behavior.

| Flag | Result |
|---|---|
| `--detach` | Runs the service in the background with a PID file. The service gets its own process group, so it survives when you close the terminal. |
| `--systemd` | Linux only. Writes a systemd unit and enables it, so systemd restarts the service after a failure. Root gets a system unit. Any other user gets a user unit. |

## Providers

| Provider | Isolation | Notes |
|---|---|---|
| `native` (default) | Seatbelt on macOS, bubblewrap on Linux | Needs no container runtime. Provisioning compiles the profile, pins its SHA-256, and checks it before every execution. |
| `openshell` | libkrun microVM | Adds a guest kernel boundary. Needs a hypervisor and a prepared image cache. |

You select the provider. The launcher never changes it for you. A failure stops
the run.

## What provisioning does

1. Resolves each asset and checks it against the `SHA256SUMS` of the release.
2. Compiles the policy into a profile and pins its SHA-256 in `service.json`.
3. Starts the service and runs one smoke execution.
4. Writes `~/.config/openbox-sandbox/agent.env`.

`agent.env` holds the whole boundary contract for an SDK client. The service
checks the pinned profile before every execution.

Both providers check every asset against the manifest of the release. This
applies to a file the launcher downloads now and to a file that already sits on
disk. The launcher deletes a file that does not match, then fetches it again. No flag and no
environment variable turns this check off.

A source checkout builds the service that it runs. Everywhere else, the release
asset must match. Check `obs` yourself, as step 2 shows, because a launcher
cannot vouch for itself.

## Lifecycle and policy

A sandbox moves through five states: create, ready, exec, delete, and terminal
absence. The service owns this lifecycle across a restart. Output has a fixed
limit. A failure stops the run.

### Filesystem

A command writes to `/sandbox` and to nothing else. Each network policy declares
`/tmp` as read only, one time. No network middleware runs, so the proxy cannot
widen that rule.

### Network

A network policy starts one HTTP proxy for each execution, on a loopback port
that the service picks at runtime. The service clears the command environment.
It then sets `HTTP_PROXY` and the related variables.

The proxy resolves DNS outside the sandbox. It refuses every host that the
pinned policy does not list.

- On macOS, Seatbelt opens that one port. A direct socket has no route out.
- On Linux, bubblewrap shares the network namespace and cannot filter by
  address. Use a deny-network policy, or use `openshell`.

### Evidence

A result carries typed `sandbox_evidence`. The evidence names each proxy
request, its host, its port, and the decision to allow it or to deny it. On
macOS the service also reports violation counts and categories from the unified
log.

## Layout

| Path | Contents |
|---|---|
| `openbox-sandbox` (root) | The sandbox service |
| `packaging/launcher` | `obs`, the launcher for operators and developers |
| `packaging/release` | `obs-release`, the release tool for maintainers only. No release carries it. |
| OpenShell | The external gateway and driver runtime. Pinned here, maintained elsewhere. |

This repository contains no shell scripts. The launcher does everything in Rust.

## Development

Run these gates in this order.

```bash
cargo build --release --locked --bin openbox-sandbox
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check
cargo fmt --manifest-path packaging/launcher/Cargo.toml -- --check
cargo clippy --manifest-path packaging/launcher/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path packaging/launcher/Cargo.toml
cargo fmt --manifest-path packaging/release/Cargo.toml -- --check
cargo clippy --manifest-path packaging/release/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path packaging/release/Cargo.toml
```

### Build a release

Remap the paths of the build machine. A release artifact must not name the home
directory of the person who built it.

```bash
export RUSTFLAGS="--remap-path-prefix=$PWD=/openbox-sandbox --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup"
```

`obs-release publish` refuses a payload that still holds those paths.
