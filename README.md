# OpenBox Sandbox

Runs one authorized command inside an isolated sandbox, behind a loopback-only
TLS 1.3 mTLS service. The service is provider-only: it never calls governance
services, interprets verdicts, or executes commands on the host.

Integration PoC/showcase material belongs exclusively to the separate `OpenBox-AI/openbox-sandbox-poc` repository and is not a dependency.

## Providers

| Provider | Isolation | Notes |
|---|---|---|
| `native` (default) | Seatbelt on macOS, bubblewrap on Linux | No container runtime. The profile is compiled at provisioning, SHA-256 pinned, and verified before every execution. |
| `openshell` | libkrun microVM | Guest-kernel boundary. Needs a hypervisor and a prepared image cache. |

Selection is explicit and fails closed. There is no fallback.

## Use

Local sandbox, macOS on Apple Silicon:

```sh
curl -fL -o obs https://github.com/OpenBox-AI/openbox-sandbox/releases/download/v0.1.0-dev/obs-darwin-arm64
chmod +x obs
./obs provision --yes
```

Linux x86_64 needs the `bubblewrap` package; download `obs-linux-x86_64` and run
the same commands.

Provisioning verifies each asset, compiles and pins the sandbox profile, starts
the mTLS service, runs a smoke execution, and writes
`~/.config/openbox-sandbox/agent.env`, which is the entire boundary contract for
an SDK client.

The service runs in that terminal, and Ctrl-C stops it after draining work in
flight. Two flags change that:

| Flag | Effect |
|---|---|
| `--detach` | Run in the background with a PID file, in its own process group, so a closing terminal cannot kill it. |
| `--systemd` | Linux only. Write a systemd unit and enable it, so the service restarts on failure. Root installs a system unit, any other user a user unit. |

```sh
./obs status       # readiness
./obs uninstall    # remove everything it created
```

## Lifecycle and policy

`create → ready → exec → delete → terminal absence`, with durable ownership and
restart reconciliation. Output is bounded and failures are conservative.

Writable paths are exactly `[/sandbox]`. Every non-empty network policy declares
`/tmp` read-only once, with no network middleware, so the proxy baseline cannot
widen it.

A network-enabled policy starts an execution-scoped HTTP proxy on an ephemeral
loopback port. The command environment is cleared, then `HTTP_PROXY` and its
variants are set. The proxy resolves DNS outside the sandbox and refuses any host
the pinned policy does not list. On macOS, Seatbelt permits only that port, so a
direct socket has no path out. Linux cannot filter a shared network namespace by
address: use a deny-network policy, or `openshell`, where that matters.

Results carry typed `sandbox_evidence`: every proxy request with its allowed or
denied decision, host, and port. On macOS the service also reports violation
counts and categories from the unified log.

## Layout

- root `openbox-sandbox` — the mTLS sandbox service.
- `packaging/launcher` / `obs` — the operator and developer launcher.
- `packaging/release` / `obs-release` — maintainer-only release tooling, never
  published as a release asset.
- OpenShell — external gateway and driver runtime, pinned but not maintained here.

The repository contains no shell scripts. Everything the launcher does is Rust.

## Development

```sh
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

The repository language gate runs as part of `cargo test`.
