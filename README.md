# OpenBox Sandbox

Runs one authorized command inside an isolated sandbox, behind a loopback-only
TLS 1.3 mTLS service. The service is provider-only: it never calls governance
services, interprets verdicts, or executes commands on the host.

Integration PoC/showcase material belongs exclusively to the separate `OpenBox-AI/openbox-sandbox-poc` repository and is not a dependency.

---

## Quick start

macOS on Apple Silicon. For Linux x86_64, install the `bubblewrap` package and
download `obs-linux-x86_64` instead.

```sh
# 1. Download the launcher and the manifest
curl -fL -O https://github.com/OpenBox-AI/openbox-sandbox/releases/download/v0.1.0-dev/obs-darwin-arm64
curl -fL -O https://github.com/OpenBox-AI/openbox-sandbox/releases/download/v0.1.0-dev/SHA256SUMS

# 2. Verify, then rename
shasum -a 256 -c SHA256SUMS 2>/dev/null | grep obs-darwin-arm64
chmod +x obs-darwin-arm64 && mv obs-darwin-arm64 obs

# 3. Provision
./obs provision
```

Verify **before** renaming: the manifest lists the release filename, so the
check only works while the file still has it. Assets you did not download report
`FAILED open or read`, which is why the check is filtered to the one line that
matters.

That check detects a corrupt download or assets mixed between releases. It is
not proof of authorship, because the manifest ships from the same release.

## Commands

| Command | Does |
|---|---|
| `obs provision` | Compile the policy, start the service, write `agent.env` |
| `obs status` | Report readiness |
| `obs verify` | Prove a live create → exec → delete over mTLS |
| `obs uninstall` | Remove everything it created |
| `obs update` | Replace `obs` itself from a release |

## How the service runs

By default the service runs in your terminal, and Ctrl-C stops it after draining
work in flight. Two flags change that:

| Flag | Effect |
|---|---|
| `--detach` | Background, with a PID file, in its own process group, so a closing terminal cannot kill it. |
| `--systemd` | Linux only. Write a systemd unit and enable it, so the service restarts on failure. Root installs a system unit, any other user a user unit. |

## Providers

| Provider | Isolation | Notes |
|---|---|---|
| `native` (default) | Seatbelt on macOS, bubblewrap on Linux | No container runtime. The profile is compiled at provisioning, SHA-256 pinned, and verified before every execution. |
| `openshell` | libkrun microVM | Guest-kernel boundary. Needs a hypervisor and a prepared image cache. |

Selection is explicit and fails closed. There is no fallback.

## What provisioning does

1. Resolves every asset and checks it against that release's `SHA256SUMS`.
2. Compiles the policy into a profile and pins its SHA-256 in `service.json`.
3. Starts the mTLS service and runs one smoke execution.
4. Writes `~/.config/openbox-sandbox/agent.env`, the entire boundary contract
   for an SDK client.

The pinned profile is verified before every execution.

Asset verification covers files that were already on disk as well as fresh
downloads, and a mismatch is re-fetched. No flag or environment variable
switches it off. A source checkout builds the service it runs; everywhere else
the release asset must match. Verify `obs` itself as shown above, because a
launcher cannot vouch for itself.

## Lifecycle and policy

`create → ready → exec → delete → terminal absence`, with durable ownership and
restart reconciliation. Output is bounded and failures are conservative.

**Filesystem.** Writable paths are exactly `[/sandbox]`. Every non-empty network
policy declares `/tmp` read-only once, with no network middleware, so the proxy
baseline cannot widen it.

**Network.** A network-enabled policy starts an execution-scoped HTTP proxy on
an ephemeral loopback port. The command environment is cleared, then
`HTTP_PROXY` and its variants are set. The proxy resolves DNS outside the
sandbox and refuses any host the pinned policy does not list.

- On macOS, Seatbelt permits only that port, so a direct socket has no path out.
- On Linux, a shared network namespace cannot be filtered by address. Use a
  deny-network policy, or `openshell`, where that matters.

**Evidence.** Results carry typed `sandbox_evidence`: every proxy request with
its allowed or denied decision, host, and port. On macOS the service also
reports violation counts and categories from the unified log.

## Layout

| Path | Is |
|---|---|
| `openbox-sandbox` (root) | The mTLS sandbox service |
| `packaging/launcher` → `obs` | The operator and developer launcher |
| `packaging/release` → `obs-release` | Maintainer-only release tooling, never published as a release asset |
| OpenShell | External gateway and driver runtime, pinned but not maintained here |

The repository contains no shell scripts. Everything the launcher does is Rust.

## Development

Every gate, in the order CI would run them:

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

### Building a release

Release binaries are built with the build machine's paths remapped, so no
artifact carries the builder's home directory:

```sh
export RUSTFLAGS="--remap-path-prefix=$PWD=/openbox-sandbox \
  --remap-path-prefix=$HOME/.cargo=/cargo \
  --remap-path-prefix=$HOME/.rustup=/rustup"
```

`obs-release publish` refuses a payload that still contains them.
