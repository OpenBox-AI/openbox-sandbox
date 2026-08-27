# `obs` cross-platform launcher

`obs` is the operator and developer launcher in `packaging/launcher`. It is not
the sandbox service:

- root `openbox-sandbox` binary: mTLS sandbox service and durable lifecycle owner;
- `obs`: asset resolution, provisioning, and lifecycle commands;
- OpenShell: external gateway and driver runtime, never embedded in either.

Release assets carrying the launcher are `obs-darwin-arm64` and
`obs-linux-x86_64`. The service ships beside them as
`openbox-sandbox-darwin-arm64` and `openbox-sandbox-linux-x86_64`.

## Build and basic use

```sh
cargo build --release --manifest-path packaging/launcher/Cargo.toml
packaging/launcher/target/release/obs --help
packaging/launcher/target/release/obs provision --dry-run
```

The launcher resolves an operator-provided OpenShell installation from
`OPENBOX_BUNDLE_DIR`, well-known prefixes, or `PATH`. OpenShell stays external.
Bundle acquisition and verification are part of `obs provision`, which manages
the gateway as a per-user process.

`obs --verify-runtime` checks local artifact presence, the exact release
version, and any operator-supplied hashes. It does not connect to a gateway,
validate mTLS, create a sandbox, or prove execution. There is no way to switch
those checks off.

## Asset verification

Every asset the launcher resolves is checked against the `SHA256SUMS` of the
release line in use, whether it was just downloaded or already on disk, and a
mismatch is removed and re-fetched. A source checkout builds the service it
runs, because no manifest exists for a build that has not happened yet.
`--sandbox-bin` says where a binary is, not whether to check it.

## Drivers

| Driver | Requirement | Posture |
|---|---|---|
| `podman` | Podman | Preferred Linux container path. |
| `docker` | Docker | Container path with a root daemon. |
| `kubernetes` | `kubectl` and a cluster | Isolation delegated to the cluster. |
| `vm` | KVM or Hypervisor.framework | OpenShell libkrun microVM path. |

macOS prefers `vm`; container drivers there require `--allow-degraded`. Windows
is unsupported directly; use WSL2.

## Version gate

The service protocol is pinned to OpenShell source commit
`f169084923503a02a94425857b938de2841cab0c` (`f1690849`). The launcher accepts
either that source marker or the locked release **0.0.88**, and the live
lifecycle test proves the wire contract at runtime. Neither the pin nor the
hash check can be overridden.

For a source build at the exact pin:

```sh
cargo build --release --locked --bin openbox-sandbox
cargo build --release --manifest-path packaging/launcher/Cargo.toml
OPENSHELL_BIN_OVERRIDE=/path/to/openshell-target/release \
  packaging/launcher/target/release/obs provision
  packaging/launcher/target/release/obs uninstall
```

## Native provider

Provisioning compiles the selected release policy into an owner-only
Seatbelt or bubblewrap profile and pins its hash. Network-enabled profiles make
the service create an ephemeral localhost proxy for each execution; no proxy
port is persisted in launcher or service configuration. On macOS the compiled
profile admits only that runtime port, and the service attaches proxy decisions
plus unified-log Seatbelt violation counts to terminal results. Linux has no
unprivileged bubblewrap deny log, so violation evidence is omitted; see the root
README for the Linux address-filter limitation.

## Live lifecycle proof

The live create → ready → exec → delete proof lives as the ignored Go/Rust
integration test `live_service_create_exec_delete` in the source tree, run
from a provisioned checkout with `cargo test`. It is not a subcommand:
`obs verify` was removed because a shipped binary cannot assume a local
toolchain.

Teardown signals only PID-file processes whose command identity matches the
launcher. Unrelated port listeners and VM drivers are reported and left
untouched, so a stale listener is refused rather than killed.

## Releases

Release artifacts are checksummed in `SHA256SUMS`; verify a downloaded
directory with `sha256sum -c SHA256SUMS`. Cutting and publishing a release is
`obs-release`, a maintainer-only binary in `packaging/release`. It is not part
of `obs` and is never published as a release asset. It refuses to publish a
payload whose manifest does not cover every file, whose binaries embed the
build machine's paths, or that contains credential material.
