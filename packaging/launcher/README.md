# `obs` cross-platform launcher

`obs` is the dependency-free operator/developer launcher in
`packaging/launcher`. It is not the production sandbox service:

- root `openbox-sandbox` binary: mTLS sandbox service and durable lifecycle owner;
- `obs`: artifact discovery, external gateway launch, and source-checkout dogfood commands;
- OpenShell: external gateway/driver runtime, never embedded in either artifact.

The launcher release keeps the existing download names for compatibility:

- `openbox-sandbox-darwin-arm64`
- `openbox-sandbox-linux-amd64`
- `openbox-sandbox-linux-arm64`

Those files contain the `obs` executable. This cross-platform launcher track is
distinct from the deployment-specific Linux service installer payload described
in [`../../docs/installation.md`](../../docs/installation.md).

## Build and basic use

```sh
cd packaging/launcher
cargo build --release
cargo run -- --help
cargo run -- --dry-run
cargo run -- --driver vm
```

The launcher resolves an operator-provided OpenShell installation from
`OPENBOX_BUNDLE_DIR`, well-known prefixes, or `PATH`. OpenShell remains
external.

`obs setup` no longer exists: bundle acquisition + verification is part of
`obs provision` (auto-fetch via `OPENBOX_OPENSHELL_BUNDLE_URL`). The external
gateway is managed as a per-user process by `obs provision`.

`obs --verify-runtime` verifies only local artifact presence, exact release
version, and any operator-supplied hashes. For development, append
`--skip-hash` to skip those operator hashes while retaining version checks. It
does **not** connect to a gateway, validate mTLS, create a sandbox, or prove
execution.

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

The root service protocol was pinned to OpenShell source commit
`f169084923503a02a94425857b938de2841cab0c` (`f1690849`). The hosted-bin flow
locks the released version **0.0.88** instead of building from source; the
wizard accepts either the `gf1690849` source marker or the locked release, and
the live verify test proves the wire contract at runtime.

For source builds at the exact pin, use:

```sh
cargo build --release --locked --bin openbox-sandbox
cargo build --release --manifest-path packaging/launcher/Cargo.toml
OPENSHELL_BIN_OVERRIDE=/path/to/openshell-target/release \
  packaging/launcher/target/release/obs provision
packaging/launcher/target/release/obs verify
packaging/launcher/target/release/obs uninstall
```

`obs verify` first hashes the exact root service binary recorded in `agent.env`
and requires it to match the provisioned adapter identity. It then runs the
actual live proof: client → mTLS root service → external OpenShell gateway →
create → ready → exec → delete → terminal absence. It needs a provisioned source
checkout and a working host VM/OpenShell runtime. Teardown signals only
PID-file processes whose command identity matches the wizard; unrelated port
listeners and VM drivers are reported and left untouched.

## Release and SBOM verification

The launcher crate has no third-party Cargo dependencies. Syft scans each final
binary as built; it commonly reports the launcher as a file component rather
than reconstructing a Cargo dependency graph. OpenShell is not included because
it is not embedded.

Each launcher artifact has:

- SPDX 2.3: `<artifact>.spdx.json`
- CycloneDX: `<artifact>.cyclonedx.json`
- keyless cosign bundle for the SPDX file:
  `<artifact>.spdx.json.sbom.bundle.json`

Generate both local formats with `scripts/generate-sbom.sh`. It requires a
preinstalled Syft v1.20.0 (or an explicit `SYFT_BIN`) and never downloads tools
or invokes `sudo`. Verify a downloaded release directory with
`scripts/verify-release.sh`; checksums and both SBOM files are required, and an
available `cosign` installation verifies the SPDX bundle.
See [`SINGLE_BIN_MACOS_PLAN.md`](SINGLE_BIN_MACOS_PLAN.md) for the retained
release design record.

## Hosted-bin (toolchain-free) flow

OpenShell is locked to released version **0.0.88** (NVIDIA's prebuilt
tarballs, sha256-verified; the released VM driver ships with the supervisor
embedded) and assembled with our binaries into GitHub release assets.
Consumers never install a toolchain, never build, and never need the source
tree:

1. `curl` the release assets (stable URLs once public; versioned tags like
   `v0.1.0`, and `releases/latest/download/` always points at the current
   release):
   `https://github.com/OpenBox-AI/openbox-sandbox/releases/latest/download/<asset>`
   — obs (single binary with the operational scripts EMBEDDED), the
   `openbox-sandbox` service, the prebuilt verify harness, the OpenShell
   bundle tarball, the sandbox policy, `SHA256SUMS`, and Syft SBOMs.
2. Verify checksums (`sha256sum -c SHA256SUMS`) and scan with Syft v1.20.0.
3. `obs provision` with `OPENBOX_OPENSHELL_BUNDLE_URL=<release base>`
   (private repos additionally need `GH_TOKEN`), `OPENBOX_SANDBOX_BIN`
   (absolute), and `OPENBOX_POLICY_FILE` (absolute — the policy is a release
   asset, not a repo file) auto-fetches + verifies the bundle, starts the
   stack, and warms the VM driver image cache by default (one create→ready→
   delete cycle; `OPENBOX_WARM_CACHE=0` skips). The version gate accepts the
   locked release `0.0.88` or the root-protocol source marker `gf1690849`.
5. `obs verify` with `OPENBOX_VERIFY_BIN=<prebuilt-harness>` runs the live
   lifecycle proof without cargo.
6. `obs uninstall` tears the stack down cleanly. Pass the **same**
   `OPENBOX_SANDBOX_BIN`/`OPENSHELL_BUNDLE_DIR`/`OPENBOX_POLICY_FILE` env used
   for provision: the wizard's teardown safety check compares the running
   service's command line against the resolved binary path and refuses to
   signal mismatches.

Publish immutable versioned releases with the manual `hosted-bin release`
GitHub Actions workflow on `main`. Supply a new semantic version for each run;
the workflow rejects existing release tags, verifies checksums, creates and
validates a draft, then publishes it. If a run fails after creating its draft,
delete that unpublished draft before retrying the same version.

`mise` and the `gh` CLI are **not** required anywhere in this flow: the
OpenShell `tasks/scripts/vm/*` build scripts run directly, and the vm-runtime
tarball is publicly downloadable with `curl`.
