# OpenBox Sandbox — macOS distribution as thin client

## Architecture

OpenBox Sandbox is a **thin communication / service client**, not a
self-contained runtime. It connects to an operator-installed OpenShell gateway
over mTLS:

```
OpenBox Sandbox → mTLS/API → operator-installed OpenShell gateway → driver/runtime
```

OpenBox Sandbox does NOT embed, extract, or ship:
- The OpenShell gateway, CLI, or VM driver
- Any VM runtime assets (libkrun, guest kernel, etc.)
- Sandbox OCI images
- Hypervisor entitlements

All of those are the **environment owner's responsibility** to install and
maintain. This removes the OpenBox packaging responsibility for the OpenShell
VM driver and avoids maintaining a self-extracting universal macOS binary.

## Why thin client

- OpenBox Sandbox does not create microVMs directly — the OpenShell gateway does.
- Therefore OpenBox Sandbox needs no `com.apple.security.hypervisor` entitlement.
- No embedded helper extraction, no nested executable signing, no runtime re-signing.
- Removes the huge payload from the OpenBox binary distribution.
- OpenBox Sandbox connects only to a **configured / known** OpenShell gateway.

## macOS distribution posture

- First release does **not** require Apple Developer ID.
- A downloaded OpenBox Sandbox executable may receive one Gatekeeper "unverified
  developer" approval after internet download.
- Once approved, it runs normally.
- Do not attempt to bypass Gatekeeper or silently accept untrusted replacement binaries.
- Developer ID + notarization can be added later for smooth public distribution.

## Dependency pinning

OpenShell is pinned to an exact tested release (currently **0.0.85**). This is
fail-closed: a version drift can break the sandbox-name / hook contracts.

### Startup version guard — `src/pin.rs`

The launcher runs `<gateway> --version` and **refuses to run** unless it reports
`REQUIRED_VERSION`. Override for local testing with
`OPENBOX_SANDBOX_REQUIRED_OPENSHELL_VERSION`.

Operator-pinned binary sha256 (opt-in): set `OPENBOX_SANDBOX_GATEWAY_SHA256` /
`OPENBOX_SANDBOX_DRIVER_SHA256` to pin exact on-disk bytes (air-gapped deploys).
`--skip-hash` / `OPENBOX_SANDBOX_SKIP_ARTIFACT_HASH=1` disables even that.

### Operator installation tooling — `scripts/fetch-openshell-deps.sh`

The existing fetcher is **operator installation tooling**, not part of an OpenBox
payload. It:

- Detects macOS/Linux architecture.
- Downloads OpenShell `0.0.85` release tarballs.
- Parses NVIDIA published checksum files.
- Verifies each tarball before extraction.
- Emits a ready-to-use bundle directory.

```
./packaging/launcher/scripts/fetch-openshell-deps.sh   # → ./openbox-sandbox-bundle
OPENBOX_BUNDLE_DIR=./openbox-sandbox-bundle cargo run -- --dry-run
```

Homebrew can remain an optional install path (`brew install openshell`), but
launcher compatibility requires the **exact** pinned version, not "latest".

A pin bump is **one edit in two files**: `REQUIRED_VERSION` in `src/pin.rs` and
`OPENSHELL_VERSION` in the fetch script.

## `--verify-runtime` flag

Reports the runtime environment without starting anything:

- Configured gateway endpoint.
- Local gateway detection and version.
- mTLS readiness.
- Compatibility result (pass / fail against pinned version).
- VM driver presence (informational).
- CONSTRAIN fail-closed posture reminder.

No secrets are exposed.

## Fail-closed behavior

If the gateway is unavailable, incompatible, unauthenticated, or sandbox
execution fails:

- The governed `CONSTRAIN` activity **fails**.
- There is **no host fallback**.
- This is the same behavior as the Core governance layer: CONSTRAIN is
  fail-closed by design.

## Evidence telemetry (unchanged)

- `ActivityStarted` hook-attached flat sandbox span.
- Canonical `hook_type=sandbox_execution`.
- Core derives/stores `span_type=sandbox_execution`.
- Lifecycle `ActivityCompleted` remains span-free.

## SBOM / provenance

### What the SBOM covers

The SBOM is generated from the **launcher binary** (thin client) using
[Syft](https://github.com/anchore/syft). It covers:

- The launcher crate itself (proprietary, not published)
- Rust standard library
- Minimal transitive dependencies

The launcher has very few dependencies — it locates and pins externally-installed
artifacts, it does not bundle them.

### What is NOT in the SBOM

OpenShell is an **external runtime dependency** — not embedded in the binary.
It is documented separately:

- Required version: `0.0.85`
- Source/release URL: `https://github.com/NVIDIA/OpenShell`
- Installation verification: `scripts/fetch-openshell-deps.sh` verifies tarball
  SHA-256 against NVIDIA's published checksums
- Version pin enforced at startup by `src/pin.rs`

### Dual SBOM format

Matching the `krnl-labs/kontrol-plane` pattern, each release produces:

| Format | File | Purpose |
|--------|------|---------|
| SPDX 2.3 | `<binary>.spdx.json` | Primary — machine-readable, standard |
| CycloneDX | `<binary>.cyclonedx.json` | Secondary — compatibility with CycloneDX tools |

### SBOM signing (cosign keyless)

Matching the `OpenBox-AI/common-pipeline` pattern, each SBOM is signed using
[cosign keyless signing](https://docs.sigstore.dev/cosign/key_management/signing_with_self-managed_keys/) with GitHub OIDC:

```
cosign sign-blob \
  --bundle <binary>.spdx.json.sbom.bundle.json \
  --yes \
  <binary>.spdx.json
```

No private keys are managed. The signing identity is the GitHub Actions workflow:

```
https://github.com/OpenBox-AI/openbox-sandbox/.github/workflows/build.yml@refs/tags/v*
```

### Release asset manifest

Each release includes an `asset-manifest.json` (matching the
`openbox-sandbox-poc` evidence pattern) with SHA-256 tracked fields:

```json
{
  "schema_version": 1,
  "product": "openbox-sandbox",
  "version": "v0.1.0",
  "supply_chain": {
    "sbom": { "format": "SPDX-2.3", "package_count": 12, "sha256": "..." },
    "signature": { "method": "cosign-keyless-oidc", "verified": true }
  },
  "binaries": {
    "openbox-sandbox-darwin-arm64": { "sha256": "...", "sbom_sha256": "..." },
    "openbox-sandbox-linux-amd64": { "sha256": "...", "sbom_sha256": "..." },
    "openbox-sandbox-linux-arm64": { "sha256": "...", "sbom_sha256": "..." }
  }
}
```

### CI pipeline

The GitHub Actions workflow (`.github/workflows/build.yml`) runs on every push
to `main` and on PRs:

1. **cargo-deny** — license, advisory, and source audit
2. **Build matrix** — macOS aarch64, Linux amd64, Linux arm64 (cross-compiled)
3. **SBOM generation** — syft dual-format (SPDX + CycloneDX) per binary
4. **SBOM signing** — cosign keyless with GitHub OIDC
5. **Security scan** — Trivy filesystem scan + credential scan
6. **Manifest** (tag pushes) — SHA256SUMS + asset-manifest.json + GitHub Release
7. **Verify** (tag pushes) — download, checksum, SBOM compare, smoke test

### Operator verification

```bash
# Download from GitHub Release
curl -LO https://github.com/OpenBox-AI/openbox-sandbox/releases/download/v0.1.0/SHA256SUMS
curl -LO https://github.com/OpenBox-AI/openbox-sandbox/releases/download/v0.1.0/openbox-sandbox-darwin-arm64

# Verify checksum
shasum -a 256 -c SHA256SUMS

# Verify cosign signature (optional)
cosign verify-blob \
  --bundle openbox-sandbox-darwin-arm64.spdx.json.sbom.bundle.json \
  --certificate-identity-regexp "https://github.com/OpenBox-AI/openbox-sandbox/.github/workflows/build.yml@refs/tags/.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  openbox-sandbox-darwin-arm64.spdx.json

# Inspect SBOM
syft openbox-sandbox-darwin-arm64 -o spdx-json=local-check.spdx.json
diff local-check.spdx.json openbox-sandbox-darwin-arm64.spdx.json

# Run
./openbox-sandbox-darwin-arm64 --verify-runtime
```

### Why no code signing (yet)

- First release does not require Apple Developer ID.
- A downloaded binary may receive one Gatekeeper "unverified developer" approval.
- Developer ID + notarization can be added later for smooth public distribution.
- The SHA256SUMS manifest + cosign keyless signature provide verification without
  code signing.

## Local deployment model

For the "gateway on this host" deployment:

1. Operator fetches the pinned OpenShell release (fetch script or Homebrew).
2. OpenBox Sandbox launcher detects the local gateway via `bundle.rs`.
3. Version pin is verified against the local binary.
4. Launcher execs the gateway in the foreground.

## Remote-client deployment model

For connecting to a remote gateway:

1. Configure the gateway endpoint (env or config file).
2. `--verify-runtime` validates compatibility.
3. OpenBox Sandbox connects over mTLS.
4. No local OpenShell installation required.

## Platform matrix

| | macOS | Linux native | WSL2 |
|---|---|---|---|
| Preferred driver | `vm` (libkrun + Hypervisor.framework) | `podman`/`docker` (strict Landlock if kernel has it) | `podman`/`docker` (best-effort Landlock) |
| Entitlement / signing | OpenShell handles hypervisor entitlement; OpenBox has none | none | none |
| Landlock | best_effort (guest kernel lacks it) | strict on kernels with `CONFIG_SECURITY_LANDLOCK` | best_effort |
| Fetcher triple | `*-apple-darwin` | `*-unknown-linux-gnu` | same as Linux |

## Definition of done

Operator installs OpenShell, then:
1. Download the OpenBox Sandbox launcher binary.
2. Approve Gatekeeper once (macOS).
3. Run `openbox-sandbox --verify-runtime` — reports compatible.
4. Run `openbox-sandbox` — connects to the gateway, CONSTRAIN works.
5. `CONSTRAIN` sandbox execution runs in a real microVM (or container).
6. No host fallback on sandbox failure.
