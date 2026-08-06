# `obs` cross-platform launcher release design

This filename is retained for existing links. The implemented scope now covers
macOS and Linux launcher artifacts; it is not the Linux sandbox-service
installer design.

## Module seam

```text
client → mTLS → openbox-sandbox service → external OpenShell gateway → runtime
```

- `openbox-sandbox` is the root production-intent mTLS sandbox service.
- `obs` is the dependency-free operator/developer launcher.
- OpenShell is external. It is not linked, embedded, or shipped inside `obs`.

The launcher may locate and start a local external gateway. Source-checkout
`provision`, `status`, `verify`, and `uninstall` commands support dogfood; they
do not turn the launcher into the service.

## Two release tracks

### Cross-platform launcher

`.github/workflows/build.yml` builds `packaging/launcher` and preserves the
existing public artifact names:

- `openbox-sandbox-darwin-arm64`
- `openbox-sandbox-linux-amd64`
- `openbox-sandbox-linux-arm64`

Each file is the `obs` executable. These are portable launcher downloads and do
not contain OpenShell or the root service installer payload.

### Linux sandbox-service deployment

The root [`../../install.sh`](../../install.sh) consumes a deployment-specific
`release/` directory containing the `openbox-sandbox` service binary,
configuration, mTLS material, systemd unit context, checksums, and an approved
OpenShell package/source attestation. Its exact layout and rollback behavior are
documented in [`../../docs/installation.md`](../../docs/installation.md).

The two release directories are not interchangeable.

## Compatibility pins

The launcher artifact track verifies OpenShell release version `0.0.85` and
optional operator-provided binary hashes. The fetch script verifies the upstream
release tarball checksums before extraction.

The root service adapter has a separate, exact source protocol pin:

```text
f169084923503a02a94425857b938de2841cab0c
```

The 0.0.85 release predates that protocol. `obs provision` therefore fails
closed unless the gateway, CLI, and VM driver report the exact `f1690849`
source marker. Its error gives source-build commands and the
`OPENSHELL_BIN_OVERRIDE` path needed to select those binaries. There is no
compatibility bypass in the dogfood provisioning path.

## Honest verification levels

`obs --verify-runtime` is offline/local compatibility checking only. It verifies
resolved artifacts, their exact launcher release version, and configured
operator hashes. `obs --verify-runtime --skip-hash` is the explicit development
form that skips operator hashes while retaining version checks. Neither form
connects to a gateway, inspects mTLS, boots a VM, or executes a command.

After `obs provision`, `obs verify` first requires the recorded root service
binary SHA-256 to match the provisioned adapter identity, then runs the opt-in
root test `live_service_create_exec_delete`. That is the live proof over mTLS:
create → ready → exec → delete → terminal absence. A normal `cargo test` run is
not equivalent because the live test skips when no endpoint environment exists.

## SBOM and provenance

The launcher `Cargo.toml` has no third-party dependencies. Syft scans the final
standalone binary, so the generated document generally describes the launcher
file and discoverable binary metadata; it does not claim a dependency graph
that does not exist. The Rust standard library is statically incorporated by the
Rust build but is not necessarily represented by Syft as a separate package.
External OpenShell artifacts are outside this SBOM.

The existing workflow emits two formats per launcher artifact:

| Format | File |
|---|---|
| SPDX 2.3 | `<artifact>.spdx.json` |
| CycloneDX | `<artifact>.cyclonedx.json` |

The SPDX document is signed with cosign keyless GitHub OIDC and uploaded with
`<artifact>.spdx.json.sbom.bundle.json`. `SHA256SUMS` covers the launcher and
release sidecars. `asset-manifest.json` records binary, SPDX, and cosign-bundle
hashes.

Local generation requires a preinstalled Syft v1.20.0 (or explicit
`SYFT_BIN`); the generator never installs tools or escalates privileges:

```sh
packaging/launcher/scripts/generate-sbom.sh \
  packaging/launcher/target/release/obs packaging/launcher/sbom-output
```

Local verification of downloaded assets:

```sh
packaging/launcher/scripts/verify-release.sh /path/to/launcher-release
```

The verifier checks the checksum manifest and requires both SBOM formats. When
cosign is installed, it verifies the SPDX bundle against the tagged
`build.yml` GitHub Actions identity. These checks establish artifact integrity
and provenance, not runtime behavior; use `obs verify` for the live proof.

## macOS posture

OpenShell's VM driver, not `obs` or the root service, needs the hypervisor
entitlement. The dogfood provisioning script ad-hoc signs a source-built driver
with that entitlement. Public Developer ID signing/notarization remains a
separate distribution decision; checksum and keyless SBOM verification do not
replace Gatekeeper policy.
