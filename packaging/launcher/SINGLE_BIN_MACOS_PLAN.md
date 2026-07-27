# Single-binary `openbox-sandbox` for macOS (Apple Silicon) — plan

Goal: **one downloadable executable** that, with no other install, starts a real
governed sandbox runtime on macOS using the libkrun **microVM** driver.

This is achievable on macOS specifically because the microVM path needs no
container runtime and no host Linux kernel — libkrun supplies its own guest
kernel, and (important) **that runtime is already embedded** in
`openshell-driver-vm`.

## What we already have (facts, not aspiration)

- **`openshell-driver-vm` self-embeds the whole microVM runtime.**
  `crates/openshell-driver-vm/build.rs` + `src/embedded_runtime.rs` /
  `src/rootfs.rs` `include_bytes!` the zstd-compressed `libkrun.dylib`,
  `libkrunfw.5.dylib` (guest kernel), `gvproxy`, `umoci`, and the sandbox
  supervisor. So the kernel + VMM + net + OCI-unpack are inside one binary.
- **The launcher already has the self-extract seam.** `bundle.rs::resolve()`
  probes `$OPENBOX_BUNDLE_DIR` first. A self-extracting build only has to
  populate that dir before `resolve()`; no other launcher code changes.
- **The gateway self-bootstraps PKI.** `openshell-gateway generate-certs`
  creates the CA/server/client mTLS bundle — no manual cert steps.
- **The launcher already detects the hypervisor and selects the `vm` driver**
  on macOS.

## The artifact set the single bin must carry (macOS aarch64, vm driver)

| Artifact | Approx size | Notes |
|---|---:|---|
| launcher (this crate) | ~1 MB | the outer executable / entry point |
| `openbox-sandbox` service adapter | ~6 MB | the runtime adapter the dispatcher talks to |
| `openshell-gateway` | ~50 MB | daemon; has `generate-certs` |
| `openshell-driver-vm` | ~30–75 MB | **runtime already embedded**; needs the hypervisor entitlement |
| `policy-deny-network.yaml` + `-dev.yaml` | <10 KB | strict + best_effort tiers |
| base sandbox OCI image | ~6 MB (wolfi) … 1.1 GB (nvidia community) | **choose a small base**; embed or pull on first run |

`openshell` (the CLI) is **not** needed for the gateway runtime path — it can be
dropped from the payload. Everything else compresses to roughly **80–100 MB**
for a small base image; the giant nvidia community base is not required.

## No runtime re-sign (recommended) — sign once at build, extract verbatim

The re-sign step below only exists if you *append the payload after signing the
launcher* and *extract unsigned build outputs*. Flip both and there is **zero
runtime signing**:

- **A code signature lives inside the Mach-O bytes.** Copy/extract the file and
  the signature comes with it. zstd is lossless, so
  `sign → zstd → embed → (runtime) unzstd → write` yields the exact signed bytes.
- **This already works today for the dylibs.** `openshell-driver-vm` extracts
  `libkrun.dylib` / `libkrunfw.5.dylib` and dlopens them every run with no
  re-sign — they load because they carry signatures from their build. That is
  literally the "extract verbatim, no resign" mechanism in production use.
- **The only runtime `codesign` today** is the start script applying the
  hypervisor entitlement to `openshell-driver-vm` at gateway-start. Eliminate it
  by moving that `codesign --entitlements` to a **build step** and shipping the
  driver pre-signed.

Build order that needs no runtime signing:
1. Take the prebuilt `libkrun.dylib` / `libkrunfw.5.dylib`; sign them (ad-hoc or
   Developer ID). zstd them.
2. Build `openshell-driver-vm` with `OPENSHELL_VM_RUNTIME_COMPRESSED_DIR` set to
   those signed+compressed dylibs (so the driver embeds already-signed runtime).
3. **Codesign `openshell-driver-vm` once, at build, with the hypervisor
   entitlement** (`entitlements.plist`). Sign `openshell-gateway`, the adapter,
   and `gvproxy` too.
4. zstd + embed all of them into the launcher via `include_bytes!` **before**
   signing the launcher, OR ship them as signed siblings in a signed wrapper.
5. Codesign the launcher once, at build. Its signature covers the embedded
   blobs; each embedded blob already carries its own signature.
6. First run: extract verbatim to cache and run. **No re-sign, ever.**

Requirement: don't mutate any signed file after signing. That means **embed the
payload inside the binary (section / `include_bytes!`) and sign the whole thing
afterwards** — never `cat launcher payload.tar.zst > out` (that appends past the
signature and invalidates the launcher's own sig).

Distribution note: ad-hoc build-time signatures run on any local machine with no
re-sign. For Gatekeeper on a *downloaded* file, notarize — either notarize each
embedded binary, or (simpler) ship inside a notarized `.pkg`/`.dmg` so the
extracted, already-signed binaries are trusted. Still no *runtime* signing.

### Endgame: one signed Mach-O, nothing to extract
The purest "no resign and nothing to sign but one file" is collapsing to a
**single process**: statically link libkrun and run the gateway + driver in-process
instead of spawning `openshell-driver-vm`. Then there is exactly one Mach-O to
sign (with the hypervisor entitlement) and no extracted executables/dylibs at
all. libkrun dlopens `libkrunfw` by design, so this needs a static-libkrunfw
path and merging the driver into the gateway process — a real but larger
architectural change. Near term, use embed-signed + extract-verbatim above.

## (Only if you insist on append-after-sign) runtime re-sign fallback

libkrun needs `com.apple.security.hypervisor`
(`crates/openshell-driver-vm/entitlements.plist`), and the driver must be
codesigned. A naive "append a tar to a Mach-O and extract at runtime" **breaks
signatures** — extracted Mach-O files are unsigned and macOS will refuse the
hypervisor entitlement. This is the crux; everything else is plumbing.

Two viable shapes:

### Shape A — self-extracting single executable (best match for "single bin", dev/internal)
1. Build all artifacts release-mode for `aarch64-apple-darwin`.
2. **Sign each artifact once, at build** (ad-hoc or Developer ID): the driver-vm
   with the hypervisor entitlement, plus gateway/adapter/gvproxy and the libkrun
   dylibs. `zstd` them.
3. **Embed** the signed+compressed payload **inside** the launcher via a Mach-O
   section / `include_bytes!` (not appended after signing), then codesign the
   launcher last.
4. First run: extract **verbatim** to a per-user cache
   (`~/Library/Caches/openbox-sandbox/<contenthash>/`) and set
   `OPENBOX_BUNDLE_DIR`. Signatures are inside the bytes → **no re-sign**.
5. Run `openshell-gateway generate-certs`, then exec the gateway with
   `--drivers vm`.
6. Cache-validate by content hash so later runs skip extraction entirely.

Limitation: ad-hoc signatures run on any local machine with no re-sign, but a
*downloaded* file needs notarization — use Shape B for that.

### Shape B — signed, notarized `.pkg` (or `.app`) for real distribution
1. Same artifacts, but lay them out inside a bundle and **codesign each Mach-O
   with a Developer ID + the hypervisor entitlement at build time** (hardened
   runtime), then **notarize + staple**.
2. Ship as a `.pkg` that installs to `/usr/local/opt/openbox-sandbox` (or an
   `.app`); the launcher there resolves siblings via the existing install-prefix
   probe in `bundle.rs`.
3. This is not literally one file, but it is one signed download that runs with
   no prior install and passes Gatekeeper.

**Recommendation:** build Shape A now (matches "single bin", unblocks internal
use), and treat Shape B as the release/distribution track. Both reuse the same
payload and the same `OPENBOX_BUNDLE_DIR` seam.

## Dependency pinning (release tarball + sha256, not brew-latest)

`brew install openshell` tracks **latest**, which is exactly the drift that
already bit this project (the 40-char → 19-char `MAX_ROUTABLE_NAME_LEN`
mismatch after a pin bump). So the pin is enforced two ways:

### 1. Startup version guard (always on) — `src/pin.rs`
The launcher runs `<gateway> --version` and **refuses to run** unless it reports
`REQUIRED_VERSION` ("0.0.85"). Override for local testing with
`OPENBOX_SANDBOX_REQUIRED_OPENSHELL_VERSION`. This is the reliable runtime guard:
Homebrew re-signs mach-Os on install (ARM64), so the on-disk binary hash is not
stable and is **not** used as the default check.

Operator-pinned binary sha256 (opt-in): set `OPENBOX_SANDBOX_GATEWAY_SHA256` /
`OPENBOX_SANDBOX_DRIVER_SHA256` to pin exact on-disk bytes (air-gapped deploys).
`--skip-hash` / `OPENBOX_SANDBOX_SKIP_ARTIFACT_HASH=1` disables even that.

### 2. Supply-chain guard (at fetch time) — `scripts/fetch-openshell-deps.sh`
Fetches the pinned OpenShell release tarballs for `aarch64-apple-darwin` and
**verifies each tarball's sha256** against the pinned values (the same hashes
the Homebrew formula pins) before extracting. A moved or compromised release
cannot substitute. This is the right layer for the hash: it is over the
*tarball*, not the extracted binary.

```
./packaging/launcher/scripts/fetch-openshell-deps.sh   # → ./openbox-sandbox-bundle
OPENBOX_BUNDLE_DIR=./openbox-sandbox-bundle cargo run -- --dry-run
```

A pin bump is **one edit in two files**: `REQUIRED_VERSION` in `src/pin.rs` and
the `SHA` map + `OPENSHELL_VERSION` in the fetch script.

> **Why not `brew install openshell@0.0.85`?** Versioned formulae often don't
> exist, and `brew pin` only stops upgrades *after* the right version is
> installed. The release tarballs Brew wraps are the actual source of truth, so
> the fetcher goes straight there with checksums.

## Phased plan

### Phase 0 — pin a small base image (0.5 day)
- Switch the default sandbox image from the 1.1 GB nvidia community base to a
  minimal base (e.g. wolfi-base, ~6 MB) that still runs the poc reconcile
  binary, OR keep "pull on first run" as a fallback flag.
- Decide: **embed** the base as an OCI layout (offline, bigger bin) vs **pull**
  on first run (smaller bin, needs network once).

### Phase 1 — release artifacts + payload builder (1–2 days)
- `packaging/launcher/scripts/build-macos-payload.sh`:
  - `cargo build --release` the adapter, gateway, driver-vm (with
    `OPENSHELL_VM_RUNTIME_COMPRESSED_DIR` set so the runtime embeds).
  - Assemble payload dir: `{openbox-sandbox, openshell-gateway,
    openshell-driver-vm, entitlements.plist, policy-deny-network.yaml,
    policy-deny-network-dev.yaml, oci/}`.
  - `tar | zstd` → `payload.tar.zst`; emit a manifest with a content hash.

### Phase 2 — self-extract in the launcher (1–2 days)
- Add `packaging/launcher/src/selfextract.rs`:
  - locate the appended trailer in the running executable,
  - extract to `~/Library/Caches/openbox-sandbox/<hash>/` iff not already present,
  - ad-hoc codesign the driver-vm with the extracted entitlements,
  - return the dir; `bundle::resolve()` picks it up via `OPENBOX_BUNDLE_DIR`.
- Add a `--print-bundle` / `--extract-only` flag for debugging.

### Phase 3 — appender + final single binary (0.5 day)
- `append-payload` step: concatenate `launcher` + `payload.tar.zst` + trailer.
- Output `dist/openbox-sandbox-macos-arm64` — the single file.
- Smoke: `./openbox-sandbox --dry-run` (resolves from the embedded payload),
  then a real `--driver vm` create/exec/delete.

### Phase 4 — distribution track (Shape B) (1–2 days, when needed)
- Developer ID signing + hardened runtime + entitlements at build time.
- Notarize + staple; package as `.pkg`.
- CI job `release-macos-arm64` producing both the self-extracting bin and the
  notarized pkg.

## Honest caveats (must ship in the README/UX)

- **Landlock is best_effort on macOS.** The embedded libkrun guest kernel lacks
  `CONFIG_SECURITY_LANDLOCK`, so in-guest filesystem confinement is degraded
  (microVM isolation is still real). Strict Landlock needs a Linux host or a
  custom libkrunfw built with the `openshell.kconfig` (`CONFIG_SECURITY_LANDLOCK=y`).
  This is a *posture* caveat, not a packaging blocker.
- **Ad-hoc signing (Shape A) is local-only.** Distribution needs Shape B.
- **First run does real work** (extract + sign + generate-certs); subsequent runs
  are cache-fast.
- **This is macOS aarch64 only.** Linux keeps the container drivers; a single bin
  there still can't bundle a container runtime (the microVM avoids that, but the
  packaging effort is a separate track).

## Linux / WSL2 — same script, different driver, no entitlements

The fetch script is **interchangeable** across macOS, Linux, and WSL2: it detects the host triple and pulls the matching OpenShell release tarballs (`apple-darwin` / `unknown-linux-gnu` / `unknown-linux-musl`), verifying each against OpenShell's published `*-checksums-sha256.txt`. No per-platform hash edits.

Real differences (all in the launcher's existing detection, not the fetcher):

| | macOS | Linux native | WSL2 |
|---|---|---|---|
| Preferred driver | `vm` (libkrun + Hypervisor.framework) | `podman`/`docker` (container, **strict Landlock** if kernel has it) | `podman`/`docker` inside WSL2 (best-effort Landlock; the WSL2 kernel generally **lacks Landlock**) |
| `vm` driver hypervisor | Hypervisor.framework (entitlement) | `/dev/kvm` (no entitlement, no signing required) | nested KVM only if the Windows host enables it; otherwise `vm` is unavailable |
| Signing | ad-hoc + `com.apple.security.hypervisor` (brew/release already applies it) | **none** — Linux needs no entitlements or codesigning | **none** |
| Landlock | best_effort (guest kernel lacks it) | strict on kernels with `CONFIG_SECURITY_LANDLOCK`; else `--allow-degraded` | best_effort / degraded |
| Artifacts | `*-apple-darwin` tarballs | `*-unknown-linux-gnu` tarballs (gateway/driver), `*-unknown-linux-musl` (cli) | same as Linux |

So on Linux/WSL2:
- **No signing story at all** — the hypervisor entitlement is macOS-only; on Linux the `vm` driver just needs `/dev/kvm`, or you use the container drivers directly.
- **The container drivers are first-class**, not degraded-by-default like on macOS. Landlock is strict on a real Linux kernel with it.
- WSL2's kernel usually lacks Landlock, so the container path runs `--allow-degraded` there (namespaces/cgroups/seccomp still apply; only the Landlock layer is absent) — the same posture as the macOS container-in-VM path.

The startup `--version` pin guard (`src/pin.rs`) is identical on all platforms. A pin bump is still one edit: `REQUIRED_VERSION`.

### Why "same script" holds
- One fetch script, one pin manifest, one launcher. The triple is detected; the checksum file is downloaded per release and parsed for the matching asset; everything else is platform-neutral.
- The macOS signing/entitlement problem does not exist on Linux/WSL2, so the "no resign" question is moot there.

### What is NOT the same
- The **single self-contained binary** goal is macOS-specific in motivation (it exists because the container drivers are degraded on macOS). On Linux the container drivers are the real, strict path — a single bin is less valuable when Podman/Docker give you better isolation than the microVM. A Linux single bin would still need a container runtime as a dep, which a single file cannot bundle.
- So: **same fetch + same launcher + same pin; different "native" driver and no entitlement burden on Linux/WSL2.**

## Definition of done

`curl` one file, `chmod +x`, run it, and get a working mTLS OpenShell gateway on
the microVM driver — CONSTRAIN → run_in_sandbox executes in a real microVM,
exit 0, cleanup deleted — with **no** Homebrew/OpenShell/Podman/Docker installed
first.
