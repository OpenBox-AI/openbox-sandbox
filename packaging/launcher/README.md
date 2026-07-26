# openbox-sandbox single-binary launcher

One launcher binary per OS/arch. It detects the available OpenShell **compute
driver**, resolves the real gateway/CLI/policy artifacts, and starts the
OpenShell gateway. Override the driver with `--driver`; preview without starting
anything with `--dry-run`.

## Drivers

| Driver (`--driver`) | Needs | Notes |
|---|---|---|
| `podman` | Podman | Rootless container; preferred container path. |
| `docker` | Docker | Container with a root daemon (bigger privileged surface). |
| `kubernetes` | `kubectl` + a cluster | Sandboxes delegated to the cluster. |
| `vm` | A hypervisor only | **libkrun microVM** — KVM on Linux, Hypervisor.framework on macOS. Self-contained: embeds its runtime + guest kernel, needs **no container runtime**. |

So the only hard dependency is **one of**: Podman, Docker, a Kubernetes cluster, or a
hypervisor (for the microVM driver).

## Platform behavior

| Platform | Result |
|---|---|
| Linux | Any driver. Container path uses Landlock (**strict**) or **best_effort** when the kernel lacks it. microVM needs `/dev/kvm`. |
| macOS | The **microVM (`vm`) driver is the real target** (Apple Hypervisor.framework, own guest kernel). Container drivers only run **degraded** inside the runtime's VM and require `--allow-degraded`. |
| Windows | Unsupported directly; run inside **WSL2**. |

The container-degraded tier maps to the `allow_degraded_landlock` service flag and
`policy-deny-network-dev.yaml` (`best_effort`); namespaces, cgroups, and seccomp still
apply, only the Landlock layer is absent.

## Artifact resolution

For each artifact (`openshell-gateway`, `openshell`, `policy-deny-network.yaml`,
`policy-deny-network-dev.yaml`) the launcher probes, in order:

1. `$OPENBOX_BUNDLE_DIR/<name>` — an operator-provided bundle directory.
2. A platform install prefix (`/opt/homebrew/opt/openshell`, `/usr/local`, ...).
3. `PATH` (for the two binaries).
4. The in-repo build/deploy tree, so `cargo run` works from a source checkout.

A future self-extracting build can populate `$OPENBOX_BUNDLE_DIR` from an
appended payload before resolution; nothing else changes. See `src/bundle.rs`.

## Build / run

```sh
cd packaging/launcher
cargo run -- --dry-run             # detect, resolve artifacts, print the plan
cargo run -- --driver vm           # start the OpenShell gateway with the vm driver
cargo run -- --driver podman --allow-degraded
cargo run -- --help
```

`--dry-run` resolves everything and prints the plan without starting a process.
Without it, the launcher execs the resolved gateway in the foreground and exits
with the gateway's status.

Driver detection/selection, posture, artifact resolution, and gateway launch
pass `clippy -D warnings` + `fmt`. A single binary cannot bundle the Linux
kernel or a container runtime; the microVM driver avoids that dependency by
using libkrun.
