# Docker Sandboxes runtime — design note

This note records the design of the **Docker Sandboxes** execution runtime
(`DockerSandboxesRuntime` in `src/docker_sandboxes/`), a selectable second
implementation of the provider-neutral `SandboxRuntime` trait. It drives
Docker's standalone **`sbx`** CLI (the Docker Sandboxes product,
docs.docker.com/ai/sandboxes) instead of the `OpenShell` gateway.

Related material: `docs/research/docker-sandboxes.md` (on the
`research/docker-sandboxes` branch) covers the *OpenShell* docker compute
driver; this note covers Docker Inc.'s **Docker Sandboxes** product, which is a
different surface (its own CLI, its own microVM runtime, its own `sandboxd`
daemon). Do not conflate the two.

---

## 1. The product surface (what we drive)

Docker Sandboxes runs each sandbox as a **microVM with its own Docker daemon,
filesystem, and network**. Sandboxes persist until removed; a workspace host
directory is mounted into the VM at its host absolute path (filesystem
passthrough), and outbound traffic routes through a host-side proxy governed
by network access policies (`sbx policy`). Docker Desktop is **not** required;
the standalone CLI talks to a local `sandboxd` daemon over a Unix socket.

There is **no documented third-party daemon/API** for driving sandboxes
programmatically — the supported programmatic surface is the `sbx` CLI itself.
This adapter therefore shells out to the CLI, exactly like established
third-party integrations (e.g. the reference programmatic driver documented in
Crabbox's provider docs). The adapter targets the following `sbx` contract
(validated against `sbx` v0.38.0; minimum supported `v0.31.3`):

| Operation | Command |
|---|---|
| Probe | `sbx version` (local, no auth) |
| Ownership preflight / list | `sbx ls --json` |
| Create | `sbx create --name <id> --template <image> --quiet shell <workspace>` |
| Exec | `sbx exec [--user <u>] --workdir <dir> <name> <argv...>` |
| Remove | `sbx rm --force <name>` |

`sbx create` requires an agent positional; `shell` is the generic agent and is
fixed by the adapter. The workspace path is required by the CLI and comes from
the service configuration. `sbx ls --json` accepts both a top-level array and
an object wrapper (`sandboxes`/`items`/`data`/`results`) with name/status field
variants (`name`/`Name`/`sandboxName`/`sandbox_name`,
`status`/`state`/`Status`/`State`); the parser accepts the same variants so
output renames don't break the adapter.

**Authentication**: sandbox operations require a Docker account
(`sbx login`, OAuth). `sbx version` does not. Non-zero stderr bodies are
classified against conservative markers (`sign in to Docker`,
`not authenticated`, `401 unauthorized`, `no valid user session`) and mapped to
typed `Auth`/`Transport` failures; raw stderr never leaves the adapter.

**One-time host setup** (deployment concern, not runtime code):
`sbx policy init <allow-all|balanced|deny-all>` initializes the global network
policy — without it, the first sandbox start prompts interactively. The OBS
default posture (`policy-deny-network`) maps to `sbx policy init deny-all`.

---

## 2. Trait mapping

The `SandboxRuntime` contract (`src/runtime_contract/runtime.rs`) is preserved
exactly: the readiness deadline, the exec deadline, output ceilings, and the
confirmed delete all keep their semantics. Each method maps as follows.

### `create(CreateRequest, OperationContext)`

1. **Local validation** (before any submission → `NotCreated`):
   - the request-owned id must be a valid `sbx` sandbox name (the
     `sbx-<15-hex>` shape always is);
   - the template must be an immutable `repository@sha256:<64hex>` reference
     (same rule as the OpenShell adapter; the deployment's bundle template is
     the image source, and an optional `docker_sandboxes.template` config pin
     must match the request exactly);
   - the policy document must be `application/yaml` and its SHA-256 must match
     the expected identity (integrity proof — see §3 for what this does *not*
     claim).
2. **Ownership preflight**: `sbx ls --json`; a listed name is a `Conflict`
   (cleanup forbidden). Preflight failures are `NotCreated`.
3. **Submission**: `sbx create --name <request_id> --template <image> --quiet
   shell <workspace>`. A spawn failure is `NotCreated`; a non-zero exit or a
   budget cancellation/deadline after the process started is `PossiblyCreated`
   (the CLI may have committed before failing) with mandatory cleanup by the
   retained request id. Success returns a `CreatedSandbox` whose opaque
   provider handle carries the sandbox name.

The preflight mirrors the OpenShell adapter's `get_sandbox` preflight: it
detects pre-existing names before submission so `Conflict` never deletes an
unowned sandbox.

### `wait_ready(CreatedSandbox, expected_policy, OperationContext)`

Polls `sbx ls --json` at the configured poll interval until the sandbox status
is `running` (the VM is booted), bounded by the operation deadline:

- `running` → readiness probe (if configured; see below) → attest;
- `stopped`/`created`/`starting`/`provisioning`/`pending`/`initializing` or
  absent → poll again (absence may be mid-registration; the deadline bounds
  it);
- `error`/`failed`/`degraded` → `WorkloadError`;
- any other status string → `Protocol` (deterministic failure, no guessing).

The optional `exec_profile.readiness_probe` argv is executed once status is
`running`; readiness is attested only when it exits zero (a failed probe is a
`WorkloadError`). Without a probe, `running` is the readiness attestation.

Policy attestation: see §3.

### `exec(ReadySandbox, ExecRequest, OperationContext)`

Exactly one `sbx exec` with:

- **argv** appended element-for-element (no shell quoting), with
  `--workdir` from the exec profile (default `/sandbox`, the contract
  workdir) and `--user` from the exec profile when set;
- **exec deadline** enforced by this adapter: the child runs under the
  operation budget; on cancellation/deadline the process is killed
  (kill-on-drop guard, no orphans) and the result is a `PossiblyDispatched`
  failure with `FailureTimeout::Unknown` and the byte counts observed so far;
- **output ceilings** enforced *during* capture (per-stream, combined, and
  chunk ceilings, same arithmetic as the OpenShell `OutputCollector`); the
  first overflow kills the child and returns
  `ExecFailure::output_limit_exceeded` with the counts;
- **exit code** propagated by `sbx exec` → `ExecCompleted` with the observed
  code (124 → `ObservedTimeout::Possible`, mirroring the OpenShell mapping);
  a process killed by signal (no exit code) → `MissingTerminalExit`.

CLI-vs-command ambiguity (inherent to CLI driving): a non-zero `sbx exec` exit
is normally the command's propagated exit code, but if stderr carries a
distinctive Docker Sandboxes marker (`no such sandbox`, auth phrases) the
result is a `PossiblyDispatched` `Transport` failure instead — the sandbox was
not there to run the command. The marker set is deliberately conservative so a
command that merely *prints* `command not found` is never misclassified (that
phrase is not in the set).

One documented semantic nuance: `sbx exec` auto-starts a *stopped* sandbox.
The service boundary only calls `exec` on attested-ready sandboxes, and
`wait_ready` requires `running`, so in the normal flow exec never auto-starts;
if the sandbox is stopped by an outside actor between readiness and exec, the
exec still dispatches (auto-start) and is classified `PossiblyDispatched` on
failure — safe, never a silent retry.

### `delete(CleanupTarget, OperationContext)` / `wait_deleted(...)`

- `delete` → `sbx rm --force <name>` (non-interactive; the CLI also handles
  in-use sandboxes). Success → `Deleted`; a stderr absence hint
  (`no such sandbox`/`not found`) → `AlreadyAbsent`; other failures →
  `CleanupFailure` preserving the retained target.
- `wait_deleted` polls `sbx ls --json` until the name is absent (deadline →
  `CleanupFailure::Deadline`). `sbx stop` is deliberately **not** used: it
  retains sandbox state, which is not "terminal absence".

---

## 3. Policy: what is attested, and what is not

Docker Sandboxes has **no OpenShell-compatible supervisor policy engine**
(no Landlock/seccomp/OPA policy delivery). The adapter cannot attest
in-sandbox policy enforcement, and it says so honestly:

- `create` verifies the policy document's media type and SHA-256 against the
  expected identity (integrity: the request carries the attested document);
- the optional `docker_sandboxes.policy` config pin is the deployment's
  attestation anchor: `wait_ready` fails with `PolicyMismatch` unless the
  request's expected policy equals the pin exactly;
- `ReadySandbox::attest` therefore transitions on the *deployment-pinned*
  identity, not on an observed in-sandbox policy.

Isolation itself is provided by the Docker Sandboxes microVM boundary (separate
kernel, own daemon/filesystem/network) plus whatever network policy the host
operator configured via `sbx policy init`. Operators who need OpenShell-grade
per-sandbox policy attestation must keep the `openshell` runtime kind.

---

## 4. Config wiring

The service config (`src/config.rs`) gains a `runtime_kind` field
(`"openshell"` default — existing configs and the bootstrap/provision scripts
are unchanged — or `"docker-sandboxes"`) and an optional
`docker_sandboxes` section:

```json
{
  "runtime_kind": "docker-sandboxes",
  "runtime_connect_timeout_ms": 10000,
  "runtime_poll_interval_ms": 500,
  "docker_sandboxes": {
    "sbx_binary": "/usr/local/bin/sbx",
    "workspace": "/var/lib/openbox-sandbox/workspace",
    "template": "registry.example/openbox/sandbox@sha256:REPLACE_WITH_IMAGE_SHA256",
    "policy": { "id": "openbox-deny-network", "version": 1,
                "sha256": "REPLACE_WITH_POLICY_SHA256" },
    "exec_profile": {
      "user": "sandbox",
      "workdir": "/sandbox",
      "readiness_probe": ["/bin/true"]
    }
  }
}
```

Validation rules (strict, in the repo's style):

- `"openshell"` kind: `runtime_endpoint` + `runtime_mtls_directory` required,
  `docker_sandboxes` must be absent.
- `"docker-sandboxes"` kind: the OpenShell fields must be absent (no dead
  config), `docker_sandboxes` required.
- `sbx_binary`: bare name (resolved from `PATH`) or absolute owner-controlled
  regular file (no symlink components, no group/world-writable bits).
- `workspace`: absolute, existing directory, no symlink components. Ownership
  is intentionally **not** required — the sandbox workload, not the service
  user, is the reader/writer of the shared mount.
- `template`: optional immutable `@sha256:` pin that every create request must
  match.
- `policy`: optional `PolicyIdentity` pin (see §3).
- `exec_profile.user`: name/uid/`uid:gid` charset, no whitespace/paths.
- `exec_profile.workdir`: absolute (default `/sandbox`).
- `exec_profile.readiness_probe`: non-empty argv (default unset).

`main.rs` selects the runtime: `RuntimeKind::Openshell` builds the existing
`OpenShellConfig`/`OpenShellRuntime`; `RuntimeKind::DockerSandboxes` builds
`DockerSandboxesConfig` (library-side validation, same
`runtime_connect_timeout_ms` for the `sbx version` probe and
`runtime_poll_interval_ms` for readiness/deletion polling) and connects via
`DockerSandboxesRuntime::connect` — a `sbx version` probe that rejects
binaries older than the supported baseline and reports
`BinaryUnavailable`/`VersionProbeFailed`/`UnsupportedVersion` distinctly.
`--check-config` validates the config without contacting the runtime, exactly
as for OpenShell.

---

## 5. Process model and failure classification

`src/docker_sandboxes/runner.rs` owns all subprocess I/O:

- every `sbx` invocation runs with stdin null and piped stdout/stderr under
  the operation budget; a kill-on-drop guard guarantees a cancelled future
  never orphans the child;
- short commands (`version`, `ls`, `create`, `rm`) capture up to a 1 MiB
  ceiling and report `SbxRunFailure::{Spawn, Cancelled, Deadline, NonZero}`;
- `exec` captures concurrently with per-stream/combined/chunk ceilings shared
  between the two reader tasks, and reports `ExecCapture` (exit code, bounded
  bodies, overflow kind, counts, timeout evidence, stderr hints).

Classification maps onto the contract's ownership discipline:

| Situation | Outcome |
|---|---|
| Spawn failure (any verb) | `NotCreated`/`NotDispatched`/`CleanupFailure`, `Transport` |
| Auth markers on stderr | `Auth` (create) / `Transport` (exec, readiness, cleanup) |
| Create non-zero after start | `PossiblyCreated` (cleanup by retained id) |
| Preflight name collision | `Conflict` (no cleanup) |
| Budget cancel/deadline mid-exec | `PossiblyDispatched` + `Unknown` timeout + counts |
| Output ceiling hit | `OutputLimitExceeded` + counts |
| Exit 124 | `ExecCompleted`, `ObservedTimeout::Possible` |
| Signal death (no exit code) | `MissingTerminalExit` |
| `rm` of an absent sandbox | `AlreadyAbsent` |

---

## 6. Testing

- **Unit tests** (`src/docker_sandboxes/process.rs`, `config.rs`, `policy.rs`,
  `provider.rs`, `runner.rs`, `operations.rs`): argv construction (exact
  command lines, flag-before-name ordering, no shell quoting), `sbx ls --json`
  tolerant parsing, version parsing/gating, stderr classification, config
  validation (kind exclusivity, binary/workspace/user/workdir/probe/template
  rules), bounded capture ceilings, connect probing (via a fake `sbx` script
  in a tempdir — hermetic, no Docker account needed), and failure mapping.
- **Conformance suite** (`src/docker_sandboxes/conformance_tests.rs`): the
  unchanged 20-scenario provider-neutral suite runs against the adapter with a
  scripted `SbxRunner`, mirroring the OpenShell adapter's scripted-transport
  harness — operation order, create-submission counts, exact argv, no-exec-
  retry, cleanup ownership, and per-scenario results are all asserted. The
  scripted runner models provider behavior including a confirmed-timeout
  event; the real runner's honest mapping is 124 → `Possible` (the CLI offers
  no confirmed-timeout signal — see §7).
- **Live tests** (`tests/live_docker_sandboxes.rs`): env-gated
  (`OPENBOX_LIVE_DOCKER_SANDBOXES_IMAGE`), skipped by default; they drive a
  real create → wait_ready → exec → delete → wait_deleted lifecycle and assert
  real microVM evidence (`uname -a` contains `Linux`) and real exit-code
  propagation (`exit 42`).

## 7. Live smoke test steps (exact)

On macOS (verified on this machine for install + daemon; the remaining blocker
is the Docker account):

```sh
# 1. Install the CLI (Homebrew tap)
brew trust docker/tap && brew install docker/tap/sbx
sbx version                      # e.g. "sbx version: v0.38.0 <commit>"

# 2. One-time host setup
sbx daemon start                 # or let it auto-start on first command
sbx login                        # Docker account OAuth — REQUIRED for sandbox ops
sbx policy init deny-all         # one-time global network policy (no prompts)
sbx diagnose                     # all checks pass

# 3. Smoke the CLI by hand (optional but recommended)
sbx create --name smoke-1 --template <image> --quiet shell <workspace-dir>
sbx ls --json                    # smoke-1 → "running"
sbx exec smoke-1 uname -a        # Linux microVM kernel banner
sbx exec smoke-1 sh -c 'exit 42'; echo $?   # 42 must propagate
sbx rm --force smoke-1           # confirmed removal
sbx ls --json                    # absent

# 4. Drive the adapter end-to-end
cargo test --all-features --test live_docker_sandboxes -- --nocapture \
  --skip 'does_not_exist'   # or set env vars and run the two live tests:
OPENBOX_LIVE_DOCKER_SANDBOXES_IMAGE='<repo>@sha256:<64hex>' \
  cargo test --all-features --test live_docker_sandboxes -- --nocapture

# 5. Full service with the docker runtime (see deploy/openbox-sandbox.docker-sandboxes.example.json)
#    OPENBOX_SANDBOX_CONFIG=... ./target/debug/openbox-sandbox --check-config
```

Live verification checklist: (a) `sbx ls --json` status vocabulary is exactly
`running`/`stopped` (the adapter's status table depends on it); (b) `sbx exec`
propagates the command exit code and does not print a banner to captured
stderr; (c) `sbx rm --force` on a missing sandbox exits non-zero with a
`no such sandbox` message; (d) image pull of an `@sha256:` reference through
`--template` works.

## 8. Known limitations / deliberate acceptances

- **No in-sandbox policy attestation** (see §3) — the microVM boundary and
  host network policy are the containment story.
- **CLI-driving ambiguity** — exit codes and stderr are shared channels
  between `sbx` and the command; the conservative marker classification is
  documented per operation.
- **Confirmed timeout evidence is not producible** from the CLI; 124 maps to
  `Possible`. Deployments needing confirmed timeouts must wrap exec argv in a
  supervisor that reports them.
- **One runtime per process** — `runtime_kind` is a startup choice, not a
  per-request multiplexer.
- **Status vocabulary drift** — `sbx ls --json` status strings are not a
  versioned API; the adapter fails deterministically (`Protocol`) on unknown
  statuses rather than guessing.
- **Not exercised live on this machine** — install, daemon start, and
  `sbx version` were verified, but every sandbox operation requires
  `sbx login` (a Docker account), so the lifecycle was proven only through the
  unit + conformance surface. The exact live steps are in §7.
