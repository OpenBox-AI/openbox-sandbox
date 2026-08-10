# OpenBox Constrained Command Enforcement

## Overview

OpenBox can return `CONSTRAIN` for an action, but it does not execute the
action or enforce isolation. The runtime needs an enforcement layer that routes
constrained commands to a sandbox and never to the host.

OpenShell provides the first sandbox implementation, but the design remains
provider-neutral.

## Objective

A command that receives `CONSTRAIN` executes in a sandbox or not at all. It
never executes on the host.

The runtime makes at most one dispatch attempt per logical command. It never
retries or switches executors after a possible dispatch.

## Component Boundary

The runtime package owns the sole public command-execution entry point:

```text
GovernedDispatcher.execute(Command)
```

The dispatcher keeps host and sandbox executor capabilities private. Runtime
command call sites cannot access either executor directly.

OpenBox Sandbox remains sandbox-only. It does not call OpenBox, interpret
verdicts, or execute host commands.

Only the dispatcher process may access the OpenBox Sandbox runtime credential.

## Supported Action

Version 1 supports non-interactive commands:

```text
Command {
  argv: string[]
  timeout_seconds?: number
}
```

Before governance, the dispatcher validates and snapshots one immutable
effective command:

```text
EffectiveCommand {
  argv: nonempty string[]
  timeout_seconds: 1..300
}
```

The default timeout is 30 seconds.

The dispatcher:

- preserves each `argv` element exactly, including empty elements;
- rejects NUL characters and input above configured size limits;
- never converts `argv` into a shell string;
- closes `stdin`;
- disables TTY allocation;
- accepts no caller-provided environment, working directory, mounts, or
  credentials; and
- rejects every unsupported field or action type.

Version 1 never modifies a command. Any remediation or patch directive causes
no execution. Future remediation must create a new action and obtain a new
governance decision.

## Governance Request

The dispatcher assigns a stable `dispatch_id` to each logical command.

It sends a canonical `ActivityStarted` request:

```yaml
activity_id: "<dispatch_id>"
activity_type: "openbox.command.v1"
activity_input:
  schema_version: 1
  argv:
    - "<argument>"
  timeout_seconds: 30
```

The dispatcher computes an internal digest from the canonical effective
command. It sends the same immutable command snapshot to the selected executor.

The governance client returns the response directly to the dispatcher. Callers
cannot supply a separate or cached decision.

The dispatcher accepts only an authoritative response from the evaluation call
for that `dispatch_id`. It rejects:

- missing or malformed responses;
- unknown verdicts;
- stale or mismatched responses;
- synthetic or fallback decisions;
- `fallback_used: true`;
- conflicting `action` and `verdict` fields;
- failed guardrails;
- invalid constraint shapes; and
- remediation or patch directives.

Any rejected response selects no executor.

## Governance Behavior

| OpenBox result | Runtime behavior |
| --- | --- |
| `ALLOW` | Make at most one host dispatch attempt. |
| `CONSTRAIN` | Make at most one sandbox dispatch attempt. |
| `REQUIRE_APPROVAL` | Execute nowhere. |
| `BLOCK` | Execute nowhere. |
| `HALT` | Execute nowhere. |
| Invalid, fallback, or unauthoritative response | Execute nowhere. |

Only an authoritative `ALLOW` may select the host.

The dispatcher returns a terminal or indeterminate result to the caller. The
caller must not execute the command after receiving that result.

## At-Most-Once Dispatch

Each logical command uses one stable `dispatch_id`.

Before the dispatcher invokes an executor, it records a durable may-dispatch
state.

Duplicate, concurrent, replayed, or restarted calls with the same `dispatch_id`
do not invoke an executor again. They return the stored terminal result when
available. Otherwise, they return an indeterminate result.

After a possible dispatch, the dispatcher:

- never calls the same executor again;
- never switches to another executor;
- never creates a second sandbox lifecycle for that command; and
- never relies on an outer workflow or activity retry.

The durable record stores identifiers, state, and the command digest. It does
not store raw `argv`, `stdout`, `stderr`, or credentials.

## CONSTRAIN Behavior

`CONSTRAIN` always selects sandbox execution.

This remains true when `constraints` is omitted, `null`, or empty.

Version 1 supports no nonempty constraint directives:

- omitted, `null`, or empty constraints select the pinned deny-network policy;
- every nonempty constraint collection fails closed; and
- unknown fields, values, types, or combinations fail closed.

The runtime never builds policy documents from governance response data.

Sandbox creation, readiness, execution, timeout, transport, or cleanup failures
never cause host execution.

## Sandbox Policy

The deployment supplies a trusted, immutable sandbox asset bundle containing:

- a digest-pinned sandbox template;
- a policy ID and version;
- the exact policy document;
- the policy document SHA-256 digest; and
- provider compatibility information.

The default policy:

- denies network access;
- exposes no host mounts, files, credentials, sockets, devices, or provider
  configuration;
- permits writes only in the sandbox working directory;
- runs the process as an unprivileged user and group;
- applies filesystem, process, namespace, capability, and syscall restrictions;
- applies CPU, memory, process-count, disk, and output limits; and
- requires full isolation support in production.

Production deployments must not use degraded or best-effort isolation.

Before execution, the provider must attest that the expected policy ID,
version, body hash, and template are active.

## Sandbox Provider Requirements

A sandbox provider must support:

- creation with an explicit pinned template and policy;
- readiness and exact policy attestation;
- exact `argv` execution without shell reconstruction;
- bounded `stdout` and `stderr` collection;
- terminal exit reporting;
- filesystem, process, resource, and network isolation;
- request-owned cleanup;
- deletion; and
- confirmation of terminal absence.

Version 1 creates one fresh sandbox for each constrained command.

## Sandbox Lifecycle

The dispatcher uses this lifecycle:

```text
create
-> wait for workload and policy readiness
-> dispatch command once
-> delete
-> confirm terminal absence
```

The dispatcher creates and stores a request-owned cleanup ID before any create
call that could reach the provider.

Creation results define cleanup authority:

| Creation state | Cleanup behavior |
| --- | --- |
| `NotCreated` | Do not delete. |
| `Conflict` | Do not delete. |
| Created | Delete and confirm absence. |
| `PossiblyCreated` | Delete and confirm absence. |

Cleanup uses independent deadlines and continues after caller cancellation.

If cleanup cannot confirm terminal absence, the runtime retains durable
reconciliation state and reports `pending_reconciliation`. A later cleanup
attempt may continue, but it must never dispatch the command again.

Cleanup failure does not hide or replace the original execution result.

## Result

The caller receives a tagged result with independent fields:

```text
GovernedCommandResult {
  governance
  selected_executor
  dispatch_state
  execution_outcome
  timeout_state
  cleanup_state
  error?
}
```

The fields use these values:

```text
selected_executor:
  none | host | sandbox

dispatch_state:
  not_dispatched | possibly_dispatched | completed

timeout_state:
  not_observed | possible | confirmed | unknown

cleanup_state:
  not_needed | confirmed_absent | pending_reconciliation
```

For valid governance responses, `governance` contains the unchanged OpenBox
decision.

Only `completed` carries:

- bounded raw `stdout` bytes;
- bounded raw `stderr` bytes; and
- an observed nonnegative exit code.

Indeterminate failures return output byte counts rather than partial output
bodies.

Exit code `124` alone indicates only a possible timeout. It does not prove one.

Errors use stable codes and identify the failed phase. Callers must not inspect
error messages to determine behavior.

## OpenShell Reference Implementation

OpenShell provides the first sandbox adapter.

The adapter handles:

- policy-bearing creation;
- exact readiness and policy checks;
- buffered, bounded output;
- ambiguous timeout exit `124`;
- missing terminal-exit events;
- transport failures before and after possible dispatch; and
- request-owned deletion and terminal-absence checks.

The dispatcher, adapter, and runtime must not log raw `argv`, `stdout`, or
`stderr`. Production deployments must disable or redact provider
command-preview logs.

OpenShell-specific behavior remains inside the adapter.

## Security Requirements

- `CONSTRAIN` never reaches the host executor.
- Only authoritative `ALLOW` reaches the host executor.
- Invalid or fallback governance selects no executor.
- The dispatcher uses the same immutable command for governance and execution.
- Executors receive `argv` directly and never through a shell.
- Each `dispatch_id` causes at most one possible execution dispatch.
- Retries and restarts never cause a second dispatch.
- Sandbox policy mappings never weaken the security baseline.
- Sandboxes receive no host files, mounts, credentials, provider settings, or
  control sockets.
- The default sandbox policy denies network access.
- Cleanup deletes only request-owned sandboxes.
- Ownership conflicts never grant deletion authority.
- Sensitive command and output content never enters logs or durable dispatch
  records.

## Success Criteria

- A valid `CONSTRAIN` decision with omitted, `null`, or empty constraints
  causes one sandbox commit and zero host calls.
- Every `CONSTRAIN` case causes zero host calls, including all sandbox
  failures.
- A valid `ALLOW` decision causes at most one host dispatch and zero sandbox
  commits.
- Unsupported actions, invalid decisions, fallback decisions, failed
  guardrails, nonempty constraints, and remediation directives execute nowhere.
- The command sent to OpenBox matches the command sent to the executor element
  by element, including the effective timeout.
- Adversarial `argv` containing spaces, quotes, dollar signs, and shell
  metacharacters receives no shell reinterpretation.
- Lost responses, cancellations, duplicate calls, concurrent calls, and process
  restarts never cause a second dispatch.
- Sandbox transport failure after possible dispatch returns an indeterminate
  result and causes no retry.
- `stdout`, `stderr`, exit code, timeout evidence, dispatch state, and cleanup
  state remain independent and correct.
- Cleanup uses only the retained request-owned ID.
- Ownership conflicts never delete foreign sandboxes.
- Cleanup state survives cancellation and process restart.
- End-to-end tests deny DNS and TCP egress.
- End-to-end tests deny reads and writes to controlled host sentinel paths
  outside the sandbox workspace.
- End-to-end tests verify process and resource isolation.
- The OpenShell adapter passes the same provider-neutral lifecycle and
  isolation suite.

## Non-Goals

- OpenBox protocol changes
- Human approval handling
- Command remediation
- Sandbox reuse
- Interactive execution
- General tool-call translation
- Streaming or unbounded output
- Caller-provided environment, `stdin`, working directory, mounts, or
  credentials
- Standardization of every provider-specific feature in version 1

## References

- Current verdict semantics: `openbox-core/internal/content/governance.go`
- Provider-neutral sandbox contract: `src/runtime_contract/`
- Durable dispatch boundary: `src/service/boundary.rs`
- Provider conformance suite: `src/test_support/conformance.rs`
- OpenShell SDK: `OpenShell/crates/openshell-sdk/`
- OpenShell protocol: `OpenShell/proto/openshell.proto`
