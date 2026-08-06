# Context and Glossary

This file defines the shared vocabulary for this repository. It is intentionally
free of implementation detail: it fixes what the terms *mean*, not how they are
built.

## OpenBox Sandbox (OBS)

OpenBox Sandbox is the project. Its production-intent component is the
`openbox-sandbox` mTLS service that runs untrusted work inside an isolated
sandbox by driving an external OpenShell gateway/driver runtime. The
operator/developer launcher — the `obs` executable — locates, pins, and runs the
externally-provided OpenBox and OpenShell artifacts; it never embeds them.

"OBS" refers to the project and its sandbox as a whole. It does **not** refer to
the launcher command alone (`obs`) or to the service binary (`openbox-sandbox`).

## Sandbox policy

Sandbox policy is the set of isolation and security constraints under which a
sandboxed operation is allowed to run — what the workload may access and the
degree of isolation the environment must provide. It governs *whether and how*
an operation is permitted to execute. It is a security/containment concern.

## Retry policy

Retry policy is the set of rules governing whether and how an operation may be
*re-attempted* after a failure. It governs *re-execution over time*, not
containment.

Retry policy is distinct from sandbox policy: sandbox policy constrains a single
execution's isolation, while retry policy decides whether another execution
attempt happens at all. A change to one does not imply a change to the other.

## Possible dispatch

An operation is a **possible dispatch** when it may have reached the provider but
its outcome is indeterminate — the system cannot prove whether it took effect.

A possible dispatch is **not safe for automatic redispatch**: re-attempting it
automatically could cause the operation to take effect more than once. Retry
policy must treat a possible dispatch as ambiguous and must not silently retry
it; any recovery requires evidence that the original attempt did not take effect.
