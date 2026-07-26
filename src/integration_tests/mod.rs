//! UNIT TESTS ONLY — NOT SYSTEM VALIDATION.
//!
//! This module uses `FakeSandboxRuntime` / fake transports. A green result
//! here proves LOGIC in isolation, not that the broker actually works against
//! a real OpenShell gateway. Under the standing "no fake tests in production"
//! rule, do not report passing counts from this module as "validated" or
//! "integration proven". Real coverage lives in `tests/live_openshell.rs`.

mod boundary;
mod client_conformance;
mod failure_invariants;
mod protocol;
mod restart;
mod runtime_validation;
mod serde_roundtrip;
mod store;
mod tls_boundary;