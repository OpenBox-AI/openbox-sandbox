//! TEST SUPPORT IS NOT SYSTEM VALIDATION BY DEFAULT.
//!
//! Most tests in this module use `FakeSandboxRuntime` or fake transports and
//! prove logic in isolation. `live_service` is the explicit exception: when its
//! endpoint environment is configured, it exercises the running mTLS service
//! and external `OpenShell` gateway. Do not report an ordinary `cargo test` as
//! live validation because the live test skips when no endpoint is configured.

mod boundary;
mod client_conformance;
mod dispatcher;
mod failure_invariants;
mod live_service;
mod protocol;
mod restart;
mod runtime_validation;
mod serde_roundtrip;
mod store;
mod tls_boundary;
