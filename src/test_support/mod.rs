//! Deterministic test support for provider-neutral sandbox runtime conformance.
//!
//! This crate contains no production dispatcher, governance logic, host executor, provider
//! adapter, or real I/O.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod conformance;
mod fake;
mod fixtures;
mod lifecycle_driver;

pub use conformance::{
    ConformanceCase, ConformanceFailure, ConformanceHarness, ConformanceObservation,
    ConformanceObserver, ConformanceOperation, ConformanceReport, ConformanceScenario,
    FakeConformanceHarness, run_conformance_suite,
};
pub use fake::{
    FakeCreatePlan, FakeDeletePlan, FakeExecEvent, FakeExecPlan, FakeReadinessPlan, FakeRecording,
    FakeSandboxRuntime, FakeScript, FakeWaitDeletedPlan, FixedIdGenerator, RecordedCall,
};
pub use fixtures::{
    adversarial_argv, cancelled_exec_contexts_fixture, create_request_fixture,
    exec_request_fixture, lifecycle_contexts_fixture, output_limits_fixture, policy_fixture,
    raw_stderr_fixture, raw_stdout_fixture, request_id_fixture,
};
pub use lifecycle_driver::{
    LifecycleAttempt, LifecycleCleanup, LifecycleContexts, LifecycleOutcome, run_lifecycle,
};
