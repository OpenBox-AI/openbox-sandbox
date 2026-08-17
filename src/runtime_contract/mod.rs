//! Provider-neutral sandbox runtime contract values.
//!
//! Defines validated requests, lifecycle type states, terminal results, and typed failure
//! invariants. It intentionally contains no provider adapter, runtime I/O trait,
//! governance dispatcher, language binding, or orchestration-framework integration.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod error;
mod request;
mod result;
mod runtime;
#[cfg(feature = "serde")]
mod serde_base64;
mod state;
mod validation;

pub use error::{
    CleanupFailure, CleanupFailureCode, CreateFailure, CreateFailureCode, ExecFailure,
    ExecFailureCode, OperatorDetail, OutputLimitKind, ReadinessFailure, ReadinessFailureCode,
};
pub use request::{
    Argv, CommandTimeout, CreateRequest, ExecRequest, OperationContext, OperationDeadline,
    OutputLimits, PolicyDocument, PolicyIdentity, RequestOwnedId, SANDBOX_WORKDIR, Sha256Digest,
    TemplateIdentity,
};
pub use result::{
    DeleteOutcome, EgressDecision, EgressDecisionKind, ExecCompleted, ObservedExitCode,
    OutputByteCounts, SandboxEvidence, ViolationCategory, ViolationEvidence,
};
pub use runtime::SandboxRuntime;
pub use state::{
    CleanupState, CleanupTarget, CreatedSandbox, CreationState, DispatchState, FailureTimeout,
    ObservedTimeout, OpaqueProviderHandle, ProviderCapability, ReadySandbox,
};
pub use validation::{ValidationCode, ValidationError};
