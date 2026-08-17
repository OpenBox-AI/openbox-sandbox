//! Client-side `OpenBox` sandbox service.
//!
//! One private package contains the strict runtime contract, authenticated wire
//! boundary, durable lifecycle owner, and pinned `OpenShell` provider adapter.

#![forbid(unsafe_code)]

mod dispatcher;
#[cfg(test)]
mod integration_tests;
mod openshell;
mod protocol;
mod runtime_contract;
mod service;
mod srt;
#[cfg(test)]
mod test_client;
#[cfg(test)]
mod test_support;

pub use dispatcher::{
    ActivityStarted, Command, CommandSizeLimits, DispatchId, DispatchReconciliationReport,
    DispatcherBuildError, DispatcherConfig, EffectiveCommand, ErrorPhase, ExecutionOutcome,
    GovernanceClient, GovernanceClientError, GovernanceOutcome, GovernanceRejection,
    GovernanceVerdict, GovernedCleanupState, GovernedCommandResult, GovernedDispatchState,
    GovernedDispatcher, GovernedError, GovernedErrorCode, HostExecutionFailure,
    HostExecutionFailureCode, HostExecutor, IsolationSupport, SandboxAssetBundle, SelectedExecutor,
    TimeoutState,
};
pub use openshell::{
    OPENSHELL_SOURCE_PIN, OpenShellConfig, OpenShellConnectError, OpenShellConnectErrorCode,
    OpenShellRuntime,
};
pub use protocol::{
    AssetBundleIdentity, BoundaryFailure, BoundaryFailureCode, CapabilityToken, DeadlineMillis,
    FrameError, HealthStatus, MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES, OperationId,
    PROTOCOL_VERSION, ProtocolValidationError, RequestEnvelope, ResponseEnvelope, ServiceRequest,
    ServiceResponse, decode_request, decode_response, read_request, read_response, write_request,
    write_response,
};
pub use runtime_contract::{
    Argv, CleanupFailure, CleanupFailureCode, CleanupState, CleanupTarget, CommandTimeout,
    CreateFailure, CreateFailureCode, CreateRequest, CreatedSandbox, CreationState, DeleteOutcome,
    DispatchState, EgressDecision, EgressDecisionKind, ExecCompleted, ExecFailure, ExecFailureCode,
    ExecRequest, FailureTimeout, ObservedExitCode, ObservedTimeout, OpaqueProviderHandle,
    OperationContext, OperationDeadline, OperatorDetail, OutputByteCounts, OutputLimitKind,
    OutputLimits, PolicyDocument, PolicyIdentity, ProviderCapability, ReadinessFailure,
    ReadinessFailureCode, ReadySandbox, RequestOwnedId, SANDBOX_WORKDIR, SandboxEvidence,
    SandboxRuntime, Sha256Digest, TemplateIdentity, ValidationCode, ValidationError,
    ViolationCategory, ViolationEvidence,
};
pub use service::{
    AuthValueError, CallerFingerprint, CallerIdentity, CallerRole, DurableRecord, DurableStage,
    DurableStore, ReconciliationReport, SandboxServiceBoundary, SandboxTlsServer, ServerError,
    StoreError, TlsServerConfig,
};
pub use srt::{SrtConfig, SrtConfigError, SrtRuntime, compile_srt_policy, sha256_file};
#[cfg(test)]
pub use test_support::{
    ConformanceCase, ConformanceFailure, ConformanceHarness, ConformanceObservation,
    ConformanceObserver, ConformanceOperation, ConformanceReport, ConformanceScenario,
    FakeConformanceHarness, FakeCreatePlan, FakeDeletePlan, FakeExecEvent, FakeExecPlan,
    FakeReadinessPlan, FakeRecording, FakeSandboxRuntime, FakeScript, FakeWaitDeletedPlan,
    FixedIdGenerator, LifecycleAttempt, LifecycleCleanup, LifecycleContexts, LifecycleOutcome,
    RecordedCall, adversarial_argv, cancelled_exec_contexts_fixture, create_request_fixture,
    exec_request_fixture, lifecycle_contexts_fixture, output_limits_fixture, policy_fixture,
    raw_stderr_fixture, raw_stdout_fixture, request_id_fixture, run_conformance_suite,
    run_lifecycle,
};

#[cfg(test)]
pub use test_client::{SandboxRuntimeClient, SandboxRuntimeClientConfig};
