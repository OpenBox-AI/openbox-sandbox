//! Reusable scenario-based conformance runner and fake harness.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{
    CleanupState, CreateFailureCode, CreateRequest, CreationState, DispatchState, ExecFailureCode,
    ExecRequest, FailureTimeout, ObservedTimeout, OutputLimitKind, OutputLimits,
    ReadinessFailureCode, RequestOwnedId, SandboxRuntime,
};

use crate::{
    FakeCreatePlan, FakeDeletePlan, FakeExecEvent, FakeExecPlan, FakeReadinessPlan,
    FakeSandboxRuntime, FakeScript, FakeWaitDeletedPlan, LifecycleAttempt, LifecycleContexts,
    LifecycleOutcome, RecordedCall, cancelled_exec_contexts_fixture, create_request_fixture,
    exec_request_fixture, lifecycle_contexts_fixture, output_limits_fixture, policy_fixture,
    raw_stderr_fixture, raw_stdout_fixture, run_lifecycle,
};

/// Runtime scenarios that every provider harness must support without changing the suite.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConformanceScenario {
    /// Successful exit zero with exact raw output.
    HappyPath,
    /// Completed nonzero exit seven.
    NonzeroExit,
    /// Raw exit 124 with ambiguous timeout evidence.
    Exit124PossibleTimeout,
    /// Completed exit with confirmed timeout evidence.
    ConfirmedTimeout,
    /// Stream ends without a terminal exit.
    MissingTerminalExit,
    /// Stdout exceeds its limit.
    StdoutOverflow,
    /// Stderr exceeds its limit.
    StderrOverflow,
    /// Combined output exceeds its limit.
    CombinedOverflow,
    /// One transport chunk exceeds its limit.
    ChunkOverflow,
    /// Create is proven not to have run.
    CreateNotCreated,
    /// Create encounters an ownership conflict.
    CreateConflict,
    /// Create commits but its response is lost.
    CreateLostResponse,
    /// Workload readiness reports the wrong active policy.
    PolicyMismatch,
    /// Readiness reaches its operation deadline.
    ReadinessDeadline,
    /// Cancellation is observed before command dispatch.
    CancelBeforeDispatch,
    /// Cancellation is observed after possible dispatch.
    CancelAfterDispatch,
    /// Transport fails before command dispatch.
    TransportBeforeDispatch,
    /// Transport fails after possible dispatch.
    TransportAfterDispatch,
    /// Delete fails after a terminal process result.
    CleanupFailure,
    /// Terminal-absence waiting reaches its deadline.
    WaitDeletedDeadline,
}

impl ConformanceScenario {
    /// Every reusable runtime scenario in stable execution order.
    pub const ALL: [Self; 20] = [
        Self::HappyPath,
        Self::NonzeroExit,
        Self::Exit124PossibleTimeout,
        Self::ConfirmedTimeout,
        Self::MissingTerminalExit,
        Self::StdoutOverflow,
        Self::StderrOverflow,
        Self::CombinedOverflow,
        Self::ChunkOverflow,
        Self::CreateNotCreated,
        Self::CreateConflict,
        Self::CreateLostResponse,
        Self::PolicyMismatch,
        Self::ReadinessDeadline,
        Self::CancelBeforeDispatch,
        Self::CancelAfterDispatch,
        Self::TransportBeforeDispatch,
        Self::TransportAfterDispatch,
        Self::CleanupFailure,
        Self::WaitDeletedDeadline,
    ];
}

/// Provider-neutral operation names used by conformance observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConformanceOperation {
    /// Create.
    Create,
    /// Wait ready.
    WaitReady,
    /// Execute.
    Exec,
    /// Delete.
    Delete,
    /// Wait deleted.
    WaitDeleted,
}

/// Provider-neutral observation snapshot used by suite assertions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConformanceObservation {
    operations: Vec<ConformanceOperation>,
    create_submissions: u64,
    exec_dispatches: u64,
    exec_argv: Vec<Vec<String>>,
    delete_targets: Vec<RequestOwnedId>,
    wait_deleted_targets: Vec<RequestOwnedId>,
}

impl ConformanceObservation {
    /// Creates an observation supplied by a provider harness.
    pub fn new(
        operations: Vec<ConformanceOperation>,
        create_submissions: u64,
        exec_dispatches: u64,
        exec_argv: Vec<Vec<String>>,
        delete_targets: Vec<RequestOwnedId>,
        wait_deleted_targets: Vec<RequestOwnedId>,
    ) -> Self {
        Self {
            operations,
            create_submissions,
            exec_dispatches,
            exec_argv,
            delete_targets,
            wait_deleted_targets,
        }
    }

    /// Returns operations in invocation order.
    pub fn operations(&self) -> &[ConformanceOperation] {
        &self.operations
    }

    /// Returns create submission count.
    pub const fn create_submissions(&self) -> u64 {
        self.create_submissions
    }

    /// Returns command dispatch count.
    pub const fn exec_dispatches(&self) -> u64 {
        self.exec_dispatches
    }

    /// Returns every exact argv observed at the runtime boundary.
    pub fn exec_argv(&self) -> &[Vec<String>] {
        &self.exec_argv
    }

    /// Returns delete targets.
    pub fn delete_targets(&self) -> &[RequestOwnedId] {
        &self.delete_targets
    }

    /// Returns wait-deleted targets.
    pub fn wait_deleted_targets(&self) -> &[RequestOwnedId] {
        &self.wait_deleted_targets
    }
}

/// Supplies one observation after a conformance case runs.
pub trait ConformanceObserver: Send + Sync {
    /// Returns the current provider-neutral observation.
    fn observe(&self) -> ConformanceObservation;
}

/// One independently configured scenario case.
pub struct ConformanceCase {
    runtime: Arc<dyn SandboxRuntime>,
    observer: Arc<dyn ConformanceObserver>,
    create_request: CreateRequest,
    exec_request: ExecRequest,
    contexts: LifecycleContexts,
}

/// Owned components of one conformance case for boundary-preserving harness wrappers.
pub type ConformanceCaseParts = (
    Arc<dyn SandboxRuntime>,
    Arc<dyn ConformanceObserver>,
    CreateRequest,
    ExecRequest,
    LifecycleContexts,
);

impl ConformanceCase {
    /// Creates a provider case consumed by the unchanged conformance runner.
    pub fn new(
        runtime: Arc<dyn SandboxRuntime>,
        observer: Arc<dyn ConformanceObserver>,
        create_request: CreateRequest,
        exec_request: ExecRequest,
        contexts: LifecycleContexts,
    ) -> Self {
        Self {
            runtime,
            observer,
            create_request,
            exec_request,
            contexts,
        }
    }

    /// Consumes a case so a delivery-boundary harness can wrap its runtime without changing the suite.
    pub fn into_parts(self) -> ConformanceCaseParts {
        (
            self.runtime,
            self.observer,
            self.create_request,
            self.exec_request,
            self.contexts,
        )
    }
}

/// Factory implemented once per fake or real provider test harness.
pub trait ConformanceHarness: Send + Sync {
    /// Builds one isolated fresh-sandbox case for the requested scenario.
    fn build_case(&self, scenario: ConformanceScenario) -> ConformanceCase;
}

/// A conformance invariant violation with no command or output content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceFailure {
    scenario: ConformanceScenario,
    invariant: &'static str,
}

impl ConformanceFailure {
    fn new(scenario: ConformanceScenario, invariant: &'static str) -> Self {
        Self {
            scenario,
            invariant,
        }
    }

    /// Returns the failing scenario.
    pub const fn scenario(&self) -> ConformanceScenario {
        self.scenario
    }

    /// Returns the stable failed invariant name.
    pub const fn invariant(&self) -> &'static str {
        self.invariant
    }
}

impl fmt::Display for ConformanceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "conformance failed: {:?}/{}",
            self.scenario, self.invariant
        )
    }
}

impl std::error::Error for ConformanceFailure {}

/// Successful suite report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceReport {
    scenarios: Vec<ConformanceScenario>,
}

impl ConformanceReport {
    /// Returns all scenarios that passed.
    pub fn scenarios(&self) -> &[ConformanceScenario] {
        &self.scenarios
    }
}

/// Runs the unchanged runtime conformance scenarios against a provider harness.
pub async fn run_conformance_suite(
    harness: &dyn ConformanceHarness,
) -> Result<ConformanceReport, ConformanceFailure> {
    let mut passed = Vec::with_capacity(ConformanceScenario::ALL.len());
    let mut ids = HashSet::with_capacity(ConformanceScenario::ALL.len());
    for scenario in ConformanceScenario::ALL {
        let case = harness.build_case(scenario);
        let request_id = case.create_request.request_id().clone();
        if !ids.insert(request_id.clone()) {
            return Err(ConformanceFailure::new(scenario, "fresh_request_owned_id"));
        }
        let expected_argv = case.exec_request.argv().as_slice().to_vec();
        let outcome = run_lifecycle(
            case.runtime.as_ref(),
            case.create_request,
            case.exec_request,
            case.contexts,
        )
        .await;
        let observation = case.observer.observe();
        verify_case(
            scenario,
            &request_id,
            &expected_argv,
            &outcome,
            &observation,
        )?;
        passed.push(scenario);
    }
    Ok(ConformanceReport { scenarios: passed })
}

fn verify_case(
    scenario: ConformanceScenario,
    request_id: &RequestOwnedId,
    expected_argv: &[String],
    outcome: &LifecycleOutcome,
    observation: &ConformanceObservation,
) -> Result<(), ConformanceFailure> {
    if outcome.request_id() != request_id {
        return Err(ConformanceFailure::new(scenario, "request_id_integrity"));
    }
    if observation.exec_dispatches() > 1 {
        return Err(ConformanceFailure::new(scenario, "no_exec_retry"));
    }
    for argv in observation.exec_argv() {
        if argv != expected_argv {
            return Err(ConformanceFailure::new(scenario, "exact_argv"));
        }
    }

    let expected_operations: &[ConformanceOperation] = match scenario {
        ConformanceScenario::CreateNotCreated | ConformanceScenario::CreateConflict => {
            &[ConformanceOperation::Create]
        }
        ConformanceScenario::CreateLostResponse => &[
            ConformanceOperation::Create,
            ConformanceOperation::Delete,
            ConformanceOperation::WaitDeleted,
        ],
        ConformanceScenario::PolicyMismatch | ConformanceScenario::ReadinessDeadline => &[
            ConformanceOperation::Create,
            ConformanceOperation::WaitReady,
            ConformanceOperation::Delete,
            ConformanceOperation::WaitDeleted,
        ],
        _ => &[
            ConformanceOperation::Create,
            ConformanceOperation::WaitReady,
            ConformanceOperation::Exec,
            ConformanceOperation::Delete,
            ConformanceOperation::WaitDeleted,
        ],
    };
    if observation.operations() != expected_operations {
        return Err(ConformanceFailure::new(scenario, "operation_order"));
    }
    let expected_create_submissions = u64::from(scenario != ConformanceScenario::CreateNotCreated);
    if observation.create_submissions() != expected_create_submissions {
        return Err(ConformanceFailure::new(scenario, "create_submission_count"));
    }

    let no_owned_sandbox = matches!(
        scenario,
        ConformanceScenario::CreateNotCreated | ConformanceScenario::CreateConflict
    );
    if no_owned_sandbox {
        if outcome.cleanup().state() != CleanupState::NotNeeded
            || !observation.delete_targets().is_empty()
            || !observation.wait_deleted_targets().is_empty()
        {
            return Err(ConformanceFailure::new(scenario, "cleanup_forbidden"));
        }
    } else if observation.delete_targets() != [request_id.clone()]
        || observation.wait_deleted_targets() != [request_id.clone()]
    {
        return Err(ConformanceFailure::new(scenario, "cleanup_required"));
    } else {
        let expected_cleanup = if matches!(
            scenario,
            ConformanceScenario::CleanupFailure | ConformanceScenario::WaitDeletedDeadline
        ) {
            CleanupState::Failed
        } else {
            CleanupState::Deleted
        };
        if outcome.cleanup().state() != expected_cleanup {
            return Err(ConformanceFailure::new(scenario, "cleanup_state"));
        }
    }

    verify_scenario(scenario, outcome, observation)
}

#[allow(clippy::too_many_lines)]
fn verify_scenario(
    scenario: ConformanceScenario,
    outcome: &LifecycleOutcome,
    observation: &ConformanceObservation,
) -> Result<(), ConformanceFailure> {
    match scenario {
        ConformanceScenario::HappyPath => {
            let LifecycleAttempt::ExecCompleted(completed) = outcome.attempt() else {
                return Err(ConformanceFailure::new(scenario, "happy_completed"));
            };
            if completed.exit_code().get() != 0
                || completed.stdout() != raw_stdout_fixture()
                || completed.stderr() != raw_stderr_fixture()
                || completed.timeout() != ObservedTimeout::NotObserved
            {
                return Err(ConformanceFailure::new(scenario, "happy_exact_result"));
            }
        }
        ConformanceScenario::NonzeroExit => {
            require_exit(scenario, outcome, 7, ObservedTimeout::NotObserved)?;
        }
        ConformanceScenario::Exit124PossibleTimeout => {
            require_exit(scenario, outcome, 124, ObservedTimeout::Possible)?;
        }
        ConformanceScenario::ConfirmedTimeout => {
            require_exit(scenario, outcome, 124, ObservedTimeout::Confirmed)?;
        }
        ConformanceScenario::MissingTerminalExit => {
            require_exec_failure(
                scenario,
                outcome,
                ExecFailureCode::MissingTerminalExit,
                DispatchState::PossiblyDispatched,
                FailureTimeout::Unknown,
            )?;
        }
        ConformanceScenario::StdoutOverflow => {
            require_overflow(scenario, outcome, OutputLimitKind::Stdout)?;
        }
        ConformanceScenario::StderrOverflow => {
            require_overflow(scenario, outcome, OutputLimitKind::Stderr)?;
        }
        ConformanceScenario::CombinedOverflow => {
            require_overflow(scenario, outcome, OutputLimitKind::Combined)?;
        }
        ConformanceScenario::ChunkOverflow => {
            require_overflow(scenario, outcome, OutputLimitKind::Chunk)?;
        }
        ConformanceScenario::CreateNotCreated => {
            require_create_state(scenario, outcome, CreationState::NotCreated)?;
        }
        ConformanceScenario::CreateConflict => {
            require_create_state(scenario, outcome, CreationState::Conflict)?;
        }
        ConformanceScenario::CreateLostResponse => {
            require_create_state(scenario, outcome, CreationState::PossiblyCreated)?;
            if outcome.cleanup().state() != CleanupState::Deleted {
                return Err(ConformanceFailure::new(scenario, "lost_create_cleanup"));
            }
        }
        ConformanceScenario::PolicyMismatch => {
            require_readiness_failure(scenario, outcome, ReadinessFailureCode::PolicyMismatch)?;
        }
        ConformanceScenario::ReadinessDeadline => {
            require_readiness_failure(scenario, outcome, ReadinessFailureCode::Deadline)?;
        }
        ConformanceScenario::CancelBeforeDispatch => {
            require_exec_failure(
                scenario,
                outcome,
                ExecFailureCode::Cancelled,
                DispatchState::NotDispatched,
                FailureTimeout::NotObserved,
            )?;
        }
        ConformanceScenario::CancelAfterDispatch => {
            require_exec_failure(
                scenario,
                outcome,
                ExecFailureCode::Cancelled,
                DispatchState::PossiblyDispatched,
                FailureTimeout::Unknown,
            )?;
        }
        ConformanceScenario::TransportBeforeDispatch => {
            require_exec_failure(
                scenario,
                outcome,
                ExecFailureCode::Transport,
                DispatchState::NotDispatched,
                FailureTimeout::NotObserved,
            )?;
        }
        ConformanceScenario::TransportAfterDispatch => {
            require_exec_failure(
                scenario,
                outcome,
                ExecFailureCode::Transport,
                DispatchState::PossiblyDispatched,
                FailureTimeout::Unknown,
            )?;
        }
        ConformanceScenario::CleanupFailure => {
            require_exit(scenario, outcome, 0, ObservedTimeout::NotObserved)?;
            if outcome.cleanup().state() != CleanupState::Failed {
                return Err(ConformanceFailure::new(
                    scenario,
                    "cleanup_failure_preserved",
                ));
            }
        }
        ConformanceScenario::WaitDeletedDeadline => {
            require_exit(scenario, outcome, 0, ObservedTimeout::NotObserved)?;
            if outcome.cleanup().state() != CleanupState::Failed {
                return Err(ConformanceFailure::new(scenario, "wait_deleted_deadline"));
            }
        }
    }

    let expected_dispatches = match scenario {
        ConformanceScenario::CreateNotCreated
        | ConformanceScenario::CreateConflict
        | ConformanceScenario::CreateLostResponse
        | ConformanceScenario::PolicyMismatch
        | ConformanceScenario::ReadinessDeadline
        | ConformanceScenario::CancelBeforeDispatch
        | ConformanceScenario::TransportBeforeDispatch => 0,
        _ => 1,
    };
    if observation.exec_dispatches() != expected_dispatches {
        return Err(ConformanceFailure::new(scenario, "dispatch_count"));
    }
    Ok(())
}

fn require_exit(
    scenario: ConformanceScenario,
    outcome: &LifecycleOutcome,
    exit: i32,
    timeout: ObservedTimeout,
) -> Result<(), ConformanceFailure> {
    let LifecycleAttempt::ExecCompleted(completed) = outcome.attempt() else {
        return Err(ConformanceFailure::new(scenario, "completed_exit"));
    };
    if completed.exit_code().get() != exit || completed.timeout() != timeout {
        return Err(ConformanceFailure::new(scenario, "exit_timeout_mapping"));
    }
    Ok(())
}

fn require_exec_failure(
    scenario: ConformanceScenario,
    outcome: &LifecycleOutcome,
    code: ExecFailureCode,
    dispatch: DispatchState,
    timeout: FailureTimeout,
) -> Result<(), ConformanceFailure> {
    let LifecycleAttempt::ExecFailed(error) = outcome.attempt() else {
        return Err(ConformanceFailure::new(scenario, "typed_exec_failure"));
    };
    if error.code() != code
        || error.dispatch_state() != dispatch
        || error.timeout_state() != timeout
    {
        return Err(ConformanceFailure::new(scenario, "exec_failure_mapping"));
    }
    Ok(())
}

fn require_overflow(
    scenario: ConformanceScenario,
    outcome: &LifecycleOutcome,
    limit: OutputLimitKind,
) -> Result<(), ConformanceFailure> {
    require_exec_failure(
        scenario,
        outcome,
        ExecFailureCode::OutputLimitExceeded,
        DispatchState::PossiblyDispatched,
        FailureTimeout::Unknown,
    )?;
    let LifecycleAttempt::ExecFailed(error) = outcome.attempt() else {
        unreachable!("checked above")
    };
    if error.output_limit() != Some(limit) {
        return Err(ConformanceFailure::new(scenario, "output_limit_kind"));
    }
    Ok(())
}

fn require_create_state(
    scenario: ConformanceScenario,
    outcome: &LifecycleOutcome,
    state: CreationState,
) -> Result<(), ConformanceFailure> {
    let LifecycleAttempt::CreateFailed(error) = outcome.attempt() else {
        return Err(ConformanceFailure::new(scenario, "typed_create_failure"));
    };
    if error.state() != state {
        return Err(ConformanceFailure::new(scenario, "creation_state"));
    }
    Ok(())
}

fn require_readiness_failure(
    scenario: ConformanceScenario,
    outcome: &LifecycleOutcome,
    code: ReadinessFailureCode,
) -> Result<(), ConformanceFailure> {
    let LifecycleAttempt::ReadinessFailed(error) = outcome.attempt() else {
        return Err(ConformanceFailure::new(scenario, "typed_readiness_failure"));
    };
    if error.code() != code {
        return Err(ConformanceFailure::new(scenario, "readiness_code"));
    }
    Ok(())
}

impl ConformanceObserver for FakeSandboxRuntime {
    fn observe(&self) -> ConformanceObservation {
        let recording = self.recording();
        let mut operations = Vec::with_capacity(recording.calls().len());
        let mut exec_argv = Vec::new();
        let mut delete_targets = Vec::new();
        let mut wait_deleted_targets = Vec::new();
        for call in recording.calls() {
            match call {
                RecordedCall::Create { .. } => operations.push(ConformanceOperation::Create),
                RecordedCall::WaitReady { .. } => operations.push(ConformanceOperation::WaitReady),
                RecordedCall::Exec { request, .. } => {
                    operations.push(ConformanceOperation::Exec);
                    exec_argv.push(request.argv().as_slice().to_vec());
                }
                RecordedCall::Delete { target, .. } => {
                    operations.push(ConformanceOperation::Delete);
                    delete_targets.push(target.request_id().clone());
                }
                RecordedCall::WaitDeleted { target, .. } => {
                    operations.push(ConformanceOperation::WaitDeleted);
                    wait_deleted_targets.push(target.request_id().clone());
                }
            }
        }
        ConformanceObservation::new(
            operations,
            recording.create_submissions(),
            recording.exec_dispatches(),
            exec_argv,
            delete_targets,
            wait_deleted_targets,
        )
    }
}

/// First conformance harness, backed entirely by the deterministic recording fake.
#[derive(Debug)]
pub struct FakeConformanceHarness {
    next_id: AtomicU64,
}

impl FakeConformanceHarness {
    /// Creates a harness whose cases receive deterministic distinct IDs.
    pub const fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
        }
    }
}

impl Default for FakeConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl ConformanceHarness for FakeConformanceHarness {
    fn build_case(&self, scenario: ConformanceScenario) -> ConformanceCase {
        let index = self.next_id.fetch_add(1, Ordering::Relaxed);
        let create_request = create_request_fixture(index);
        let mut limits = output_limits_fixture();
        let mut contexts = lifecycle_contexts_fixture();
        let mut script = FakeScript::new();

        match scenario {
            ConformanceScenario::CreateNotCreated => {
                script.push_create(FakeCreatePlan::Fail {
                    state: CreationState::NotCreated,
                    code: CreateFailureCode::Validation,
                });
            }
            ConformanceScenario::CreateConflict => {
                script.push_create(FakeCreatePlan::Fail {
                    state: CreationState::Conflict,
                    code: CreateFailureCode::Provider,
                });
            }
            ConformanceScenario::CreateLostResponse => {
                script
                    .push_create(FakeCreatePlan::CommitThenLoseResponse)
                    .push_delete(FakeDeletePlan::Deleted)
                    .push_wait_deleted(FakeWaitDeletedPlan::Absent);
            }
            _ => {
                script.push_create(FakeCreatePlan::Succeed {
                    provider_handle: format!("provider-{index}").into_bytes(),
                });
                match scenario {
                    ConformanceScenario::PolicyMismatch => {
                        script.push_readiness(FakeReadinessPlan::Ready {
                            observed_policy: policy_fixture(2),
                        });
                    }
                    ConformanceScenario::ReadinessDeadline => {
                        script.push_readiness(FakeReadinessPlan::Fail {
                            code: ReadinessFailureCode::Deadline,
                        });
                    }
                    _ => {
                        script.push_readiness(FakeReadinessPlan::Ready {
                            observed_policy: policy_fixture(1),
                        });
                        let plan = exec_plan(scenario, &mut limits);
                        script.push_exec(plan);
                        if scenario == ConformanceScenario::CancelBeforeDispatch {
                            contexts = cancelled_exec_contexts_fixture();
                        }
                    }
                }
                match scenario {
                    ConformanceScenario::CleanupFailure => {
                        script
                            .push_delete(FakeDeletePlan::Fail(crate::CleanupFailureCode::Transport))
                            .push_wait_deleted(FakeWaitDeletedPlan::Absent);
                    }
                    ConformanceScenario::WaitDeletedDeadline => {
                        script
                            .push_delete(FakeDeletePlan::Deleted)
                            .push_wait_deleted(FakeWaitDeletedPlan::Fail(
                                crate::CleanupFailureCode::Deadline,
                            ));
                    }
                    _ => {
                        script
                            .push_delete(FakeDeletePlan::Deleted)
                            .push_wait_deleted(FakeWaitDeletedPlan::Absent);
                    }
                }
            }
        }

        let exec_request = exec_request_fixture(limits);
        let fake = FakeSandboxRuntime::new(script);
        ConformanceCase::new(
            Arc::new(fake.clone()),
            Arc::new(fake),
            create_request,
            exec_request,
            contexts,
        )
    }
}

fn exec_plan(scenario: ConformanceScenario, limits: &mut OutputLimits) -> FakeExecPlan {
    let events = match scenario {
        ConformanceScenario::HappyPath => vec![
            FakeExecEvent::Stdout(raw_stdout_fixture()),
            FakeExecEvent::Stderr(raw_stderr_fixture()),
            FakeExecEvent::Exit {
                code: 0,
                timeout: ObservedTimeout::NotObserved,
            },
        ],
        ConformanceScenario::NonzeroExit => vec![FakeExecEvent::Exit {
            code: 7,
            timeout: ObservedTimeout::NotObserved,
        }],
        ConformanceScenario::Exit124PossibleTimeout => vec![FakeExecEvent::Exit {
            code: 124,
            timeout: ObservedTimeout::Possible,
        }],
        ConformanceScenario::ConfirmedTimeout => vec![FakeExecEvent::Exit {
            code: 124,
            timeout: ObservedTimeout::Confirmed,
        }],
        ConformanceScenario::MissingTerminalExit => {
            vec![FakeExecEvent::Stdout(vec![1, 2, 3])]
        }
        ConformanceScenario::StdoutOverflow => {
            *limits = OutputLimits::new(2, 10, 20, 10).expect("valid limits");
            vec![FakeExecEvent::Stdout(vec![1, 2, 3])]
        }
        ConformanceScenario::StderrOverflow => {
            *limits = OutputLimits::new(10, 2, 20, 10).expect("valid limits");
            vec![FakeExecEvent::Stderr(vec![1, 2, 3])]
        }
        ConformanceScenario::CombinedOverflow => {
            *limits = OutputLimits::new(10, 10, 4, 10).expect("valid limits");
            vec![
                FakeExecEvent::Stdout(vec![1, 2, 3]),
                FakeExecEvent::Stderr(vec![4, 5]),
            ]
        }
        ConformanceScenario::ChunkOverflow => {
            *limits = OutputLimits::new(10, 10, 20, 2).expect("valid limits");
            vec![FakeExecEvent::Stdout(vec![1, 2, 3])]
        }
        ConformanceScenario::CancelBeforeDispatch => vec![FakeExecEvent::Exit {
            code: 0,
            timeout: ObservedTimeout::NotObserved,
        }],
        ConformanceScenario::CancelAfterDispatch => vec![FakeExecEvent::Cancelled],
        ConformanceScenario::TransportBeforeDispatch => {
            return FakeExecPlan::NotDispatched {
                code: ExecFailureCode::Transport,
            };
        }
        ConformanceScenario::TransportAfterDispatch => vec![FakeExecEvent::TransportFailure],
        ConformanceScenario::CleanupFailure | ConformanceScenario::WaitDeletedDeadline => {
            vec![FakeExecEvent::Exit {
                code: 0,
                timeout: ObservedTimeout::NotObserved,
            }]
        }
        ConformanceScenario::CreateNotCreated
        | ConformanceScenario::CreateConflict
        | ConformanceScenario::CreateLostResponse
        | ConformanceScenario::PolicyMismatch
        | ConformanceScenario::ReadinessDeadline => {
            return FakeExecPlan::NotDispatched {
                code: ExecFailureCode::Protocol,
            };
        }
    };
    FakeExecPlan::Stream { events }
}
