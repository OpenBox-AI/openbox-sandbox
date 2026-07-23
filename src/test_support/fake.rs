//! Deterministic recording fake for the provider-neutral runtime contract.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::{
    CleanupFailure, CleanupFailureCode, CleanupTarget, CreateFailure, CreateFailureCode,
    CreateRequest, CreatedSandbox, CreationState, DeleteOutcome, ExecCompleted, ExecFailure,
    ExecFailureCode, ExecRequest, FailureTimeout, ObservedExitCode, ObservedTimeout,
    OpaqueProviderHandle, OperationContext, OperationDeadline, OperatorDetail, OutputByteCounts,
    OutputLimitKind, PolicyIdentity, ReadinessFailure, ReadinessFailureCode, ReadySandbox,
    RequestOwnedId, SandboxRuntime,
};
use async_trait::async_trait;

/// One scripted creation result or ambiguity point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FakeCreatePlan {
    /// Return a successfully created handle with these opaque provider bytes.
    Succeed {
        /// Nonempty opaque provider identifier.
        provider_handle: Vec<u8>,
    },
    /// Return a caller-selected typed creation failure.
    Fail {
        /// Authoritative creation state.
        state: CreationState,
        /// Stable failure code.
        code: CreateFailureCode,
    },
    /// Simulate a committed create whose successful response was lost.
    CommitThenLoseResponse,
    /// Observe cancellation before request submission.
    CancelBeforeSubmission,
    /// Observe cancellation after request submission became ambiguous.
    CancelAfterSubmission,
    /// Observe an operation deadline before request submission.
    DeadlineBeforeSubmission,
    /// Observe an operation deadline after request submission became ambiguous.
    DeadlineAfterSubmission,
}

/// One scripted readiness outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FakeReadinessPlan {
    /// Attest this observed policy against the expected identity.
    Ready {
        /// Provider-observed active policy identity.
        observed_policy: PolicyIdentity,
    },
    /// Return a typed post-create readiness failure.
    Fail {
        /// Stable readiness failure code.
        code: ReadinessFailureCode,
    },
}

/// One event in a possibly dispatched execution stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FakeExecEvent {
    /// Deliver one raw stdout chunk.
    Stdout(Vec<u8>),
    /// Deliver one raw stderr chunk.
    Stderr(Vec<u8>),
    /// Deliver the typed terminal exit event.
    Exit {
        /// Raw provider exit value; negative sentinels become protocol failures.
        code: i32,
        /// Provider timeout evidence associated with completion.
        timeout: ObservedTimeout,
    },
    /// Lose the transport after possible dispatch.
    TransportFailure,
    /// Observe cancellation after possible dispatch.
    Cancelled,
    /// Observe the operation deadline after possible dispatch.
    Deadline,
    /// Observe another provider protocol failure after possible dispatch.
    ProtocolFailure,
}

/// One scripted execution attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FakeExecPlan {
    /// Fail with proof that no dispatch occurred.
    NotDispatched {
        /// Stable pre-dispatch failure code.
        code: ExecFailureCode,
    },
    /// Dispatch exactly once and consume the supplied event stream.
    Stream {
        /// Ordered output, failure, and terminal events.
        events: Vec<FakeExecEvent>,
    },
}

/// One scripted delete outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeDeletePlan {
    /// Acknowledge deletion.
    Deleted,
    /// Report that the target was already absent.
    AlreadyAbsent,
    /// Return a typed cleanup failure.
    Fail(CleanupFailureCode),
}

/// One scripted terminal-absence outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeWaitDeletedPlan {
    /// Confirm terminal absence.
    Absent,
    /// Return a typed cleanup failure.
    Fail(CleanupFailureCode),
}

/// Queued deterministic outcomes for all five runtime operations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FakeScript {
    create: VecDeque<FakeCreatePlan>,
    readiness: VecDeque<FakeReadinessPlan>,
    exec: VecDeque<FakeExecPlan>,
    delete: VecDeque<FakeDeletePlan>,
    wait_deleted: VecDeque<FakeWaitDeletedPlan>,
}

impl FakeScript {
    /// Creates an empty script. An exhausted queue returns a typed protocol failure.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a create plan.
    pub fn push_create(&mut self, plan: FakeCreatePlan) -> &mut Self {
        self.create.push_back(plan);
        self
    }

    /// Appends a readiness plan.
    pub fn push_readiness(&mut self, plan: FakeReadinessPlan) -> &mut Self {
        self.readiness.push_back(plan);
        self
    }

    /// Appends an execution plan.
    pub fn push_exec(&mut self, plan: FakeExecPlan) -> &mut Self {
        self.exec.push_back(plan);
        self
    }

    /// Appends a delete plan.
    pub fn push_delete(&mut self, plan: FakeDeletePlan) -> &mut Self {
        self.delete.push_back(plan);
        self
    }

    /// Appends a wait-deleted plan.
    pub fn push_wait_deleted(&mut self, plan: FakeWaitDeletedPlan) -> &mut Self {
        self.wait_deleted.push_back(plan);
        self
    }
}

/// One fully recorded runtime call in invocation order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordedCall {
    /// A create call.
    Create {
        /// Full fixed-shape request.
        request: CreateRequest,
        /// Relative operation deadline.
        deadline: OperationDeadline,
        /// Whether cancellation was already set on entry.
        cancelled_on_entry: bool,
        /// Whether the fake classified the call as submitted.
        submitted: bool,
        /// Whether commit was proven (`Some(true)`), disproven (`Some(false)`), or ambiguous.
        committed: Option<bool>,
    },
    /// A readiness call.
    WaitReady {
        /// Caller-owned sandbox identifier.
        request_id: RequestOwnedId,
        /// Expected policy identity.
        expected_policy: PolicyIdentity,
        /// Relative operation deadline.
        deadline: OperationDeadline,
        /// Whether cancellation was already set on entry.
        cancelled_on_entry: bool,
    },
    /// An execution call.
    Exec {
        /// Caller-owned sandbox identifier.
        request_id: RequestOwnedId,
        /// Exact immutable execution request.
        request: ExecRequest,
        /// Relative operation deadline.
        deadline: OperationDeadline,
        /// Whether cancellation was already set on entry.
        cancelled_on_entry: bool,
        /// Whether one dispatch attempt was made.
        dispatched: bool,
    },
    /// A delete call.
    Delete {
        /// Retained cleanup target.
        target: CleanupTarget,
        /// Relative operation deadline.
        deadline: OperationDeadline,
        /// Whether cancellation was already set on entry.
        cancelled_on_entry: bool,
    },
    /// A terminal-absence wait call.
    WaitDeleted {
        /// Retained cleanup target.
        target: CleanupTarget,
        /// Relative operation deadline.
        deadline: OperationDeadline,
        /// Whether cancellation was already set on entry.
        cancelled_on_entry: bool,
    },
}

/// Immutable snapshot of fake calls and dispatch/submission counts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FakeRecording {
    calls: Vec<RecordedCall>,
    create_submissions: u64,
    exec_dispatches: u64,
}

impl FakeRecording {
    /// Returns all calls in exact invocation order.
    pub fn calls(&self) -> &[RecordedCall] {
        &self.calls
    }

    /// Returns the number of create request submissions.
    pub const fn create_submissions(&self) -> u64 {
        self.create_submissions
    }

    /// Returns the number of command dispatch attempts.
    pub const fn exec_dispatches(&self) -> u64 {
        self.exec_dispatches
    }
}

#[derive(Debug)]
struct FakeState {
    script: FakeScript,
    recording: FakeRecording,
}

/// Thread-safe deterministic fake implementing [`SandboxRuntime`].
///
/// It performs no host execution, network I/O, provider I/O, retries, sleeps, or wall-clock reads.
#[derive(Clone, Debug)]
pub struct FakeSandboxRuntime {
    state: Arc<Mutex<FakeState>>,
}

impl FakeSandboxRuntime {
    /// Creates a fake from queued outcomes.
    pub fn new(script: FakeScript) -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeState {
                script,
                recording: FakeRecording::default(),
            })),
        }
    }

    /// Returns an immutable snapshot of calls and counts.
    pub fn recording(&self) -> FakeRecording {
        self.lock().recording.clone()
    }

    fn lock(&self) -> MutexGuard<'_, FakeState> {
        self.state.lock().expect("fake runtime mutex poisoned")
    }
}

fn detail(message: &'static str) -> OperatorDetail {
    OperatorDetail::redacted(message)
}

fn create_failure(
    state: CreationState,
    request_id: &RequestOwnedId,
    code: CreateFailureCode,
) -> CreateFailure {
    match state {
        CreationState::NotCreated => {
            CreateFailure::not_created(code, detail("fake create failure"))
        }
        CreationState::PossiblyCreated => CreateFailure::possibly_created(
            CleanupTarget::new(request_id.clone()),
            code,
            detail("fake ambiguous create failure"),
        ),
        CreationState::Conflict => CreateFailure::conflict(code, detail("fake ownership conflict")),
    }
}

#[async_trait]
impl SandboxRuntime for FakeSandboxRuntime {
    async fn create(
        &self,
        request: CreateRequest,
        context: OperationContext,
    ) -> Result<CreatedSandbox, CreateFailure> {
        let cancelled_on_entry = context.cancellation().is_cancelled();
        if cancelled_on_entry {
            self.lock().recording.calls.push(RecordedCall::Create {
                request,
                deadline: context.deadline(),
                cancelled_on_entry: true,
                submitted: false,
                committed: Some(false),
            });
            return Err(CreateFailure::not_created(
                CreateFailureCode::Cancelled,
                detail("fake cancellation before create submission"),
            ));
        }

        let plan = self
            .lock()
            .script
            .create
            .pop_front()
            .unwrap_or(FakeCreatePlan::Fail {
                state: CreationState::NotCreated,
                code: CreateFailureCode::Protocol,
            });
        let (submitted, committed) = match &plan {
            FakeCreatePlan::Succeed { .. } | FakeCreatePlan::CommitThenLoseResponse => {
                (true, Some(true))
            }
            FakeCreatePlan::CancelAfterSubmission
            | FakeCreatePlan::DeadlineAfterSubmission
            | FakeCreatePlan::Fail {
                state: CreationState::PossiblyCreated,
                ..
            } => (true, None),
            FakeCreatePlan::Fail {
                state: CreationState::Conflict,
                ..
            } => (true, Some(false)),
            FakeCreatePlan::Fail {
                state: CreationState::NotCreated,
                ..
            }
            | FakeCreatePlan::CancelBeforeSubmission
            | FakeCreatePlan::DeadlineBeforeSubmission => (false, Some(false)),
        };
        {
            let mut state = self.lock();
            state.recording.create_submissions += u64::from(submitted);
            state.recording.calls.push(RecordedCall::Create {
                request: request.clone(),
                deadline: context.deadline(),
                cancelled_on_entry: false,
                submitted,
                committed,
            });
        }

        let request_id = request.request_id().clone();
        let expected_policy = request.expected_policy().clone();
        match plan {
            FakeCreatePlan::Succeed { provider_handle } => {
                let provider_handle = OpaqueProviderHandle::new(provider_handle).map_err(|_| {
                    CreateFailure::possibly_created(
                        CleanupTarget::new(request_id.clone()),
                        CreateFailureCode::Protocol,
                        detail("fake committed create response had an invalid provider handle"),
                    )
                })?;
                Ok(CreatedSandbox::from_runtime(
                    request_id,
                    provider_handle,
                    expected_policy,
                ))
            }
            FakeCreatePlan::Fail { state, code } => Err(create_failure(state, &request_id, code)),
            FakeCreatePlan::CommitThenLoseResponse => Err(CreateFailure::possibly_created(
                CleanupTarget::new(request_id),
                CreateFailureCode::Transport,
                detail("fake committed create response lost"),
            )),
            FakeCreatePlan::CancelBeforeSubmission => Err(CreateFailure::not_created(
                CreateFailureCode::Cancelled,
                detail("fake cancellation before create submission"),
            )),
            FakeCreatePlan::CancelAfterSubmission => Err(CreateFailure::possibly_created(
                CleanupTarget::new(request_id),
                CreateFailureCode::Cancelled,
                detail("fake cancellation after create submission"),
            )),
            FakeCreatePlan::DeadlineBeforeSubmission => Err(CreateFailure::not_created(
                CreateFailureCode::Deadline,
                detail("fake deadline before create submission"),
            )),
            FakeCreatePlan::DeadlineAfterSubmission => Err(CreateFailure::possibly_created(
                CleanupTarget::new(request_id),
                CreateFailureCode::Deadline,
                detail("fake deadline after create submission"),
            )),
        }
    }

    async fn wait_ready(
        &self,
        sandbox: CreatedSandbox,
        expected_policy: PolicyIdentity,
        context: OperationContext,
    ) -> Result<ReadySandbox, ReadinessFailure> {
        let cleanup_target = sandbox.cleanup_target();
        let request_id = sandbox.request_id().clone();
        let cancelled_on_entry = context.cancellation().is_cancelled();
        {
            let mut state = self.lock();
            state.recording.calls.push(RecordedCall::WaitReady {
                request_id,
                expected_policy: expected_policy.clone(),
                deadline: context.deadline(),
                cancelled_on_entry,
            });
        }
        if cancelled_on_entry {
            return Err(ReadinessFailure::new(
                cleanup_target,
                ReadinessFailureCode::Cancelled,
                detail("fake readiness cancelled"),
            ));
        }
        let plan = self
            .lock()
            .script
            .readiness
            .pop_front()
            .unwrap_or(FakeReadinessPlan::Fail {
                code: ReadinessFailureCode::Protocol,
            });
        match plan {
            FakeReadinessPlan::Ready { observed_policy } => {
                ReadySandbox::attest(sandbox, expected_policy, &observed_policy).map_err(|_| {
                    ReadinessFailure::new(
                        cleanup_target,
                        ReadinessFailureCode::PolicyMismatch,
                        detail("fake active policy mismatch"),
                    )
                })
            }
            FakeReadinessPlan::Fail { code } => Err(ReadinessFailure::new(
                cleanup_target,
                code,
                detail("fake readiness failure"),
            )),
        }
    }

    async fn exec(
        &self,
        sandbox: ReadySandbox,
        request: ExecRequest,
        context: OperationContext,
    ) -> Result<ExecCompleted, ExecFailure> {
        let cleanup_target = sandbox.cleanup_target();
        let request_id = sandbox.request_id().clone();
        let cancelled_on_entry = context.cancellation().is_cancelled();
        if cancelled_on_entry {
            self.lock().recording.calls.push(RecordedCall::Exec {
                request_id,
                request,
                deadline: context.deadline(),
                cancelled_on_entry: true,
                dispatched: false,
            });
            let failure = ExecFailure::not_dispatched(
                cleanup_target,
                ExecFailureCode::Cancelled,
                detail("fake cancellation before dispatch"),
            )
            .expect("cancelled is a valid pre-dispatch code");
            return Err(failure);
        }
        let plan = self
            .lock()
            .script
            .exec
            .pop_front()
            .unwrap_or(FakeExecPlan::NotDispatched {
                code: ExecFailureCode::Protocol,
            });
        let dispatched = matches!(plan, FakeExecPlan::Stream { .. });
        {
            let mut state = self.lock();
            state.recording.exec_dispatches += u64::from(dispatched);
            state.recording.calls.push(RecordedCall::Exec {
                request_id,
                request: request.clone(),
                deadline: context.deadline(),
                cancelled_on_entry: false,
                dispatched,
            });
        }
        match plan {
            FakeExecPlan::NotDispatched { code } => ExecFailure::not_dispatched(
                cleanup_target.clone(),
                code,
                detail("fake pre-dispatch failure"),
            )
            .map_or_else(|_| Err(unreachable_failure(cleanup_target)), Err),
            FakeExecPlan::Stream { events } => collect_stream(cleanup_target, request, events),
        }
    }

    async fn delete(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<DeleteOutcome, CleanupFailure> {
        let cancelled_on_entry = context.cancellation().is_cancelled();
        {
            let mut state = self.lock();
            state.recording.calls.push(RecordedCall::Delete {
                target: target.clone(),
                deadline: context.deadline(),
                cancelled_on_entry,
            });
        }
        if cancelled_on_entry {
            return Err(CleanupFailure::new(
                target,
                CleanupFailureCode::Cancelled,
                detail("fake delete cancelled"),
            ));
        }
        let plan = self
            .lock()
            .script
            .delete
            .pop_front()
            .unwrap_or(FakeDeletePlan::Fail(CleanupFailureCode::Protocol));
        match plan {
            FakeDeletePlan::Deleted => Ok(DeleteOutcome::Deleted),
            FakeDeletePlan::AlreadyAbsent => Ok(DeleteOutcome::AlreadyAbsent),
            FakeDeletePlan::Fail(code) => Err(CleanupFailure::new(
                target,
                code,
                detail("fake delete failure"),
            )),
        }
    }

    async fn wait_deleted(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<(), CleanupFailure> {
        let cancelled_on_entry = context.cancellation().is_cancelled();
        {
            let mut state = self.lock();
            state.recording.calls.push(RecordedCall::WaitDeleted {
                target: target.clone(),
                deadline: context.deadline(),
                cancelled_on_entry,
            });
        }
        if cancelled_on_entry {
            return Err(CleanupFailure::new(
                target,
                CleanupFailureCode::Cancelled,
                detail("fake wait-deleted cancelled"),
            ));
        }
        let plan = self
            .lock()
            .script
            .wait_deleted
            .pop_front()
            .unwrap_or(FakeWaitDeletedPlan::Fail(CleanupFailureCode::Protocol));
        match plan {
            FakeWaitDeletedPlan::Absent => Ok(()),
            FakeWaitDeletedPlan::Fail(code) => Err(CleanupFailure::new(
                target,
                code,
                detail("fake wait-deleted failure"),
            )),
        }
    }
}

fn unreachable_failure(target: CleanupTarget) -> ExecFailure {
    ExecFailure::not_dispatched(
        target,
        ExecFailureCode::Protocol,
        detail("fake constructed an invalid pre-dispatch plan"),
    )
    .expect("protocol is a valid pre-dispatch code")
}

#[allow(clippy::too_many_lines)]
fn collect_stream(
    cleanup_target: CleanupTarget,
    request: ExecRequest,
    events: Vec<FakeExecEvent>,
) -> Result<ExecCompleted, ExecFailure> {
    let limits = request.output_limits();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut counts = OutputByteCounts::default();
    let mut terminal: Option<(ObservedExitCode, ObservedTimeout)> = None;

    for event in events {
        if terminal.is_some() {
            return Err(possible_failure(
                cleanup_target,
                ExecFailureCode::Protocol,
                counts,
                "fake event followed terminal exit",
            ));
        }
        match event {
            FakeExecEvent::Stdout(chunk) => {
                counts = OutputByteCounts::new(
                    counts
                        .stdout_bytes()
                        .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX)),
                    counts.stderr_bytes(),
                );
                if u64::try_from(chunk.len()).unwrap_or(u64::MAX) > limits.chunk_bytes() {
                    return overflow(cleanup_target, counts, OutputLimitKind::Chunk);
                }
                if counts.stdout_bytes() > limits.stdout_bytes() {
                    return overflow(cleanup_target, counts, OutputLimitKind::Stdout);
                }
                if counts
                    .combined_bytes()
                    .is_none_or(|total| total > limits.combined_bytes())
                {
                    return overflow(cleanup_target, counts, OutputLimitKind::Combined);
                }
                stdout.extend_from_slice(&chunk);
            }
            FakeExecEvent::Stderr(chunk) => {
                counts = OutputByteCounts::new(
                    counts.stdout_bytes(),
                    counts
                        .stderr_bytes()
                        .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX)),
                );
                if u64::try_from(chunk.len()).unwrap_or(u64::MAX) > limits.chunk_bytes() {
                    return overflow(cleanup_target, counts, OutputLimitKind::Chunk);
                }
                if counts.stderr_bytes() > limits.stderr_bytes() {
                    return overflow(cleanup_target, counts, OutputLimitKind::Stderr);
                }
                if counts
                    .combined_bytes()
                    .is_none_or(|total| total > limits.combined_bytes())
                {
                    return overflow(cleanup_target, counts, OutputLimitKind::Combined);
                }
                stderr.extend_from_slice(&chunk);
            }
            FakeExecEvent::Exit { code, timeout } => {
                let exit = ObservedExitCode::new(code).map_err(|_| {
                    possible_failure(
                        cleanup_target.clone(),
                        ExecFailureCode::Protocol,
                        counts,
                        "fake negative exit sentinel",
                    )
                })?;
                terminal = Some((exit, timeout));
            }
            FakeExecEvent::TransportFailure => {
                return Err(possible_failure(
                    cleanup_target,
                    ExecFailureCode::Transport,
                    counts,
                    "fake post-dispatch transport failure",
                ));
            }
            FakeExecEvent::Cancelled => {
                return Err(possible_failure(
                    cleanup_target,
                    ExecFailureCode::Cancelled,
                    counts,
                    "fake post-dispatch cancellation",
                ));
            }
            FakeExecEvent::Deadline => {
                return Err(possible_failure(
                    cleanup_target,
                    ExecFailureCode::Deadline,
                    counts,
                    "fake post-dispatch deadline",
                ));
            }
            FakeExecEvent::ProtocolFailure => {
                return Err(possible_failure(
                    cleanup_target,
                    ExecFailureCode::Protocol,
                    counts,
                    "fake post-dispatch protocol failure",
                ));
            }
        }
    }

    let Some((exit_code, timeout)) = terminal else {
        let failure = ExecFailure::missing_terminal_exit(
            cleanup_target,
            FailureTimeout::Unknown,
            counts,
            detail("fake stream ended without terminal exit"),
        )
        .expect("missing terminal exit state is valid");
        return Err(failure);
    };
    Ok(ExecCompleted::new(exit_code, stdout, stderr, timeout))
}

fn possible_failure(
    target: CleanupTarget,
    code: ExecFailureCode,
    counts: OutputByteCounts,
    message: &'static str,
) -> ExecFailure {
    ExecFailure::possibly_dispatched(
        target,
        code,
        FailureTimeout::Unknown,
        counts,
        detail(message),
    )
    .expect("ordinary post-dispatch code is valid")
}

fn overflow(
    target: CleanupTarget,
    counts: OutputByteCounts,
    kind: OutputLimitKind,
) -> Result<ExecCompleted, ExecFailure> {
    Err(ExecFailure::output_limit_exceeded(
        target,
        FailureTimeout::Unknown,
        counts,
        kind,
        detail("fake output limit exceeded"),
    )
    .expect("output overflow state is valid"))
}

/// Deterministic caller-owned identifier source for lifecycle tests.
#[derive(Clone, Debug)]
pub struct FixedIdGenerator {
    ids: Arc<Mutex<VecDeque<RequestOwnedId>>>,
}

impl FixedIdGenerator {
    /// Creates a source from an exact identifier sequence.
    pub fn new(ids: impl IntoIterator<Item = RequestOwnedId>) -> Self {
        Self {
            ids: Arc::new(Mutex::new(ids.into_iter().collect())),
        }
    }

    /// Returns the next fixed identifier, or `None` when exhausted.
    pub fn next_id(&self) -> Option<RequestOwnedId> {
        self.ids
            .lock()
            .expect("fixed ID mutex poisoned")
            .pop_front()
    }
}
