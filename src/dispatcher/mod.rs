//! Governed, durable, at-most-once command dispatch.
//!
//! This module is the only command-routing boundary. It owns governance, host execution, sandbox
//! execution, trusted assets, and durable dispatch authority. The sandbox service itself remains
//! provider-only and does not interpret governance.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod store;
mod types;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{
    Argv, CleanupTarget, CommandTimeout, CreateRequest, DispatchState, ExecCompleted, ExecFailure,
    ExecRequest, FailureTimeout, ObservedTimeout, OperationContext, OperationDeadline,
    OutputByteCounts, RequestOwnedId, SandboxRuntime,
};
use store::{DispatchRecord, DispatchStore, DispatchStoreGuard};

pub use types::{
    ActivityStarted, Command, CommandSizeLimits, DispatchId, DispatcherConfig, EffectiveCommand,
    ErrorPhase, ExecutionOutcome, GovernanceOutcome, GovernanceRejection, GovernanceVerdict,
    GovernedCleanupState, GovernedCommandResult, GovernedDispatchState, GovernedError,
    GovernedErrorCode, IsolationSupport, SandboxAssetBundle, SelectedExecutor, TimeoutState,
};

/// Stable host execution failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostExecutionFailureCode {
    /// Host transport failed.
    Transport,
    /// The command deadline elapsed.
    Deadline,
    /// Execution was cancelled.
    Cancelled,
    /// The host executor violated the exact-argv protocol.
    Protocol,
    /// Another normalized host executor failure occurred.
    Executor,
}

/// Redacted host failure with explicit dispatch ambiguity and byte-count-only evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostExecutionFailure {
    dispatch_state: DispatchState,
    timeout_state: FailureTimeout,
    counts: OutputByteCounts,
    code: HostExecutionFailureCode,
}

impl HostExecutionFailure {
    /// Constructs a pre-dispatch failure proven by the trusted host executor.
    pub const fn not_dispatched(code: HostExecutionFailureCode) -> Self {
        Self {
            dispatch_state: DispatchState::NotDispatched,
            timeout_state: FailureTimeout::NotObserved,
            counts: OutputByteCounts::new(0, 0),
            code,
        }
    }

    /// Constructs a failure after the host may have received the command.
    pub fn possibly_dispatched(
        code: HostExecutionFailureCode,
        timeout_state: FailureTimeout,
        counts: OutputByteCounts,
    ) -> Result<Self, crate::ValidationError> {
        if timeout_state == FailureTimeout::NotObserved {
            return Err(crate::ValidationError::new(
                "host_execution_failure",
                crate::ValidationCode::InvalidCombination,
            ));
        }
        Ok(Self {
            dispatch_state: DispatchState::PossiblyDispatched,
            timeout_state,
            counts,
            code,
        })
    }

    /// Returns whether dispatch was proven absent or may have occurred.
    pub const fn dispatch_state(&self) -> DispatchState {
        self.dispatch_state
    }
    /// Returns timeout evidence.
    pub const fn timeout_state(&self) -> FailureTimeout {
        self.timeout_state
    }
    /// Returns byte-count-only output evidence.
    pub const fn counts(&self) -> OutputByteCounts {
        self.counts
    }
    /// Returns the stable category.
    pub const fn code(&self) -> HostExecutionFailureCode {
        self.code
    }
}

/// Trusted exact-argv host execution capability held privately by the dispatcher.
///
/// Implementations must close stdin, disable TTY allocation, avoid shell reconstruction, enforce
/// the effective timeout and output bounds, and never retry automatically.
#[async_trait]
pub trait HostExecutor: Send + Sync {
    /// Attempts one exact command dispatch.
    async fn execute(
        &self,
        command: &EffectiveCommand,
    ) -> Result<ExecCompleted, HostExecutionFailure>;
}

/// Stable governance client failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernanceClientError {
    /// Governance transport failed.
    Transport,
    /// Governance timed out.
    Deadline,
    /// The governance response was missing.
    MissingResponse,
    /// The governance service returned a protocol error.
    Protocol,
}

/// Direct authoritative `OpenBox` evaluation capability held privately by the dispatcher.
#[async_trait]
pub trait GovernanceClient: Send + Sync {
    /// Evaluates the current canonical activity and returns the direct raw response.
    async fn evaluate(
        &self,
        activity: ActivityStarted,
    ) -> Result<serde_json::Value, GovernanceClientError>;
}

/// Dispatcher construction failure that never exposes credentials or asset contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatcherBuildError;

impl core::fmt::Display for DispatcherBuildError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("governed dispatcher initialization failed")
    }
}

impl std::error::Error for DispatcherBuildError {}

/// Result of a durable cleanup-only reconciliation pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DispatchReconciliationReport {
    confirmed_absent: u64,
    pending: u64,
}

impl DispatchReconciliationReport {
    /// Returns records whose request-owned resources are now proven absent.
    pub const fn confirmed_absent(self) -> u64 {
        self.confirmed_absent
    }
    /// Returns records still requiring cleanup reconciliation.
    pub const fn pending(self) -> u64 {
        self.pending
    }
}

struct DispatcherInner {
    governance: Arc<dyn GovernanceClient>,
    host: Arc<dyn HostExecutor>,
    sandbox: Arc<dyn SandboxRuntime>,
    config: DispatcherConfig,
    store: DispatchStore,
    gate: Mutex<()>,
    terminal_cache: StdMutex<HashMap<DispatchId, GovernedCommandResult>>,
}

/// Sole public command execution entry point with durable at-most-once authority.
#[derive(Clone)]
pub struct GovernedDispatcher {
    inner: Arc<DispatcherInner>,
}

impl GovernedDispatcher {
    /// Creates a dispatcher that privately owns all three capabilities and trusted assets.
    pub fn new(
        governance: Arc<dyn GovernanceClient>,
        host: Arc<dyn HostExecutor>,
        sandbox: Arc<dyn SandboxRuntime>,
        config: DispatcherConfig,
    ) -> Result<Self, DispatcherBuildError> {
        let store = DispatchStore::initialize(config.state_directory.clone())
            .map_err(|_| DispatcherBuildError)?;
        Ok(Self {
            inner: Arc::new(DispatcherInner {
                governance,
                host,
                sandbox,
                config,
                store,
                gate: Mutex::new(()),
                terminal_cache: StdMutex::new(HashMap::new()),
            }),
        })
    }

    /// Validates, governs, and at most once dispatches one logical command.
    ///
    /// Dropping this future does not cancel an accepted lifecycle: the detached dispatcher task
    /// continues cleanup using independent deadlines. The returned authority result is final;
    /// callers must never execute the command independently.
    pub async fn execute(&self, command: Command) -> GovernedCommandResult {
        let dispatch_id = command.dispatch_id().clone();
        let inner = self.inner.clone();
        tokio::spawn(async move { inner.execute_owned(command).await })
            .await
            .unwrap_or_else(|_| {
                GovernedCommandResult::new(
                    dispatch_id,
                    GovernanceOutcome::Unavailable,
                    SelectedExecutor::None,
                    GovernedDispatchState::PossiblyDispatched,
                    ExecutionOutcome::indeterminate(OutputByteCounts::default()),
                    TimeoutState::Unknown,
                    GovernedCleanupState::PendingReconciliation,
                    Some(GovernedError::new(
                        GovernedErrorCode::ReplayIndeterminate,
                        ErrorPhase::DispatchPersistence,
                    )),
                )
            })
    }

    /// Reconciles only retained request-owned cleanup IDs; it never governs, creates, or executes.
    pub async fn reconcile_pending(&self) -> Result<DispatchReconciliationReport, GovernedError> {
        let inner = self.inner.clone();
        tokio::task::spawn(async move { inner.reconcile_all().await })
            .await
            .map_err(|_| {
                GovernedError::new(
                    GovernedErrorCode::PersistenceFailed,
                    ErrorPhase::SandboxReconciliation,
                )
            })?
    }
}

impl DispatcherInner {
    async fn execute_owned(&self, command: Command) -> GovernedCommandResult {
        let _gate = self.gate.lock().await;
        let Ok(guard) = self.store.lock() else {
            return persistence_result(command.dispatch_id().clone(), SelectedExecutor::None);
        };
        self.execute_locked(command, &guard).await
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_locked(
        &self,
        command: Command,
        guard: &DispatchStoreGuard<'_>,
    ) -> GovernedCommandResult {
        let (dispatch_id, argv, timeout, resume_only) = command.into_parts();
        let effective = match EffectiveCommand::validate(argv, timeout, self.config.command_limits)
        {
            Ok(command) => command,
            Err(error) => {
                let code = if error.code() == crate::ValidationCode::InvalidLength {
                    GovernedErrorCode::CommandTooLarge
                } else {
                    GovernedErrorCode::InvalidCommand
                };
                return GovernedCommandResult::validation(dispatch_id, code);
            }
        };
        let digest = effective.digest();

        let Ok(existing) = guard.load(&dispatch_id) else {
            return persistence_result(dispatch_id, SelectedExecutor::None);
        };
        if let Some(mut record) = existing {
            if record.command_digest() != &digest {
                return GovernedCommandResult::validation(
                    dispatch_id,
                    GovernedErrorCode::DigestMismatch,
                );
            }
            let cached = self
                .terminal_cache
                .lock()
                .expect("terminal cache mutex poisoned")
                .get(&dispatch_id)
                .cloned();
            if let Some(cached) = cached {
                return cached;
            }
            if record.cleanup_state() == GovernedCleanupState::PendingReconciliation {
                self.reconcile_record(&mut record, guard).await;
            }
            return record.replay_result();
        }
        if resume_only {
            return GovernedCommandResult::validation(
                dispatch_id,
                GovernedErrorCode::DigestMismatch,
            );
        }

        let mut record = DispatchRecord::new(dispatch_id.clone(), digest);
        if guard.write(&record).is_err() {
            return persistence_result(dispatch_id, SelectedExecutor::None);
        }

        let activity = ActivityStarted::new(dispatch_id.clone(), &effective);
        let Ok(raw_response) = self.governance.evaluate(activity).await else {
            let result = GovernedCommandResult::new(
                dispatch_id,
                GovernanceOutcome::Unavailable,
                SelectedExecutor::None,
                GovernedDispatchState::NotDispatched,
                ExecutionOutcome::NotExecuted,
                TimeoutState::NotObserved,
                GovernedCleanupState::NotNeeded,
                Some(GovernedError::new(
                    GovernedErrorCode::GovernanceUnavailable,
                    ErrorPhase::Governance,
                )),
            );
            return self.finish(record, result, guard);
        };
        let (verdict, governance) = match validate_governance_response(&dispatch_id, raw_response) {
            Ok(accepted) => accepted,
            Err((reason, raw)) => {
                let result = GovernedCommandResult::new(
                    dispatch_id,
                    GovernanceOutcome::Rejected { reason },
                    SelectedExecutor::None,
                    GovernedDispatchState::NotDispatched,
                    ExecutionOutcome::NotExecuted,
                    TimeoutState::NotObserved,
                    GovernedCleanupState::NotNeeded,
                    Some(GovernedError::new(
                        GovernedErrorCode::GovernanceRejected,
                        ErrorPhase::Governance,
                    )),
                );
                let _ = raw;
                return self.finish(record, result, guard);
            }
        };

        match verdict {
            GovernanceVerdict::Allow => {
                record.select_host(governance.clone());
                if guard.write(&record).is_err() {
                    return persistence_result(dispatch_id, SelectedExecutor::Host);
                }
                let result = self.execute_host(dispatch_id, governance, &effective).await;
                self.finish(record, result, guard)
            }
            GovernanceVerdict::Constrain => {
                let cleanup_id = RequestOwnedId::generate();
                record.select_sandbox(governance.clone(), cleanup_id.clone());
                // This write is both the may-create fence and the durable cleanup-ID fence.
                if guard.write(&record).is_err() {
                    return persistence_result(dispatch_id, SelectedExecutor::Sandbox);
                }
                let result = self
                    .execute_sandbox(
                        dispatch_id,
                        governance,
                        effective,
                        cleanup_id,
                        &mut record,
                        guard,
                    )
                    .await;
                self.finish(record, result, guard)
            }
            GovernanceVerdict::RequireApproval
            | GovernanceVerdict::Block
            | GovernanceVerdict::Halt => {
                let result = GovernedCommandResult::new(
                    dispatch_id,
                    governance,
                    SelectedExecutor::None,
                    GovernedDispatchState::NotDispatched,
                    ExecutionOutcome::NotExecuted,
                    TimeoutState::NotObserved,
                    GovernedCleanupState::NotNeeded,
                    None,
                );
                self.finish(record, result, guard)
            }
        }
    }

    async fn execute_host(
        &self,
        dispatch_id: DispatchId,
        governance: GovernanceOutcome,
        command: &EffectiveCommand,
    ) -> GovernedCommandResult {
        match self.host.execute(command).await {
            Ok(result) => {
                let result = normalize_exit_124(result);
                let timeout = TimeoutState::from(result.timeout());
                GovernedCommandResult::new(
                    dispatch_id,
                    governance,
                    SelectedExecutor::Host,
                    GovernedDispatchState::Completed,
                    ExecutionOutcome::Completed { result },
                    timeout,
                    GovernedCleanupState::NotNeeded,
                    None,
                )
            }
            Err(failure) => {
                let (dispatch, execution) = match failure.dispatch_state() {
                    DispatchState::NotDispatched => (
                        GovernedDispatchState::NotDispatched,
                        ExecutionOutcome::NotExecuted,
                    ),
                    DispatchState::PossiblyDispatched => (
                        GovernedDispatchState::PossiblyDispatched,
                        ExecutionOutcome::indeterminate(failure.counts()),
                    ),
                };
                GovernedCommandResult::new(
                    dispatch_id,
                    governance,
                    SelectedExecutor::Host,
                    dispatch,
                    execution,
                    TimeoutState::from(failure.timeout_state()),
                    GovernedCleanupState::NotNeeded,
                    Some(GovernedError::new(
                        GovernedErrorCode::HostFailed,
                        ErrorPhase::HostDispatch,
                    )),
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn execute_sandbox(
        &self,
        dispatch_id: DispatchId,
        governance: GovernanceOutcome,
        command: EffectiveCommand,
        cleanup_id: RequestOwnedId,
        record: &mut DispatchRecord,
        guard: &DispatchStoreGuard<'_>,
    ) -> GovernedCommandResult {
        let create = CreateRequest::new(
            cleanup_id,
            self.config.assets.template().clone(),
            self.config.assets.policy_document().clone(),
            self.config.assets.policy().clone(),
        );
        let created = match self
            .sandbox
            .create(create, operation_context(self.config.create_deadline))
            .await
        {
            Ok(created) => created,
            Err(failure) => {
                let cleanup = failure.cleanup_target().cloned();
                let mut result = GovernedCommandResult::new(
                    dispatch_id,
                    governance,
                    SelectedExecutor::Sandbox,
                    GovernedDispatchState::NotDispatched,
                    ExecutionOutcome::NotExecuted,
                    TimeoutState::NotObserved,
                    if cleanup.is_some() {
                        GovernedCleanupState::PendingReconciliation
                    } else {
                        GovernedCleanupState::NotNeeded
                    },
                    Some(GovernedError::new(
                        GovernedErrorCode::SandboxCreateFailed,
                        ErrorPhase::SandboxCreate,
                    )),
                );
                if let Some(target) = cleanup {
                    let cleanup_state = self.cleanup(target).await;
                    result.set_cleanup_state(cleanup_state);
                    if cleanup_state == GovernedCleanupState::ConfirmedAbsent {
                        record.cleanup_confirmed();
                    }
                }
                return result;
            }
        };
        let cleanup_target = created.cleanup_target();
        let ready = match self
            .sandbox
            .wait_ready(
                created,
                self.config.assets.policy().clone(),
                operation_context(self.config.readiness_deadline),
            )
            .await
        {
            Ok(ready) if ready.active_policy() == self.config.assets.policy() => ready,
            Ok(ready) => {
                let target = ready.cleanup_target();
                let cleanup_state = self.cleanup(target).await;
                if cleanup_state == GovernedCleanupState::ConfirmedAbsent {
                    record.cleanup_confirmed();
                }
                return GovernedCommandResult::new(
                    dispatch_id,
                    governance,
                    SelectedExecutor::Sandbox,
                    GovernedDispatchState::NotDispatched,
                    ExecutionOutcome::NotExecuted,
                    TimeoutState::NotObserved,
                    cleanup_state,
                    Some(GovernedError::new(
                        GovernedErrorCode::SandboxAttestationFailed,
                        ErrorPhase::SandboxAttestation,
                    )),
                );
            }
            Err(failure) => {
                let cleanup_state = self.cleanup(failure.cleanup_target().clone()).await;
                if cleanup_state == GovernedCleanupState::ConfirmedAbsent {
                    record.cleanup_confirmed();
                }
                let (code, phase) = if failure.code() == crate::ReadinessFailureCode::PolicyMismatch
                {
                    (
                        GovernedErrorCode::SandboxAttestationFailed,
                        ErrorPhase::SandboxAttestation,
                    )
                } else {
                    (
                        GovernedErrorCode::SandboxReadinessFailed,
                        ErrorPhase::SandboxReadiness,
                    )
                };
                return GovernedCommandResult::new(
                    dispatch_id,
                    governance,
                    SelectedExecutor::Sandbox,
                    GovernedDispatchState::NotDispatched,
                    ExecutionOutcome::NotExecuted,
                    TimeoutState::NotObserved,
                    cleanup_state,
                    Some(GovernedError::new(code, phase)),
                );
            }
        };

        record.sandbox_ready();
        if guard.write(record).is_err() {
            let cleanup_state = self.cleanup(cleanup_target).await;
            return GovernedCommandResult::new(
                dispatch_id,
                governance,
                SelectedExecutor::Sandbox,
                GovernedDispatchState::NotDispatched,
                ExecutionOutcome::NotExecuted,
                TimeoutState::NotObserved,
                cleanup_state,
                Some(GovernedError::new(
                    GovernedErrorCode::PersistenceFailed,
                    ErrorPhase::DispatchPersistence,
                )),
            );
        }
        let argv = Argv::new(command.argv().to_vec()).expect("effective argv is nonempty");
        let timeout = CommandTimeout::new(command.timeout_seconds())
            .expect("effective timeout was validated");
        let request = ExecRequest::new(argv, timeout, self.config.output_limits);
        record.sandbox_dispatch_possible();
        if guard.write(record).is_err() {
            let cleanup_state = self.cleanup(cleanup_target).await;
            return GovernedCommandResult::new(
                dispatch_id,
                governance,
                SelectedExecutor::Sandbox,
                GovernedDispatchState::NotDispatched,
                ExecutionOutcome::NotExecuted,
                TimeoutState::NotObserved,
                cleanup_state,
                Some(GovernedError::new(
                    GovernedErrorCode::PersistenceFailed,
                    ErrorPhase::DispatchPersistence,
                )),
            );
        }
        let deadline = Duration::from_secs(u64::from(command.timeout_seconds()))
            .saturating_add(self.config.dispatch_deadline_slack);
        let attempt = self
            .sandbox
            .exec(ready, request, operation_context(deadline))
            .await;
        let cleanup_state = self.cleanup(cleanup_target).await;
        if cleanup_state == GovernedCleanupState::ConfirmedAbsent {
            record.cleanup_confirmed();
        }
        sandbox_result(dispatch_id, governance, attempt, cleanup_state)
    }

    async fn cleanup(&self, target: CleanupTarget) -> GovernedCleanupState {
        let _delete = self
            .sandbox
            .delete(
                target.clone(),
                operation_context(self.config.cleanup_deadline),
            )
            .await;
        if self
            .sandbox
            .wait_deleted(target, operation_context(self.config.cleanup_deadline))
            .await
            .is_ok()
        {
            GovernedCleanupState::ConfirmedAbsent
        } else {
            GovernedCleanupState::PendingReconciliation
        }
    }

    fn finish(
        &self,
        mut record: DispatchRecord,
        mut result: GovernedCommandResult,
        guard: &DispatchStoreGuard<'_>,
    ) -> GovernedCommandResult {
        record.terminal(&result);
        if guard.write(&record).is_err() {
            result.set_error_if_none(GovernedError::new(
                GovernedErrorCode::PersistenceFailed,
                ErrorPhase::DispatchPersistence,
            ));
        }
        self.terminal_cache
            .lock()
            .expect("terminal cache mutex poisoned")
            .insert(result.dispatch_id().clone(), result.clone());
        result
    }

    async fn reconcile_record(&self, record: &mut DispatchRecord, guard: &DispatchStoreGuard<'_>) {
        let Some(cleanup_id) = record.cleanup_id().cloned() else {
            return;
        };
        if self.cleanup(CleanupTarget::new(cleanup_id)).await
            == GovernedCleanupState::ConfirmedAbsent
        {
            record.cleanup_confirmed();
            let _ = guard.write(record);
            if let Some(cached) = self
                .terminal_cache
                .lock()
                .expect("terminal cache mutex poisoned")
                .get_mut(record.dispatch_id())
            {
                cached.set_cleanup_state(GovernedCleanupState::ConfirmedAbsent);
            }
        }
    }

    async fn reconcile_all(&self) -> Result<DispatchReconciliationReport, GovernedError> {
        let _gate = self.gate.lock().await;
        let guard = self.store.lock().map_err(|_| {
            GovernedError::new(
                GovernedErrorCode::PersistenceFailed,
                ErrorPhase::SandboxReconciliation,
            )
        })?;
        let mut records = guard.load_all().map_err(|_| {
            GovernedError::new(
                GovernedErrorCode::PersistenceFailed,
                ErrorPhase::SandboxReconciliation,
            )
        })?;
        let mut report = DispatchReconciliationReport::default();
        for record in &mut records {
            if record.cleanup_state() != GovernedCleanupState::PendingReconciliation {
                continue;
            }
            self.reconcile_record(record, &guard).await;
            if record.cleanup_state() == GovernedCleanupState::ConfirmedAbsent {
                report.confirmed_absent = report.confirmed_absent.saturating_add(1);
            } else {
                report.pending = report.pending.saturating_add(1);
            }
        }
        Ok(report)
    }
}

#[allow(clippy::too_many_lines)]
fn validate_governance_response(
    dispatch_id: &DispatchId,
    response: serde_json::Value,
) -> Result<(GovernanceVerdict, GovernanceOutcome), (GovernanceRejection, serde_json::Value)> {
    let reject = |reason| Err((reason, response.clone()));
    let Some(object) = response.as_object() else {
        return reject(if response.is_null() {
            GovernanceRejection::Missing
        } else {
            GovernanceRejection::Malformed
        });
    };
    let allowed: HashSet<&str> = [
        "activity_id",
        "verdict",
        "action",
        "authoritative",
        "synthetic",
        "fallback_used",
        "guardrails_passed",
        "stale",
        "constraints",
        "remediation",
        "patch",
        "replacement",
        "transformation",
    ]
    .into_iter()
    .collect();
    if object.keys().any(|key| !allowed.contains(key.as_str())) {
        return reject(GovernanceRejection::UnsupportedField);
    }
    if ["remediation", "patch", "replacement", "transformation"]
        .iter()
        .any(|field| object.contains_key(*field))
    {
        return reject(GovernanceRejection::Remediation);
    }
    if object
        .get("activity_id")
        .and_then(serde_json::Value::as_str)
        != Some(dispatch_id.as_str())
    {
        return reject(GovernanceRejection::MismatchedActivity);
    }
    if object
        .get("authoritative")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return reject(GovernanceRejection::Unauthoritative);
    }
    if object
        .get("synthetic")
        .is_some_and(|value| value.as_bool() != Some(false))
    {
        return reject(GovernanceRejection::Synthetic);
    }
    if object
        .get("fallback_used")
        .is_some_and(|value| value.as_bool() != Some(false))
    {
        return reject(GovernanceRejection::Fallback);
    }
    if object
        .get("stale")
        .is_some_and(|value| value.as_bool() != Some(false))
    {
        return reject(GovernanceRejection::Stale);
    }
    if object
        .get("guardrails_passed")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return reject(GovernanceRejection::FailedGuardrails);
    }
    let Some(verdict_text) = object.get("verdict").and_then(serde_json::Value::as_str) else {
        return reject(GovernanceRejection::Malformed);
    };
    let verdict = match verdict_text {
        "ALLOW" => GovernanceVerdict::Allow,
        "CONSTRAIN" => GovernanceVerdict::Constrain,
        "REQUIRE_APPROVAL" => GovernanceVerdict::RequireApproval,
        "BLOCK" => GovernanceVerdict::Block,
        "HALT" => GovernanceVerdict::Halt,
        _ => return reject(GovernanceRejection::UnknownVerdict),
    };
    if object
        .get("action")
        .is_some_and(|action| action.as_str() != Some(verdict_text))
    {
        return reject(GovernanceRejection::ConflictingAction);
    }
    if let Some(constraints) = object.get("constraints") {
        match constraints {
            serde_json::Value::Null => {}
            serde_json::Value::Array(values) if values.is_empty() => {}
            serde_json::Value::Object(values) if values.is_empty() => {}
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                return reject(GovernanceRejection::UnsupportedConstraint);
            }
            _ => return reject(GovernanceRejection::InvalidConstraints),
        }
    }
    Ok((
        verdict,
        GovernanceOutcome::Authoritative { verdict, response },
    ))
}

fn sandbox_result(
    dispatch_id: DispatchId,
    governance: GovernanceOutcome,
    attempt: Result<ExecCompleted, ExecFailure>,
    cleanup_state: GovernedCleanupState,
) -> GovernedCommandResult {
    match attempt {
        Ok(result) => {
            let result = normalize_exit_124(result);
            let timeout = TimeoutState::from(result.timeout());
            let mut governed = GovernedCommandResult::new(
                dispatch_id,
                governance,
                SelectedExecutor::Sandbox,
                GovernedDispatchState::Completed,
                ExecutionOutcome::Completed { result },
                timeout,
                cleanup_state,
                None,
            );
            if cleanup_state == GovernedCleanupState::PendingReconciliation {
                governed.set_error_if_none(GovernedError::new(
                    GovernedErrorCode::CleanupPending,
                    ErrorPhase::SandboxCleanup,
                ));
            }
            governed
        }
        Err(failure) => {
            let (dispatch, execution) = match failure.dispatch_state() {
                DispatchState::NotDispatched => (
                    GovernedDispatchState::NotDispatched,
                    ExecutionOutcome::NotExecuted,
                ),
                DispatchState::PossiblyDispatched => (
                    GovernedDispatchState::PossiblyDispatched,
                    ExecutionOutcome::indeterminate(failure.counts()),
                ),
            };
            let code = if failure.code() == crate::ExecFailureCode::Transport {
                GovernedErrorCode::SandboxTransportFailed
            } else {
                GovernedErrorCode::SandboxExecutionFailed
            };
            let phase = if failure.code() == crate::ExecFailureCode::Transport {
                ErrorPhase::SandboxTransport
            } else if dispatch == GovernedDispatchState::NotDispatched {
                ErrorPhase::SandboxDispatch
            } else {
                ErrorPhase::SandboxExecution
            };
            GovernedCommandResult::new(
                dispatch_id,
                governance,
                SelectedExecutor::Sandbox,
                dispatch,
                execution,
                TimeoutState::from(failure.timeout_state()),
                cleanup_state,
                Some(GovernedError::new(code, phase)),
            )
        }
    }
}

fn normalize_exit_124(result: ExecCompleted) -> ExecCompleted {
    if result.exit_code().get() == 124 && result.timeout() == ObservedTimeout::NotObserved {
        return ExecCompleted::new(
            result.exit_code(),
            result.stdout().to_vec(),
            result.stderr().to_vec(),
            ObservedTimeout::Possible,
        );
    }
    result
}

fn operation_context(deadline: Duration) -> OperationContext {
    OperationContext::new(
        CancellationToken::new(),
        OperationDeadline::new(deadline).expect("dispatcher deadlines are positive"),
    )
}

fn persistence_result(
    dispatch_id: DispatchId,
    selected_executor: SelectedExecutor,
) -> GovernedCommandResult {
    GovernedCommandResult::new(
        dispatch_id,
        GovernanceOutcome::Unavailable,
        selected_executor,
        GovernedDispatchState::NotDispatched,
        ExecutionOutcome::NotExecuted,
        TimeoutState::NotObserved,
        if selected_executor == SelectedExecutor::Sandbox {
            GovernedCleanupState::PendingReconciliation
        } else {
            GovernedCleanupState::NotNeeded
        },
        Some(GovernedError::new(
            GovernedErrorCode::PersistenceFailed,
            ErrorPhase::DispatchPersistence,
        )),
    )
}
