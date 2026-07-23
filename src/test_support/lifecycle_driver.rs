//! Test-only lifecycle driver that preserves attempts while always reconciling owned sandboxes.

use crate::{
    CleanupFailure, CleanupState, CleanupTarget, CreateFailure, CreateRequest, DeleteOutcome,
    ExecCompleted, ExecFailure, ExecRequest, OperationContext, ReadinessFailure, RequestOwnedId,
    SandboxRuntime,
};

/// Independent operation contexts for one complete test lifecycle.
#[derive(Clone, Debug)]
pub struct LifecycleContexts {
    create: OperationContext,
    readiness: OperationContext,
    exec: OperationContext,
    delete: OperationContext,
    wait_deleted: OperationContext,
}

impl LifecycleContexts {
    /// Creates explicit contexts for all five operations.
    pub const fn new(
        create: OperationContext,
        readiness: OperationContext,
        exec: OperationContext,
        delete: OperationContext,
        wait_deleted: OperationContext,
    ) -> Self {
        Self {
            create,
            readiness,
            exec,
            delete,
            wait_deleted,
        }
    }
}

/// The original lifecycle attempt, retained independently from cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleAttempt {
    /// Creation failed before a handle was returned.
    CreateFailed(CreateFailure),
    /// Readiness failed after successful creation.
    ReadinessFailed(ReadinessFailure),
    /// Execution reached a typed terminal exit.
    ExecCompleted(ExecCompleted),
    /// Execution failed with explicit dispatch ambiguity.
    ExecFailed(ExecFailure),
}

/// Results of both cleanup operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleCleanup {
    state: CleanupState,
    delete: Option<Result<DeleteOutcome, CleanupFailure>>,
    wait_deleted: Option<Result<(), CleanupFailure>>,
}

impl LifecycleCleanup {
    const fn not_needed() -> Self {
        Self {
            state: CleanupState::NotNeeded,
            delete: None,
            wait_deleted: None,
        }
    }

    /// Returns whether cleanup was unnecessary, terminally confirmed, or failed.
    pub const fn state(&self) -> CleanupState {
        self.state
    }

    /// Returns the delete outcome when cleanup was required.
    pub const fn delete(&self) -> Option<&Result<DeleteOutcome, CleanupFailure>> {
        self.delete.as_ref()
    }

    /// Returns the terminal-absence outcome when cleanup was required.
    pub const fn wait_deleted(&self) -> Option<&Result<(), CleanupFailure>> {
        self.wait_deleted.as_ref()
    }
}

/// Complete test lifecycle result preserving both the original attempt and cleanup status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleOutcome {
    request_id: RequestOwnedId,
    attempt: LifecycleAttempt,
    cleanup: LifecycleCleanup,
}

impl LifecycleOutcome {
    /// Returns the caller-owned identifier used by the attempt.
    pub const fn request_id(&self) -> &RequestOwnedId {
        &self.request_id
    }

    /// Returns the original create/readiness/exec outcome.
    pub const fn attempt(&self) -> &LifecycleAttempt {
        &self.attempt
    }

    /// Returns cleanup results without masking the original attempt.
    pub const fn cleanup(&self) -> &LifecycleCleanup {
        &self.cleanup
    }
}

/// Runs one `create → wait_ready → exec → delete → wait_deleted` test lifecycle.
///
/// There is exactly one execution call and no automatic retry. Cleanup uses fresh contexts and is
/// attempted after every successful or ambiguous creation, including when delete itself fails.
pub async fn run_lifecycle(
    runtime: &dyn SandboxRuntime,
    create_request: CreateRequest,
    exec_request: ExecRequest,
    contexts: LifecycleContexts,
) -> LifecycleOutcome {
    let request_id = create_request.request_id().clone();
    let expected_policy = create_request.expected_policy().clone();
    let created = match runtime.create(create_request, contexts.create).await {
        Ok(created) => created,
        Err(error) => {
            let cleanup = if let Some(target) = error.cleanup_target().cloned() {
                cleanup(runtime, target, contexts.delete, contexts.wait_deleted).await
            } else {
                LifecycleCleanup::not_needed()
            };
            return LifecycleOutcome {
                request_id,
                attempt: LifecycleAttempt::CreateFailed(error),
                cleanup,
            };
        }
    };

    let cleanup_target = created.cleanup_target();
    let ready = match runtime
        .wait_ready(created, expected_policy, contexts.readiness)
        .await
    {
        Ok(ready) => ready,
        Err(error) => {
            let cleanup = cleanup(
                runtime,
                cleanup_target,
                contexts.delete,
                contexts.wait_deleted,
            )
            .await;
            return LifecycleOutcome {
                request_id,
                attempt: LifecycleAttempt::ReadinessFailed(error),
                cleanup,
            };
        }
    };

    let attempt = match runtime.exec(ready, exec_request, contexts.exec).await {
        Ok(completed) => LifecycleAttempt::ExecCompleted(completed),
        Err(error) => LifecycleAttempt::ExecFailed(error),
    };
    let cleanup = cleanup(
        runtime,
        cleanup_target,
        contexts.delete,
        contexts.wait_deleted,
    )
    .await;
    LifecycleOutcome {
        request_id,
        attempt,
        cleanup,
    }
}

async fn cleanup(
    runtime: &dyn SandboxRuntime,
    target: CleanupTarget,
    delete_context: OperationContext,
    wait_context: OperationContext,
) -> LifecycleCleanup {
    let delete = runtime.delete(target.clone(), delete_context).await;
    let wait_deleted = runtime.wait_deleted(target, wait_context).await;
    let state = if delete.is_ok() && wait_deleted.is_ok() {
        CleanupState::Deleted
    } else {
        CleanupState::Failed
    };
    LifecycleCleanup {
        state,
        delete: Some(delete),
        wait_deleted: Some(wait_deleted),
    }
}
