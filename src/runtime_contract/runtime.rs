//! Provider-neutral asynchronous runtime boundary.

use async_trait::async_trait;

use crate::{
    CleanupFailure, CleanupTarget, CreateFailure, CreateRequest, CreatedSandbox, DeleteOutcome,
    ExecCompleted, ExecFailure, ExecRequest, OperationContext, PolicyIdentity, ReadinessFailure,
    ReadySandbox,
};

/// The single provider-neutral owner of sandbox lifecycle I/O.
///
/// Implementations must not retry execution automatically. Callers retain a [`CleanupTarget`]
/// before each consuming transition so successful and ambiguous creation can always be reconciled.
#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    /// Creates one request-owned sandbox from an explicit template and policy.
    async fn create(
        &self,
        request: CreateRequest,
        context: OperationContext,
    ) -> Result<CreatedSandbox, CreateFailure>;

    /// Waits until both workload readiness and the expected policy are attested.
    async fn wait_ready(
        &self,
        sandbox: CreatedSandbox,
        expected_policy: PolicyIdentity,
        context: OperationContext,
    ) -> Result<ReadySandbox, ReadinessFailure>;

    /// Dispatches exactly one command attempt to a ready sandbox.
    async fn exec(
        &self,
        sandbox: ReadySandbox,
        request: ExecRequest,
        context: OperationContext,
    ) -> Result<ExecCompleted, ExecFailure>;

    /// Requests deletion by retained request-owned cleanup target.
    async fn delete(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<DeleteOutcome, CleanupFailure>;

    /// Waits until the retained request-owned identifier is terminally absent.
    async fn wait_deleted(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<(), CleanupFailure>;
}
