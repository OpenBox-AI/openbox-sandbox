use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::{
    AssetBundleIdentity, BoundaryFailure, BoundaryFailureCode, CapabilityToken, DeadlineMillis,
    HealthStatus, OperationId, PROTOCOL_VERSION, RequestEnvelope, ResponseEnvelope, ServiceRequest,
    ServiceResponse,
};
use crate::{
    CleanupFailure, CleanupFailureCode, CleanupTarget, CreatedSandbox, DispatchState, ExecFailure,
    ExecFailureCode, ExecRequest, FailureTimeout, OperationContext, OperationDeadline,
    OperatorDetail, OutputByteCounts, ReadySandbox, RequestOwnedId, SandboxRuntime,
};
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;

use crate::service::store::{DurableRecord, DurableStage, DurableStore, StoreError};
use crate::{CallerIdentity, CallerRole};

struct OwnedEntry {
    record: DurableRecord,
    lifecycle_token: CapabilityToken,
    lifecycle: Lifecycle,
}

enum Lifecycle {
    Created(CreatedSandbox),
    Ready(ReadySandbox),
    CleanupOnly,
}

struct PreparedExec {
    caller: crate::CallerFingerprint,
    request_id: RequestOwnedId,
    request: ExecRequest,
    expires_at: Instant,
}

pub struct SandboxServiceBoundary {
    runtime: Arc<dyn SandboxRuntime>,
    bundle: AssetBundleIdentity,
    store: DurableStore,
    owned: Mutex<HashMap<RequestOwnedId, OwnedEntry>>,
    prepared: Mutex<HashMap<CapabilityToken, PreparedExec>>,
    active: Mutex<HashMap<OperationId, CancellationToken>>,
    lifecycle_changed: Notify,
    draining: AtomicBool,
    startup_reconciled: AtomicBool,
}

impl SandboxServiceBoundary {
    pub fn new(
        runtime: Arc<dyn SandboxRuntime>,
        bundle: AssetBundleIdentity,
        store: DurableStore,
    ) -> Self {
        Self {
            runtime,
            bundle,
            store,
            owned: Mutex::new(HashMap::new()),
            prepared: Mutex::new(HashMap::new()),
            active: Mutex::new(HashMap::new()),
            lifecycle_changed: Notify::new(),
            draining: AtomicBool::new(false),
            startup_reconciled: AtomicBool::new(false),
        }
    }

    pub const fn bundle(&self) -> &AssetBundleIdentity {
        &self.bundle
    }

    pub const fn store(&self) -> &DurableStore {
        &self.store
    }

    pub fn start_draining(&self) {
        self.draining.store(true, Ordering::Release);
    }

    pub async fn active_operation_count(&self) -> usize {
        self.active.lock().await.len()
    }

    pub async fn cancel_operation(&self, operation_id: &OperationId) -> bool {
        self.active
            .lock()
            .await
            .get(operation_id)
            .is_some_and(|token| {
                token.cancel();
                true
            })
    }

    pub async fn cancel_all_operations(&self) {
        for token in self.active.lock().await.values() {
            token.cancel();
        }
    }

    pub async fn reconcile_startup(
        &self,
        delete_deadline: Duration,
        wait_deadline: Duration,
    ) -> Result<ReconciliationReport, StoreError> {
        self.startup_reconciled.store(false, Ordering::Release);
        let records = self.store.load_all().await?;
        let mut removed = 0_u64;
        let mut unresolved = 0_u64;
        for record in records {
            if record.stage() == DurableStage::Unowned {
                self.store.remove(record.request_id()).await?;
                removed = removed.saturating_add(1);
                continue;
            }
            let target = CleanupTarget::new(record.request_id().clone());
            let delete = self
                .runtime
                .delete(
                    target.clone(),
                    operation_context(CancellationToken::new(), delete_deadline)?,
                )
                .await;
            let wait = self
                .runtime
                .wait_deleted(
                    target,
                    operation_context(CancellationToken::new(), wait_deadline)?,
                )
                .await;
            if wait.is_ok() {
                self.store.remove(record.request_id()).await?;
                removed = removed.saturating_add(1);
            } else {
                let _ = delete;
                unresolved = unresolved.saturating_add(1);
            }
        }
        if unresolved == 0 {
            self.startup_reconciled.store(true, Ordering::Release);
            Ok(ReconciliationReport {
                removed_records: removed,
                unresolved_records: 0,
            })
        } else {
            Err(StoreError)
        }
    }

    pub async fn handle(
        &self,
        caller: &CallerIdentity,
        envelope: RequestEnvelope,
    ) -> ResponseEnvelope {
        let protocol_version = envelope.protocol_version();
        let operation_id = envelope.operation_id().clone();
        if protocol_version != PROTOCOL_VERSION {
            return response(
                operation_id,
                boundary_failure(BoundaryFailureCode::ProtocolVersion, None, None),
            );
        }
        if envelope.asset_bundle() != &self.bundle {
            return response(
                operation_id,
                boundary_failure(BoundaryFailureCode::AssetBundleMismatch, None, None),
            );
        }
        let (_, _, request) = envelope.into_parts();
        if matches!(request, ServiceRequest::Cancel { .. }) {
            return self.handle_cancel(operation_id, request).await;
        }
        let cancellation = CancellationToken::new();
        {
            let mut active = self.active.lock().await;
            if active
                .insert(operation_id.clone(), cancellation.clone())
                .is_some()
            {
                return response(
                    operation_id,
                    boundary_failure(BoundaryFailureCode::LifecycleConflict, None, None),
                );
            }
        }
        let outcome = self.dispatch(caller, request, cancellation).await;
        self.active.lock().await.remove(&operation_id);
        ResponseEnvelope::new(operation_id, outcome)
    }

    async fn dispatch(
        &self,
        caller: &CallerIdentity,
        request: ServiceRequest,
        cancellation: CancellationToken,
    ) -> ServiceResponse {
        match request {
            ServiceRequest::Health => self.health().await,
            ServiceRequest::Create {
                request,
                deadline_ms,
            } => {
                self.create(caller, request, deadline_ms, cancellation)
                    .await
            }
            ServiceRequest::WaitReady {
                request_id,
                lifecycle_token,
                expected_policy,
                deadline_ms,
            } => {
                self.wait_ready(
                    caller,
                    request_id,
                    lifecycle_token,
                    expected_policy,
                    deadline_ms,
                    cancellation,
                )
                .await
            }
            ServiceRequest::PrepareExec {
                request_id,
                lifecycle_token,
                request,
                deadline_ms,
            } => {
                self.prepare_exec(caller, request_id, lifecycle_token, request, deadline_ms)
                    .await
            }
            ServiceRequest::CommitExec {
                request_id,
                prepare_token,
                deadline_ms,
            } => {
                self.commit_exec(caller, request_id, prepare_token, deadline_ms, cancellation)
                    .await
            }
            ServiceRequest::Delete {
                target,
                deadline_ms,
            } => self.delete(caller, target, deadline_ms, cancellation).await,
            ServiceRequest::WaitDeleted {
                target,
                deadline_ms,
            } => {
                self.wait_deleted(caller, target, deadline_ms, cancellation)
                    .await
            }
            ServiceRequest::BeginDrain => self.begin_drain(caller).await,
            ServiceRequest::DrainStatus => self.drain_status().await,
            ServiceRequest::Cancel { .. } => {
                boundary_failure(BoundaryFailureCode::InvalidRequest, None, None)
            }
        }
    }

    async fn health(&self) -> ServiceResponse {
        let pending = self.store.load_all().await.map_or(u64::MAX, |records| {
            u64::try_from(records.len()).unwrap_or(u64::MAX)
        });
        let active = u64::try_from(self.active.lock().await.len()).unwrap_or(u64::MAX);
        let startup_reconciled = self.startup_reconciled.load(Ordering::Acquire);
        let draining = self.draining.load(Ordering::Acquire);
        ServiceResponse::Health {
            status: HealthStatus::new(
                startup_reconciled && !draining && pending != u64::MAX,
                draining,
                startup_reconciled,
                active,
                pending,
            ),
        }
    }

    async fn create(
        &self,
        caller: &CallerIdentity,
        request: crate::CreateRequest,
        deadline: DeadlineMillis,
        cancellation: CancellationToken,
    ) -> ServiceResponse {
        if self.reject_new_work() {
            return boundary_failure(BoundaryFailureCode::Draining, None, None);
        }
        if request.template() != self.bundle.template()
            || request.expected_policy() != self.bundle.policy()
        {
            return boundary_failure(BoundaryFailureCode::AssetBundleMismatch, None, None);
        }
        let request_id = request.request_id().clone();
        if self.owned.lock().await.contains_key(&request_id) {
            return boundary_failure(BoundaryFailureCode::LifecycleConflict, None, None);
        }
        let Ok(mut record) = DurableRecord::new(
            request_id.clone(),
            caller.fingerprint().clone(),
            DurableStage::CreatePossible,
            request.template().clone(),
            request.expected_policy().clone(),
        ) else {
            return boundary_failure(BoundaryFailureCode::DurableState, None, None);
        };
        if self.store.write(&record).await.is_err() {
            return boundary_failure(BoundaryFailureCode::DurableState, None, None);
        }
        let result = self
            .runtime
            .create(request, operation_context_ms(cancellation, deadline))
            .await;
        match result {
            Ok(created) => {
                let lifecycle_token = CapabilityToken::generate();
                if record.transition(DurableStage::Created).is_err()
                    || self.store.write(&record).await.is_err()
                {
                    let target = created.cleanup_target();
                    self.put_owned(request_id, record, lifecycle_token, Lifecycle::CleanupOnly)
                        .await;
                    return boundary_failure(BoundaryFailureCode::DurableState, Some(target), None);
                }
                self.put_owned(
                    request_id.clone(),
                    record,
                    lifecycle_token.clone(),
                    Lifecycle::Created(created),
                )
                .await;
                ServiceResponse::Created {
                    request_id,
                    lifecycle_token,
                }
            }
            Err(failure) => {
                if failure.cleanup_target().is_some() {
                    let _ = record.transition(DurableStage::CleanupOnly);
                    let _ = self.store.write(&record).await;
                    self.put_owned(
                        request_id,
                        record,
                        CapabilityToken::generate(),
                        Lifecycle::CleanupOnly,
                    )
                    .await;
                } else {
                    let _ = record.transition(DurableStage::Unowned);
                    let _ = self.store.write(&record).await;
                    let _ = self.store.remove(&request_id).await;
                }
                ServiceResponse::CreateFailed { failure }
            }
        }
    }

    async fn wait_ready(
        &self,
        caller: &CallerIdentity,
        request_id: RequestOwnedId,
        lifecycle_token: CapabilityToken,
        expected_policy: crate::PolicyIdentity,
        deadline: DeadlineMillis,
        cancellation: CancellationToken,
    ) -> ServiceResponse {
        let Some(entry) = self
            .take_owned(caller, &request_id, Some(&lifecycle_token))
            .await
        else {
            return boundary_failure(BoundaryFailureCode::LifecycleConflict, None, None);
        };
        let OwnedEntry {
            mut record,
            lifecycle_token,
            lifecycle,
        } = entry;
        let Lifecycle::Created(created) = lifecycle else {
            self.put_owned(request_id, record, lifecycle_token, lifecycle)
                .await;
            return boundary_failure(BoundaryFailureCode::LifecycleConflict, None, None);
        };
        if &expected_policy != self.bundle.policy() || record.policy() != &expected_policy {
            let target = created.cleanup_target();
            let _ = record.transition(DurableStage::CleanupOnly);
            let _ = self.store.write(&record).await;
            self.put_owned(request_id, record, lifecycle_token, Lifecycle::CleanupOnly)
                .await;
            return boundary_failure(BoundaryFailureCode::AssetBundleMismatch, Some(target), None);
        }
        let target = created.cleanup_target();
        match self
            .runtime
            .wait_ready(
                created,
                expected_policy,
                operation_context_ms(cancellation, deadline),
            )
            .await
        {
            Ok(ready) => {
                let active_policy = ready.active_policy().clone();
                if record.transition(DurableStage::Ready).is_err()
                    || self.store.write(&record).await.is_err()
                {
                    self.put_owned(request_id, record, lifecycle_token, Lifecycle::CleanupOnly)
                        .await;
                    return boundary_failure(BoundaryFailureCode::DurableState, Some(target), None);
                }
                let ready_token = CapabilityToken::generate();
                self.put_owned(
                    request_id.clone(),
                    record,
                    ready_token.clone(),
                    Lifecycle::Ready(ready),
                )
                .await;
                ServiceResponse::Ready {
                    request_id,
                    lifecycle_token: ready_token,
                    active_policy,
                }
            }
            Err(failure) => {
                let _ = record.transition(DurableStage::CleanupOnly);
                let _ = self.store.write(&record).await;
                self.put_owned(request_id, record, lifecycle_token, Lifecycle::CleanupOnly)
                    .await;
                ServiceResponse::ReadinessFailed { failure }
            }
        }
    }

    async fn prepare_exec(
        &self,
        caller: &CallerIdentity,
        request_id: RequestOwnedId,
        lifecycle_token: CapabilityToken,
        request: ExecRequest,
        deadline: DeadlineMillis,
    ) -> ServiceResponse {
        if self.reject_new_work() {
            return boundary_failure(BoundaryFailureCode::Draining, None, None);
        }
        {
            let owned = self.owned.lock().await;
            let Some(entry) = owned.get(&request_id) else {
                return boundary_failure(BoundaryFailureCode::LifecycleConflict, None, None);
            };
            if entry.record.caller() != caller.fingerprint()
                || entry.lifecycle_token != lifecycle_token
                || !matches!(entry.lifecycle, Lifecycle::Ready(_))
            {
                return boundary_failure(BoundaryFailureCode::Authorization, None, None);
            }
        }
        let mut prepared = self.prepared.lock().await;
        if prepared.values().any(|item| item.request_id == request_id) {
            return boundary_failure(BoundaryFailureCode::LifecycleConflict, None, None);
        }
        let token = CapabilityToken::generate();
        prepared.insert(
            token.clone(),
            PreparedExec {
                caller: caller.fingerprint().clone(),
                request_id,
                request,
                expires_at: Instant::now() + deadline.duration(),
            },
        );
        ServiceResponse::ExecPrepared {
            prepare_token: token,
        }
    }

    async fn commit_exec(
        &self,
        caller: &CallerIdentity,
        request_id: RequestOwnedId,
        token: CapabilityToken,
        deadline: DeadlineMillis,
        cancellation: CancellationToken,
    ) -> ServiceResponse {
        if self.reject_new_work() {
            return boundary_failure(
                BoundaryFailureCode::Draining,
                Some(CleanupTarget::new(request_id)),
                Some(DispatchState::NotDispatched),
            );
        }
        let Some(prepared) = self.prepared.lock().await.remove(&token) else {
            return boundary_failure(
                BoundaryFailureCode::LifecycleConflict,
                Some(CleanupTarget::new(request_id)),
                Some(DispatchState::NotDispatched),
            );
        };
        if prepared.caller != *caller.fingerprint() || prepared.request_id != request_id {
            return boundary_failure(
                BoundaryFailureCode::Authorization,
                Some(CleanupTarget::new(request_id)),
                Some(DispatchState::NotDispatched),
            );
        }
        let Some(entry) = self.take_owned(caller, &request_id, None).await else {
            return boundary_failure(
                BoundaryFailureCode::LifecycleConflict,
                Some(CleanupTarget::new(request_id)),
                Some(DispatchState::NotDispatched),
            );
        };
        let OwnedEntry {
            mut record,
            lifecycle_token,
            lifecycle,
        } = entry;
        let Lifecycle::Ready(ready) = lifecycle else {
            self.put_owned(request_id.clone(), record, lifecycle_token, lifecycle)
                .await;
            return boundary_failure(
                BoundaryFailureCode::LifecycleConflict,
                Some(CleanupTarget::new(request_id)),
                Some(DispatchState::NotDispatched),
            );
        };
        let target = ready.cleanup_target();
        if prepared.expires_at <= Instant::now() {
            self.put_owned(request_id, record, lifecycle_token, Lifecycle::Ready(ready))
                .await;
            return ServiceResponse::ExecFailed {
                failure: ExecFailure::not_dispatched(
                    target,
                    ExecFailureCode::Deadline,
                    OperatorDetail::redacted("prepared execution expired before dispatch"),
                )
                .expect("deadline is a valid pre-dispatch failure"),
            };
        }
        if record.transition(DurableStage::ExecPossible).is_err()
            || self.store.write(&record).await.is_err()
        {
            self.put_owned(request_id, record, lifecycle_token, Lifecycle::Ready(ready))
                .await;
            return boundary_failure(
                BoundaryFailureCode::DurableState,
                Some(target),
                Some(DispatchState::NotDispatched),
            );
        }
        let result = self
            .runtime
            .exec(
                ready,
                prepared.request,
                operation_context_ms(cancellation, deadline),
            )
            .await;
        let _ = record.transition(DurableStage::CleanupOnly);
        let _ = self.store.write(&record).await;
        self.put_owned(request_id, record, lifecycle_token, Lifecycle::CleanupOnly)
            .await;
        match result {
            Ok(result) => ServiceResponse::Executed { result },
            Err(failure) => ServiceResponse::ExecFailed { failure },
        }
    }

    async fn delete(
        &self,
        caller: &CallerIdentity,
        target: CleanupTarget,
        deadline: DeadlineMillis,
        cancellation: CancellationToken,
    ) -> ServiceResponse {
        let request_id = target.request_id().clone();
        let started = Instant::now();
        let entry = match self
            .acquire_for_cleanup(caller, &request_id, deadline, &cancellation)
            .await
        {
            Ok(entry) => entry,
            Err(failure) => return cleanup_acquire_failure(target, failure),
        };
        let OwnedEntry {
            mut record,
            lifecycle_token,
            lifecycle,
        } = entry;
        self.prepared
            .lock()
            .await
            .retain(|_, item| item.request_id != request_id);
        if record.transition(DurableStage::DeletePending).is_err()
            || self.store.write(&record).await.is_err()
        {
            self.put_owned(request_id, record, lifecycle_token, lifecycle)
                .await;
            return boundary_failure(BoundaryFailureCode::DurableState, Some(target), None);
        }
        let Some(remaining) = deadline
            .duration()
            .checked_sub(started.elapsed())
            .filter(|duration| !duration.is_zero())
        else {
            self.put_owned(request_id, record, lifecycle_token, lifecycle)
                .await;
            return cleanup_failure_response(target, CleanupFailureCode::Deadline);
        };
        let result = self
            .runtime
            .delete(
                target.clone(),
                operation_context(cancellation, remaining)
                    .expect("remaining cleanup deadline is positive"),
            )
            .await;
        self.put_owned(request_id, record, lifecycle_token, Lifecycle::CleanupOnly)
            .await;
        match result {
            Ok(outcome) => ServiceResponse::Deleted { outcome },
            Err(failure) => ServiceResponse::CleanupFailed { failure },
        }
    }

    async fn wait_deleted(
        &self,
        caller: &CallerIdentity,
        target: CleanupTarget,
        deadline: DeadlineMillis,
        cancellation: CancellationToken,
    ) -> ServiceResponse {
        let request_id = target.request_id().clone();
        let started = Instant::now();
        let entry = match self
            .acquire_for_cleanup(caller, &request_id, deadline, &cancellation)
            .await
        {
            Ok(entry) => entry,
            Err(failure) => return cleanup_acquire_failure(target, failure),
        };
        let Some(remaining) = deadline
            .duration()
            .checked_sub(started.elapsed())
            .filter(|duration| !duration.is_zero())
        else {
            self.put_owned(
                request_id,
                entry.record,
                entry.lifecycle_token,
                entry.lifecycle,
            )
            .await;
            return cleanup_failure_response(target, CleanupFailureCode::Deadline);
        };
        let result = self
            .runtime
            .wait_deleted(
                target.clone(),
                operation_context(cancellation, remaining)
                    .expect("remaining cleanup deadline is positive"),
            )
            .await;
        match result {
            Ok(()) => {
                if self.store.remove(&request_id).await.is_err() {
                    self.put_owned(
                        request_id,
                        entry.record,
                        entry.lifecycle_token,
                        entry.lifecycle,
                    )
                    .await;
                    boundary_failure(BoundaryFailureCode::DurableState, Some(target), None)
                } else {
                    ServiceResponse::TerminallyAbsent
                }
            }
            Err(failure) => {
                self.put_owned(
                    request_id,
                    entry.record,
                    entry.lifecycle_token,
                    Lifecycle::CleanupOnly,
                )
                .await;
                ServiceResponse::CleanupFailed { failure }
            }
        }
    }

    async fn handle_cancel(
        &self,
        operation_id: OperationId,
        request: ServiceRequest,
    ) -> ResponseEnvelope {
        let ServiceRequest::Cancel {
            target_operation_id,
        } = request
        else {
            return response(
                operation_id,
                boundary_failure(BoundaryFailureCode::InvalidRequest, None, None),
            );
        };
        let found = self.cancel_operation(&target_operation_id).await;
        ResponseEnvelope::new(operation_id, ServiceResponse::Cancelled { found })
    }

    async fn begin_drain(&self, caller: &CallerIdentity) -> ServiceResponse {
        if caller.role() != CallerRole::Administrator {
            return boundary_failure(BoundaryFailureCode::Authorization, None, None);
        }
        self.draining.store(true, Ordering::Release);
        self.drain_status().await
    }

    async fn drain_status(&self) -> ServiceResponse {
        let active_operations = u64::try_from(self.active.lock().await.len()).unwrap_or(u64::MAX);
        ServiceResponse::Draining { active_operations }
    }

    async fn take_owned(
        &self,
        caller: &CallerIdentity,
        request_id: &RequestOwnedId,
        lifecycle_token: Option<&CapabilityToken>,
    ) -> Option<OwnedEntry> {
        let mut owned = self.owned.lock().await;
        let entry = owned.remove(request_id)?;
        let token_matches = lifecycle_token.is_none_or(|token| token == &entry.lifecycle_token);
        if entry.record.caller() == caller.fingerprint() && token_matches {
            Some(entry)
        } else {
            owned.insert(request_id.clone(), entry);
            None
        }
    }

    async fn acquire_for_cleanup(
        &self,
        caller: &CallerIdentity,
        request_id: &RequestOwnedId,
        deadline: DeadlineMillis,
        cancellation: &CancellationToken,
    ) -> Result<OwnedEntry, CleanupAcquireFailure> {
        let expires_at = Instant::now() + deadline.duration();
        loop {
            let changed = self.lifecycle_changed.notified();
            if let Some(entry) = self.take_owned(caller, request_id, None).await {
                return Ok(entry);
            }
            let records = self
                .store
                .load_all()
                .await
                .map_err(|_| CleanupAcquireFailure::DurableState)?;
            let Some(record) = records
                .iter()
                .find(|record| record.request_id() == request_id)
            else {
                return Err(CleanupAcquireFailure::NotOwned);
            };
            if record.caller() != caller.fingerprint() || record.stage() == DurableStage::Unowned {
                return Err(CleanupAcquireFailure::NotOwned);
            }
            tokio::select! {
                () = cancellation.cancelled() => return Err(CleanupAcquireFailure::Cancelled),
                () = tokio::time::sleep_until(expires_at.into()) => return Err(CleanupAcquireFailure::Deadline),
                () = changed => {}
            }
        }
    }

    async fn put_owned(
        &self,
        request_id: RequestOwnedId,
        record: DurableRecord,
        lifecycle_token: CapabilityToken,
        lifecycle: Lifecycle,
    ) {
        self.owned.lock().await.insert(
            request_id,
            OwnedEntry {
                record,
                lifecycle_token,
                lifecycle,
            },
        );
        self.lifecycle_changed.notify_waiters();
    }

    fn reject_new_work(&self) -> bool {
        self.draining.load(Ordering::Acquire) || !self.startup_reconciled.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupAcquireFailure {
    NotOwned,
    Cancelled,
    Deadline,
    DurableState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconciliationReport {
    removed_records: u64,
    unresolved_records: u64,
}

impl ReconciliationReport {
    pub const fn removed_records(self) -> u64 {
        self.removed_records
    }

    pub const fn unresolved_records(self) -> u64 {
        self.unresolved_records
    }
}

fn response(operation_id: OperationId, response: ServiceResponse) -> ResponseEnvelope {
    ResponseEnvelope::new(operation_id, response)
}

fn boundary_failure(
    code: BoundaryFailureCode,
    target: Option<CleanupTarget>,
    dispatch_state: Option<DispatchState>,
) -> ServiceResponse {
    ServiceResponse::BoundaryFailed {
        failure: BoundaryFailure::new(
            code,
            target,
            dispatch_state,
            OperatorDetail::redacted("sandbox service boundary rejected the operation"),
        ),
    }
}

fn cleanup_acquire_failure(
    target: CleanupTarget,
    failure: CleanupAcquireFailure,
) -> ServiceResponse {
    match failure {
        CleanupAcquireFailure::NotOwned => {
            boundary_failure(BoundaryFailureCode::LifecycleConflict, None, None)
        }
        CleanupAcquireFailure::DurableState => {
            boundary_failure(BoundaryFailureCode::DurableState, Some(target), None)
        }
        CleanupAcquireFailure::Cancelled => {
            cleanup_failure_response(target, CleanupFailureCode::Cancelled)
        }
        CleanupAcquireFailure::Deadline => {
            cleanup_failure_response(target, CleanupFailureCode::Deadline)
        }
    }
}

fn cleanup_failure_response(target: CleanupTarget, code: CleanupFailureCode) -> ServiceResponse {
    ServiceResponse::CleanupFailed {
        failure: CleanupFailure::new(
            target,
            code,
            OperatorDetail::redacted("cleanup could not acquire the durable lifecycle state"),
        ),
    }
}

fn operation_context_ms(
    cancellation: CancellationToken,
    deadline: DeadlineMillis,
) -> OperationContext {
    OperationContext::new(
        cancellation,
        OperationDeadline::new(deadline.duration())
            .expect("protocol deadlines are validated positive"),
    )
}

fn operation_context(
    cancellation: CancellationToken,
    deadline: Duration,
) -> Result<OperationContext, StoreError> {
    Ok(OperationContext::new(
        cancellation,
        OperationDeadline::new(deadline).map_err(|_| StoreError)?,
    ))
}

#[allow(dead_code)]
fn process_loss_after_commit(target: CleanupTarget) -> ExecFailure {
    ExecFailure::possibly_dispatched(
        target,
        ExecFailureCode::Transport,
        FailureTimeout::Unknown,
        OutputByteCounts::default(),
        OperatorDetail::redacted("sandbox service response lost after possible dispatch"),
    )
    .expect("process loss after commit is indeterminate")
}
