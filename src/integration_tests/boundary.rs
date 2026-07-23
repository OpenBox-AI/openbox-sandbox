use std::sync::Arc;
use std::time::Duration;

use crate::{
    AssetBundleIdentity, BoundaryFailureCode, CapabilityToken, DeadlineMillis, OperationId,
    RequestEnvelope, ServiceRequest, ServiceResponse, decode_request,
};
use crate::{
    CallerFingerprint, CallerIdentity, CallerRole, DurableRecord, DurableStage, DurableStore,
    SandboxServiceBoundary,
};
use crate::{
    CleanupTarget, CreationState, DeleteOutcome, ObservedTimeout, Sha256Digest, TemplateIdentity,
};
use crate::{
    FakeCreatePlan, FakeDeletePlan, FakeExecEvent, FakeExecPlan, FakeReadinessPlan,
    FakeSandboxRuntime, FakeScript, FakeWaitDeletedPlan, create_request_fixture,
    exec_request_fixture, output_limits_fixture, policy_fixture, raw_stderr_fixture,
    raw_stdout_fixture, request_id_fixture,
};

fn caller(role: CallerRole) -> CallerIdentity {
    CallerIdentity::new(CallerFingerprint::parse("d".repeat(64)).unwrap(), role)
}

fn bundle() -> AssetBundleIdentity {
    let request = create_request_fixture(1);
    AssetBundleIdentity::new(
        1,
        Sha256Digest::parse("a".repeat(64)).unwrap(),
        request.template().clone(),
        request.expected_policy().clone(),
        "test-runtime-v1",
    )
    .unwrap()
}

fn envelope(bundle: &AssetBundleIdentity, request: ServiceRequest) -> RequestEnvelope {
    RequestEnvelope::new(OperationId::generate(), bundle.clone(), request)
}

fn deadline() -> DeadlineMillis {
    DeadlineMillis::new(5_000).unwrap()
}

fn full_script() -> FakeScript {
    let mut script = FakeScript::new();
    script
        .push_create(FakeCreatePlan::Succeed {
            provider_handle: b"provider-id".to_vec(),
        })
        .push_readiness(FakeReadinessPlan::Ready {
            observed_policy: policy_fixture(1),
        })
        .push_exec(FakeExecPlan::Stream {
            events: vec![
                FakeExecEvent::Stdout(raw_stdout_fixture()),
                FakeExecEvent::Stderr(raw_stderr_fixture()),
                FakeExecEvent::Exit {
                    code: 7,
                    timeout: ObservedTimeout::NotObserved,
                },
            ],
        })
        .push_delete(FakeDeletePlan::Deleted)
        .push_wait_deleted(FakeWaitDeletedPlan::Absent);
    script
}

async fn initialized_boundary(
    script: FakeScript,
    directory: &std::path::Path,
) -> (Arc<FakeSandboxRuntime>, SandboxServiceBoundary) {
    let runtime = Arc::new(FakeSandboxRuntime::new(script));
    let store = DurableStore::initialize(directory).unwrap();
    let boundary = SandboxServiceBoundary::new(runtime.clone(), bundle(), store);
    boundary
        .reconcile_startup(Duration::from_secs(1), Duration::from_secs(1))
        .await
        .unwrap();
    (runtime, boundary)
}

async fn create_and_ready(
    boundary: &SandboxServiceBoundary,
    caller: &CallerIdentity,
) -> CapabilityToken {
    let response = boundary
        .handle(
            caller,
            envelope(
                boundary.bundle(),
                ServiceRequest::Create {
                    request: create_request_fixture(1),
                    deadline_ms: deadline(),
                },
            ),
        )
        .await
        .into_response();
    let ServiceResponse::Created {
        lifecycle_token, ..
    } = response
    else {
        panic!("sandbox was not created")
    };

    let response = boundary
        .handle(
            caller,
            envelope(
                boundary.bundle(),
                ServiceRequest::WaitReady {
                    request_id: request_id_fixture(1),
                    lifecycle_token,
                    expected_policy: policy_fixture(1),
                    deadline_ms: deadline(),
                },
            ),
        )
        .await
        .into_response();
    let ServiceResponse::Ready {
        lifecycle_token, ..
    } = response
    else {
        panic!("sandbox was not ready")
    };
    lifecycle_token
}

#[tokio::test]
async fn complete_boundary_lifecycle_preserves_bytes_dispatch_and_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let (runtime, boundary) = initialized_boundary(full_script(), directory.path()).await;
    let caller = caller(CallerRole::Runtime);
    let lifecycle_token = create_and_ready(&boundary, &caller).await;

    let response = boundary
        .handle(
            &caller,
            envelope(
                boundary.bundle(),
                ServiceRequest::PrepareExec {
                    request_id: request_id_fixture(1),
                    lifecycle_token,
                    request: exec_request_fixture(output_limits_fixture()),
                    deadline_ms: deadline(),
                },
            ),
        )
        .await
        .into_response();
    let ServiceResponse::ExecPrepared { prepare_token } = response else {
        panic!("execution was not prepared")
    };
    assert_eq!(runtime.recording().exec_dispatches(), 0);

    let response = boundary
        .handle(
            &caller,
            envelope(
                boundary.bundle(),
                ServiceRequest::CommitExec {
                    request_id: request_id_fixture(1),
                    prepare_token,
                    deadline_ms: deadline(),
                },
            ),
        )
        .await
        .into_response();
    let ServiceResponse::Executed { result } = response else {
        panic!("execution did not complete")
    };
    assert_eq!(result.exit_code().get(), 7);
    assert_eq!(result.stdout(), raw_stdout_fixture());
    assert_eq!(result.stderr(), raw_stderr_fixture());
    assert_eq!(runtime.recording().exec_dispatches(), 1);

    let target = CleanupTarget::new(request_id_fixture(1));
    let response = boundary
        .handle(
            &caller,
            envelope(
                boundary.bundle(),
                ServiceRequest::Delete {
                    target: target.clone(),
                    deadline_ms: deadline(),
                },
            ),
        )
        .await
        .into_response();
    assert_eq!(
        response,
        ServiceResponse::Deleted {
            outcome: DeleteOutcome::Deleted
        }
    );
    let response = boundary
        .handle(
            &caller,
            envelope(
                boundary.bundle(),
                ServiceRequest::WaitDeleted {
                    target,
                    deadline_ms: deadline(),
                },
            ),
        )
        .await
        .into_response();
    assert_eq!(response, ServiceResponse::TerminallyAbsent);
    assert!(boundary.store().load_all().await.unwrap().is_empty());
}

#[tokio::test]
async fn prepare_is_non_dispatching_and_wrong_capability_never_executes() {
    let directory = tempfile::tempdir().unwrap();
    let (runtime, boundary) = initialized_boundary(full_script(), directory.path()).await;
    let caller = caller(CallerRole::Runtime);
    let lifecycle_token = create_and_ready(&boundary, &caller).await;

    let response = boundary
        .handle(
            &caller,
            envelope(
                boundary.bundle(),
                ServiceRequest::PrepareExec {
                    request_id: request_id_fixture(1),
                    lifecycle_token,
                    request: exec_request_fixture(output_limits_fixture()),
                    deadline_ms: deadline(),
                },
            ),
        )
        .await
        .into_response();
    assert!(matches!(response, ServiceResponse::ExecPrepared { .. }));
    let response = boundary
        .handle(
            &caller,
            envelope(
                boundary.bundle(),
                ServiceRequest::CommitExec {
                    request_id: request_id_fixture(1),
                    prepare_token: CapabilityToken::generate(),
                    deadline_ms: deadline(),
                },
            ),
        )
        .await
        .into_response();
    let ServiceResponse::BoundaryFailed { failure } = response else {
        panic!("wrong capability was not rejected")
    };
    assert_eq!(failure.code(), BoundaryFailureCode::LifecycleConflict);
    assert_eq!(
        failure.dispatch_state(),
        Some(crate::DispatchState::NotDispatched)
    );
    assert_eq!(runtime.recording().exec_dispatches(), 0);
}

#[tokio::test]
async fn asset_skew_is_rejected_before_runtime_io() {
    let directory = tempfile::tempdir().unwrap();
    let (runtime, boundary) = initialized_boundary(FakeScript::new(), directory.path()).await;
    let mismatched = AssetBundleIdentity::new(
        1,
        Sha256Digest::parse("b".repeat(64)).unwrap(),
        TemplateIdentity::new("different-template").unwrap(),
        policy_fixture(1),
        "test-runtime-v1",
    )
    .unwrap();
    let response = boundary
        .handle(
            &caller(CallerRole::Runtime),
            envelope(
                &mismatched,
                ServiceRequest::Create {
                    request: create_request_fixture(1),
                    deadline_ms: deadline(),
                },
            ),
        )
        .await
        .into_response();
    let ServiceResponse::BoundaryFailed { failure } = response else {
        panic!("asset skew was not rejected")
    };
    assert_eq!(failure.code(), BoundaryFailureCode::AssetBundleMismatch);
    assert!(runtime.recording().calls().is_empty());
}

#[tokio::test]
async fn restart_reconciliation_deletes_only_durable_owned_record() {
    let directory = tempfile::tempdir().unwrap();
    let store = DurableStore::initialize(directory.path()).unwrap();
    let request = create_request_fixture(9);
    let record = DurableRecord::new(
        request.request_id().clone(),
        caller(CallerRole::Runtime).fingerprint().clone(),
        DurableStage::CreatePossible,
        request.template().clone(),
        request.expected_policy().clone(),
    )
    .unwrap();
    store.write(&record).await.unwrap();
    let mut script = FakeScript::new();
    script
        .push_delete(FakeDeletePlan::Deleted)
        .push_wait_deleted(FakeWaitDeletedPlan::Absent);
    let runtime = Arc::new(FakeSandboxRuntime::new(script));
    let boundary = SandboxServiceBoundary::new(runtime.clone(), bundle(), store);
    let report = boundary
        .reconcile_startup(Duration::from_secs(1), Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(report.removed_records(), 1);
    assert_eq!(runtime.recording().calls().len(), 2);
    assert!(boundary.store().load_all().await.unwrap().is_empty());
}

#[tokio::test]
async fn conflict_is_unowned_and_never_reconciled_for_deletion() {
    let directory = tempfile::tempdir().unwrap();
    let mut script = FakeScript::new();
    script.push_create(FakeCreatePlan::Fail {
        state: CreationState::Conflict,
        code: crate::CreateFailureCode::Provider,
    });
    let (runtime, boundary) = initialized_boundary(script, directory.path()).await;
    let response = boundary
        .handle(
            &caller(CallerRole::Runtime),
            envelope(
                boundary.bundle(),
                ServiceRequest::Create {
                    request: create_request_fixture(1),
                    deadline_ms: deadline(),
                },
            ),
        )
        .await
        .into_response();
    assert!(matches!(response, ServiceResponse::CreateFailed { .. }));
    assert!(boundary.store().load_all().await.unwrap().is_empty());
    assert_eq!(runtime.recording().calls().len(), 1);
}

#[tokio::test]
async fn durable_records_never_contain_argv_or_output_bodies() {
    let directory = tempfile::tempdir().unwrap();
    let (_runtime, boundary) = initialized_boundary(full_script(), directory.path()).await;
    let caller = caller(CallerRole::Runtime);
    let lifecycle_token = create_and_ready(&boundary, &caller).await;
    let _ = boundary
        .handle(
            &caller,
            envelope(
                boundary.bundle(),
                ServiceRequest::PrepareExec {
                    request_id: request_id_fixture(1),
                    lifecycle_token,
                    request: exec_request_fixture(output_limits_fixture()),
                    deadline_ms: deadline(),
                },
            ),
        )
        .await;
    let record_path = directory
        .path()
        .join(format!("{}.json", request_id_fixture(1)));
    let bytes = std::fs::read(record_path).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    for forbidden in ["/bin/proof", "space value", "$HOME", "stdout", "stderr"] {
        assert!(!text.contains(forbidden));
    }
}

#[tokio::test]
async fn protocol_version_skew_is_rejected_before_runtime_io() {
    let directory = tempfile::tempdir().unwrap();
    let (runtime, boundary) = initialized_boundary(FakeScript::new(), directory.path()).await;
    let envelope = envelope(boundary.bundle(), ServiceRequest::Health);
    let mut value = serde_json::to_value(envelope).unwrap();
    value["protocol_version"] = serde_json::json!(99);
    let skewed = decode_request(&serde_json::to_vec(&value).unwrap()).unwrap();
    let response = boundary
        .handle(&caller(CallerRole::Runtime), skewed)
        .await
        .into_response();
    let ServiceResponse::BoundaryFailed { failure } = response else {
        panic!("protocol skew was not rejected")
    };
    assert_eq!(failure.code(), BoundaryFailureCode::ProtocolVersion);
    assert!(runtime.recording().calls().is_empty());
}

#[tokio::test]
async fn drain_requires_administrator_blocks_new_work_and_allows_owned_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let mut script = FakeScript::new();
    script
        .push_create(FakeCreatePlan::Succeed {
            provider_handle: b"provider".to_vec(),
        })
        .push_readiness(FakeReadinessPlan::Ready {
            observed_policy: policy_fixture(1),
        })
        .push_delete(FakeDeletePlan::Deleted)
        .push_wait_deleted(FakeWaitDeletedPlan::Absent);
    let (runtime, boundary) = initialized_boundary(script, directory.path()).await;
    let runtime_caller = caller(CallerRole::Runtime);
    let _lifecycle_token = create_and_ready(&boundary, &runtime_caller).await;

    let response = boundary
        .handle(
            &runtime_caller,
            envelope(boundary.bundle(), ServiceRequest::BeginDrain),
        )
        .await
        .into_response();
    let ServiceResponse::BoundaryFailed { failure } = response else {
        panic!("runtime caller unexpectedly began drain")
    };
    assert_eq!(failure.code(), BoundaryFailureCode::Authorization);

    let response = boundary
        .handle(
            &caller(CallerRole::Administrator),
            envelope(boundary.bundle(), ServiceRequest::BeginDrain),
        )
        .await
        .into_response();
    assert!(matches!(response, ServiceResponse::Draining { .. }));
    let response = boundary
        .handle(
            &runtime_caller,
            envelope(
                boundary.bundle(),
                ServiceRequest::Create {
                    request: create_request_fixture(2),
                    deadline_ms: deadline(),
                },
            ),
        )
        .await
        .into_response();
    let ServiceResponse::BoundaryFailed { failure } = response else {
        panic!("draining service accepted new create")
    };
    assert_eq!(failure.code(), BoundaryFailureCode::Draining);

    let target = CleanupTarget::new(request_id_fixture(1));
    let deleted = boundary
        .handle(
            &runtime_caller,
            envelope(
                boundary.bundle(),
                ServiceRequest::Delete {
                    target: target.clone(),
                    deadline_ms: deadline(),
                },
            ),
        )
        .await
        .into_response();
    assert!(matches!(deleted, ServiceResponse::Deleted { .. }));
    let absent = boundary
        .handle(
            &runtime_caller,
            envelope(
                boundary.bundle(),
                ServiceRequest::WaitDeleted {
                    target,
                    deadline_ms: deadline(),
                },
            ),
        )
        .await
        .into_response();
    assert_eq!(absent, ServiceResponse::TerminallyAbsent);
    assert_eq!(runtime.recording().create_submissions(), 1);
}
