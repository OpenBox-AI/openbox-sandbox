use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::AssetBundleIdentity;
use crate::test_client::{SandboxRuntimeClient, SandboxRuntimeClientConfig};
use crate::{
    CallerFingerprint, CallerRole, DurableStage, DurableStore, SandboxServiceBoundary,
    SandboxTlsServer, TlsServerConfig,
};
use crate::{
    CleanupFailure, CleanupTarget, CreateFailure, CreateRequest, CreatedSandbox, DeleteOutcome,
    DispatchState, ExecCompleted, ExecFailure, ExecFailureCode, ExecRequest, FailureTimeout,
    OperationContext, OperatorDetail, OutputByteCounts, PolicyIdentity, ReadinessFailure,
    ReadySandbox, SandboxRuntime, Sha256Digest,
};
use crate::{
    FakeCreatePlan, FakeDeletePlan, FakeReadinessPlan, FakeSandboxRuntime, FakeScript,
    FakeWaitDeletedPlan, create_request_fixture, exec_request_fixture, output_limits_fixture,
    policy_fixture,
};
use async_trait::async_trait;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

struct TestPki {
    ca: PathBuf,
    server_certificate: PathBuf,
    server_key: PathBuf,
    client_certificate: PathBuf,
    client_key: PathBuf,
    client_der: Vec<u8>,
}

fn pki(directory: &Path) -> TestPki {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let ca = directory.join("ca.pem");
    std::fs::write(&ca, ca_certificate.pem()).unwrap();
    let (server_certificate, server_key, _) = leaf(
        directory,
        "server",
        "localhost",
        ExtendedKeyUsagePurpose::ServerAuth,
        &issuer,
    );
    let (client_certificate, client_key, client_der) = leaf(
        directory,
        "client",
        "runtime-client",
        ExtendedKeyUsagePurpose::ClientAuth,
        &issuer,
    );
    TestPki {
        ca,
        server_certificate,
        server_key,
        client_certificate,
        client_key,
        client_der,
    }
}

fn leaf(
    directory: &Path,
    prefix: &str,
    subject_alt_name: &str,
    usage: ExtendedKeyUsagePurpose,
    issuer: &Issuer<'_, KeyPair>,
) -> (PathBuf, PathBuf, Vec<u8>) {
    let mut params = CertificateParams::new(vec![subject_alt_name.to_owned()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&key, issuer).unwrap();
    let certificate_path = directory.join(format!("{prefix}.crt"));
    let private_key_path = directory.join(format!("{prefix}.key"));
    std::fs::write(&certificate_path, certificate.pem()).unwrap();
    std::fs::write(&private_key_path, key.serialize_pem()).unwrap();
    (
        certificate_path,
        private_key_path,
        certificate.der().to_vec(),
    )
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

fn context() -> OperationContext {
    OperationContext::new(
        CancellationToken::new(),
        crate::OperationDeadline::new(Duration::from_secs(10)).unwrap(),
    )
}

struct BlockingCreateRuntime {
    inner: FakeSandboxRuntime,
    submitted: Arc<Notify>,
    submission_count: AtomicU64,
}

#[async_trait]
impl SandboxRuntime for BlockingCreateRuntime {
    async fn create(
        &self,
        request: CreateRequest,
        context: OperationContext,
    ) -> Result<CreatedSandbox, CreateFailure> {
        self.submission_count.fetch_add(1, Ordering::Relaxed);
        self.submitted.notify_one();
        context.cancellation().cancelled().await;
        Err(CreateFailure::possibly_created(
            CleanupTarget::new(request.request_id().clone()),
            crate::CreateFailureCode::Cancelled,
            OperatorDetail::redacted("blocking test create cancelled"),
        ))
    }

    async fn wait_ready(
        &self,
        sandbox: CreatedSandbox,
        expected_policy: PolicyIdentity,
        context: OperationContext,
    ) -> Result<ReadySandbox, ReadinessFailure> {
        self.inner
            .wait_ready(sandbox, expected_policy, context)
            .await
    }

    async fn exec(
        &self,
        sandbox: ReadySandbox,
        request: ExecRequest,
        context: OperationContext,
    ) -> Result<ExecCompleted, ExecFailure> {
        self.inner.exec(sandbox, request, context).await
    }

    async fn delete(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<DeleteOutcome, CleanupFailure> {
        self.inner.delete(target, context).await
    }

    async fn wait_deleted(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<(), CleanupFailure> {
        self.inner.wait_deleted(target, context).await
    }
}

struct BlockingExecRuntime {
    inner: FakeSandboxRuntime,
    dispatched: Arc<Notify>,
    dispatch_count: AtomicU64,
}

#[async_trait]
impl SandboxRuntime for BlockingExecRuntime {
    async fn create(
        &self,
        request: CreateRequest,
        context: OperationContext,
    ) -> Result<CreatedSandbox, CreateFailure> {
        self.inner.create(request, context).await
    }

    async fn wait_ready(
        &self,
        sandbox: CreatedSandbox,
        expected_policy: PolicyIdentity,
        context: OperationContext,
    ) -> Result<ReadySandbox, ReadinessFailure> {
        self.inner
            .wait_ready(sandbox, expected_policy, context)
            .await
    }

    async fn exec(
        &self,
        sandbox: ReadySandbox,
        _request: ExecRequest,
        context: OperationContext,
    ) -> Result<ExecCompleted, ExecFailure> {
        self.dispatch_count.fetch_add(1, Ordering::Relaxed);
        self.dispatched.notify_one();
        context.cancellation().cancelled().await;
        Err(ExecFailure::possibly_dispatched(
            sandbox.cleanup_target(),
            ExecFailureCode::Cancelled,
            FailureTimeout::Unknown,
            OutputByteCounts::default(),
            OperatorDetail::redacted("blocking test execution cancelled"),
        )
        .expect("blocking execution was dispatched"))
    }

    async fn delete(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<DeleteOutcome, CleanupFailure> {
        self.inner.delete(target, context).await
    }

    async fn wait_deleted(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<(), CleanupFailure> {
        self.inner.wait_deleted(target, context).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn service_crash_after_dispatch_is_indeterminate_and_restart_reconciles_without_retry() {
    let directory = tempfile::tempdir().unwrap();
    let pki = pki(directory.path());
    let mut initial_script = FakeScript::new();
    initial_script
        .push_create(FakeCreatePlan::Succeed {
            provider_handle: b"provider".to_vec(),
        })
        .push_readiness(FakeReadinessPlan::Ready {
            observed_policy: policy_fixture(1),
        });
    let dispatched = Arc::new(Notify::new());
    let runtime = Arc::new(BlockingExecRuntime {
        inner: FakeSandboxRuntime::new(initial_script),
        dispatched: dispatched.clone(),
        dispatch_count: AtomicU64::new(0),
    });
    let store = DurableStore::initialize(directory.path().join("state")).unwrap();
    let boundary = Arc::new(SandboxServiceBoundary::new(
        runtime.clone(),
        bundle(),
        store.clone(),
    ));
    boundary
        .reconcile_startup(Duration::from_secs(1), Duration::from_secs(1))
        .await
        .unwrap();
    let caller = CallerFingerprint::from_certificate_der(&pki.client_der).unwrap();
    let config = TlsServerConfig::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &pki.server_certificate,
        &pki.server_key,
        &pki.ca,
        HashMap::from([(caller, CallerRole::Runtime)]),
        4,
        Duration::from_secs(2),
    )
    .unwrap();
    let server = SandboxTlsServer::bind(config, boundary).await.unwrap();
    let address = server.local_address().unwrap();
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(server.run(shutdown));
    let client = SandboxRuntimeClient::connect(
        SandboxRuntimeClientConfig::new(
            address,
            "localhost",
            &pki.ca,
            &pki.client_certificate,
            &pki.client_key,
            bundle(),
        )
        .unwrap(),
    )
    .unwrap();
    let created = client
        .create(create_request_fixture(1), context())
        .await
        .unwrap();
    let ready = client
        .wait_ready(created, policy_fixture(1), context())
        .await
        .unwrap();
    let execution = tokio::spawn(async move {
        client
            .exec(
                ready,
                exec_request_fixture(output_limits_fixture()),
                context(),
            )
            .await
    });
    dispatched.notified().await;
    server_task.abort();
    assert!(server_task.await.is_err());
    let failure = tokio::time::timeout(Duration::from_secs(2), execution)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.dispatch_state(), DispatchState::PossiblyDispatched);
    assert_eq!(runtime.dispatch_count.load(Ordering::Relaxed), 1);
    let records = store.load_all().await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].stage(), DurableStage::ExecPossible);

    let mut cleanup_script = FakeScript::new();
    cleanup_script
        .push_delete(FakeDeletePlan::Deleted)
        .push_wait_deleted(FakeWaitDeletedPlan::Absent);
    let cleanup_runtime = Arc::new(FakeSandboxRuntime::new(cleanup_script));
    let restarted = SandboxServiceBoundary::new(cleanup_runtime.clone(), bundle(), store);
    let report = restarted
        .reconcile_startup(Duration::from_secs(1), Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(report.removed_records(), 1);
    assert_eq!(cleanup_runtime.recording().exec_dispatches(), 0);
    assert_eq!(cleanup_runtime.recording().calls().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn service_crash_after_create_submission_retains_id_and_restart_reconciles() {
    let directory = tempfile::tempdir().unwrap();
    let pki = pki(directory.path());
    let submitted = Arc::new(Notify::new());
    let runtime = Arc::new(BlockingCreateRuntime {
        inner: FakeSandboxRuntime::new(FakeScript::new()),
        submitted: submitted.clone(),
        submission_count: AtomicU64::new(0),
    });
    let store = DurableStore::initialize(directory.path().join("create-state")).unwrap();
    let boundary = Arc::new(SandboxServiceBoundary::new(
        runtime.clone(),
        bundle(),
        store.clone(),
    ));
    boundary
        .reconcile_startup(Duration::from_secs(1), Duration::from_secs(1))
        .await
        .unwrap();
    let caller = CallerFingerprint::from_certificate_der(&pki.client_der).unwrap();
    let config = TlsServerConfig::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &pki.server_certificate,
        &pki.server_key,
        &pki.ca,
        HashMap::from([(caller, CallerRole::Runtime)]),
        4,
        Duration::from_secs(2),
    )
    .unwrap();
    let server = SandboxTlsServer::bind(config, boundary).await.unwrap();
    let address = server.local_address().unwrap();
    let server_task = tokio::spawn(server.run(CancellationToken::new()));
    let client = SandboxRuntimeClient::connect(
        SandboxRuntimeClientConfig::new(
            address,
            "localhost",
            &pki.ca,
            &pki.client_certificate,
            &pki.client_key,
            bundle(),
        )
        .unwrap(),
    )
    .unwrap();
    let creation =
        tokio::spawn(async move { client.create(create_request_fixture(1), context()).await });
    submitted.notified().await;
    server_task.abort();
    assert!(server_task.await.is_err());
    let failure = tokio::time::timeout(Duration::from_secs(2), creation)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.state(), crate::CreationState::PossiblyCreated);
    assert_eq!(runtime.submission_count.load(Ordering::Relaxed), 1);
    let records = store.load_all().await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].stage(), DurableStage::CreatePossible);
    assert_eq!(
        records[0].request_id(),
        create_request_fixture(1).request_id()
    );

    let mut cleanup_script = FakeScript::new();
    cleanup_script
        .push_delete(FakeDeletePlan::Deleted)
        .push_wait_deleted(FakeWaitDeletedPlan::Absent);
    let cleanup_runtime = Arc::new(FakeSandboxRuntime::new(cleanup_script));
    let restarted = SandboxServiceBoundary::new(cleanup_runtime.clone(), bundle(), store);
    let report = restarted
        .reconcile_startup(Duration::from_secs(1), Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(report.removed_records(), 1);
    assert_eq!(cleanup_runtime.recording().exec_dispatches(), 0);
    assert_eq!(cleanup_runtime.recording().calls().len(), 2);
}
