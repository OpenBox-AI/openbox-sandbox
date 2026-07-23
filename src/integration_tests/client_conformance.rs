use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::AssetBundleIdentity;
use crate::test_client::{SandboxRuntimeClient, SandboxRuntimeClientConfig};
use crate::{
    CallerFingerprint, CallerRole, DurableStore, SandboxServiceBoundary, SandboxTlsServer,
    TlsServerConfig,
};
use crate::{
    CleanupFailure, CleanupTarget, CreateFailure, CreateRequest, CreatedSandbox, DeleteOutcome,
    ExecCompleted, ExecFailure, ExecRequest, OperationContext, PolicyIdentity, ReadinessFailure,
    ReadySandbox, SandboxRuntime, Sha256Digest,
};
use crate::{
    ConformanceCase, ConformanceHarness, ConformanceObservation, ConformanceObserver,
    ConformanceOperation, FakeConformanceHarness, run_conformance_suite,
};
use async_trait::async_trait;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
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

#[derive(Default)]
struct ClientRecording {
    operations: Vec<ConformanceOperation>,
    exec_argv: Vec<Vec<String>>,
    delete_targets: Vec<crate::RequestOwnedId>,
    wait_deleted_targets: Vec<crate::RequestOwnedId>,
}

struct RecordingClient {
    inner: SandboxRuntimeClient,
    recording: Arc<Mutex<ClientRecording>>,
}

#[async_trait]
impl SandboxRuntime for RecordingClient {
    async fn create(
        &self,
        request: CreateRequest,
        context: OperationContext,
    ) -> Result<CreatedSandbox, CreateFailure> {
        self.recording
            .lock()
            .unwrap()
            .operations
            .push(ConformanceOperation::Create);
        self.inner.create(request, context).await
    }

    async fn wait_ready(
        &self,
        sandbox: CreatedSandbox,
        expected_policy: PolicyIdentity,
        context: OperationContext,
    ) -> Result<ReadySandbox, ReadinessFailure> {
        self.recording
            .lock()
            .unwrap()
            .operations
            .push(ConformanceOperation::WaitReady);
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
        {
            let mut recording = self.recording.lock().unwrap();
            recording.operations.push(ConformanceOperation::Exec);
            recording.exec_argv.push(request.argv().as_slice().to_vec());
        }
        self.inner.exec(sandbox, request, context).await
    }

    async fn delete(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<DeleteOutcome, CleanupFailure> {
        {
            let mut recording = self.recording.lock().unwrap();
            recording.operations.push(ConformanceOperation::Delete);
            recording.delete_targets.push(target.request_id().clone());
        }
        self.inner.delete(target, context).await
    }

    async fn wait_deleted(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<(), CleanupFailure> {
        {
            let mut recording = self.recording.lock().unwrap();
            recording.operations.push(ConformanceOperation::WaitDeleted);
            recording
                .wait_deleted_targets
                .push(target.request_id().clone());
        }
        self.inner.wait_deleted(target, context).await
    }
}

struct BoundaryObserver {
    client: Arc<Mutex<ClientRecording>>,
    provider: Arc<dyn ConformanceObserver>,
}

impl ConformanceObserver for BoundaryObserver {
    fn observe(&self) -> ConformanceObservation {
        let client = self.client.lock().unwrap();
        let provider = self.provider.observe();
        ConformanceObservation::new(
            client.operations.clone(),
            provider.create_submissions(),
            provider.exec_dispatches(),
            client.exec_argv.clone(),
            client.delete_targets.clone(),
            client.wait_deleted_targets.clone(),
        )
    }
}

struct BoundaryHarness {
    fake: FakeConformanceHarness,
    pki: TestPki,
    state_root: PathBuf,
    next: AtomicU64,
    servers: Mutex<Vec<(CancellationToken, tokio::task::JoinHandle<()>)>>,
}

impl BoundaryHarness {
    fn new(directory: &Path) -> Self {
        Self {
            fake: FakeConformanceHarness::new(),
            pki: pki(directory),
            state_root: directory.join("states"),
            next: AtomicU64::new(1),
            servers: Mutex::new(Vec::new()),
        }
    }

    async fn shutdown(&self) {
        let servers = std::mem::take(&mut *self.servers.lock().unwrap());
        for (shutdown, _) in &servers {
            shutdown.cancel();
        }
        for (_, task) in servers {
            task.await.unwrap();
        }
    }
}

impl ConformanceHarness for BoundaryHarness {
    fn build_case(&self, scenario: crate::ConformanceScenario) -> ConformanceCase {
        let (provider_runtime, provider_observer, create_request, exec_request, contexts) =
            self.fake.build_case(scenario).into_parts();
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        let bundle = AssetBundleIdentity::new(
            1,
            Sha256Digest::parse("a".repeat(64)).unwrap(),
            create_request.template().clone(),
            create_request.expected_policy().clone(),
            "test-runtime-v1",
        )
        .unwrap();
        let store =
            DurableStore::initialize(self.state_root.join(format!("case-{index}"))).unwrap();
        let boundary = Arc::new(SandboxServiceBoundary::new(
            provider_runtime,
            bundle.clone(),
            store,
        ));
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let caller = CallerFingerprint::from_certificate_der(&self.pki.client_der).unwrap();
        let config = TlsServerConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &self.pki.server_certificate,
            &self.pki.server_key,
            &self.pki.ca,
            HashMap::from([(caller, CallerRole::Runtime)]),
            4,
            Duration::from_secs(2),
        )
        .unwrap();
        let server =
            SandboxTlsServer::from_std_listener(config, listener, boundary.clone()).unwrap();
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let task = tokio::spawn(async move {
            boundary
                .reconcile_startup(Duration::from_secs(1), Duration::from_secs(1))
                .await
                .unwrap();
            ready_tx.send(()).unwrap();
            server.run(server_shutdown).await.unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        self.servers.lock().unwrap().push((shutdown, task));

        let client = SandboxRuntimeClient::connect(
            SandboxRuntimeClientConfig::new(
                address,
                "localhost",
                &self.pki.ca,
                &self.pki.client_certificate,
                &self.pki.client_key,
                bundle,
            )
            .unwrap(),
        )
        .unwrap();
        let recording = Arc::new(Mutex::new(ClientRecording::default()));
        let runtime = Arc::new(RecordingClient {
            inner: client,
            recording: recording.clone(),
        });
        let observer = Arc::new(BoundaryObserver {
            client: recording,
            provider: provider_observer,
        });
        ConformanceCase::new(runtime, observer, create_request, exec_request, contexts)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unchanged_twenty_scenario_suite_passes_through_mtls_client_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let harness = BoundaryHarness::new(directory.path());
    let report = run_conformance_suite(&harness).await.unwrap();
    assert_eq!(report.scenarios(), crate::ConformanceScenario::ALL);
    harness.shutdown().await;
}
