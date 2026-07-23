use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::test_client::{SandboxRuntimeClient, SandboxRuntimeClientConfig};
use crate::{AssetBundleIdentity, CapabilityToken};
use crate::{
    CallerFingerprint, CallerRole, DurableStore, SandboxServiceBoundary, SandboxTlsServer,
    TlsServerConfig,
};
use crate::{
    CleanupTarget, CreatedSandbox, CreationState, DispatchState, ObservedTimeout,
    OpaqueProviderHandle, OperationContext, OperationDeadline, ReadySandbox, SandboxRuntime,
    Sha256Digest,
};
use crate::{
    FakeCreatePlan, FakeDeletePlan, FakeExecEvent, FakeExecPlan, FakeReadinessPlan,
    FakeSandboxRuntime, FakeScript, FakeWaitDeletedPlan, create_request_fixture,
    exec_request_fixture, output_limits_fixture, policy_fixture, request_id_fixture,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio_util::sync::CancellationToken;

struct TestIdentity {
    certificate: PathBuf,
    private_key: PathBuf,
    der: Vec<u8>,
}

struct TestPki {
    ca: PathBuf,
    server: TestIdentity,
    client: TestIdentity,
    unauthorized_client: TestIdentity,
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

    TestPki {
        ca,
        server: leaf(
            directory,
            "server",
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
            &issuer,
        ),
        client: leaf(
            directory,
            "client",
            "runtime-client",
            ExtendedKeyUsagePurpose::ClientAuth,
            &issuer,
        ),
        unauthorized_client: leaf(
            directory,
            "unauthorized",
            "unauthorized-client",
            ExtendedKeyUsagePurpose::ClientAuth,
            &issuer,
        ),
    }
}

fn leaf(
    directory: &Path,
    prefix: &str,
    subject_alt_name: &str,
    usage: ExtendedKeyUsagePurpose,
    issuer: &Issuer<'_, KeyPair>,
) -> TestIdentity {
    let mut params = CertificateParams::new(vec![subject_alt_name.to_owned()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&key, issuer).unwrap();
    let certificate_path = directory.join(format!("{prefix}.crt"));
    let private_key = directory.join(format!("{prefix}.key"));
    std::fs::write(&certificate_path, certificate.pem()).unwrap();
    std::fs::write(&private_key, key.serialize_pem()).unwrap();
    TestIdentity {
        certificate: certificate_path,
        private_key,
        der: certificate.der().to_vec(),
    }
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
        OperationDeadline::new(Duration::from_secs(5)).unwrap(),
    )
}

fn script() -> FakeScript {
    let mut script = FakeScript::new();
    script
        .push_create(FakeCreatePlan::Succeed {
            provider_handle: b"provider".to_vec(),
        })
        .push_readiness(FakeReadinessPlan::Ready {
            observed_policy: policy_fixture(1),
        })
        .push_exec(FakeExecPlan::Stream {
            events: vec![FakeExecEvent::Exit {
                code: 7,
                timeout: ObservedTimeout::NotObserved,
            }],
        })
        .push_delete(FakeDeletePlan::Deleted)
        .push_wait_deleted(FakeWaitDeletedPlan::Absent);
    script
}

async fn start_server(
    directory: &Path,
    pki: &TestPki,
    runtime: Arc<FakeSandboxRuntime>,
) -> (SocketAddr, CancellationToken, tokio::task::JoinHandle<()>) {
    let store = DurableStore::initialize(directory.join("state")).unwrap();
    let boundary = Arc::new(SandboxServiceBoundary::new(runtime, bundle(), store));
    boundary
        .reconcile_startup(Duration::from_secs(1), Duration::from_secs(1))
        .await
        .unwrap();
    let fingerprint = CallerFingerprint::from_certificate_der(&pki.client.der).unwrap();
    let config = TlsServerConfig::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &pki.server.certificate,
        &pki.server.private_key,
        &pki.ca,
        HashMap::from([(fingerprint, CallerRole::Runtime)]),
        16,
        Duration::from_secs(2),
    )
    .unwrap();
    let server = SandboxTlsServer::bind(config, boundary).await.unwrap();
    let address = server.local_address().unwrap();
    let shutdown = CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        server.run(server_shutdown).await.unwrap();
    });
    (address, shutdown, task)
}

fn client(
    address: SocketAddr,
    pki: &TestPki,
    identity: &TestIdentity,
    server_name: &str,
) -> SandboxRuntimeClient {
    SandboxRuntimeClient::connect(
        SandboxRuntimeClientConfig::new(
            address,
            server_name,
            &pki.ca,
            &identity.certificate,
            &identity.private_key,
            bundle(),
        )
        .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn mtls_boundary_runs_complete_runtime_lifecycle() {
    let directory = tempfile::tempdir().unwrap();
    let pki = pki(directory.path());
    let runtime = Arc::new(FakeSandboxRuntime::new(script()));
    let (address, shutdown, task) = start_server(directory.path(), &pki, runtime.clone()).await;
    let runtime_client = client(address, &pki, &pki.client, "localhost");

    let created = runtime_client
        .create(create_request_fixture(1), context())
        .await
        .unwrap();
    let ready = runtime_client
        .wait_ready(created, policy_fixture(1), context())
        .await
        .unwrap();
    let completed = runtime_client
        .exec(
            ready,
            exec_request_fixture(output_limits_fixture()),
            context(),
        )
        .await
        .unwrap();
    assert_eq!(completed.exit_code().get(), 7);
    let target = CleanupTarget::new(request_id_fixture(1));
    runtime_client
        .delete(target.clone(), context())
        .await
        .unwrap();
    runtime_client
        .wait_deleted(target, context())
        .await
        .unwrap();
    assert_eq!(runtime.recording().exec_dispatches(), 1);

    shutdown.cancel();
    task.await.unwrap();

    let offline = client(address, &pki, &pki.client, "localhost");
    let failure = offline
        .create(create_request_fixture(2), context())
        .await
        .unwrap_err();
    assert_eq!(failure.state(), CreationState::NotCreated);

    let lifecycle_token = CapabilityToken::generate();
    let created = CreatedSandbox::from_runtime(
        request_id_fixture(2),
        OpaqueProviderHandle::new(lifecycle_token.as_str().as_bytes().to_vec()).unwrap(),
        policy_fixture(1),
    );
    let ready = ReadySandbox::attest(created, policy_fixture(1), &policy_fixture(1)).unwrap();
    let failure = offline
        .exec(
            ready,
            exec_request_fixture(output_limits_fixture()),
            context(),
        )
        .await
        .unwrap_err();
    assert_eq!(failure.dispatch_state(), DispatchState::NotDispatched);
}

#[tokio::test]
async fn ca_valid_but_unlisted_caller_and_wrong_server_name_never_reach_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let pki = pki(directory.path());
    let runtime = Arc::new(FakeSandboxRuntime::new(FakeScript::new()));
    let (address, shutdown, task) = start_server(directory.path(), &pki, runtime.clone()).await;

    let unauthorized = client(address, &pki, &pki.unauthorized_client, "localhost");
    let failure = unauthorized
        .create(create_request_fixture(1), context())
        .await
        .unwrap_err();
    assert_eq!(failure.state(), CreationState::PossiblyCreated);

    let wrong_server = client(address, &pki, &pki.client, "wrong.invalid");
    let failure = wrong_server
        .create(create_request_fixture(1), context())
        .await
        .unwrap_err();
    assert_eq!(failure.state(), CreationState::NotCreated);
    assert!(runtime.recording().calls().is_empty());

    shutdown.cancel();
    task.await.unwrap();
}
