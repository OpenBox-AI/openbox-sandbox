//! UNIT TESTS ONLY — NOT SYSTEM VALIDATION.
//!
//! This module uses `FakeSandboxRuntime` / fake transports. A green result
//! here proves LOGIC in isolation, not that the broker actually works against
//! a real `OpenShell` gateway. Under the standing "no fake tests in production"
//! rule, do not report passing counts from this module as "validated" or
//! "integration proven". Real coverage lives in `tests/live_openshell.rs`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::{
    CleanupFailure, CleanupTarget, CreateFailure, CreateRequest, CreatedSandbox, CreationState,
    DeleteOutcome, ExecCompleted, ExecFailure, ExecRequest, ObservedTimeout, OperationContext,
    OperationDeadline, OutputLimits, PolicyDocument, PolicyIdentity, ReadySandbox, RequestOwnedId,
    SandboxRuntime, Sha256Digest, TemplateIdentity,
};
use crate::{
    ConformanceCase, ConformanceHarness, ConformanceObservation, ConformanceObserver,
    ConformanceOperation, ConformanceScenario, LifecycleContexts, adversarial_argv,
    cancelled_exec_contexts_fixture, output_limits_fixture, raw_stderr_fixture, raw_stdout_fixture,
    run_conformance_suite,
};
use async_trait::async_trait;
use openshell_core::proto::{
    CreateSandboxRequest, DeleteSandboxRequest, DeleteSandboxResponse, ExecSandboxRequest,
    GetSandboxPolicyStatusRequest, GetSandboxPolicyStatusResponse, GetSandboxRequest, ObjectMeta,
    PolicyStatus, Sandbox, SandboxPhase, SandboxPolicy, SandboxPolicyRevision, SandboxResponse,
    SandboxSpec, SandboxStatus,
};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use crate::OpenShellRuntime;
use crate::openshell::policy::deterministic_policy_hash;
use crate::openshell::transport::{
    CreateTransportError, ExecEventStream, ExecTransportError, ExecTransportEvent,
    OpenShellTransport,
};

const POLICY_YAML: &str = include_str!("../../deploy/policies/policy-deny-network.yaml");
const IMAGE: &str = "example.invalid/openbox-proof@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Default)]
struct RuntimeRecording {
    operations: Vec<ConformanceOperation>,
    exec_argv: Vec<Vec<String>>,
    delete_targets: Vec<RequestOwnedId>,
    wait_deleted_targets: Vec<RequestOwnedId>,
}

struct RecordingRuntime {
    inner: OpenShellRuntime,
    recording: Arc<Mutex<RuntimeRecording>>,
}

#[async_trait]
impl SandboxRuntime for RecordingRuntime {
    async fn create(
        &self,
        request: CreateRequest,
        context: OperationContext,
    ) -> Result<CreatedSandbox, CreateFailure> {
        self.recording
            .lock()
            .expect("recording mutex poisoned")
            .operations
            .push(ConformanceOperation::Create);
        self.inner.create(request, context).await
    }

    async fn wait_ready(
        &self,
        sandbox: CreatedSandbox,
        expected_policy: PolicyIdentity,
        context: OperationContext,
    ) -> Result<ReadySandbox, crate::ReadinessFailure> {
        self.recording
            .lock()
            .expect("recording mutex poisoned")
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
            let mut recording = self.recording.lock().expect("recording mutex poisoned");
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
            let mut recording = self.recording.lock().expect("recording mutex poisoned");
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
            let mut recording = self.recording.lock().expect("recording mutex poisoned");
            recording.operations.push(ConformanceOperation::WaitDeleted);
            recording
                .wait_deleted_targets
                .push(target.request_id().clone());
        }
        self.inner.wait_deleted(target, context).await
    }
}

struct AdapterObserver {
    runtime: Arc<Mutex<RuntimeRecording>>,
    transport: Arc<ScriptTransport>,
}

impl ConformanceObserver for AdapterObserver {
    fn observe(&self) -> ConformanceObservation {
        let runtime = self.runtime.lock().expect("recording mutex poisoned");
        let transport = self.transport.lock();
        ConformanceObservation::new(
            runtime.operations.clone(),
            transport.create_submissions,
            transport.exec_dispatches,
            runtime.exec_argv.clone(),
            runtime.delete_targets.clone(),
            runtime.wait_deleted_targets.clone(),
        )
    }
}

struct AdapterHarness {
    next_id: AtomicU64,
}

impl AdapterHarness {
    const fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
        }
    }
}

impl ConformanceHarness for AdapterHarness {
    fn build_case(&self, scenario: ConformanceScenario) -> ConformanceCase {
        let index = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request_id = RequestOwnedId::parse(format!("sbx-1{index:014x}")).unwrap();
        let transport = Arc::new(ScriptTransport::new(scenario));
        let inner = OpenShellRuntime::from_transport(transport.clone(), Duration::from_millis(1));
        let recording = Arc::new(Mutex::new(RuntimeRecording::default()));
        let runtime = Arc::new(RecordingRuntime {
            inner,
            recording: recording.clone(),
        });
        let observer = Arc::new(AdapterObserver {
            runtime: recording,
            transport,
        });
        let create_request = create_request(scenario, request_id);
        let exec_request = exec_request(scenario);
        ConformanceCase::new(
            runtime,
            observer,
            create_request,
            exec_request,
            contexts(scenario),
        )
    }
}

#[derive(Default)]
struct ScriptState {
    create_submissions: u64,
    exec_dispatches: u64,
    created: bool,
    deleted: bool,
    name: String,
    sandbox_id: String,
    spec: Option<SandboxSpec>,
    policy: Option<SandboxPolicy>,
}

struct ScriptTransport {
    scenario: ConformanceScenario,
    mutate_create_response_spec: bool,
    state: Mutex<ScriptState>,
}

impl ScriptTransport {
    fn new(scenario: ConformanceScenario) -> Self {
        Self {
            scenario,
            mutate_create_response_spec: false,
            state: Mutex::new(ScriptState::default()),
        }
    }

    fn with_mutated_create_response() -> Self {
        Self {
            scenario: ConformanceScenario::HappyPath,
            mutate_create_response_spec: true,
            state: Mutex::new(ScriptState::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, ScriptState> {
        self.state.lock().expect("transport mutex poisoned")
    }

    fn sandbox(state: &ScriptState, phase: SandboxPhase) -> SandboxResponse {
        SandboxResponse {
            sandbox: Some(Sandbox {
                metadata: Some(ObjectMeta {
                    id: state.sandbox_id.clone(),
                    name: state.name.clone(),
                    ..ObjectMeta::default()
                }),
                spec: state.spec.clone(),
                status: Some(SandboxStatus {
                    phase: phase as i32,
                    current_policy_version: u32::from(phase == SandboxPhase::Ready),
                    ..SandboxStatus::default()
                }),
            }),
        }
    }
}

#[async_trait]
impl OpenShellTransport for ScriptTransport {
    async fn create_sandbox(
        &self,
        request: CreateSandboxRequest,
    ) -> Result<SandboxResponse, CreateTransportError> {
        let mut state = self.lock();
        state.create_submissions += 1;
        state.name = request.name;
        state.sandbox_id = format!("provider-{}", state.name);
        state.spec = request.spec;
        state.policy = state.spec.as_ref().and_then(|spec| spec.policy.clone());
        match self.scenario {
            ConformanceScenario::CreateConflict => Err(CreateTransportError::Conflict),
            ConformanceScenario::CreateLostResponse => {
                state.created = true;
                Err(CreateTransportError::PossiblySubmitted(
                    tonic::Status::unavailable("lost response"),
                ))
            }
            _ => {
                state.created = true;
                let mut response = Self::sandbox(&state, SandboxPhase::Provisioning);
                if self.mutate_create_response_spec {
                    response
                        .sandbox
                        .as_mut()
                        .and_then(|sandbox| sandbox.spec.as_mut())
                        .expect("script response has a spec")
                        .environment
                        .insert("IMPLICIT_CAPABILITY".to_owned(), "forbidden".to_owned());
                }
                Ok(response)
            }
        }
    }

    async fn get_sandbox(
        &self,
        _request: GetSandboxRequest,
    ) -> Result<SandboxResponse, tonic::Status> {
        let state = self.lock();
        if !state.created || state.deleted {
            return Err(tonic::Status::not_found("absent"));
        }
        let phase = if self.scenario == ConformanceScenario::ReadinessDeadline {
            SandboxPhase::Provisioning
        } else {
            SandboxPhase::Ready
        };
        Ok(Self::sandbox(&state, phase))
    }

    async fn get_sandbox_policy_status(
        &self,
        _request: GetSandboxPolicyStatusRequest,
    ) -> Result<GetSandboxPolicyStatusResponse, tonic::Status> {
        let state = self.lock();
        let policy = state.policy.clone().expect("created policy");
        let policy_hash = if self.scenario == ConformanceScenario::PolicyMismatch {
            "mismatched-policy-hash".to_owned()
        } else {
            deterministic_policy_hash(&policy)
        };
        Ok(GetSandboxPolicyStatusResponse {
            revision: Some(SandboxPolicyRevision {
                version: 1,
                policy_hash,
                status: PolicyStatus::Loaded as i32,
                created_at_ms: 1,
                loaded_at_ms: 1,
                policy: Some(policy),
                ..SandboxPolicyRevision::default()
            }),
            active_version: 1,
        })
    }

    async fn exec_sandbox(
        &self,
        _request: ExecSandboxRequest,
    ) -> Result<Box<dyn ExecEventStream>, ExecTransportError> {
        if self.scenario == ConformanceScenario::TransportBeforeDispatch {
            return Err(ExecTransportError::NotSubmitted(
                tonic::Status::unavailable("before dispatch"),
            ));
        }
        self.lock().exec_dispatches += 1;
        let events = stream_events(self.scenario);
        Ok(Box::new(ScriptStream {
            events: events.into(),
        }))
    }

    async fn delete_sandbox(
        &self,
        _request: DeleteSandboxRequest,
    ) -> Result<DeleteSandboxResponse, tonic::Status> {
        let mut state = self.lock();
        match self.scenario {
            ConformanceScenario::CleanupFailure => {
                state.deleted = true;
                Err(tonic::Status::unavailable("delete failed"))
            }
            ConformanceScenario::WaitDeletedDeadline => Ok(DeleteSandboxResponse { deleted: true }),
            _ => {
                state.deleted = true;
                Ok(DeleteSandboxResponse { deleted: true })
            }
        }
    }
}

struct ScriptStream {
    events: VecDeque<Result<ExecTransportEvent, tonic::Status>>,
}

#[async_trait]
impl ExecEventStream for ScriptStream {
    async fn message(&mut self) -> Result<Option<ExecTransportEvent>, tonic::Status> {
        self.events.pop_front().transpose()
    }
}

fn stream_events(scenario: ConformanceScenario) -> Vec<Result<ExecTransportEvent, tonic::Status>> {
    let exit = |code, timeout| Ok(ExecTransportEvent::Exit { code, timeout });
    match scenario {
        ConformanceScenario::HappyPath => vec![
            Ok(ExecTransportEvent::Stdout(raw_stdout_fixture())),
            Ok(ExecTransportEvent::Stderr(raw_stderr_fixture())),
            exit(0, ObservedTimeout::NotObserved),
        ],
        ConformanceScenario::NonzeroExit => vec![exit(7, ObservedTimeout::NotObserved)],
        ConformanceScenario::Exit124PossibleTimeout => {
            vec![exit(124, ObservedTimeout::Possible)]
        }
        ConformanceScenario::ConfirmedTimeout => {
            vec![exit(124, ObservedTimeout::Confirmed)]
        }
        ConformanceScenario::MissingTerminalExit => {
            vec![Ok(ExecTransportEvent::Stdout(vec![1, 2, 3]))]
        }
        ConformanceScenario::StdoutOverflow | ConformanceScenario::ChunkOverflow => {
            vec![Ok(ExecTransportEvent::Stdout(vec![0; 65]))]
        }
        ConformanceScenario::StderrOverflow => {
            vec![Ok(ExecTransportEvent::Stderr(vec![0; 65]))]
        }
        ConformanceScenario::CombinedOverflow => vec![
            Ok(ExecTransportEvent::Stdout(vec![0; 48])),
            Ok(ExecTransportEvent::Stderr(vec![0; 49])),
        ],
        ConformanceScenario::CancelAfterDispatch => {
            vec![Err(tonic::Status::cancelled("cancelled"))]
        }
        ConformanceScenario::TransportAfterDispatch => {
            vec![Err(tonic::Status::unavailable("transport"))]
        }
        ConformanceScenario::CleanupFailure | ConformanceScenario::WaitDeletedDeadline => {
            vec![exit(0, ObservedTimeout::NotObserved)]
        }
        ConformanceScenario::CancelBeforeDispatch
        | ConformanceScenario::TransportBeforeDispatch
        | ConformanceScenario::CreateNotCreated
        | ConformanceScenario::CreateConflict
        | ConformanceScenario::CreateLostResponse
        | ConformanceScenario::PolicyMismatch
        | ConformanceScenario::ReadinessDeadline => vec![],
    }
}

fn create_request(scenario: ConformanceScenario, request_id: RequestOwnedId) -> CreateRequest {
    let image = if scenario == ConformanceScenario::CreateNotCreated {
        "example.invalid/openbox-proof:mutable"
    } else {
        IMAGE
    };
    CreateRequest::new(
        request_id,
        TemplateIdentity::new(image).unwrap(),
        PolicyDocument::new("application/yaml", POLICY_YAML.as_bytes().to_vec()).unwrap(),
        policy_identity(),
    )
}

fn policy_identity() -> PolicyIdentity {
    let digest = Sha256::digest(POLICY_YAML.as_bytes()).iter().fold(
        String::with_capacity(64),
        |mut output, byte| {
            use core::fmt::Write as _;
            write!(output, "{byte:02x}").unwrap();
            output
        },
    );
    PolicyIdentity::new(
        "conformance-policy",
        1,
        Sha256Digest::parse(digest).unwrap(),
    )
    .unwrap()
}

fn exec_request(scenario: ConformanceScenario) -> ExecRequest {
    let limits = match scenario {
        ConformanceScenario::StdoutOverflow => OutputLimits::new(64, 128, 192, 128).unwrap(),
        ConformanceScenario::StderrOverflow => OutputLimits::new(128, 64, 192, 128).unwrap(),
        ConformanceScenario::CombinedOverflow => OutputLimits::new(128, 128, 96, 128).unwrap(),
        ConformanceScenario::ChunkOverflow => OutputLimits::new(128, 128, 192, 64).unwrap(),
        _ => output_limits_fixture(),
    };
    ExecRequest::new(adversarial_argv(), crate::CommandTimeout::default(), limits)
}

fn contexts(scenario: ConformanceScenario) -> LifecycleContexts {
    if scenario == ConformanceScenario::CancelBeforeDispatch {
        return cancelled_exec_contexts_fixture();
    }
    let normal = || operation_context(Duration::from_secs(1));
    LifecycleContexts::new(
        normal(),
        operation_context(if scenario == ConformanceScenario::ReadinessDeadline {
            Duration::from_millis(10)
        } else {
            Duration::from_secs(1)
        }),
        normal(),
        normal(),
        operation_context(if scenario == ConformanceScenario::WaitDeletedDeadline {
            Duration::from_millis(10)
        } else {
            Duration::from_secs(1)
        }),
    )
}

fn operation_context(duration: Duration) -> OperationContext {
    OperationContext::new(
        CancellationToken::new(),
        OperationDeadline::new(duration).unwrap(),
    )
}

#[tokio::test]
async fn pinned_adapter_passes_the_unchanged_twenty_scenario_suite() {
    let report = run_conformance_suite(&AdapterHarness::new()).await.unwrap();
    assert_eq!(report.scenarios(), ConformanceScenario::ALL);
}

#[tokio::test]
async fn gateway_added_create_capability_is_rejected_with_cleanup_ownership() {
    let transport = Arc::new(ScriptTransport::with_mutated_create_response());
    let runtime = OpenShellRuntime::from_transport(transport.clone(), Duration::from_millis(1));
    let request_id = RequestOwnedId::parse("sbx-200000000000001").unwrap();
    let failure = runtime
        .create(
            create_request(ConformanceScenario::HappyPath, request_id.clone()),
            operation_context(Duration::from_secs(1)),
        )
        .await
        .unwrap_err();

    assert_eq!(failure.state(), CreationState::PossiblyCreated);
    assert_eq!(
        failure.cleanup_target().map(CleanupTarget::request_id),
        Some(&request_id)
    );
    assert!(transport.lock().created);
}
