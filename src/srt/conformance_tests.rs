use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use crate::{
    Argv, CleanupFailure, CleanupFailureCode, CleanupTarget, CommandTimeout, ConformanceCase,
    ConformanceHarness, ConformanceObservation, ConformanceObserver, ConformanceOperation,
    ConformanceScenario, CreateFailure, CreateFailureCode, CreateRequest, CreatedSandbox,
    DeleteOutcome, ExecCompleted, ExecFailure, ExecFailureCode, ExecRequest, FailureTimeout,
    LifecycleContexts, ObservedExitCode, ObservedTimeout, OperationContext, OperationDeadline,
    OperatorDetail, OutputByteCounts, OutputLimits, PolicyDocument, PolicyIdentity,
    ReadinessFailure, ReadinessFailureCode, ReadySandbox, RequestOwnedId, SandboxRuntime,
    Sha256Digest, SrtConfig, SrtRuntime, TemplateIdentity, adversarial_argv, compile_srt_policy,
    run_conformance_suite,
};

const POLICY: &str = include_str!("../../deploy/policies/policy-deny-network.yaml");

#[derive(Default)]
struct Recording {
    operations: Vec<ConformanceOperation>,
    create_submissions: u64,
    exec_dispatches: u64,
    exec_argv: Vec<Vec<String>>,
    delete_targets: Vec<RequestOwnedId>,
    wait_deleted_targets: Vec<RequestOwnedId>,
}

struct Observer(Arc<Mutex<Recording>>);

impl ConformanceObserver for Observer {
    fn observe(&self) -> ConformanceObservation {
        let value = self.0.lock().unwrap();
        ConformanceObservation::new(
            value.operations.clone(),
            value.create_submissions,
            value.exec_dispatches,
            value.exec_argv.clone(),
            value.delete_targets.clone(),
            value.wait_deleted_targets.clone(),
        )
    }
}

struct ScenarioRuntime {
    inner: SrtRuntime,
    scenario: ConformanceScenario,
    recording: Arc<Mutex<Recording>>,
    _temporary: tempfile::TempDir,
}

#[async_trait]
impl SandboxRuntime for ScenarioRuntime {
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
        if self.scenario == ConformanceScenario::CreateNotCreated {
            return Err(CreateFailure::not_created(
                CreateFailureCode::Validation,
                detail("scripted pre-submission validation"),
            ));
        }
        self.recording.lock().unwrap().create_submissions += 1;
        if self.scenario == ConformanceScenario::CreateConflict {
            return Err(CreateFailure::conflict(
                CreateFailureCode::Provider,
                detail("scripted native workspace conflict"),
            ));
        }
        let target = CleanupTarget::new(request.request_id().clone());
        let created = self.inner.create(request, context).await?;
        if self.scenario == ConformanceScenario::CreateLostResponse {
            return Err(CreateFailure::possibly_created(
                target,
                CreateFailureCode::Transport,
                detail("scripted response loss after local create"),
            ));
        }
        Ok(created)
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
        let target = sandbox.cleanup_target();
        match self.scenario {
            ConformanceScenario::PolicyMismatch => Err(ReadinessFailure::new(
                target,
                ReadinessFailureCode::PolicyMismatch,
                detail("scripted local profile mismatch"),
            )),
            ConformanceScenario::ReadinessDeadline => Err(ReadinessFailure::new(
                target,
                ReadinessFailureCode::Deadline,
                detail("scripted local readiness deadline"),
            )),
            _ => {
                self.inner
                    .wait_ready(sandbox, expected_policy, context)
                    .await
            }
        }
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
        let target = sandbox.cleanup_target();
        if self.scenario == ConformanceScenario::CancelBeforeDispatch {
            return self.inner.exec(sandbox, request, context).await;
        }
        if self.scenario == ConformanceScenario::TransportBeforeDispatch {
            return Err(ExecFailure::not_dispatched(
                target,
                ExecFailureCode::Transport,
                detail("scripted native spawn failure"),
            )
            .unwrap());
        }
        self.recording.lock().unwrap().exec_dispatches += 1;
        match self.scenario {
            ConformanceScenario::Exit124PossibleTimeout => Ok(completed(
                124,
                Vec::new(),
                Vec::new(),
                ObservedTimeout::Possible,
            )),
            ConformanceScenario::ConfirmedTimeout => Ok(completed(
                124,
                Vec::new(),
                Vec::new(),
                ObservedTimeout::Confirmed,
            )),
            ConformanceScenario::MissingTerminalExit => Err(ExecFailure::missing_terminal_exit(
                target,
                FailureTimeout::Unknown,
                OutputByteCounts::new(3, 0),
                detail("scripted missing local exit"),
            )
            .unwrap()),
            ConformanceScenario::CancelAfterDispatch => Err(ExecFailure::possibly_dispatched(
                target,
                ExecFailureCode::Cancelled,
                FailureTimeout::Unknown,
                OutputByteCounts::default(),
                detail("scripted cancellation after native spawn"),
            )
            .unwrap()),
            ConformanceScenario::TransportAfterDispatch => Err(ExecFailure::possibly_dispatched(
                target,
                ExecFailureCode::Transport,
                FailureTimeout::Unknown,
                OutputByteCounts::default(),
                detail("scripted observation loss after native spawn"),
            )
            .unwrap()),
            _ => {
                let replacement = native_exec_request(self.scenario, request.output_limits());
                self.inner.exec(sandbox, replacement, context).await
            }
        }
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
        match self.scenario {
            ConformanceScenario::CleanupFailure => {
                let _ = self.inner.delete(target.clone(), fresh_context()).await;
                Err(CleanupFailure::new(
                    target,
                    CleanupFailureCode::Transport,
                    detail("scripted native cleanup failure"),
                ))
            }
            ConformanceScenario::WaitDeletedDeadline => Ok(DeleteOutcome::Deleted),
            _ => self.inner.delete(target, context).await,
        }
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
        if self.scenario == ConformanceScenario::WaitDeletedDeadline {
            return Err(CleanupFailure::new(
                target,
                CleanupFailureCode::Deadline,
                detail("scripted native absence deadline"),
            ));
        }
        self.inner.wait_deleted(target, context).await
    }
}

struct Harness {
    next: AtomicU64,
}

impl Harness {
    const fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }
}

impl ConformanceHarness for Harness {
    fn build_case(&self, scenario: ConformanceScenario) -> ConformanceCase {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let workspaces = root.join("workspaces");
        let profile = root.join(if cfg!(target_os = "macos") {
            "policy.sb"
        } else {
            "policy.json"
        });
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("deploy/policies/policy-deny-network.yaml");
        let profile_sha = compile_srt_policy(&source, &profile, &workspaces).unwrap();
        let policy = policy_identity();
        let inner = SrtRuntime::new(
            SrtConfig::new(
                profile,
                Sha256Digest::parse(profile_sha).unwrap(),
                workspaces,
                policy.clone(),
            )
            .unwrap(),
        )
        .unwrap();
        let recording = Arc::new(Mutex::new(Recording::default()));
        let runtime = Arc::new(ScenarioRuntime {
            inner,
            scenario,
            recording: recording.clone(),
            _temporary: temporary,
        });
        let request_id = RequestOwnedId::parse(format!("sbx-3{index:014x}")).unwrap();
        let create = CreateRequest::new(
            request_id,
            TemplateIdentity::new("native://srt").unwrap(),
            PolicyDocument::new("application/yaml", POLICY.as_bytes().to_vec()).unwrap(),
            policy,
        );
        let limits = match scenario {
            ConformanceScenario::StdoutOverflow => OutputLimits::new(64, 128, 192, 128).unwrap(),
            ConformanceScenario::StderrOverflow => OutputLimits::new(128, 64, 192, 128).unwrap(),
            ConformanceScenario::CombinedOverflow => OutputLimits::new(128, 128, 96, 128).unwrap(),
            ConformanceScenario::ChunkOverflow => OutputLimits::new(128, 128, 192, 64).unwrap(),
            _ => OutputLimits::new(64, 64, 96, 64).unwrap(),
        };
        let exec = ExecRequest::new(adversarial_argv(), CommandTimeout::default(), limits);
        let contexts = if scenario == ConformanceScenario::CancelBeforeDispatch {
            let cancellation = CancellationToken::new();
            cancellation.cancel();
            LifecycleContexts::new(
                fresh_context(),
                fresh_context(),
                OperationContext::new(cancellation, deadline()),
                fresh_context(),
                fresh_context(),
            )
        } else {
            LifecycleContexts::new(
                fresh_context(),
                fresh_context(),
                fresh_context(),
                fresh_context(),
                fresh_context(),
            )
        };
        ConformanceCase::new(
            runtime,
            Arc::new(Observer(recording)),
            create,
            exec,
            contexts,
        )
    }
}

fn native_exec_request(scenario: ConformanceScenario, limits: OutputLimits) -> ExecRequest {
    let script = match scenario {
        ConformanceScenario::HappyPath => "printf '\\000\\377out'; printf '\\000\\376err' >&2",
        ConformanceScenario::NonzeroExit => "exit 7",
        ConformanceScenario::StdoutOverflow | ConformanceScenario::ChunkOverflow => {
            "printf xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        }
        ConformanceScenario::StderrOverflow => {
            "printf xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx >&2"
        }
        ConformanceScenario::CombinedOverflow => {
            "printf xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; printf yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy >&2"
        }
        _ => "exit 0",
    };
    ExecRequest::new(
        Argv::new(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            script.to_owned(),
        ])
        .unwrap(),
        CommandTimeout::default(),
        limits,
    )
}

fn completed(
    exit: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timeout: ObservedTimeout,
) -> ExecCompleted {
    ExecCompleted::new(
        ObservedExitCode::new(exit).unwrap(),
        stdout,
        stderr,
        timeout,
    )
}

fn policy_identity() -> PolicyIdentity {
    use core::fmt::Write as _;

    let sha = Sha256::digest(POLICY.as_bytes()).iter().fold(
        String::with_capacity(64),
        |mut encoded, byte| {
            write!(encoded, "{byte:02x}").unwrap();
            encoded
        },
    );
    PolicyIdentity::new(
        "native-srt-conformance",
        1,
        Sha256Digest::parse(sha).unwrap(),
    )
    .unwrap()
}

fn deadline() -> OperationDeadline {
    OperationDeadline::new(Duration::from_secs(5)).unwrap()
}

fn fresh_context() -> OperationContext {
    OperationContext::new(CancellationToken::new(), deadline())
}

fn detail(message: &'static str) -> OperatorDetail {
    OperatorDetail::redacted(message)
}

#[tokio::test]
async fn native_adapter_passes_the_unchanged_twenty_scenario_suite() {
    if cfg!(target_os = "linux")
        && std::process::Command::new("bwrap")
            .arg("--version")
            .output()
            .is_err()
    {
        eprintln!("SKIP native srt conformance: bwrap absent");
        return;
    }
    let report = run_conformance_suite(&Harness::new()).await.unwrap();
    assert_eq!(report.scenarios(), ConformanceScenario::ALL);
}
