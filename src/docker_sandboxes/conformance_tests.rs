//! UNIT TESTS ONLY — NOT SYSTEM VALIDATION.
//!
//! This module uses a scripted `sbx` runner. A green result here proves LOGIC
//! in isolation, not that the adapter works against a real Docker Sandboxes
//! installation. Under the standing "no fake tests in production" rule, do
//! not report passing counts from this module as "validated" or "integration
//! proven". Real coverage requires an authenticated host; the exact live
//! smoke-test steps are documented in `docs/design/docker-sandboxes-runtime.md`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{
    CleanupFailure, CleanupTarget, CreateFailure, CreateRequest, CreatedSandbox, DeleteOutcome,
    ExecCompleted, ExecFailure, ExecRequest, ObservedTimeout, OperationContext, OperationDeadline,
    OutputByteCounts, OutputLimitKind, OutputLimits, PolicyDocument, PolicyIdentity, ReadySandbox,
    RequestOwnedId, SandboxRuntime, Sha256Digest, TemplateIdentity,
};
use crate::{
    ConformanceCase, ConformanceHarness, ConformanceObservation, ConformanceObserver,
    ConformanceOperation, ConformanceScenario, LifecycleContexts, adversarial_argv,
    cancelled_exec_contexts_fixture, output_limits_fixture, raw_stderr_fixture, raw_stdout_fixture,
    run_conformance_suite,
};
use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use crate::docker_sandboxes::DockerSandboxesRuntime;
use crate::docker_sandboxes::config::DockerSandboxesConfig;
use crate::docker_sandboxes::process::SbxStderrHints;
use crate::docker_sandboxes::provider::SbxProviderState;
use crate::docker_sandboxes::runner::{
    ExecCapture, ExecRunFailure, ListedSandbox, SbxRunFailure, SbxRunner,
};
use crate::openshell::budget::OperationBudget;

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
    inner: DockerSandboxesRuntime,
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
    runner: Arc<ScriptSbxRunner>,
}

impl ConformanceObserver for AdapterObserver {
    fn observe(&self) -> ConformanceObservation {
        let runtime = self.runtime.lock().expect("recording mutex poisoned");
        let runner = self.runner.lock();
        ConformanceObservation::new(
            runtime.operations.clone(),
            runner.create_submissions,
            runner.exec_dispatches,
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
        let runner = Arc::new(ScriptSbxRunner::new(scenario, request_id.to_string()));
        let config = runtime_config(scenario);
        let inner = DockerSandboxesRuntime::from_runner(config, runner.clone());
        let recording = Arc::new(Mutex::new(RuntimeRecording::default()));
        let runtime = Arc::new(RecordingRuntime {
            inner,
            recording: recording.clone(),
        });
        let observer = Arc::new(AdapterObserver {
            runtime: recording,
            runner,
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

fn runtime_config(scenario: ConformanceScenario) -> DockerSandboxesConfig {
    let mut config = DockerSandboxesConfig::new("/usr/bin/sbx", "/workspace")
        .expect("test configuration is valid")
        .with_poll_interval(Duration::from_millis(1))
        .expect("test poll interval is valid");
    if scenario == ConformanceScenario::PolicyMismatch {
        config = config.with_policy(
            PolicyIdentity::new(
                "conformance-policy",
                1,
                Sha256Digest::parse("0".repeat(64)).unwrap(),
            )
            .unwrap(),
        );
    }
    config
}

#[derive(Default)]
struct ScriptState {
    create_submissions: u64,
    exec_dispatches: u64,
    created: bool,
    deleted: bool,
    name: String,
}

struct ScriptSbxRunner {
    scenario: ConformanceScenario,
    request_name: String,
    state: Mutex<ScriptState>,
}

impl ScriptSbxRunner {
    fn new(scenario: ConformanceScenario, request_name: String) -> Self {
        Self {
            scenario,
            request_name,
            state: Mutex::new(ScriptState::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ScriptState> {
        self.state.lock().expect("runner mutex poisoned")
    }

    fn listed(&self, state: &ScriptState) -> Vec<ListedSandbox> {
        let status = match self.scenario {
            ConformanceScenario::ReadinessDeadline => "provisioning",
            _ => "running",
        };
        let present = match self.scenario {
            ConformanceScenario::CreateConflict => true,
            ConformanceScenario::WaitDeletedDeadline => state.created,
            _ => state.created && !state.deleted,
        };
        if present {
            let name = if self.scenario == ConformanceScenario::CreateConflict {
                self.request_name.clone()
            } else {
                state.name.clone()
            };
            vec![ListedSandbox {
                name,
                status: status.to_owned(),
            }]
        } else {
            Vec::new()
        }
    }
}

#[async_trait]
impl SbxRunner for ScriptSbxRunner {
    async fn version(&self, _timeout: Duration) -> Result<String, SbxRunFailure> {
        Ok("sbx version: v0.38.0 scripted".to_owned())
    }

    async fn create(
        &self,
        args: &[String],
        _budget: &OperationBudget,
    ) -> Result<(), SbxRunFailure> {
        let mut state = self.lock();
        state.name = args
            .iter()
            .skip_while(|argument| *argument != "--name")
            .nth(1)
            .cloned()
            .expect("scripted create argv carries --name");
        state.create_submissions += 1;
        match self.scenario {
            ConformanceScenario::CreateLostResponse => {
                state.created = true;
                Err(SbxRunFailure::NonZero {
                    exit_code: 1,
                    stderr: b"create response lost".to_vec(),
                })
            }
            ConformanceScenario::CreateNotCreated | ConformanceScenario::CreateConflict => {
                Err(SbxRunFailure::NonZero {
                    exit_code: 1,
                    stderr: b"unexpected create call".to_vec(),
                })
            }
            _ => {
                state.created = true;
                Ok(())
            }
        }
    }

    async fn list(&self, _budget: &OperationBudget) -> Result<Vec<ListedSandbox>, SbxRunFailure> {
        let mut state = self.lock();
        // The docker create path's provider interaction is the ownership
        // preflight: the suite counts it as the single create submission for
        // the `CreateConflict` scenario (no `sbx create` is ever issued).
        if self.scenario == ConformanceScenario::CreateConflict {
            state.create_submissions += 1;
        }
        Ok(self.listed(&state))
    }

    async fn exec(
        &self,
        _args: &[String],
        _budget: &OperationBudget,
        _limits: OutputLimits,
    ) -> Result<ExecCapture, ExecRunFailure> {
        if self.scenario == ConformanceScenario::TransportBeforeDispatch {
            Err(ExecRunFailure::Spawn)
        } else {
            self.lock().exec_dispatches += 1;
            script_capture(self.scenario)
        }
    }

    async fn remove(
        &self,
        _args: &[String],
        _budget: &OperationBudget,
    ) -> Result<(), SbxRunFailure> {
        let mut state = self.lock();
        state.deleted = true;
        if self.scenario == ConformanceScenario::CleanupFailure {
            Err(SbxRunFailure::NonZero {
                exit_code: 1,
                stderr: b"remove failed".to_vec(),
            })
        } else {
            Ok(())
        }
    }
}

#[allow(clippy::too_many_lines)]
fn script_capture(scenario: ConformanceScenario) -> Result<ExecCapture, ExecRunFailure> {
    let stdout = || raw_stdout_fixture();
    let stderr = || raw_stderr_fixture();
    let capture = |exit_code, stdout, stderr, timeout, overflow, counts| ExecCapture {
        exit_code,
        stdout,
        stderr,
        overflow,
        counts,
        timeout,
        cli_hints: SbxStderrHints::default(),
    };
    match scenario {
        ConformanceScenario::HappyPath => Ok(capture(
            Some(0),
            stdout(),
            stderr(),
            ObservedTimeout::NotObserved,
            None,
            OutputByteCounts::new(8, 9),
        )),
        ConformanceScenario::NonzeroExit => Ok(capture(
            Some(7),
            Vec::new(),
            Vec::new(),
            ObservedTimeout::NotObserved,
            None,
            OutputByteCounts::default(),
        )),
        ConformanceScenario::Exit124PossibleTimeout => Ok(capture(
            Some(124),
            Vec::new(),
            Vec::new(),
            ObservedTimeout::Possible,
            None,
            OutputByteCounts::default(),
        )),
        ConformanceScenario::ConfirmedTimeout => Ok(capture(
            Some(124),
            Vec::new(),
            Vec::new(),
            ObservedTimeout::Confirmed,
            None,
            OutputByteCounts::default(),
        )),
        ConformanceScenario::MissingTerminalExit => Ok(ExecCapture {
            exit_code: None,
            stdout: vec![1, 2, 3],
            stderr: Vec::new(),
            overflow: None,
            counts: OutputByteCounts::new(3, 0),
            timeout: ObservedTimeout::NotObserved,
            cli_hints: SbxStderrHints::default(),
        }),
        ConformanceScenario::StdoutOverflow => Ok(capture(
            None,
            Vec::new(),
            Vec::new(),
            ObservedTimeout::NotObserved,
            Some(OutputLimitKind::Stdout),
            OutputByteCounts::new(65, 0),
        )),
        ConformanceScenario::StderrOverflow => Ok(capture(
            None,
            Vec::new(),
            Vec::new(),
            ObservedTimeout::NotObserved,
            Some(OutputLimitKind::Stderr),
            OutputByteCounts::new(0, 65),
        )),
        ConformanceScenario::CombinedOverflow => Ok(capture(
            None,
            Vec::new(),
            Vec::new(),
            ObservedTimeout::NotObserved,
            Some(OutputLimitKind::Combined),
            OutputByteCounts::new(48, 49),
        )),
        ConformanceScenario::ChunkOverflow => Ok(capture(
            None,
            Vec::new(),
            Vec::new(),
            ObservedTimeout::NotObserved,
            Some(OutputLimitKind::Chunk),
            OutputByteCounts::new(65, 0),
        )),
        ConformanceScenario::CancelAfterDispatch => {
            Err(ExecRunFailure::Cancelled(OutputByteCounts::new(3, 4)))
        }
        ConformanceScenario::TransportAfterDispatch => Ok(ExecCapture {
            exit_code: Some(1),
            stdout: Vec::new(),
            stderr: b"no such sandbox: sbx-scripted".to_vec(),
            overflow: None,
            counts: OutputByteCounts::new(0, 28),
            timeout: ObservedTimeout::NotObserved,
            cli_hints: SbxStderrHints {
                absent: true,
                ..SbxStderrHints::default()
            },
        }),
        ConformanceScenario::CleanupFailure | ConformanceScenario::WaitDeletedDeadline => {
            Ok(capture(
                Some(0),
                Vec::new(),
                Vec::new(),
                ObservedTimeout::NotObserved,
                None,
                OutputByteCounts::default(),
            ))
        }
        ConformanceScenario::CancelBeforeDispatch
        | ConformanceScenario::TransportBeforeDispatch
        | ConformanceScenario::CreateNotCreated
        | ConformanceScenario::CreateConflict
        | ConformanceScenario::CreateLostResponse
        | ConformanceScenario::PolicyMismatch
        | ConformanceScenario::ReadinessDeadline => unreachable!("scenario does not exec"),
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
async fn provider_handle_round_trips_through_the_runtime_boundary() {
    let name = RequestOwnedId::parse("sbx-200000000000001").unwrap();
    let handle = SbxProviderState {
        sandbox_name: name.to_string(),
    }
    .encode()
    .unwrap();
    let decoded = SbxProviderState::decode(&handle).unwrap();
    assert_eq!(decoded.sandbox_name, name.as_str());
    assert!(!format!("{handle:?}").contains("sbx-200000000000001"));
}
