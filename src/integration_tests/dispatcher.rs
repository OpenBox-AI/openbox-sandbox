use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};

use crate::{
    ActivityStarted, Command, CreateFailureCode, DispatcherConfig, EffectiveCommand, ExecCompleted,
    ExecutionOutcome, FailureTimeout, GovernanceClient, GovernanceClientError,
    GovernedCleanupState, GovernedDispatchState, GovernedDispatcher, HostExecutionFailure,
    HostExecutionFailureCode, HostExecutor, IsolationSupport, ObservedExitCode, ObservedTimeout,
    OutputByteCounts, OutputLimits, PolicyDocument, PolicyIdentity, RecordedCall,
    SandboxAssetBundle, SelectedExecutor, Sha256Digest, TemplateIdentity,
};
use crate::{
    FakeCreatePlan, FakeDeletePlan, FakeExecEvent, FakeExecPlan, FakeReadinessPlan,
    FakeSandboxRuntime, FakeScript, FakeWaitDeletedPlan,
};

type ResponseBuilder = dyn Fn(&ActivityStarted) -> serde_json::Value + Send + Sync;

struct GovernanceFake {
    calls: AtomicU64,
    activities: Mutex<Vec<ActivityStarted>>,
    response: Arc<ResponseBuilder>,
}

impl GovernanceFake {
    fn new(
        response: impl Fn(&ActivityStarted) -> serde_json::Value + Send + Sync + 'static,
    ) -> Self {
        Self {
            calls: AtomicU64::new(0),
            activities: Mutex::new(Vec::new()),
            response: Arc::new(response),
        }
    }
}

#[async_trait]
impl GovernanceClient for GovernanceFake {
    async fn evaluate(
        &self,
        activity: ActivityStarted,
    ) -> Result<serde_json::Value, GovernanceClientError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let response = (self.response)(&activity);
        self.activities.lock().unwrap().push(activity);
        Ok(response)
    }
}

#[derive(Default)]
struct HostFake {
    calls: AtomicU64,
    commands: Mutex<Vec<(Vec<String>, u16)>>,
    failure: Mutex<Option<HostExecutionFailure>>,
}

#[async_trait]
impl HostExecutor for HostFake {
    async fn execute(
        &self,
        command: &EffectiveCommand,
    ) -> Result<ExecCompleted, HostExecutionFailure> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.commands
            .lock()
            .unwrap()
            .push((command.argv().to_vec(), command.timeout_seconds()));
        let failure = self.failure.lock().unwrap().clone();
        if let Some(failure) = failure {
            return Err(failure);
        }
        Ok(ExecCompleted::new(
            ObservedExitCode::new(0).unwrap(),
            b"stdout".to_vec(),
            b"stderr".to_vec(),
            ObservedTimeout::NotObserved,
        ))
    }
}

fn authoritative(activity: &ActivityStarted, verdict: &str) -> serde_json::Value {
    serde_json::json!({
        "activity_id": activity.activity_id().as_str(),
        "verdict": verdict,
        "authoritative": true,
        "synthetic": false,
        "fallback_used": false,
        "guardrails_passed": true,
        "stale": false
    })
}

fn assets() -> SandboxAssetBundle {
    let template_digest = Sha256Digest::parse("a".repeat(64)).unwrap();
    let template = TemplateIdentity::new(format!(
        "example.invalid/openbox@sha256:{}",
        template_digest.as_str()
    ))
    .unwrap();
    let body = b"version: 1\nnetwork_policies: {}\n".to_vec();
    let digest =
        Sha256::digest(&body)
            .iter()
            .fold(String::with_capacity(64), |mut output, byte| {
                use core::fmt::Write as _;
                write!(output, "{byte:02x}").unwrap();
                output
            });
    let policy =
        PolicyIdentity::new("deny-network", 1, Sha256Digest::parse(digest).unwrap()).unwrap();
    SandboxAssetBundle::new(
        template,
        template_digest,
        policy,
        PolicyDocument::new("application/yaml", body).unwrap(),
        "fake-v1",
        IsolationSupport::Full,
        true,
        true,
    )
    .unwrap()
}

fn config(directory: &std::path::Path) -> DispatcherConfig {
    DispatcherConfig::new(
        directory,
        assets(),
        OutputLimits::new(1024, 1024, 2048, 1024).unwrap(),
    )
    .unwrap()
}

// Fake runtime policy identity must match the deployment assets rather than the generic fixture.
fn success_runtime_script(count: usize) -> FakeScript {
    let expected = assets().policy().clone();
    let mut script = FakeScript::new();
    for index in 0..count {
        script
            .push_create(FakeCreatePlan::Succeed {
                provider_handle: format!("provider-{index}").into_bytes(),
            })
            .push_readiness(FakeReadinessPlan::Ready {
                observed_policy: expected.clone(),
            })
            .push_exec(FakeExecPlan::Stream {
                events: vec![FakeExecEvent::Exit {
                    code: 0,
                    timeout: ObservedTimeout::NotObserved,
                }],
            })
            .push_delete(FakeDeletePlan::Deleted)
            .push_wait_deleted(FakeWaitDeletedPlan::Absent);
    }
    script
}

#[tokio::test]
async fn constrain_omitted_null_and_empty_constraints_use_one_sandbox_and_never_host() {
    let directory = tempfile::tempdir().unwrap();
    let responses = Arc::new(Mutex::new(vec![
        None,
        Some(serde_json::Value::Null),
        Some(serde_json::json!([])),
        Some(serde_json::json!({})),
    ]));
    let governance = Arc::new(GovernanceFake::new(move |activity| {
        let constraints = responses.lock().unwrap().remove(0);
        let mut response = authoritative(activity, "CONSTRAIN");
        if let Some(constraints) = constraints {
            response["constraints"] = constraints;
        }
        response
    }));
    let host = Arc::new(HostFake::default());
    let sandbox = Arc::new(FakeSandboxRuntime::new(success_runtime_script(4)));
    let dispatcher = GovernedDispatcher::new(
        governance,
        host.clone(),
        sandbox.clone(),
        config(directory.path()),
    )
    .unwrap();

    for _ in 0..4 {
        let result = dispatcher
            .execute(Command::new(vec!["/bin/true".to_owned()], None))
            .await;
        assert_eq!(result.selected_executor(), SelectedExecutor::Sandbox);
        assert_eq!(result.dispatch_state(), GovernedDispatchState::Completed);
        assert_eq!(
            result.cleanup_state(),
            GovernedCleanupState::ConfirmedAbsent
        );
    }
    assert_eq!(host.calls.load(Ordering::Relaxed), 0);
    assert_eq!(sandbox.recording().exec_dispatches(), 4);
    assert_eq!(sandbox.recording().create_submissions(), 4);
}

#[tokio::test]
async fn allow_is_at_most_once_under_concurrent_duplicate_calls_and_never_creates_sandbox() {
    let directory = tempfile::tempdir().unwrap();
    let governance = Arc::new(GovernanceFake::new(|activity| {
        authoritative(activity, "ALLOW")
    }));
    let host = Arc::new(HostFake::default());
    let sandbox = Arc::new(FakeSandboxRuntime::new(FakeScript::new()));
    let dispatcher = GovernedDispatcher::new(
        governance.clone(),
        host.clone(),
        sandbox.clone(),
        config(directory.path()),
    )
    .unwrap();
    let command = Command::new(vec!["/bin/echo".to_owned(), "hello".to_owned()], Some(9));
    let (left, right) = tokio::join!(
        dispatcher.execute(command.clone()),
        dispatcher.execute(command)
    );
    assert_eq!(left, right);
    assert_eq!(left.selected_executor(), SelectedExecutor::Host);
    assert_eq!(host.calls.load(Ordering::Relaxed), 1);
    assert_eq!(governance.calls.load(Ordering::Relaxed), 1);
    assert_eq!(sandbox.recording().create_submissions(), 0);
}

#[tokio::test]
async fn exact_adversarial_argv_and_default_timeout_match_governance_and_sandbox() {
    let directory = tempfile::tempdir().unwrap();
    let governance = Arc::new(GovernanceFake::new(|activity| {
        authoritative(activity, "CONSTRAIN")
    }));
    let host = Arc::new(HostFake::default());
    let sandbox = Arc::new(FakeSandboxRuntime::new(success_runtime_script(1)));
    let dispatcher = GovernedDispatcher::new(
        governance.clone(),
        host,
        sandbox.clone(),
        config(directory.path()),
    )
    .unwrap();
    let argv = [
        "hello world",
        "",
        "'quoted'",
        "\"quoted\"",
        "$HOME",
        "$(whoami)",
        "`whoami`",
        "; rm -rf /",
        "&& echo test",
        "| cat /etc/passwd",
        "> output",
        "*",
        "?",
        "foo\nbar",
    ]
    .map(str::to_owned)
    .to_vec();
    let result = dispatcher.execute(Command::new(argv.clone(), None)).await;
    assert_eq!(result.dispatch_state(), GovernedDispatchState::Completed);
    let activities = governance.activities.lock().unwrap();
    assert_eq!(activities[0].argv(), argv);
    assert_eq!(activities[0].timeout_seconds(), 30);
    let calls = sandbox.recording();
    let RecordedCall::Exec { request, .. } = calls
        .calls()
        .iter()
        .find(|call| matches!(call, RecordedCall::Exec { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    assert_eq!(request.argv().as_slice(), argv);
    assert_eq!(request.timeout().seconds(), 30);
}

#[tokio::test]
async fn invalid_commands_and_governance_matrix_execute_nowhere() {
    let directory = tempfile::tempdir().unwrap();
    let governance = Arc::new(GovernanceFake::new(|activity| {
        authoritative(activity, "ALLOW")
    }));
    let host = Arc::new(HostFake::default());
    let sandbox = Arc::new(FakeSandboxRuntime::new(FakeScript::new()));
    let dispatcher = GovernedDispatcher::new(
        governance.clone(),
        host.clone(),
        sandbox.clone(),
        config(directory.path()),
    )
    .unwrap();
    for command in [
        Command::new(vec![], None),
        Command::new(vec!["nul\0arg".to_owned()], None),
        Command::new(vec!["x".to_owned()], Some(0)),
        Command::new(vec!["x".to_owned()], Some(301)),
        Command::new(vec!["x".repeat(64 * 1024 + 1)], None),
    ] {
        let result = dispatcher.execute(command).await;
        assert_eq!(result.selected_executor(), SelectedExecutor::None);
        assert_eq!(
            result.dispatch_state(),
            GovernedDispatchState::NotDispatched
        );
    }
    assert_eq!(governance.calls.load(Ordering::Relaxed), 0);

    let malformed_cases: Vec<Arc<ResponseBuilder>> = vec![
        Arc::new(|_| serde_json::Value::Null),
        Arc::new(|activity| authoritative(activity, "UNKNOWN")),
        Arc::new(|activity| {
            let mut value = authoritative(activity, "ALLOW");
            value["fallback_used"] = serde_json::json!(true);
            value
        }),
        Arc::new(|activity| {
            let mut value = authoritative(activity, "ALLOW");
            value["guardrails_passed"] = serde_json::json!(false);
            value
        }),
        Arc::new(|activity| {
            let mut value = authoritative(activity, "ALLOW");
            value["activity_id"] = serde_json::json!(crate::DispatchId::generate().as_str());
            value
        }),
        Arc::new(|activity| {
            let mut value = authoritative(activity, "CONSTRAIN");
            value["constraints"] = serde_json::json!([{"network": "allow"}]);
            value
        }),
        Arc::new(|activity| {
            let mut value = authoritative(activity, "ALLOW");
            value["patch"] = serde_json::json!({});
            value
        }),
        Arc::new(|activity| {
            let mut value = authoritative(activity, "ALLOW");
            value["unsupported"] = serde_json::json!(true);
            value
        }),
    ];
    for (index, builder) in malformed_cases.into_iter().enumerate() {
        let case_directory = directory.path().join(format!("case-{index}"));
        let governance = Arc::new(GovernanceFake::new(move |activity| builder(activity)));
        let dispatcher = GovernedDispatcher::new(
            governance,
            host.clone(),
            sandbox.clone(),
            config(&case_directory),
        )
        .unwrap();
        let result = dispatcher
            .execute(Command::new(vec!["/bin/true".to_owned()], None))
            .await;
        assert_eq!(result.selected_executor(), SelectedExecutor::None);
        assert_eq!(
            result.dispatch_state(),
            GovernedDispatchState::NotDispatched
        );
    }
    assert_eq!(host.calls.load(Ordering::Relaxed), 0);
    assert_eq!(sandbox.recording().create_submissions(), 0);
    assert!(
        serde_json::from_str::<Command>(r#"{"argv":["true"],"environment":{"SECRET":"value"}}"#)
            .is_err()
    );
}

#[tokio::test]
async fn non_executing_authoritative_verdicts_select_no_capability() {
    for (index, verdict) in ["REQUIRE_APPROVAL", "BLOCK", "HALT"]
        .into_iter()
        .enumerate()
    {
        let directory = tempfile::tempdir().unwrap();
        let verdict = verdict.to_owned();
        let governance = Arc::new(GovernanceFake::new(move |activity| {
            authoritative(activity, &verdict)
        }));
        let host = Arc::new(HostFake::default());
        let sandbox = Arc::new(FakeSandboxRuntime::new(FakeScript::new()));
        let dispatcher = GovernedDispatcher::new(
            governance,
            host.clone(),
            sandbox.clone(),
            config(&directory.path().join(format!("verdict-{index}"))),
        )
        .unwrap();
        let result = dispatcher
            .execute(Command::new(vec!["/bin/true".to_owned()], None))
            .await;
        assert_eq!(result.selected_executor(), SelectedExecutor::None);
        assert_eq!(
            result.dispatch_state(),
            GovernedDispatchState::NotDispatched
        );
        assert_eq!(host.calls.load(Ordering::Relaxed), 0);
        assert_eq!(sandbox.recording().create_submissions(), 0);
    }
}

#[tokio::test]
async fn ownership_conflict_never_grants_cleanup_authority_or_host_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let governance = Arc::new(GovernanceFake::new(|activity| {
        authoritative(activity, "CONSTRAIN")
    }));
    let host = Arc::new(HostFake::default());
    let mut script = FakeScript::new();
    script.push_create(FakeCreatePlan::Fail {
        state: crate::CreationState::Conflict,
        code: CreateFailureCode::Provider,
    });
    let sandbox = Arc::new(FakeSandboxRuntime::new(script));
    let dispatcher = GovernedDispatcher::new(
        governance,
        host.clone(),
        sandbox.clone(),
        config(directory.path()),
    )
    .unwrap();
    let result = dispatcher
        .execute(Command::new(vec!["/bin/true".to_owned()], None))
        .await;
    assert_eq!(result.selected_executor(), SelectedExecutor::Sandbox);
    assert_eq!(result.cleanup_state(), GovernedCleanupState::NotNeeded);
    assert_eq!(host.calls.load(Ordering::Relaxed), 0);
    assert!(sandbox.recording().calls().iter().all(|call| !matches!(
        call,
        RecordedCall::Delete { .. } | RecordedCall::WaitDeleted { .. }
    )));
}

#[tokio::test]
async fn constrain_failures_never_fall_back_to_host_and_cleanup_uses_owned_id() {
    let directory = tempfile::tempdir().unwrap();
    let governance = Arc::new(GovernanceFake::new(|activity| {
        authoritative(activity, "CONSTRAIN")
    }));
    let host = Arc::new(HostFake::default());
    let mut script = FakeScript::new();
    script.push_create(FakeCreatePlan::Fail {
        state: crate::CreationState::PossiblyCreated,
        code: CreateFailureCode::Transport,
    });
    script
        .push_delete(FakeDeletePlan::Fail(crate::CleanupFailureCode::Transport))
        .push_wait_deleted(FakeWaitDeletedPlan::Fail(
            crate::CleanupFailureCode::Deadline,
        ));
    let sandbox = Arc::new(FakeSandboxRuntime::new(script));
    let dispatcher = GovernedDispatcher::new(
        governance,
        host.clone(),
        sandbox.clone(),
        config(directory.path()),
    )
    .unwrap();
    let result = dispatcher
        .execute(Command::new(vec!["/bin/true".to_owned()], None))
        .await;
    assert_eq!(result.selected_executor(), SelectedExecutor::Sandbox);
    assert_eq!(
        result.dispatch_state(),
        GovernedDispatchState::NotDispatched
    );
    assert_eq!(
        result.cleanup_state(),
        GovernedCleanupState::PendingReconciliation
    );
    assert_eq!(host.calls.load(Ordering::Relaxed), 0);
    let recording = sandbox.recording();
    assert_eq!(recording.exec_dispatches(), 0);
    let deleted = recording
        .calls()
        .iter()
        .find_map(|call| match call {
            RecordedCall::Delete { target, .. } => Some(target.request_id().clone()),
            _ => None,
        })
        .unwrap();
    let waited = recording
        .calls()
        .iter()
        .find_map(|call| match call {
            RecordedCall::WaitDeleted { target, .. } => Some(target.request_id().clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(deleted, waited);
}

#[tokio::test]
async fn possible_host_dispatch_is_not_retried_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let governance = Arc::new(GovernanceFake::new(|activity| {
        authoritative(activity, "ALLOW")
    }));
    let first_host = Arc::new(HostFake::default());
    *first_host.failure.lock().unwrap() = Some(
        HostExecutionFailure::possibly_dispatched(
            HostExecutionFailureCode::Transport,
            FailureTimeout::Unknown,
            OutputByteCounts::new(7, 8),
        )
        .unwrap(),
    );
    let sandbox = Arc::new(FakeSandboxRuntime::new(FakeScript::new()));
    let dispatcher = GovernedDispatcher::new(
        governance,
        first_host.clone(),
        sandbox.clone(),
        config(directory.path()),
    )
    .unwrap();
    let command = Command::new(vec!["/bin/proof".to_owned()], Some(30));
    let dispatch_id = command.dispatch_id().clone();
    let first = dispatcher.execute(command).await;
    assert_eq!(
        first.dispatch_state(),
        GovernedDispatchState::PossiblyDispatched
    );
    assert!(matches!(
        first.execution_outcome(),
        ExecutionOutcome::Indeterminate {
            stdout_bytes_observed: 7,
            stderr_bytes_observed: 8
        }
    ));

    let second_governance = Arc::new(GovernanceFake::new(|activity| {
        authoritative(activity, "ALLOW")
    }));
    let second_host = Arc::new(HostFake::default());
    let restarted = GovernedDispatcher::new(
        second_governance.clone(),
        second_host.clone(),
        sandbox,
        config(directory.path()),
    )
    .unwrap();
    let replay = restarted
        .execute(Command::resume(
            dispatch_id,
            vec!["/bin/proof".to_owned()],
            Some(30),
        ))
        .await;
    assert_eq!(
        replay.dispatch_state(),
        GovernedDispatchState::PossiblyDispatched
    );
    assert_eq!(second_host.calls.load(Ordering::Relaxed), 0);
    assert_eq!(second_governance.calls.load(Ordering::Relaxed), 0);
    assert_eq!(first_host.calls.load(Ordering::Relaxed), 1);

    let records = std::fs::read_dir(directory.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|value| value == "json")
        })
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    let body = std::fs::read_to_string(records[0].path()).unwrap();
    assert!(!body.contains("/bin/proof"));
    assert!(!body.contains("RAW_STDOUT_SECRET"));
    assert!(!body.contains("RAW_STDERR_SECRET"));
    assert!(body.contains("command_digest"));
}

#[test]
fn command_json_rejects_all_caller_execution_capabilities() {
    for field in [
        "environment",
        "working_directory",
        "mounts",
        "credentials",
        "stdin",
        "tty",
        "action_type",
    ] {
        let value = format!(r#"{{"argv":["true"],"{field}":null}}"#);
        assert!(
            serde_json::from_str::<Command>(&value).is_err(),
            "accepted {field}"
        );
    }
}
