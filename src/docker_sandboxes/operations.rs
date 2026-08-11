//! Lifecycle operation mapping from the provider-neutral contract onto `sbx`.
//!
//! The mapping mirrors the `OpenShell` adapter's ownership discipline:
//!
//! - `create` preflights name ownership with `sbx ls --json`, rejects policy
//!   and template violations before submission, and treats any post-submission
//!   failure as `PossiblyCreated` with mandatory cleanup by retained ID.
//! - `wait_ready` polls `sbx ls --json` for the running state, optionally
//!   probes workload readiness, and attests the deployment-pinned policy.
//! - `exec` dispatches exactly one `sbx exec` with budget-enforced deadlines
//!   and collector-enforced output ceilings.
//! - `delete` runs `sbx rm --force`; `wait_deleted` polls until absence.

use crate::docker_sandboxes::DockerSandboxesRuntime;
use crate::docker_sandboxes::policy::{validate_policy_document, validate_template};
use crate::docker_sandboxes::process::{
    build_create_args, build_exec_args, build_remove_args, valid_sandbox_name,
};
use crate::docker_sandboxes::provider::SbxProviderState;
use crate::docker_sandboxes::runner::{ExecRunFailure, SbxRunFailure};
use crate::openshell::budget::{BudgetFailure, OperationBudget};
use crate::openshell::exec::{
    MAX_CHUNK_BYTES, MAX_COMBINED_BYTES, MAX_STDERR_BYTES, MAX_STDOUT_BYTES,
    limits_within_process_ceiling,
};
use crate::{
    CleanupFailure, CleanupFailureCode, CleanupTarget, CreateFailure, CreateFailureCode,
    CreateRequest, CreatedSandbox, DeleteOutcome, ExecCompleted, ExecFailure, ExecFailureCode,
    ExecRequest, FailureTimeout, ObservedExitCode, OperationContext, OperatorDetail,
    OutputByteCounts, ReadinessFailure, ReadinessFailureCode, ReadySandbox,
};

pub async fn create(
    runtime: &DockerSandboxesRuntime,
    request: CreateRequest,
    context: OperationContext,
) -> Result<CreatedSandbox, CreateFailure> {
    let request_id = request.request_id().clone();
    let cleanup_target = CleanupTarget::new(request_id.clone());
    if !valid_sandbox_name(&request_id) {
        return Err(CreateFailure::not_created(
            CreateFailureCode::Validation,
            detail("request-owned name is not a valid sandbox name"),
        ));
    }
    validate_template(request.template()).map_err(|()| {
        CreateFailure::not_created(
            CreateFailureCode::Validation,
            detail("immutable image validation failed"),
        )
    })?;
    if runtime
        .config()
        .template()
        .is_some_and(|pinned| pinned != request.template())
    {
        return Err(CreateFailure::not_created(
            CreateFailureCode::Validation,
            detail("template pin mismatch"),
        ));
    }
    validate_policy_document(request.policy_document(), request.expected_policy()).map_err(
        |()| {
            CreateFailure::not_created(
                CreateFailureCode::Validation,
                detail("policy document validation failed"),
            )
        },
    )?;
    let budget = OperationBudget::new(context);
    budget.check().map_err(create_pre_submission_budget)?;

    let preflight = budget
        .run(runtime.runner().list(&budget))
        .await
        .map_err(create_pre_submission_budget)?;
    let preflight = preflight.map_err(|failure| create_preflight_failure(&failure))?;
    if preflight
        .iter()
        .any(|sandbox| sandbox.name == request_id.as_str())
    {
        return Err(CreateFailure::conflict(
            CreateFailureCode::Provider,
            detail("request-owned name already exists"),
        ));
    }
    budget.check().map_err(create_pre_submission_budget)?;

    let args = build_create_args(
        request_id.as_str(),
        request.template().as_str(),
        &runtime.config().workspace().to_string_lossy(),
    );
    let response = budget
        .run(runtime.runner().create(&args, &budget))
        .await
        .map_err(|failure| create_possibly_created_budget(cleanup_target.clone(), failure))?;
    response.map_err(|failure| create_submission_failure(cleanup_target.clone(), &failure))?;

    let provider_handle = SbxProviderState {
        sandbox_name: request_id.to_string(),
    }
    .encode()
    .map_err(|_| {
        CreateFailure::possibly_created(
            CleanupTarget::new(request_id.clone()),
            CreateFailureCode::Protocol,
            detail("provider state could not be retained"),
        )
    })?;
    Ok(CreatedSandbox::from_runtime(
        request_id,
        provider_handle,
        request.expected_policy().clone(),
    ))
}

pub async fn wait_ready(
    runtime: &DockerSandboxesRuntime,
    created: CreatedSandbox,
    expected_policy: crate::PolicyIdentity,
    context: OperationContext,
) -> Result<ReadySandbox, ReadinessFailure> {
    let cleanup_target = created.cleanup_target();
    if created.expected_policy() != &expected_policy {
        return Err(ReadinessFailure::new(
            cleanup_target,
            ReadinessFailureCode::PolicyMismatch,
            detail("caller policy differs from creation policy"),
        ));
    }
    if runtime
        .config()
        .policy()
        .is_some_and(|pinned| pinned != &expected_policy)
    {
        return Err(ReadinessFailure::new(
            cleanup_target,
            ReadinessFailureCode::PolicyMismatch,
            detail("policy does not match the deployment pin"),
        ));
    }
    let provider = SbxProviderState::decode(created.provider_handle()).map_err(|()| {
        ReadinessFailure::new(
            cleanup_target.clone(),
            ReadinessFailureCode::Protocol,
            detail("provider state was malformed"),
        )
    })?;
    if provider.sandbox_name != created.request_id().as_str() {
        return Err(ReadinessFailure::new(
            cleanup_target,
            ReadinessFailureCode::Protocol,
            detail("provider state identity mismatch"),
        ));
    }
    let budget = OperationBudget::new(context);

    loop {
        let listed = budget
            .run(runtime.runner().list(&budget))
            .await
            .map_err(|failure| readiness_budget(cleanup_target.clone(), failure))?
            .map_err(|failure| readiness_run_failure(cleanup_target.clone(), &failure))?;
        let status = listed
            .iter()
            .find(|sandbox| sandbox.name == created.request_id().as_str())
            .map(|sandbox| sandbox.status.as_str());
        match status {
            Some("running") => {
                if let Some(probe) = runtime.config().readiness_probe()
                    && !readiness_probe(
                        runtime,
                        &budget,
                        &provider.sandbox_name,
                        probe,
                        cleanup_target.clone(),
                    )
                    .await?
                {
                    return Err(ReadinessFailure::new(
                        cleanup_target,
                        ReadinessFailureCode::WorkloadError,
                        detail("readiness probe did not exit zero"),
                    ));
                }
                return ReadySandbox::attest(created, expected_policy.clone(), &expected_policy)
                    .map_err(|_| {
                        ReadinessFailure::new(
                            cleanup_target,
                            ReadinessFailureCode::PolicyMismatch,
                            detail("policy attestation transition failed"),
                        )
                    });
            }
            Some(
                "stopped" | "created" | "starting" | "provisioning" | "pending" | "initializing",
            )
            | None => {
                pause(runtime, &budget, cleanup_target.clone()).await?;
            }
            Some("error" | "failed" | "degraded") => {
                return Err(ReadinessFailure::new(
                    cleanup_target,
                    ReadinessFailureCode::WorkloadError,
                    detail("sandbox entered workload error"),
                ));
            }
            Some(_) => {
                return Err(ReadinessFailure::new(
                    cleanup_target,
                    ReadinessFailureCode::Protocol,
                    detail("readiness response used unknown status"),
                ));
            }
        }
    }
}

async fn readiness_probe(
    runtime: &DockerSandboxesRuntime,
    budget: &OperationBudget,
    name: &str,
    probe: &crate::Argv,
    cleanup_target: CleanupTarget,
) -> Result<bool, ReadinessFailure> {
    let limits = OutputLimitCeilings::get();
    let args = build_exec_args(
        name,
        runtime.config().exec_user(),
        runtime.config().exec_workdir(),
        probe.as_slice(),
    );
    let capture = runtime
        .runner()
        .exec(&args, budget, limits)
        .await
        .map_err(|failure| probe_failure(cleanup_target.clone(), failure))?;
    if capture.overflow.is_some() {
        return Err(ReadinessFailure::new(
            cleanup_target,
            ReadinessFailureCode::WorkloadError,
            detail("readiness probe exceeded output limits"),
        ));
    }
    Ok(capture.exit_code == Some(0))
}

fn probe_failure(target: CleanupTarget, failure: ExecRunFailure) -> ReadinessFailure {
    match failure {
        ExecRunFailure::Spawn => ReadinessFailure::new(
            target,
            ReadinessFailureCode::WorkloadError,
            detail("readiness probe could not be spawned"),
        ),
        ExecRunFailure::Cancelled(_) => ReadinessFailure::new(
            target,
            ReadinessFailureCode::Cancelled,
            detail("readiness operation stopped"),
        ),
        ExecRunFailure::Deadline(_) => ReadinessFailure::new(
            target,
            ReadinessFailureCode::Deadline,
            detail("readiness operation stopped"),
        ),
    }
}

pub async fn exec(
    runtime: &DockerSandboxesRuntime,
    ready: ReadySandbox,
    request: ExecRequest,
    context: OperationContext,
) -> Result<ExecCompleted, ExecFailure> {
    let cleanup_target = ready.cleanup_target();
    let provider = SbxProviderState::decode(ready.provider_handle()).map_err(|()| {
        ExecFailure::not_dispatched(
            cleanup_target.clone(),
            ExecFailureCode::Protocol,
            detail("provider state was malformed"),
        )
        .expect("protocol is valid before dispatch")
    })?;
    if provider.sandbox_name != ready.request_id().as_str() {
        return Err(ExecFailure::not_dispatched(
            cleanup_target,
            ExecFailureCode::Protocol,
            detail("provider state identity mismatch"),
        )
        .expect("protocol is valid before dispatch"));
    }
    if !limits_within_process_ceiling(request.output_limits()) {
        return Err(ExecFailure::not_dispatched(
            cleanup_target,
            ExecFailureCode::Protocol,
            detail("output limits exceed process ceilings"),
        )
        .expect("protocol is valid before dispatch"));
    }
    let budget = OperationBudget::new(context);
    budget.check().map_err(|failure| {
        ExecFailure::not_dispatched(
            cleanup_target.clone(),
            exec_budget_code(failure),
            detail("execution stopped before dispatch"),
        )
        .expect("budget failures are valid before dispatch")
    })?;

    let args = build_exec_args(
        &provider.sandbox_name,
        runtime.config().exec_user(),
        runtime.config().exec_workdir(),
        request.argv().as_slice(),
    );
    let capture = runtime
        .runner()
        .exec(&args, &budget, request.output_limits())
        .await
        .map_err(|failure| exec_run_failure(cleanup_target.clone(), failure))?;
    if capture.cli_hints.authentication {
        return Err(exec_possible(
            cleanup_target,
            ExecFailureCode::Transport,
            capture.counts,
        ));
    }
    if capture.cli_hints.absent {
        return Err(exec_possible(
            cleanup_target,
            ExecFailureCode::Transport,
            capture.counts,
        ));
    }
    if let Some(kind) = capture.overflow {
        return Err(ExecFailure::output_limit_exceeded(
            cleanup_target,
            FailureTimeout::Unknown,
            capture.counts,
            kind,
            detail("execution output limit exceeded"),
        )
        .expect("output overflow is valid after dispatch"));
    }
    let Some(code) = capture.exit_code else {
        return Err(ExecFailure::missing_terminal_exit(
            cleanup_target,
            FailureTimeout::Unknown,
            capture.counts,
            detail("execution ended without a terminal exit code"),
        )
        .expect("missing terminal exit is valid after dispatch"));
    };
    let exit_code = ObservedExitCode::new(code)
        .map_err(|_| exec_possible(cleanup_target, ExecFailureCode::Protocol, capture.counts))?;
    Ok(ExecCompleted::new(
        exit_code,
        capture.stdout,
        capture.stderr,
        capture.timeout,
    ))
}

pub async fn delete(
    runtime: &DockerSandboxesRuntime,
    target: CleanupTarget,
    context: OperationContext,
) -> Result<DeleteOutcome, CleanupFailure> {
    let budget = OperationBudget::new(context);
    budget
        .check()
        .map_err(|failure| cleanup_budget(target.clone(), failure))?;
    let args = build_remove_args(target.request_id().as_str());
    let response = budget
        .run(runtime.runner().remove(&args, &budget))
        .await
        .map_err(|failure| cleanup_budget(target.clone(), failure))?;
    match response {
        Err(failure) if failure.hints().absent_loose => Ok(DeleteOutcome::AlreadyAbsent),
        Err(failure) => Err(cleanup_run_failure(target, &failure)),
        Ok(()) => Ok(DeleteOutcome::Deleted),
    }
}

pub async fn wait_deleted(
    runtime: &DockerSandboxesRuntime,
    target: CleanupTarget,
    context: OperationContext,
) -> Result<(), CleanupFailure> {
    let budget = OperationBudget::new(context);
    loop {
        let listed = budget
            .run(runtime.runner().list(&budget))
            .await
            .map_err(|failure| cleanup_budget(target.clone(), failure))?
            .map_err(|failure| cleanup_run_failure(target.clone(), &failure))?;
        if !listed
            .iter()
            .any(|sandbox| sandbox.name == target.request_id().as_str())
        {
            return Ok(());
        }
        budget
            .pause(runtime.poll_interval())
            .await
            .map_err(|failure| cleanup_budget(target.clone(), failure))?;
    }
}

/// Process-ceiling output limits used by the optional readiness probe.
struct OutputLimitCeilings;

impl OutputLimitCeilings {
    fn get() -> crate::OutputLimits {
        crate::OutputLimits::new(
            MAX_STDOUT_BYTES,
            MAX_STDERR_BYTES,
            MAX_COMBINED_BYTES,
            MAX_CHUNK_BYTES,
        )
        .expect("process ceilings are valid output limits")
    }
}

async fn pause(
    runtime: &DockerSandboxesRuntime,
    budget: &OperationBudget,
    target: CleanupTarget,
) -> Result<(), ReadinessFailure> {
    budget
        .pause(runtime.poll_interval())
        .await
        .map_err(|failure| readiness_budget(target, failure))
}

fn create_preflight_failure(failure: &SbxRunFailure) -> CreateFailure {
    match failure {
        SbxRunFailure::Spawn => CreateFailure::not_created(
            CreateFailureCode::Transport,
            detail("sbx preflight could not be spawned"),
        ),
        SbxRunFailure::Cancelled => CreateFailure::not_created(
            CreateFailureCode::Cancelled,
            detail("create cancelled before submission"),
        ),
        SbxRunFailure::Deadline => CreateFailure::not_created(
            CreateFailureCode::Deadline,
            detail("create deadline before submission"),
        ),
        SbxRunFailure::NonZero { .. } if failure.hints().authentication => {
            CreateFailure::not_created(
                CreateFailureCode::Auth,
                detail("sbx preflight was not authenticated"),
            )
        }
        SbxRunFailure::NonZero { .. } => {
            CreateFailure::not_created(CreateFailureCode::Transport, detail("sbx preflight failed"))
        }
    }
}

fn create_submission_failure(target: CleanupTarget, failure: &SbxRunFailure) -> CreateFailure {
    match failure {
        SbxRunFailure::Spawn => CreateFailure::not_created(
            CreateFailureCode::Transport,
            detail("sbx create could not be spawned"),
        ),
        SbxRunFailure::Cancelled | SbxRunFailure::Deadline => {
            create_possibly_created_budget(target, budget_failure(failure))
        }
        SbxRunFailure::NonZero { .. } if failure.hints().authentication => {
            CreateFailure::possibly_created(
                target,
                CreateFailureCode::Auth,
                detail("sbx create was not authenticated"),
            )
        }
        SbxRunFailure::NonZero { .. } => CreateFailure::possibly_created(
            target,
            CreateFailureCode::Provider,
            detail("sbx create failed after possible submission"),
        ),
    }
}

const fn budget_failure(failure: &SbxRunFailure) -> BudgetFailure {
    match failure {
        SbxRunFailure::Cancelled => BudgetFailure::Cancelled,
        _ => BudgetFailure::Deadline,
    }
}

fn create_pre_submission_budget(failure: BudgetFailure) -> CreateFailure {
    match failure {
        BudgetFailure::Cancelled => CreateFailure::not_created(
            CreateFailureCode::Cancelled,
            OperatorDetail::redacted("create cancelled before submission"),
        ),
        BudgetFailure::Deadline => CreateFailure::not_created(
            CreateFailureCode::Deadline,
            OperatorDetail::redacted("create deadline before submission"),
        ),
    }
}

fn create_possibly_created_budget(target: CleanupTarget, failure: BudgetFailure) -> CreateFailure {
    let code = match failure {
        BudgetFailure::Cancelled => CreateFailureCode::Cancelled,
        BudgetFailure::Deadline => CreateFailureCode::Deadline,
    };
    CreateFailure::possibly_created(
        target,
        code,
        detail("create stopped after possible submission"),
    )
}

fn exec_run_failure(target: CleanupTarget, failure: ExecRunFailure) -> ExecFailure {
    match failure {
        ExecRunFailure::Spawn => ExecFailure::not_dispatched(
            target,
            ExecFailureCode::Transport,
            detail("sbx exec could not be spawned"),
        )
        .expect("transport failures are valid before dispatch"),
        ExecRunFailure::Cancelled(counts) => {
            exec_possible(target, ExecFailureCode::Cancelled, counts)
        }
        ExecRunFailure::Deadline(counts) => {
            exec_possible(target, ExecFailureCode::Deadline, counts)
        }
    }
}

const fn exec_budget_code(failure: BudgetFailure) -> ExecFailureCode {
    match failure {
        BudgetFailure::Cancelled => ExecFailureCode::Cancelled,
        BudgetFailure::Deadline => ExecFailureCode::Deadline,
    }
}

fn exec_possible(
    target: CleanupTarget,
    code: ExecFailureCode,
    counts: OutputByteCounts,
) -> ExecFailure {
    ExecFailure::possibly_dispatched(
        target,
        code,
        FailureTimeout::Unknown,
        counts,
        detail("execution failed after possible dispatch"),
    )
    .expect("ordinary execution failures are valid after possible dispatch")
}

fn readiness_budget(target: CleanupTarget, failure: BudgetFailure) -> ReadinessFailure {
    let code = match failure {
        BudgetFailure::Cancelled => ReadinessFailureCode::Cancelled,
        BudgetFailure::Deadline => ReadinessFailureCode::Deadline,
    };
    ReadinessFailure::new(target, code, detail("readiness operation stopped"))
}

fn readiness_run_failure(target: CleanupTarget, failure: &SbxRunFailure) -> ReadinessFailure {
    let code = match failure {
        SbxRunFailure::Cancelled => ReadinessFailureCode::Cancelled,
        SbxRunFailure::Deadline => ReadinessFailureCode::Deadline,
        SbxRunFailure::Spawn | SbxRunFailure::NonZero { .. } => ReadinessFailureCode::Transport,
    };
    ReadinessFailure::new(target, code, detail("readiness poll failed"))
}

fn cleanup_budget(target: CleanupTarget, failure: BudgetFailure) -> CleanupFailure {
    let code = match failure {
        BudgetFailure::Cancelled => CleanupFailureCode::Cancelled,
        BudgetFailure::Deadline => CleanupFailureCode::Deadline,
    };
    CleanupFailure::new(target, code, detail("cleanup operation stopped"))
}

fn cleanup_run_failure(target: CleanupTarget, failure: &SbxRunFailure) -> CleanupFailure {
    let code = match failure {
        SbxRunFailure::Spawn | SbxRunFailure::NonZero { .. } => CleanupFailureCode::Provider,
        SbxRunFailure::Cancelled => CleanupFailureCode::Cancelled,
        SbxRunFailure::Deadline => CleanupFailureCode::Deadline,
    };
    CleanupFailure::new(target, code, detail("sbx cleanup failed"))
}

fn detail(message: &'static str) -> OperatorDetail {
    OperatorDetail::redacted(message)
}

#[cfg(test)]
mod tests {
    use crate::{
        Argv, CommandTimeout, DispatchState, FailureTimeout, OutputLimits, RequestOwnedId,
    };

    use super::*;

    fn target() -> CleanupTarget {
        CleanupTarget::new(RequestOwnedId::parse("sbx-000000000000000").unwrap())
    }

    #[test]
    fn preflight_failures_are_never_created_and_auth_is_recognized() {
        let spawned = create_preflight_failure(&SbxRunFailure::Spawn);
        assert_eq!(spawned.state(), crate::CreationState::NotCreated);
        assert_eq!(spawned.code(), CreateFailureCode::Transport);

        let authenticated = create_preflight_failure(&SbxRunFailure::NonZero {
            exit_code: 1,
            stderr: b"ERROR: not authenticated to Docker".to_vec(),
        });
        assert_eq!(authenticated.state(), crate::CreationState::NotCreated);
        assert_eq!(authenticated.code(), CreateFailureCode::Auth);
    }

    #[test]
    fn submission_failures_are_ambiguous_and_own_cleanup() {
        for failure in [
            SbxRunFailure::NonZero {
                exit_code: 1,
                stderr: b"create failed".to_vec(),
            },
            SbxRunFailure::Cancelled,
            SbxRunFailure::Deadline,
        ] {
            let mapped = create_submission_failure(target(), &failure);
            assert_eq!(mapped.state(), crate::CreationState::PossiblyCreated);
            assert_eq!(mapped.cleanup_target(), Some(&target()));
        }
        let auth = create_submission_failure(
            target(),
            &SbxRunFailure::NonZero {
                exit_code: 1,
                stderr: b"sign in to Docker".to_vec(),
            },
        );
        assert_eq!(auth.code(), CreateFailureCode::Auth);
    }

    #[test]
    fn exec_failures_are_indeterminate_after_dispatch_and_before_dispatch() {
        let after = exec_run_failure(
            target(),
            ExecRunFailure::Deadline(OutputByteCounts::new(2, 0)),
        );
        assert_eq!(after.dispatch_state(), DispatchState::PossiblyDispatched);
        assert_eq!(after.timeout_state(), FailureTimeout::Unknown);
        assert_eq!(after.counts().stdout_bytes(), 2);

        let before = exec_run_failure(target(), ExecRunFailure::Spawn);
        assert_eq!(before.dispatch_state(), DispatchState::NotDispatched);
        assert_eq!(before.code(), ExecFailureCode::Transport);
    }

    #[test]
    fn readiness_and_cleanup_failures_keep_the_cleanup_target() {
        let readiness = readiness_run_failure(
            target(),
            &SbxRunFailure::NonZero {
                exit_code: 1,
                stderr: b"unavailable".to_vec(),
            },
        );
        assert_eq!(readiness.cleanup_target(), &target());
        assert_eq!(readiness.code(), ReadinessFailureCode::Transport);

        let cleanup = cleanup_run_failure(
            target(),
            &SbxRunFailure::NonZero {
                exit_code: 1,
                stderr: b"unavailable".to_vec(),
            },
        );
        assert_eq!(cleanup.cleanup_target(), &target());
        assert_eq!(cleanup.code(), CleanupFailureCode::Provider);
    }

    #[test]
    fn exec_argv_preserves_the_contract_argv_unchanged() {
        let request = ExecRequest::new(
            Argv::new(vec![
                "/bin/proof".to_owned(),
                String::new(),
                "a b".to_owned(),
            ])
            .unwrap(),
            CommandTimeout::new(30).unwrap(),
            OutputLimits::new(64, 64, 96, 64).unwrap(),
        );
        let args = build_exec_args(
            "sbx-000000000000000",
            None,
            "/sandbox",
            request.argv().as_slice(),
        );
        assert_eq!(
            &args[..4],
            ["exec", "--workdir", "/sandbox", "sbx-000000000000000"]
        );
        assert_eq!(&args[4..], request.argv().as_slice());
    }
}
