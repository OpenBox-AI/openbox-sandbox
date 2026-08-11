use crate::{
    CleanupFailure, CleanupFailureCode, CleanupTarget, CreateFailure, CreateFailureCode,
    CreateRequest, CreatedSandbox, DeleteOutcome, ExecCompleted, ExecFailure, ExecFailureCode,
    ExecRequest, FailureTimeout, OperationContext, OperatorDetail, OutputByteCounts,
    ReadinessFailure, ReadinessFailureCode, ReadySandbox,
};
use openshell_core::proto::{
    CreateSandboxRequest, DeleteSandboxRequest, ExecSandboxRequest, GetSandboxPolicyStatusRequest,
    GetSandboxRequest, PolicyStatus, SandboxPhase, SandboxPolicy, SandboxSpec, SandboxTemplate,
};
use openshell_core::{ObjectId as _, ObjectName as _};
use tonic::Code;

use crate::OpenShellRuntime;
use crate::openshell::budget::{BudgetFailure, OperationBudget};
use crate::openshell::exec::{CollectionFailure, OutputCollector, limits_within_process_ceiling};
use crate::openshell::policy::{
    deterministic_policy_hash, parse_and_validate_policy, validate_image,
};
use crate::openshell::provider::ProviderState;
use crate::openshell::transport::{CreateTransportError, ExecTransportError, OpenShellTransport};

#[allow(clippy::too_many_lines)]
pub async fn create(
    runtime: &OpenShellRuntime,
    request: CreateRequest,
    context: OperationContext,
) -> Result<CreatedSandbox, CreateFailure> {
    let request_id = request.request_id().clone();
    let cleanup_target = CleanupTarget::new(request_id.clone());
    let image = validate_image(request.template()).map_err(|()| {
        eprintln!(
            "ERROR: create validation failed: immutable image validation failed for template '{}'",
            request.template().as_str()
        );
        CreateFailure::not_created(
            CreateFailureCode::Validation,
            detail("immutable image validation failed"),
        )
    })?;
    let normalized_policy = parse_and_validate_policy(
        request.policy_document(),
        request.expected_policy(),
        runtime.allow_degraded_landlock(),
    )
    .map_err(|()| {
        eprintln!(
            "ERROR: create validation failed: policy validation failed for '{}' v{}",
            request.expected_policy().id(),
            request.expected_policy().version()
        );
        CreateFailure::not_created(
            CreateFailureCode::Validation,
            detail("policy validation failed"),
        )
    })?;
    let budget = OperationBudget::new(context);
    budget.check().map_err(|failure| {
        let f = create_pre_submission_budget(failure);
        eprintln!(
            "ERROR: create failed: code={:?} detail={}",
            f.code(),
            f.detail()
        );
        f
    })?;

    let transport = runtime.transport();
    let preflight = budget
        .run(transport.get_sandbox(build_get_request(request_id.as_str())))
        .await
        .map_err(|failure| {
            let f = create_pre_submission_budget(failure);
            eprintln!(
                "ERROR: create failed: code={:?} detail={}",
                f.code(),
                f.detail()
            );
            f
        })?;
    match preflight {
        Err(status) if status.code() == Code::NotFound => {}
        Err(status) => {
            let failure = CreateFailure::not_created(
                create_status_code(&status),
                detail("request-name preflight failed"),
            );
            eprintln!(
                "ERROR: create failed: code={:?} detail={}",
                failure.code(),
                failure.detail()
            );
            return Err(failure);
        }
        Ok(_) => {
            let failure = CreateFailure::conflict(
                CreateFailureCode::Provider,
                detail("request-owned name already exists"),
            );
            eprintln!(
                "ERROR: create failed: code={:?} detail={}",
                failure.code(),
                failure.detail()
            );
            return Err(failure);
        }
    }
    budget.check().map_err(create_pre_submission_budget)?;

    let grpc_request = build_create_request(request_id.as_str(), image, normalized_policy.clone());
    let expected_spec = grpc_request
        .spec
        .clone()
        .expect("the validated create request always contains a spec");
    let response = budget
        .run(transport.create_sandbox(grpc_request))
        .await
        .map_err(|failure| {
            let f = create_possibly_created_budget(cleanup_target.clone(), failure);
            eprintln!(
                "ERROR: create failed: code={:?} detail={}",
                f.code(),
                f.detail()
            );
            f
        })?;
    let response = match response {
        Ok(response) => response,
        Err(CreateTransportError::Conflict) => {
            let failure = CreateFailure::conflict(
                CreateFailureCode::Provider,
                detail("gateway reported an ownership conflict"),
            );
            eprintln!(
                "ERROR: create failed: code={:?} detail={}",
                failure.code(),
                failure.detail()
            );
            return Err(failure);
        }
        Err(CreateTransportError::NotSubmitted(status)) => {
            let failure = CreateFailure::not_created(
                create_status_code(&status),
                detail("create transport failed before submission"),
            );
            eprintln!(
                "ERROR: create failed: code={:?} detail={}",
                failure.code(),
                failure.detail()
            );
            return Err(failure);
        }
        Err(CreateTransportError::PossiblySubmitted(status)) => {
            let failure = CreateFailure::possibly_created(
                cleanup_target,
                create_status_code(&status),
                detail("create failed after possible submission"),
            );
            eprintln!(
                "ERROR: create failed: code={:?} detail={}",
                failure.code(),
                failure.detail()
            );
            return Err(failure);
        }
    };
    let created = response.sandbox.ok_or_else(|| {
        let failure = CreateFailure::possibly_created(
            cleanup_target.clone(),
            CreateFailureCode::Protocol,
            detail("create response omitted sandbox"),
        );
        eprintln!(
            "ERROR: create failed: code={:?} detail={}",
            failure.code(),
            failure.detail()
        );
        failure
    })?;
    if created.object_name() != request_id.as_str() || created.object_id().is_empty() {
        let failure = CreateFailure::possibly_created(
            cleanup_target,
            CreateFailureCode::Protocol,
            detail("create response identity mismatch"),
        );
        eprintln!(
            "ERROR: create failed: code={:?} detail={}",
            failure.code(),
            failure.detail()
        );
        return Err(failure);
    }
    let returned_spec = created.spec.as_ref().ok_or_else(|| {
        let failure = CreateFailure::possibly_created(
            cleanup_target.clone(),
            CreateFailureCode::Protocol,
            detail("create response omitted spec"),
        );
        eprintln!(
            "ERROR: create failed: code={:?} detail={}",
            failure.code(),
            failure.detail()
        );
        failure
    })?;
    if returned_spec != &expected_spec {
        let failure = CreateFailure::possibly_created(
            cleanup_target,
            CreateFailureCode::Protocol,
            detail("create response spec differed from request"),
        );
        eprintln!(
            "ERROR: create failed: code={:?} detail={}",
            failure.code(),
            failure.detail()
        );
        return Err(failure);
    }
    let provider_handle = ProviderState {
        sandbox_id: created.object_id().to_owned(),
        normalized_policy,
    }
    .encode()
    .map_err(|_| {
        let failure = CreateFailure::possibly_created(
            CleanupTarget::new(request_id.clone()),
            CreateFailureCode::Protocol,
            detail("provider state could not be retained"),
        );
        eprintln!(
            "ERROR: create failed: code={:?} detail={}",
            failure.code(),
            failure.detail()
        );
        failure
    })?;
    Ok(CreatedSandbox::from_runtime(
        request_id,
        provider_handle,
        request.expected_policy().clone(),
    ))
}

#[allow(clippy::too_many_lines)]
pub async fn wait_ready(
    runtime: &OpenShellRuntime,
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
    let provider = ProviderState::decode(created.provider_handle()).map_err(|()| {
        ReadinessFailure::new(
            cleanup_target.clone(),
            ReadinessFailureCode::Protocol,
            detail("provider state was malformed"),
        )
    })?;
    let budget = OperationBudget::new(context);
    let transport = runtime.transport();

    loop {
        let response = budget
            .run(transport.get_sandbox(build_get_request(created.request_id().as_str())))
            .await
            .map_err(|failure| readiness_budget(cleanup_target.clone(), failure))?
            .map_err(|status| readiness_status(cleanup_target.clone(), &status))?;
        let sandbox = response.sandbox.ok_or_else(|| {
            ReadinessFailure::new(
                cleanup_target.clone(),
                ReadinessFailureCode::Protocol,
                detail("readiness response omitted sandbox"),
            )
        })?;
        if sandbox.object_name() != created.request_id().as_str()
            || sandbox.object_id() != provider.sandbox_id
        {
            return Err(ReadinessFailure::new(
                cleanup_target,
                ReadinessFailureCode::Protocol,
                detail("readiness response identity mismatch"),
            ));
        }
        let Some(status) = sandbox.status.as_ref() else {
            pause(runtime, &budget, cleanup_target.clone()).await?;
            continue;
        };
        let phase = SandboxPhase::try_from(status.phase).map_err(|_| {
            ReadinessFailure::new(
                cleanup_target.clone(),
                ReadinessFailureCode::Protocol,
                detail("readiness response used unknown phase"),
            )
        })?;
        match phase {
            SandboxPhase::Error => {
                return Err(ReadinessFailure::new(
                    cleanup_target,
                    ReadinessFailureCode::WorkloadError,
                    detail("sandbox entered workload error"),
                ));
            }
            SandboxPhase::Ready => {
                if status.current_policy_version == 0 {
                    pause(runtime, &budget, cleanup_target.clone()).await?;
                    continue;
                }
                if u64::from(status.current_policy_version) != expected_policy.version()
                    || status.current_policy_version != provider.normalized_policy.version
                {
                    return Err(ReadinessFailure::new(
                        cleanup_target,
                        ReadinessFailureCode::PolicyMismatch,
                        detail("active policy version mismatch"),
                    ));
                }
                if policy_is_loaded(
                    runtime,
                    &budget,
                    transport,
                    created.request_id().as_str(),
                    &provider,
                    status.current_policy_version,
                    cleanup_target.clone(),
                )
                .await?
                {
                    return ReadySandbox::attest(
                        created,
                        expected_policy.clone(),
                        &expected_policy,
                    )
                    .map_err(|_| {
                        ReadinessFailure::new(
                            cleanup_target,
                            ReadinessFailureCode::PolicyMismatch,
                            detail("policy attestation transition failed"),
                        )
                    });
                }
            }
            SandboxPhase::Unspecified
            | SandboxPhase::Provisioning
            | SandboxPhase::Deleting
            | SandboxPhase::Unknown => {}
        }
        pause(runtime, &budget, cleanup_target.clone()).await?;
    }
}

async fn policy_is_loaded(
    runtime: &OpenShellRuntime,
    budget: &OperationBudget,
    transport: &dyn OpenShellTransport,
    name: &str,
    provider: &ProviderState,
    version: u32,
    cleanup_target: CleanupTarget,
) -> Result<bool, ReadinessFailure> {
    let response = budget
        .run(transport.get_sandbox_policy_status(build_policy_status_request(name, version)))
        .await
        .map_err(|failure| readiness_budget(cleanup_target.clone(), failure))?;
    let response = match response {
        Ok(response) => response,
        Err(status) if status.code() == Code::NotFound => {
            pause(runtime, budget, cleanup_target).await?;
            return Ok(false);
        }
        Err(status) => return Err(readiness_status(cleanup_target, &status)),
    };
    let revision = response.revision.ok_or_else(|| {
        ReadinessFailure::new(
            cleanup_target.clone(),
            ReadinessFailureCode::Protocol,
            detail("policy status omitted revision"),
        )
    })?;
    if revision.version != version || response.active_version != version {
        return Err(ReadinessFailure::new(
            cleanup_target,
            ReadinessFailureCode::PolicyMismatch,
            detail("policy status version mismatch"),
        ));
    }
    let status = PolicyStatus::try_from(revision.status).map_err(|_| {
        ReadinessFailure::new(
            cleanup_target.clone(),
            ReadinessFailureCode::Protocol,
            detail("policy status used unknown state"),
        )
    })?;
    match status {
        PolicyStatus::Pending => Ok(false),
        PolicyStatus::Loaded => {
            if revision.loaded_at_ms <= 0
                || revision.policy.as_ref() != Some(&provider.normalized_policy)
                || revision.policy_hash != deterministic_policy_hash(&provider.normalized_policy)
            {
                return Err(ReadinessFailure::new(
                    cleanup_target,
                    ReadinessFailureCode::PolicyMismatch,
                    detail("loaded policy content mismatch"),
                ));
            }
            Ok(true)
        }
        PolicyStatus::Unspecified | PolicyStatus::Failed | PolicyStatus::Superseded => {
            Err(ReadinessFailure::new(
                cleanup_target,
                ReadinessFailureCode::PolicyMismatch,
                detail("expected policy was not loaded"),
            ))
        }
    }
}

pub async fn exec(
    runtime: &OpenShellRuntime,
    ready: ReadySandbox,
    request: ExecRequest,
    context: OperationContext,
) -> Result<ExecCompleted, ExecFailure> {
    let cleanup_target = ready.cleanup_target();
    let provider = ProviderState::decode(ready.provider_handle()).map_err(|()| {
        ExecFailure::not_dispatched(
            cleanup_target.clone(),
            ExecFailureCode::Protocol,
            detail("provider state was malformed"),
        )
        .expect("protocol is valid before dispatch")
    })?;
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

    let grpc_request = build_exec_request(provider.sandbox_id, &request);
    let transport = runtime.transport();
    let response = budget
        .run(transport.exec_sandbox(grpc_request))
        .await
        .map_err(|failure| {
            exec_possible(
                cleanup_target.clone(),
                exec_budget_code(failure),
                OutputByteCounts::default(),
            )
        })?;
    let mut stream = match response {
        Ok(stream) => stream,
        Err(ExecTransportError::NotSubmitted(status)) => {
            return Err(ExecFailure::not_dispatched(
                cleanup_target,
                exec_status_code(&status),
                detail("execution transport failed before submission"),
            )
            .expect("transport failures are valid before dispatch"));
        }
        Err(ExecTransportError::PossiblySubmitted(status)) => {
            return Err(exec_possible(
                cleanup_target,
                exec_status_code(&status),
                OutputByteCounts::default(),
            ));
        }
    };
    let mut collector = OutputCollector::new(request.output_limits());
    loop {
        let event = budget
            .run(stream.message())
            .await
            .map_err(|failure| {
                exec_possible(
                    cleanup_target.clone(),
                    exec_budget_code(failure),
                    collector.counts(),
                )
            })?
            .map_err(|status| {
                exec_possible(
                    cleanup_target.clone(),
                    exec_status_code(&status),
                    collector.counts(),
                )
            })?;
        let Some(event) = event else {
            break;
        };
        collector
            .push(event)
            .map_err(|failure| collection_failure(cleanup_target.clone(), failure))?;
    }
    let collected = collector
        .finish()
        .map_err(|failure| collection_failure(cleanup_target, failure))?;
    Ok(ExecCompleted::new(
        collected.exit_code,
        collected.stdout,
        collected.stderr,
        collected.timeout,
    ))
}

pub async fn delete(
    runtime: &OpenShellRuntime,
    target: CleanupTarget,
    context: OperationContext,
) -> Result<DeleteOutcome, CleanupFailure> {
    let budget = OperationBudget::new(context);
    budget
        .check()
        .map_err(|failure| cleanup_budget(target.clone(), failure))?;
    let transport = runtime.transport();
    let response = budget
        .run(transport.delete_sandbox(build_delete_request(target.request_id().as_str())))
        .await
        .map_err(|failure| cleanup_budget(target.clone(), failure))?;
    match response {
        Err(status) if status.code() == Code::NotFound => Ok(DeleteOutcome::AlreadyAbsent),
        Err(status) => Err(cleanup_status(target, &status)),
        Ok(response) => {
            if response.deleted {
                Ok(DeleteOutcome::Deleted)
            } else {
                Err(CleanupFailure::new(
                    target,
                    CleanupFailureCode::Protocol,
                    detail("delete response did not acknowledge deletion"),
                ))
            }
        }
    }
}

pub async fn wait_deleted(
    runtime: &OpenShellRuntime,
    target: CleanupTarget,
    context: OperationContext,
) -> Result<(), CleanupFailure> {
    let budget = OperationBudget::new(context);
    let transport = runtime.transport();
    loop {
        let response = budget
            .run(transport.get_sandbox(build_get_request(target.request_id().as_str())))
            .await
            .map_err(|failure| cleanup_budget(target.clone(), failure))?;
        match response {
            Err(status) if status.code() == Code::NotFound => return Ok(()),
            Err(status) => return Err(cleanup_status(target, &status)),
            Ok(_) => {
                budget
                    .pause(runtime.poll_interval())
                    .await
                    .map_err(|failure| cleanup_budget(target.clone(), failure))?;
            }
        }
    }
}

fn build_create_request(name: &str, image: String, policy: SandboxPolicy) -> CreateSandboxRequest {
    CreateSandboxRequest {
        spec: Some(SandboxSpec {
            template: Some(SandboxTemplate {
                image,
                ..SandboxTemplate::default()
            }),
            policy: Some(policy),
            ..SandboxSpec::default()
        }),
        name: name.to_owned(),
        ..CreateSandboxRequest::default()
    }
}

fn build_get_request(name: &str) -> GetSandboxRequest {
    GetSandboxRequest {
        name: name.to_owned(),
        workspace: String::new(),
    }
}

fn build_policy_status_request(name: &str, version: u32) -> GetSandboxPolicyStatusRequest {
    GetSandboxPolicyStatusRequest {
        name: name.to_owned(),
        version,
        global: false,
        workspace: String::new(),
    }
}

fn build_delete_request(name: &str) -> DeleteSandboxRequest {
    DeleteSandboxRequest {
        name: name.to_owned(),
        workspace: String::new(),
    }
}

fn build_exec_request(sandbox_id: String, request: &ExecRequest) -> ExecSandboxRequest {
    ExecSandboxRequest {
        sandbox_id,
        command: request.argv().as_slice().to_vec(),
        workdir: request.workdir().to_owned(),
        timeout_seconds: u32::from(request.timeout().seconds()),
        ..ExecSandboxRequest::default()
    }
}

async fn pause(
    runtime: &OpenShellRuntime,
    budget: &OperationBudget,
    target: CleanupTarget,
) -> Result<(), ReadinessFailure> {
    budget
        .pause(runtime.poll_interval())
        .await
        .map_err(|failure| readiness_budget(target, failure))
}

fn collection_failure(target: CleanupTarget, failure: CollectionFailure) -> ExecFailure {
    match failure {
        CollectionFailure::MissingTerminalExit(counts) => ExecFailure::missing_terminal_exit(
            target,
            FailureTimeout::Unknown,
            counts,
            detail("execution stream omitted terminal exit"),
        )
        .expect("missing terminal exit is valid after dispatch"),
        CollectionFailure::Overflow { counts, kind } => ExecFailure::output_limit_exceeded(
            target,
            FailureTimeout::Unknown,
            counts,
            kind,
            detail("execution output limit exceeded"),
        )
        .expect("output overflow is valid after dispatch"),
        CollectionFailure::Protocol(counts) => {
            exec_possible(target, ExecFailureCode::Protocol, counts)
        }
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

const fn exec_budget_code(failure: BudgetFailure) -> ExecFailureCode {
    match failure {
        BudgetFailure::Cancelled => ExecFailureCode::Cancelled,
        BudgetFailure::Deadline => ExecFailureCode::Deadline,
    }
}

fn exec_status_code(status: &tonic::Status) -> ExecFailureCode {
    match status.code() {
        Code::Cancelled => ExecFailureCode::Cancelled,
        Code::DeadlineExceeded => ExecFailureCode::Deadline,
        Code::InvalidArgument
        | Code::FailedPrecondition
        | Code::OutOfRange
        | Code::Unimplemented
        | Code::DataLoss => ExecFailureCode::Protocol,
        _ => ExecFailureCode::Transport,
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

fn create_status_code(status: &tonic::Status) -> CreateFailureCode {
    match status.code() {
        Code::Unauthenticated | Code::PermissionDenied => CreateFailureCode::Auth,
        Code::Cancelled => CreateFailureCode::Cancelled,
        Code::DeadlineExceeded => CreateFailureCode::Deadline,
        Code::InvalidArgument
        | Code::FailedPrecondition
        | Code::OutOfRange
        | Code::Unimplemented
        | Code::DataLoss => CreateFailureCode::Protocol,
        _ => CreateFailureCode::Transport,
    }
}

fn readiness_budget(target: CleanupTarget, failure: BudgetFailure) -> ReadinessFailure {
    let code = match failure {
        BudgetFailure::Cancelled => ReadinessFailureCode::Cancelled,
        BudgetFailure::Deadline => ReadinessFailureCode::Deadline,
    };
    ReadinessFailure::new(target, code, detail("readiness operation stopped"))
}

fn readiness_status(target: CleanupTarget, status: &tonic::Status) -> ReadinessFailure {
    let code = match status.code() {
        Code::Cancelled => ReadinessFailureCode::Cancelled,
        Code::DeadlineExceeded => ReadinessFailureCode::Deadline,
        Code::InvalidArgument
        | Code::FailedPrecondition
        | Code::OutOfRange
        | Code::Unimplemented
        | Code::DataLoss => ReadinessFailureCode::Protocol,
        _ => ReadinessFailureCode::Transport,
    };
    ReadinessFailure::new(target, code, detail("readiness RPC failed"))
}

fn cleanup_budget(target: CleanupTarget, failure: BudgetFailure) -> CleanupFailure {
    let code = match failure {
        BudgetFailure::Cancelled => CleanupFailureCode::Cancelled,
        BudgetFailure::Deadline => CleanupFailureCode::Deadline,
    };
    CleanupFailure::new(target, code, detail("cleanup operation stopped"))
}

fn cleanup_status(target: CleanupTarget, status: &tonic::Status) -> CleanupFailure {
    let code = match status.code() {
        Code::Cancelled => CleanupFailureCode::Cancelled,
        Code::DeadlineExceeded => CleanupFailureCode::Deadline,
        Code::InvalidArgument
        | Code::FailedPrecondition
        | Code::OutOfRange
        | Code::Unimplemented
        | Code::DataLoss => CleanupFailureCode::Protocol,
        _ => CleanupFailureCode::Transport,
    };
    CleanupFailure::new(target, code, detail("cleanup RPC failed"))
}

fn detail(message: &'static str) -> OperatorDetail {
    OperatorDetail::redacted(message)
}

#[cfg(test)]
mod tests {
    use crate::{
        Argv, CommandTimeout, CreationState, DispatchState, FailureTimeout, OutputLimits,
        RequestOwnedId,
    };

    use super::*;

    fn target() -> CleanupTarget {
        CleanupTarget::new(RequestOwnedId::parse("sbx-000000000000000").unwrap())
    }

    #[test]
    fn raw_create_request_contains_only_name_image_and_policy() {
        let request = build_create_request(
            "sbx-000000000000000",
            format!("example.invalid/proof@sha256:{}", "a".repeat(64)),
            SandboxPolicy {
                version: 1,
                ..SandboxPolicy::default()
            },
        );
        assert!(request.labels.is_empty());
        assert!(request.annotations.is_empty());
        assert!(request.workspace.is_empty());
        let spec = request.spec.unwrap();
        assert!(spec.log_level.is_empty());
        assert!(spec.environment.is_empty());
        assert!(spec.providers.is_empty());
        assert!(spec.resource_requirements.is_none());
        assert_eq!(spec.policy.unwrap().version, 1);
        let template = spec.template.unwrap();
        assert!(template.image.contains("@sha256:"));
        assert!(template.runtime_class_name.is_empty());
        assert!(template.agent_socket.is_empty());
        assert!(template.labels.is_empty());
        assert!(template.annotations.is_empty());
        assert!(template.environment.is_empty());
        assert!(template.resources.is_none());
        assert!(template.user_namespaces.is_none());
        assert!(template.driver_config.is_none());
    }

    #[test]
    fn workspace_capable_requests_always_select_the_default_workspace() {
        let name = "sbx-000000000000000";
        let get = build_get_request(name);
        let policy = build_policy_status_request(name, 1);
        let delete = build_delete_request(name);

        assert_eq!(get.name, name);
        assert!(get.workspace.is_empty());
        assert_eq!(policy.name, name);
        assert_eq!(policy.version, 1);
        assert!(!policy.global);
        assert!(policy.workspace.is_empty());
        assert_eq!(delete.name, name);
        assert!(delete.workspace.is_empty());
    }

    #[test]
    fn raw_exec_request_preserves_argv_and_forbids_optional_capabilities() {
        let request = ExecRequest::new(
            Argv::new(vec![
                "/bin/proof".to_owned(),
                String::new(),
                "a b".to_owned(),
                "$HOME".to_owned(),
                "semi;colon".to_owned(),
                "/bin/proof".to_owned(),
            ])
            .unwrap(),
            CommandTimeout::new(30).unwrap(),
            OutputLimits::new(64, 64, 96, 64).unwrap(),
        );
        let grpc = build_exec_request("provider-id".to_owned(), &request);
        assert_eq!(grpc.sandbox_id, "provider-id");
        assert_eq!(grpc.command, request.argv().as_slice());
        assert_eq!(grpc.workdir, "/sandbox");
        assert_eq!(grpc.timeout_seconds, 30);
        assert!(grpc.environment.is_empty());
        assert!(grpc.stdin.is_empty());
        assert!(!grpc.tty);
        assert_eq!(grpc.cols, 0);
        assert_eq!(grpc.rows, 0);
    }

    #[test]
    fn create_budget_mapping_changes_ownership_only_after_possible_submission() {
        for failure in [BudgetFailure::Cancelled, BudgetFailure::Deadline] {
            let before = create_pre_submission_budget(failure);
            assert_eq!(before.state(), CreationState::NotCreated);
            assert!(before.cleanup_target().is_none());

            let after = create_possibly_created_budget(target(), failure);
            assert_eq!(after.state(), CreationState::PossiblyCreated);
            assert_eq!(after.cleanup_target(), Some(&target()));
        }
    }

    #[test]
    fn tonic_statuses_map_to_stable_redacted_categories() {
        assert_eq!(
            create_status_code(&tonic::Status::unauthenticated("sensitive")),
            CreateFailureCode::Auth
        );
        assert_eq!(
            create_status_code(&tonic::Status::invalid_argument("sensitive")),
            CreateFailureCode::Protocol
        );
        assert_eq!(
            create_status_code(&tonic::Status::unavailable("sensitive")),
            CreateFailureCode::Transport
        );
        assert_eq!(
            exec_status_code(&tonic::Status::deadline_exceeded("sensitive")),
            ExecFailureCode::Deadline
        );
        let readiness = readiness_status(target(), &tonic::Status::permission_denied("sensitive"));
        assert_eq!(readiness.code(), ReadinessFailureCode::Transport);
        assert!(!format!("{readiness:?}").contains("sensitive"));
    }

    #[test]
    fn every_post_dispatch_failure_is_indeterminate() {
        let failure = exec_possible(
            target(),
            ExecFailureCode::Transport,
            OutputByteCounts::new(3, 4),
        );
        assert_eq!(failure.dispatch_state(), DispatchState::PossiblyDispatched);
        assert_eq!(failure.timeout_state(), FailureTimeout::Unknown);
        assert_eq!(failure.counts().combined_bytes(), Some(7));
    }
}
