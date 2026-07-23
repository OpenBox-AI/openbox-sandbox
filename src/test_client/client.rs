use std::time::Instant;

use crate::{
    BoundaryFailure, BoundaryFailureCode, CapabilityToken, DeadlineMillis, ServiceRequest,
    ServiceResponse,
};
use crate::{
    CleanupFailure, CleanupFailureCode, CleanupTarget, CreateFailure, CreateFailureCode,
    CreateRequest, CreatedSandbox, DeleteOutcome, DispatchState, ExecCompleted, ExecFailure,
    ExecFailureCode, ExecRequest, FailureTimeout, OpaqueProviderHandle, OperationContext,
    OperationDeadline, OperatorDetail, OutputByteCounts, PolicyIdentity, ReadinessFailure,
    ReadinessFailureCode, ReadySandbox, SandboxRuntime,
};
use async_trait::async_trait;

use crate::test_client::{
    CallFailure, CallFailureKind, ClientConfigError, SandboxRuntimeClientConfig, ServiceTransport,
    SubmissionState,
};

#[derive(Clone)]
pub struct SandboxRuntimeClient {
    transport: ServiceTransport,
}

impl SandboxRuntimeClient {
    pub fn connect(config: SandboxRuntimeClientConfig) -> Result<Self, ClientConfigError> {
        Ok(Self {
            transport: ServiceTransport::new(config)?,
        })
    }

    pub const fn transport(&self) -> &ServiceTransport {
        &self.transport
    }
}

#[async_trait]
impl SandboxRuntime for SandboxRuntimeClient {
    async fn create(
        &self,
        request: CreateRequest,
        context: OperationContext,
    ) -> Result<CreatedSandbox, CreateFailure> {
        let request_id = request.request_id().clone();
        let expected_policy = request.expected_policy().clone();
        if request.template() != self.transport.bundle().template()
            || &expected_policy != self.transport.bundle().policy()
        {
            return Err(CreateFailure::not_created(
                CreateFailureCode::Validation,
                detail("asset bundle mismatch before service submission"),
            ));
        }
        let deadline = deadline_millis(&context).map_err(|()| {
            CreateFailure::not_created(
                CreateFailureCode::Validation,
                detail("service deadline is out of range"),
            )
        })?;
        let response = self
            .transport
            .call(
                ServiceRequest::Create {
                    request,
                    deadline_ms: deadline,
                },
                &context,
            )
            .await
            .map_err(|failure| create_call_failure(request_id.clone(), failure))?
            .into_response();
        match response {
            ServiceResponse::Created {
                request_id: returned_id,
                lifecycle_token,
            } if returned_id == request_id => Ok(CreatedSandbox::from_runtime(
                request_id,
                token_handle(lifecycle_token),
                expected_policy,
            )),
            ServiceResponse::CreateFailed { failure } => Err(failure),
            ServiceResponse::BoundaryFailed { failure } => Err(create_boundary_failure(&failure)),
            _ => Err(CreateFailure::possibly_created(
                CleanupTarget::new(request_id),
                CreateFailureCode::Protocol,
                detail("service create response violated the protocol"),
            )),
        }
    }

    async fn wait_ready(
        &self,
        sandbox: CreatedSandbox,
        expected_policy: PolicyIdentity,
        context: OperationContext,
    ) -> Result<ReadySandbox, ReadinessFailure> {
        let request_id = sandbox.request_id().clone();
        let cleanup_target = sandbox.cleanup_target();
        if sandbox.expected_policy() != &expected_policy
            || &expected_policy != self.transport.bundle().policy()
        {
            return Err(ReadinessFailure::new(
                cleanup_target,
                ReadinessFailureCode::PolicyMismatch,
                detail("service readiness policy mismatch"),
            ));
        }
        let lifecycle_token = parse_token(sandbox.provider_handle()).map_err(|()| {
            ReadinessFailure::new(
                cleanup_target.clone(),
                ReadinessFailureCode::Protocol,
                detail("service lifecycle capability was malformed"),
            )
        })?;
        let deadline = deadline_millis(&context).map_err(|()| {
            ReadinessFailure::new(
                cleanup_target.clone(),
                ReadinessFailureCode::Protocol,
                detail("service deadline is out of range"),
            )
        })?;
        let response = self
            .transport
            .call(
                ServiceRequest::WaitReady {
                    request_id: request_id.clone(),
                    lifecycle_token,
                    expected_policy: expected_policy.clone(),
                    deadline_ms: deadline,
                },
                &context,
            )
            .await
            .map_err(|failure| readiness_call_failure(cleanup_target.clone(), failure))?
            .into_response();
        match response {
            ServiceResponse::Ready {
                request_id: returned_id,
                lifecycle_token,
                active_policy,
            } if returned_id == request_id && active_policy == expected_policy => {
                let created = CreatedSandbox::from_runtime(
                    request_id,
                    token_handle(lifecycle_token),
                    expected_policy.clone(),
                );
                ReadySandbox::attest(created, expected_policy.clone(), &active_policy).map_err(
                    |_| {
                        ReadinessFailure::new(
                            cleanup_target,
                            ReadinessFailureCode::PolicyMismatch,
                            detail("service readiness attestation transition failed"),
                        )
                    },
                )
            }
            ServiceResponse::ReadinessFailed { failure } => Err(failure),
            ServiceResponse::BoundaryFailed { failure } => {
                Err(readiness_boundary_failure(cleanup_target, &failure))
            }
            _ => Err(ReadinessFailure::new(
                cleanup_target,
                ReadinessFailureCode::Protocol,
                detail("service readiness response violated the protocol"),
            )),
        }
    }

    async fn exec(
        &self,
        sandbox: ReadySandbox,
        request: ExecRequest,
        context: OperationContext,
    ) -> Result<ExecCompleted, ExecFailure> {
        let started = Instant::now();
        let request_id = sandbox.request_id().clone();
        let cleanup_target = sandbox.cleanup_target();
        let lifecycle_token = parse_token(sandbox.provider_handle()).map_err(|()| {
            predispatch_exec_failure(
                cleanup_target.clone(),
                ExecFailureCode::Protocol,
                "service lifecycle capability was malformed",
            )
        })?;
        let prepare_context = remaining_context(&context, started).map_err(|()| {
            predispatch_exec_failure(
                cleanup_target.clone(),
                ExecFailureCode::Deadline,
                "service execution deadline elapsed before prepare",
            )
        })?;
        let prepare_deadline = deadline_millis(&prepare_context).map_err(|()| {
            predispatch_exec_failure(
                cleanup_target.clone(),
                ExecFailureCode::Protocol,
                "service deadline is out of range",
            )
        })?;
        let prepared = self
            .transport
            .call(
                ServiceRequest::PrepareExec {
                    request_id: request_id.clone(),
                    lifecycle_token,
                    request,
                    deadline_ms: prepare_deadline,
                },
                &prepare_context,
            )
            .await
            .map_err(|failure| predispatch_call_failure(cleanup_target.clone(), failure))?
            .into_response();
        let prepare_token = match prepared {
            ServiceResponse::ExecPrepared { prepare_token } => prepare_token,
            ServiceResponse::ExecFailed { failure } => return Err(failure),
            ServiceResponse::BoundaryFailed { failure } => {
                return Err(exec_boundary_failure(
                    cleanup_target,
                    &failure,
                    DispatchState::NotDispatched,
                ));
            }
            _ => {
                return Err(predispatch_exec_failure(
                    cleanup_target,
                    ExecFailureCode::Protocol,
                    "service prepare response violated the protocol",
                ));
            }
        };
        let commit_context = remaining_context(&context, started).map_err(|()| {
            predispatch_exec_failure(
                cleanup_target.clone(),
                ExecFailureCode::Deadline,
                "service execution deadline elapsed before commit",
            )
        })?;
        let commit_deadline = deadline_millis(&commit_context).map_err(|()| {
            predispatch_exec_failure(
                cleanup_target.clone(),
                ExecFailureCode::Protocol,
                "service deadline is out of range",
            )
        })?;
        let committed = self
            .transport
            .call(
                ServiceRequest::CommitExec {
                    request_id,
                    prepare_token,
                    deadline_ms: commit_deadline,
                },
                &commit_context,
            )
            .await
            .map_err(|failure| commit_call_failure(cleanup_target.clone(), failure))?
            .into_response();
        match committed {
            ServiceResponse::Executed { result } => Ok(result),
            ServiceResponse::ExecFailed { failure } => Err(failure),
            ServiceResponse::BoundaryFailed { failure } => Err(exec_boundary_failure(
                cleanup_target,
                &failure,
                DispatchState::PossiblyDispatched,
            )),
            _ => Err(possible_exec_failure(
                cleanup_target,
                ExecFailureCode::Protocol,
                "service commit response violated the protocol",
            )),
        }
    }

    async fn delete(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<DeleteOutcome, CleanupFailure> {
        let deadline = deadline_millis(&context)
            .map_err(|()| cleanup_failure(target.clone(), CleanupFailureCode::Protocol))?;
        let response = self
            .transport
            .call(
                ServiceRequest::Delete {
                    target: target.clone(),
                    deadline_ms: deadline,
                },
                &context,
            )
            .await
            .map_err(|failure| cleanup_call_failure(target.clone(), failure))?
            .into_response();
        match response {
            ServiceResponse::Deleted { outcome } => Ok(outcome),
            ServiceResponse::CleanupFailed { failure } => Err(failure),
            ServiceResponse::BoundaryFailed { failure } => {
                Err(cleanup_boundary_failure(target, &failure))
            }
            _ => Err(cleanup_failure(target, CleanupFailureCode::Protocol)),
        }
    }

    async fn wait_deleted(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<(), CleanupFailure> {
        let deadline = deadline_millis(&context)
            .map_err(|()| cleanup_failure(target.clone(), CleanupFailureCode::Protocol))?;
        let response = self
            .transport
            .call(
                ServiceRequest::WaitDeleted {
                    target: target.clone(),
                    deadline_ms: deadline,
                },
                &context,
            )
            .await
            .map_err(|failure| cleanup_call_failure(target.clone(), failure))?
            .into_response();
        match response {
            ServiceResponse::TerminallyAbsent => Ok(()),
            ServiceResponse::CleanupFailed { failure } => Err(failure),
            ServiceResponse::BoundaryFailed { failure } => {
                Err(cleanup_boundary_failure(target, &failure))
            }
            _ => Err(cleanup_failure(target, CleanupFailureCode::Protocol)),
        }
    }
}

fn token_handle(token: CapabilityToken) -> OpaqueProviderHandle {
    OpaqueProviderHandle::new(token.as_str().as_bytes().to_vec())
        .expect("validated capability tokens are nonempty")
}

fn parse_token(handle: &OpaqueProviderHandle) -> Result<CapabilityToken, ()> {
    let value = core::str::from_utf8(handle.as_bytes()).map_err(|_| ())?;
    CapabilityToken::parse(value).map_err(|_| ())
}

fn deadline_millis(context: &OperationContext) -> Result<DeadlineMillis, ()> {
    let millis = context.deadline().duration().as_millis().max(1);
    let millis = u64::try_from(millis).map_err(|_| ())?;
    DeadlineMillis::new(millis).map_err(|_| ())
}

fn remaining_context(context: &OperationContext, started: Instant) -> Result<OperationContext, ()> {
    let remaining = context
        .deadline()
        .duration()
        .checked_sub(started.elapsed())
        .filter(|duration| !duration.is_zero())
        .ok_or(())?;
    Ok(OperationContext::new(
        context.cancellation().clone(),
        OperationDeadline::new(remaining).map_err(|_| ())?,
    ))
}

fn create_call_failure(request_id: crate::RequestOwnedId, failure: CallFailure) -> CreateFailure {
    let code = create_call_code(failure.kind());
    match failure.submission() {
        SubmissionState::NotSubmitted => {
            CreateFailure::not_created(code, detail("service create call was not submitted"))
        }
        SubmissionState::PossiblySubmitted => CreateFailure::possibly_created(
            CleanupTarget::new(request_id),
            code,
            detail("service create call may have been submitted"),
        ),
    }
}

fn create_boundary_failure(failure: &BoundaryFailure) -> CreateFailure {
    let code = create_boundary_code(failure.code());
    failure.cleanup_target().map_or_else(
        || CreateFailure::not_created(code, detail("service rejected create before ownership")),
        |target| {
            CreateFailure::possibly_created(
                target.clone(),
                code,
                detail("service retained ambiguous create ownership"),
            )
        },
    )
}

fn readiness_call_failure(target: CleanupTarget, failure: CallFailure) -> ReadinessFailure {
    ReadinessFailure::new(
        target,
        readiness_call_code(failure.kind()),
        detail("service readiness call failed"),
    )
}

fn readiness_boundary_failure(
    target: CleanupTarget,
    failure: &BoundaryFailure,
) -> ReadinessFailure {
    ReadinessFailure::new(
        target,
        readiness_boundary_code(failure.code()),
        detail("service rejected readiness"),
    )
}

fn predispatch_call_failure(target: CleanupTarget, failure: CallFailure) -> ExecFailure {
    predispatch_exec_failure(
        target,
        exec_call_code(failure.kind()),
        "service prepare call failed",
    )
}

fn commit_call_failure(target: CleanupTarget, failure: CallFailure) -> ExecFailure {
    match failure.submission() {
        SubmissionState::NotSubmitted => predispatch_exec_failure(
            target,
            exec_call_code(failure.kind()),
            "service commit was not submitted",
        ),
        SubmissionState::PossiblySubmitted => possible_exec_failure(
            target,
            exec_call_code(failure.kind()),
            "service commit response was lost",
        ),
    }
}

fn exec_boundary_failure(
    target: CleanupTarget,
    failure: &BoundaryFailure,
    conservative_default: DispatchState,
) -> ExecFailure {
    let dispatch = failure.dispatch_state().unwrap_or(conservative_default);
    match dispatch {
        DispatchState::NotDispatched => predispatch_exec_failure(
            target,
            exec_boundary_code(failure.code()),
            "service rejected execution before dispatch",
        ),
        DispatchState::PossiblyDispatched => possible_exec_failure(
            target,
            exec_boundary_code(failure.code()),
            "service execution may have dispatched",
        ),
    }
}

fn predispatch_exec_failure(
    target: CleanupTarget,
    code: ExecFailureCode,
    message: &'static str,
) -> ExecFailure {
    ExecFailure::not_dispatched(target, code, detail(message))
        .expect("pre-dispatch failure invariant")
}

fn possible_exec_failure(
    target: CleanupTarget,
    code: ExecFailureCode,
    message: &'static str,
) -> ExecFailure {
    ExecFailure::possibly_dispatched(
        target,
        code,
        FailureTimeout::Unknown,
        OutputByteCounts::default(),
        detail(message),
    )
    .expect("post-commit failure invariant")
}

fn cleanup_call_failure(target: CleanupTarget, failure: CallFailure) -> CleanupFailure {
    cleanup_failure(target, cleanup_call_code(failure.kind()))
}

fn cleanup_boundary_failure(target: CleanupTarget, failure: &BoundaryFailure) -> CleanupFailure {
    cleanup_failure(target, cleanup_boundary_code(failure.code()))
}

fn cleanup_failure(target: CleanupTarget, code: CleanupFailureCode) -> CleanupFailure {
    CleanupFailure::new(target, code, detail("service cleanup call failed"))
}

const fn create_call_code(kind: CallFailureKind) -> CreateFailureCode {
    match kind {
        CallFailureKind::Authentication => CreateFailureCode::Auth,
        CallFailureKind::Deadline => CreateFailureCode::Deadline,
        CallFailureKind::Cancelled => CreateFailureCode::Cancelled,
        CallFailureKind::Protocol => CreateFailureCode::Protocol,
        CallFailureKind::Transport => CreateFailureCode::Transport,
    }
}

const fn readiness_call_code(kind: CallFailureKind) -> ReadinessFailureCode {
    match kind {
        CallFailureKind::Deadline => ReadinessFailureCode::Deadline,
        CallFailureKind::Cancelled => ReadinessFailureCode::Cancelled,
        CallFailureKind::Protocol => ReadinessFailureCode::Protocol,
        CallFailureKind::Authentication | CallFailureKind::Transport => {
            ReadinessFailureCode::Transport
        }
    }
}

const fn exec_call_code(kind: CallFailureKind) -> ExecFailureCode {
    match kind {
        CallFailureKind::Deadline => ExecFailureCode::Deadline,
        CallFailureKind::Cancelled => ExecFailureCode::Cancelled,
        CallFailureKind::Protocol => ExecFailureCode::Protocol,
        CallFailureKind::Authentication | CallFailureKind::Transport => ExecFailureCode::Transport,
    }
}

const fn cleanup_call_code(kind: CallFailureKind) -> CleanupFailureCode {
    match kind {
        CallFailureKind::Deadline => CleanupFailureCode::Deadline,
        CallFailureKind::Cancelled => CleanupFailureCode::Cancelled,
        CallFailureKind::Protocol => CleanupFailureCode::Protocol,
        CallFailureKind::Authentication | CallFailureKind::Transport => {
            CleanupFailureCode::Transport
        }
    }
}

const fn create_boundary_code(code: BoundaryFailureCode) -> CreateFailureCode {
    match code {
        BoundaryFailureCode::Authentication | BoundaryFailureCode::Authorization => {
            CreateFailureCode::Auth
        }
        BoundaryFailureCode::ProtocolVersion
        | BoundaryFailureCode::AssetBundleMismatch
        | BoundaryFailureCode::InvalidRequest
        | BoundaryFailureCode::RequestTooLarge
        | BoundaryFailureCode::ResponseTooLarge
        | BoundaryFailureCode::LifecycleConflict => CreateFailureCode::Protocol,
        BoundaryFailureCode::Draining | BoundaryFailureCode::ServiceUnavailable => {
            CreateFailureCode::Transport
        }
        BoundaryFailureCode::DurableState | BoundaryFailureCode::Internal => {
            CreateFailureCode::Provider
        }
    }
}

const fn readiness_boundary_code(code: BoundaryFailureCode) -> ReadinessFailureCode {
    match code {
        BoundaryFailureCode::AssetBundleMismatch => ReadinessFailureCode::PolicyMismatch,
        BoundaryFailureCode::ProtocolVersion
        | BoundaryFailureCode::InvalidRequest
        | BoundaryFailureCode::RequestTooLarge
        | BoundaryFailureCode::ResponseTooLarge
        | BoundaryFailureCode::LifecycleConflict => ReadinessFailureCode::Protocol,
        BoundaryFailureCode::Authentication
        | BoundaryFailureCode::Authorization
        | BoundaryFailureCode::Draining
        | BoundaryFailureCode::ServiceUnavailable
        | BoundaryFailureCode::DurableState
        | BoundaryFailureCode::Internal => ReadinessFailureCode::Transport,
    }
}

const fn exec_boundary_code(code: BoundaryFailureCode) -> ExecFailureCode {
    match code {
        BoundaryFailureCode::ProtocolVersion
        | BoundaryFailureCode::AssetBundleMismatch
        | BoundaryFailureCode::InvalidRequest
        | BoundaryFailureCode::RequestTooLarge
        | BoundaryFailureCode::ResponseTooLarge
        | BoundaryFailureCode::LifecycleConflict => ExecFailureCode::Protocol,
        BoundaryFailureCode::Authentication
        | BoundaryFailureCode::Authorization
        | BoundaryFailureCode::Draining
        | BoundaryFailureCode::ServiceUnavailable
        | BoundaryFailureCode::DurableState
        | BoundaryFailureCode::Internal => ExecFailureCode::Transport,
    }
}

const fn cleanup_boundary_code(code: BoundaryFailureCode) -> CleanupFailureCode {
    match code {
        BoundaryFailureCode::ProtocolVersion
        | BoundaryFailureCode::AssetBundleMismatch
        | BoundaryFailureCode::InvalidRequest
        | BoundaryFailureCode::RequestTooLarge
        | BoundaryFailureCode::ResponseTooLarge
        | BoundaryFailureCode::LifecycleConflict => CleanupFailureCode::Protocol,
        BoundaryFailureCode::Authentication
        | BoundaryFailureCode::Authorization
        | BoundaryFailureCode::Draining
        | BoundaryFailureCode::ServiceUnavailable
        | BoundaryFailureCode::DurableState
        | BoundaryFailureCode::Internal => CleanupFailureCode::Transport,
    }
}

fn detail(message: &'static str) -> OperatorDetail {
    OperatorDetail::redacted(message)
}
