use crate::{
    CleanupFailure, CleanupTarget, CreateFailure, CreateRequest, DeleteOutcome, DispatchState,
    ExecCompleted, ExecFailure, ExecRequest, OperatorDetail, PolicyIdentity, ReadinessFailure,
    RequestOwnedId,
};

use crate::{AssetBundleIdentity, CapabilityToken, DeadlineMillis, OperationId};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    protocol_version: u16,
    operation_id: OperationId,
    asset_bundle: AssetBundleIdentity,
    request: ServiceRequest,
}

impl RequestEnvelope {
    pub const fn new(
        operation_id: OperationId,
        asset_bundle: AssetBundleIdentity,
        request: ServiceRequest,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            operation_id,
            asset_bundle,
            request,
        }
    }

    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub const fn asset_bundle(&self) -> &AssetBundleIdentity {
        &self.asset_bundle
    }

    pub const fn request(&self) -> &ServiceRequest {
        &self.request
    }

    pub fn into_parts(self) -> (OperationId, AssetBundleIdentity, ServiceRequest) {
        (self.operation_id, self.asset_bundle, self.request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceRequest {
    Health,
    Create {
        request: CreateRequest,
        deadline_ms: DeadlineMillis,
    },
    WaitReady {
        request_id: RequestOwnedId,
        lifecycle_token: CapabilityToken,
        expected_policy: PolicyIdentity,
        deadline_ms: DeadlineMillis,
    },
    PrepareExec {
        request_id: RequestOwnedId,
        lifecycle_token: CapabilityToken,
        request: ExecRequest,
        deadline_ms: DeadlineMillis,
    },
    CommitExec {
        request_id: RequestOwnedId,
        prepare_token: CapabilityToken,
        deadline_ms: DeadlineMillis,
    },
    Delete {
        target: CleanupTarget,
        deadline_ms: DeadlineMillis,
    },
    WaitDeleted {
        target: CleanupTarget,
        deadline_ms: DeadlineMillis,
    },
    Cancel {
        target_operation_id: OperationId,
    },
    BeginDrain,
    DrainStatus,
}

impl ServiceRequest {
    pub const fn mutates_lifecycle(&self) -> bool {
        matches!(
            self,
            Self::Create { .. }
                | Self::WaitReady { .. }
                | Self::PrepareExec { .. }
                | Self::CommitExec { .. }
                | Self::Delete { .. }
                | Self::WaitDeleted { .. }
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    protocol_version: u16,
    operation_id: OperationId,
    response: ServiceResponse,
}

impl ResponseEnvelope {
    pub const fn new(operation_id: OperationId, response: ServiceResponse) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            operation_id,
            response,
        }
    }

    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub const fn response(&self) -> &ServiceResponse {
        &self.response
    }

    pub fn into_response(self) -> ServiceResponse {
        self.response
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "response", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceResponse {
    Health {
        status: HealthStatus,
    },
    Created {
        request_id: RequestOwnedId,
        lifecycle_token: CapabilityToken,
    },
    Ready {
        request_id: RequestOwnedId,
        lifecycle_token: CapabilityToken,
        active_policy: PolicyIdentity,
    },
    ExecPrepared {
        prepare_token: CapabilityToken,
    },
    Executed {
        result: ExecCompleted,
    },
    Deleted {
        outcome: DeleteOutcome,
    },
    TerminallyAbsent,
    Cancelled {
        found: bool,
    },
    Draining {
        active_operations: u64,
    },
    CreateFailed {
        failure: CreateFailure,
    },
    ReadinessFailed {
        failure: ReadinessFailure,
    },
    ExecFailed {
        failure: ExecFailure,
    },
    CleanupFailed {
        failure: CleanupFailure,
    },
    BoundaryFailed {
        failure: BoundaryFailure,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthStatus {
    ready: bool,
    draining: bool,
    startup_reconciled: bool,
    active_operations: u64,
    pending_cleanup_records: u64,
}

impl HealthStatus {
    pub const fn new(
        ready: bool,
        draining: bool,
        startup_reconciled: bool,
        active_operations: u64,
        pending_cleanup_records: u64,
    ) -> Self {
        Self {
            ready,
            draining,
            startup_reconciled,
            active_operations,
            pending_cleanup_records,
        }
    }

    pub const fn ready(&self) -> bool {
        self.ready
    }

    pub const fn draining(&self) -> bool {
        self.draining
    }

    pub const fn startup_reconciled(&self) -> bool {
        self.startup_reconciled
    }

    pub const fn active_operations(&self) -> u64 {
        self.active_operations
    }

    pub const fn pending_cleanup_records(&self) -> u64 {
        self.pending_cleanup_records
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryFailureCode {
    Authentication,
    Authorization,
    ProtocolVersion,
    AssetBundleMismatch,
    InvalidRequest,
    RequestTooLarge,
    ResponseTooLarge,
    ServiceUnavailable,
    Draining,
    LifecycleConflict,
    DurableState,
    Internal,
}

#[derive(Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryFailure {
    code: BoundaryFailureCode,
    cleanup_target: Option<CleanupTarget>,
    dispatch_state: Option<DispatchState>,
    detail: OperatorDetail,
}

impl BoundaryFailure {
    pub const fn new(
        code: BoundaryFailureCode,
        cleanup_target: Option<CleanupTarget>,
        dispatch_state: Option<DispatchState>,
        detail: OperatorDetail,
    ) -> Self {
        Self {
            code,
            cleanup_target,
            dispatch_state,
            detail,
        }
    }

    pub const fn code(&self) -> BoundaryFailureCode {
        self.code
    }

    pub const fn cleanup_target(&self) -> Option<&CleanupTarget> {
        self.cleanup_target.as_ref()
    }

    pub const fn dispatch_state(&self) -> Option<DispatchState> {
        self.dispatch_state
    }

    pub const fn detail(&self) -> &OperatorDetail {
        &self.detail
    }
}

impl core::fmt::Debug for BoundaryFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BoundaryFailure")
            .field("code", &self.code)
            .field("has_cleanup_target", &self.cleanup_target.is_some())
            .field("dispatch_state", &self.dispatch_state)
            .field("detail", &"<redacted>")
            .finish()
    }
}
