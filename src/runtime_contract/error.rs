//! Typed, redacted lifecycle failures with construction-time invariants.

use core::fmt;

use crate::{
    CleanupTarget, CreationState, DispatchState, FailureTimeout, OutputByteCounts, ValidationCode,
    ValidationError,
};

/// Operator detail that is always redacted from `Debug` and `Display` output.
///
/// Runtime adapters must supply already-sanitized text. Serialization intentionally preserves that
/// sanitized text for a later wire boundary, while ordinary formatting never reveals it.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(transparent)
)]
pub struct OperatorDetail(String);

impl OperatorDetail {
    /// Wraps already-redacted operator detail.
    pub fn redacted(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the sanitized detail for an explicitly authorized telemetry or wire mapper.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OperatorDetail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperatorDetail(<redacted>)")
    }
}

impl fmt::Display for OperatorDetail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Stable creation failure codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum CreateFailureCode {
    /// Local validation rejected the request before submission.
    Validation,
    /// Authentication or authorization failed.
    Auth,
    /// Transport failed.
    Transport,
    /// The create deadline elapsed.
    Deadline,
    /// The operation was cancelled.
    Cancelled,
    /// The provider violated the expected protocol.
    Protocol,
    /// The provider returned another normalized failure.
    Provider,
}

/// A creation failure whose variant structurally determines cleanup ownership.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)
)]
pub enum CreateFailure {
    /// Creation was proven not to have occurred; cleanup is forbidden.
    NotCreated {
        /// Stable failure code.
        code: CreateFailureCode,
        /// Sanitized operator detail.
        detail: OperatorDetail,
    },
    /// Creation may have occurred; cleanup is mandatory by retained ID.
    PossiblyCreated {
        /// Request-owned cleanup key.
        cleanup_target: CleanupTarget,
        /// Stable failure code.
        code: CreateFailureCode,
        /// Sanitized operator detail.
        detail: OperatorDetail,
    },
    /// The identifier already existed and must not be deleted by this request.
    Conflict {
        /// Stable failure code.
        code: CreateFailureCode,
        /// Sanitized operator detail.
        detail: OperatorDetail,
    },
}

impl CreateFailure {
    /// Constructs a failure proven before server-side creation.
    pub const fn not_created(code: CreateFailureCode, detail: OperatorDetail) -> Self {
        Self::NotCreated { code, detail }
    }

    /// Constructs an ambiguous create failure with mandatory cleanup ownership.
    pub const fn possibly_created(
        cleanup_target: CleanupTarget,
        code: CreateFailureCode,
        detail: OperatorDetail,
    ) -> Self {
        Self::PossiblyCreated {
            cleanup_target,
            code,
            detail,
        }
    }

    /// Constructs an ownership conflict that must never be deleted by this request.
    pub const fn conflict(code: CreateFailureCode, detail: OperatorDetail) -> Self {
        Self::Conflict { code, detail }
    }

    /// Returns the authoritative creation state.
    pub const fn state(&self) -> CreationState {
        match self {
            Self::NotCreated { .. } => CreationState::NotCreated,
            Self::PossiblyCreated { .. } => CreationState::PossiblyCreated,
            Self::Conflict { .. } => CreationState::Conflict,
        }
    }

    /// Returns a cleanup target only for `PossiblyCreated`.
    pub const fn cleanup_target(&self) -> Option<&CleanupTarget> {
        match self {
            Self::PossiblyCreated { cleanup_target, .. } => Some(cleanup_target),
            Self::NotCreated { .. } | Self::Conflict { .. } => None,
        }
    }

    /// Returns the stable failure code.
    pub const fn code(&self) -> CreateFailureCode {
        match self {
            Self::NotCreated { code, .. }
            | Self::PossiblyCreated { code, .. }
            | Self::Conflict { code, .. } => *code,
        }
    }

    /// Returns sanitized operator detail.
    pub const fn detail(&self) -> &OperatorDetail {
        match self {
            Self::NotCreated { detail, .. }
            | Self::PossiblyCreated { detail, .. }
            | Self::Conflict { detail, .. } => detail,
        }
    }
}

impl fmt::Debug for CreateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateFailure")
            .field("state", &self.state())
            .field("code", &self.code())
            .field("has_cleanup_target", &self.cleanup_target().is_some())
            .field("detail", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for CreateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "create failed: {:?}/{:?}",
            self.state(),
            self.code()
        )
    }
}

impl std::error::Error for CreateFailure {}

/// Stable readiness failure codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum ReadinessFailureCode {
    /// The active policy did not match the expected identity.
    PolicyMismatch,
    /// The workload entered a terminal error state.
    WorkloadError,
    /// Transport failed while observing readiness.
    Transport,
    /// The readiness deadline elapsed.
    Deadline,
    /// The readiness operation was cancelled.
    Cancelled,
    /// The provider violated the expected protocol.
    Protocol,
}

/// A post-create readiness failure that always retains cleanup ownership.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct ReadinessFailure {
    cleanup_target: CleanupTarget,
    code: ReadinessFailureCode,
    detail: OperatorDetail,
}

impl ReadinessFailure {
    /// Constructs a readiness failure with mandatory cleanup ownership.
    pub const fn new(
        cleanup_target: CleanupTarget,
        code: ReadinessFailureCode,
        detail: OperatorDetail,
    ) -> Self {
        Self {
            cleanup_target,
            code,
            detail,
        }
    }

    /// Returns the request-owned cleanup key.
    pub const fn cleanup_target(&self) -> &CleanupTarget {
        &self.cleanup_target
    }

    /// Returns the stable failure code.
    pub const fn code(&self) -> ReadinessFailureCode {
        self.code
    }

    /// Returns sanitized operator detail.
    pub const fn detail(&self) -> &OperatorDetail {
        &self.detail
    }
}

impl fmt::Debug for ReadinessFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadinessFailure")
            .field("cleanup_target", &self.cleanup_target)
            .field("code", &self.code)
            .field("detail", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for ReadinessFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "readiness failed: {:?}", self.code)
    }
}

impl std::error::Error for ReadinessFailure {}

/// Stable execution failure codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum ExecFailureCode {
    /// Transport failed.
    Transport,
    /// An operation deadline elapsed.
    Deadline,
    /// The operation was cancelled.
    Cancelled,
    /// The stream ended without a typed terminal exit event.
    MissingTerminalExit,
    /// An output or chunk ceiling was exceeded.
    OutputLimitExceeded,
    /// The provider violated the expected protocol.
    Protocol,
    /// The provider returned another normalized failure.
    Provider,
}

/// The output ceiling that terminated collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum OutputLimitKind {
    /// The stdout ceiling.
    Stdout,
    /// The stderr ceiling.
    Stderr,
    /// The combined retained-output ceiling.
    Combined,
    /// The individual transport-chunk ceiling.
    Chunk,
}

/// An execution failure with explicit dispatch and timeout ambiguity.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(
        deny_unknown_fields,
        try_from = "ExecFailureWire",
        into = "ExecFailureWire"
    )
)]
pub struct ExecFailure {
    cleanup_target: CleanupTarget,
    dispatch_state: DispatchState,
    timeout_state: FailureTimeout,
    code: ExecFailureCode,
    counts: OutputByteCounts,
    output_limit: Option<OutputLimitKind>,
    detail: OperatorDetail,
}

impl ExecFailure {
    /// Constructs a failure proven not to have dispatched.
    pub fn not_dispatched(
        cleanup_target: CleanupTarget,
        code: ExecFailureCode,
        detail: OperatorDetail,
    ) -> Result<Self, ValidationError> {
        Self::validated(
            cleanup_target,
            DispatchState::NotDispatched,
            FailureTimeout::NotObserved,
            code,
            OutputByteCounts::default(),
            None,
            detail,
        )
    }

    /// Constructs an ambiguous failure after possible dispatch.
    pub fn possibly_dispatched(
        cleanup_target: CleanupTarget,
        code: ExecFailureCode,
        timeout_state: FailureTimeout,
        counts: OutputByteCounts,
        detail: OperatorDetail,
    ) -> Result<Self, ValidationError> {
        if matches!(
            code,
            ExecFailureCode::MissingTerminalExit | ExecFailureCode::OutputLimitExceeded
        ) {
            return Err(ValidationError::new(
                "exec_failure",
                ValidationCode::InvalidCombination,
            ));
        }
        Self::validated(
            cleanup_target,
            DispatchState::PossiblyDispatched,
            timeout_state,
            code,
            counts,
            None,
            detail,
        )
    }

    /// Constructs the required indeterminate missing-exit failure.
    pub fn missing_terminal_exit(
        cleanup_target: CleanupTarget,
        timeout_state: FailureTimeout,
        counts: OutputByteCounts,
        detail: OperatorDetail,
    ) -> Result<Self, ValidationError> {
        Self::validated(
            cleanup_target,
            DispatchState::PossiblyDispatched,
            timeout_state,
            ExecFailureCode::MissingTerminalExit,
            counts,
            None,
            detail,
        )
    }

    /// Constructs the required indeterminate output-overflow failure.
    pub fn output_limit_exceeded(
        cleanup_target: CleanupTarget,
        timeout_state: FailureTimeout,
        counts: OutputByteCounts,
        output_limit: OutputLimitKind,
        detail: OperatorDetail,
    ) -> Result<Self, ValidationError> {
        Self::validated(
            cleanup_target,
            DispatchState::PossiblyDispatched,
            timeout_state,
            ExecFailureCode::OutputLimitExceeded,
            counts,
            Some(output_limit),
            detail,
        )
    }

    fn validated(
        cleanup_target: CleanupTarget,
        dispatch_state: DispatchState,
        timeout_state: FailureTimeout,
        code: ExecFailureCode,
        counts: OutputByteCounts,
        output_limit: Option<OutputLimitKind>,
        detail: OperatorDetail,
    ) -> Result<Self, ValidationError> {
        let special_code = matches!(
            code,
            ExecFailureCode::MissingTerminalExit | ExecFailureCode::OutputLimitExceeded
        );
        let invalid = match dispatch_state {
            DispatchState::NotDispatched => {
                timeout_state != FailureTimeout::NotObserved
                    || counts != OutputByteCounts::default()
                    || output_limit.is_some()
                    || special_code
            }
            DispatchState::PossiblyDispatched => {
                timeout_state == FailureTimeout::NotObserved
                    || (code == ExecFailureCode::MissingTerminalExit && output_limit.is_some())
                    || (code == ExecFailureCode::OutputLimitExceeded && output_limit.is_none())
                    || (!special_code && output_limit.is_some())
            }
        };
        if invalid {
            return Err(ValidationError::new(
                "exec_failure",
                ValidationCode::InvalidCombination,
            ));
        }
        Ok(Self {
            cleanup_target,
            dispatch_state,
            timeout_state,
            code,
            counts,
            output_limit,
            detail,
        })
    }

    /// Returns the request-owned cleanup key.
    pub const fn cleanup_target(&self) -> &CleanupTarget {
        &self.cleanup_target
    }

    /// Returns whether execution could have been dispatched.
    pub const fn dispatch_state(&self) -> DispatchState {
        self.dispatch_state
    }

    /// Returns the timeout state appropriate to this failure.
    pub const fn timeout_state(&self) -> FailureTimeout {
        self.timeout_state
    }

    /// Returns the stable failure code.
    pub const fn code(&self) -> ExecFailureCode {
        self.code
    }

    /// Returns byte counts only; no partial output bodies are retained.
    pub const fn counts(&self) -> OutputByteCounts {
        self.counts
    }

    /// Returns the exceeded output limit when applicable.
    pub const fn output_limit(&self) -> Option<OutputLimitKind> {
        self.output_limit
    }

    /// Returns sanitized operator detail.
    pub const fn detail(&self) -> &OperatorDetail {
        &self.detail
    }
}

impl fmt::Debug for ExecFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecFailure")
            .field("cleanup_target", &self.cleanup_target)
            .field("dispatch_state", &self.dispatch_state)
            .field("timeout_state", &self.timeout_state)
            .field("code", &self.code)
            .field("counts", &self.counts)
            .field("output_limit", &self.output_limit)
            .field("detail", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for ExecFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "execution failed: {:?}/{:?}",
            self.dispatch_state, self.code
        )
    }
}

impl std::error::Error for ExecFailure {}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ExecFailureWire {
    cleanup_target: CleanupTarget,
    dispatch_state: DispatchState,
    timeout_state: FailureTimeout,
    code: ExecFailureCode,
    counts: OutputByteCounts,
    output_limit: Option<OutputLimitKind>,
    detail: OperatorDetail,
}

#[cfg(feature = "serde")]
impl TryFrom<ExecFailureWire> for ExecFailure {
    type Error = ValidationError;

    fn try_from(value: ExecFailureWire) -> Result<Self, Self::Error> {
        Self::validated(
            value.cleanup_target,
            value.dispatch_state,
            value.timeout_state,
            value.code,
            value.counts,
            value.output_limit,
            value.detail,
        )
    }
}

#[cfg(feature = "serde")]
impl From<ExecFailure> for ExecFailureWire {
    fn from(value: ExecFailure) -> Self {
        Self {
            cleanup_target: value.cleanup_target,
            dispatch_state: value.dispatch_state,
            timeout_state: value.timeout_state,
            code: value.code,
            counts: value.counts,
            output_limit: value.output_limit,
            detail: value.detail,
        }
    }
}

/// Stable cleanup failure codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum CleanupFailureCode {
    /// Transport failed.
    Transport,
    /// The cleanup deadline elapsed.
    Deadline,
    /// Cleanup was cancelled.
    Cancelled,
    /// The target failed an ownership check.
    Ownership,
    /// The provider violated the expected protocol.
    Protocol,
    /// The provider returned another normalized failure.
    Provider,
}

/// A cleanup failure that preserves the retained target for reconciliation.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct CleanupFailure {
    cleanup_target: CleanupTarget,
    code: CleanupFailureCode,
    detail: OperatorDetail,
}

impl CleanupFailure {
    /// Constructs a cleanup failure.
    pub const fn new(
        cleanup_target: CleanupTarget,
        code: CleanupFailureCode,
        detail: OperatorDetail,
    ) -> Self {
        Self {
            cleanup_target,
            code,
            detail,
        }
    }

    /// Returns the retained target for reconciliation.
    pub const fn cleanup_target(&self) -> &CleanupTarget {
        &self.cleanup_target
    }

    /// Returns the stable failure code.
    pub const fn code(&self) -> CleanupFailureCode {
        self.code
    }

    /// Returns sanitized operator detail.
    pub const fn detail(&self) -> &OperatorDetail {
        &self.detail
    }
}

impl fmt::Debug for CleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CleanupFailure")
            .field("cleanup_target", &self.cleanup_target)
            .field("code", &self.code)
            .field("detail", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for CleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cleanup failed: {:?}", self.code)
    }
}

impl std::error::Error for CleanupFailure {}
