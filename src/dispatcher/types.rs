use core::fmt;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use uuid::{Uuid, Variant};

use crate::{
    CommandTimeout, ExecCompleted, FailureTimeout, ObservedTimeout, OutputByteCounts, OutputLimits,
    PolicyDocument, PolicyIdentity, Sha256Digest, TemplateIdentity, ValidationCode,
    ValidationError,
};

/// Stable identity assigned by the runtime to one logical command.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct DispatchId(String);

impl DispatchId {
    /// Generates a fresh RFC 4122 UUID v4 identity.
    pub fn generate() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Parses the canonical lowercase UUID v4 representation.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        let uuid = Uuid::parse_str(&value)
            .map_err(|_| ValidationError::new("dispatch_id", ValidationCode::InvalidFormat))?;
        if value.len() != 36
            || uuid.get_version_num() != 4
            || uuid.get_variant() != Variant::RFC4122
            || uuid.to_string() != value
        {
            return Err(ValidationError::new(
                "dispatch_id",
                ValidationCode::InvalidFormat,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the canonical activity/dispatch identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DispatchId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("DispatchId").field(&self.0).finish()
    }
}

impl fmt::Display for DispatchId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for DispatchId {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<DispatchId> for String {
    fn from(value: DispatchId) -> Self {
        value.0
    }
}

/// Unvalidated V1 non-interactive command input.
///
/// Serialization exposes exactly `argv` and optional `timeout_seconds`. A dispatch identity is
/// runtime-owned metadata and is never accepted from command JSON.
#[derive(Clone, Eq, PartialEq)]
pub struct Command {
    dispatch_id: DispatchId,
    argv: Vec<String>,
    timeout_seconds: Option<u16>,
    resume_only: bool,
}

impl Command {
    /// Creates a new logical command and assigns its stable dispatch identity.
    pub fn new(argv: Vec<String>, timeout_seconds: Option<u16>) -> Self {
        Self {
            dispatch_id: DispatchId::generate(),
            argv,
            timeout_seconds,
            resume_only: false,
        }
    }

    /// Reconstructs a previously assigned logical command for replay after restart.
    ///
    /// The dispatcher accepts this only when a durable record with the same command digest exists;
    /// it can never use this operation to begin a caller-selected identity.
    pub fn resume(
        dispatch_id: DispatchId,
        argv: Vec<String>,
        timeout_seconds: Option<u16>,
    ) -> Self {
        Self {
            dispatch_id,
            argv,
            timeout_seconds,
            resume_only: true,
        }
    }

    /// Returns the runtime-assigned stable dispatch identity.
    pub const fn dispatch_id(&self) -> &DispatchId {
        &self.dispatch_id
    }

    pub(crate) fn into_parts(self) -> (DispatchId, Vec<String>, Option<u16>, bool) {
        (
            self.dispatch_id,
            self.argv,
            self.timeout_seconds,
            self.resume_only,
        )
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Command")
            .field("dispatch_id", &self.dispatch_id)
            .field("argv_element_count", &self.argv.len())
            .field("has_timeout", &self.timeout_seconds.is_some())
            .finish()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommandWire {
    argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeout_seconds: Option<u16>,
}

impl Serialize for Command {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        CommandWire {
            argv: self.argv.clone(),
            timeout_seconds: self.timeout_seconds,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Command {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CommandWire::deserialize(deserializer)?;
        Ok(Self::new(wire.argv, wire.timeout_seconds))
    }
}

/// Deployment-owned command input ceilings applied before governance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandSizeLimits {
    max_argv_elements: usize,
    max_argv_bytes: usize,
}

impl CommandSizeLimits {
    /// Creates positive element and aggregate UTF-8 byte ceilings.
    pub fn new(max_argv_elements: usize, max_argv_bytes: usize) -> Result<Self, ValidationError> {
        if max_argv_elements == 0 || max_argv_bytes == 0 {
            return Err(ValidationError::new(
                "command_size_limits",
                ValidationCode::OutOfRange,
            ));
        }
        Ok(Self {
            max_argv_elements,
            max_argv_bytes,
        })
    }

    pub(crate) const fn max_argv_elements(self) -> usize {
        self.max_argv_elements
    }

    pub(crate) const fn max_argv_bytes(self) -> usize {
        self.max_argv_bytes
    }
}

impl Default for CommandSizeLimits {
    fn default() -> Self {
        Self {
            max_argv_elements: 256,
            max_argv_bytes: 64 * 1024,
        }
    }
}

/// Immutable command snapshot shared by governance and the selected executor.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveCommand {
    argv: Vec<String>,
    timeout_seconds: u16,
}

impl EffectiveCommand {
    pub(crate) fn validate(
        argv: Vec<String>,
        timeout_seconds: Option<u16>,
        limits: CommandSizeLimits,
    ) -> Result<Self, ValidationError> {
        if argv.is_empty() {
            return Err(ValidationError::new("argv", ValidationCode::Empty));
        }
        if argv.len() > limits.max_argv_elements() {
            return Err(ValidationError::new("argv", ValidationCode::InvalidLength));
        }
        let mut bytes = 0_usize;
        for value in &argv {
            if value.contains('\0') {
                return Err(ValidationError::new("argv", ValidationCode::InvalidFormat));
            }
            bytes = bytes
                .checked_add(value.len())
                .ok_or_else(|| ValidationError::new("argv", ValidationCode::InvalidLength))?;
            if bytes > limits.max_argv_bytes() {
                return Err(ValidationError::new("argv", ValidationCode::InvalidLength));
            }
        }
        let timeout =
            CommandTimeout::new(timeout_seconds.unwrap_or(CommandTimeout::DEFAULT_SECONDS))?;
        Ok(Self {
            argv,
            timeout_seconds: timeout.seconds(),
        })
    }

    /// Returns argv exactly element-for-element, including empty elements.
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// Returns the effective timeout in seconds.
    pub const fn timeout_seconds(&self) -> u16 {
        self.timeout_seconds
    }

    /// Computes SHA-256 over the versioned, length-prefixed canonical encoding.
    pub fn digest(&self) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"openbox.command.v1\0");
        hasher.update(
            u64::try_from(self.argv.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for value in &self.argv {
            let bytes = value.as_bytes();
            hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(bytes);
        }
        hasher.update(self.timeout_seconds.to_be_bytes());
        let digest =
            hasher
                .finalize()
                .iter()
                .fold(String::with_capacity(64), |mut output, byte| {
                    use core::fmt::Write as _;
                    write!(output, "{byte:02x}").expect("writing to String cannot fail");
                    output
                });
        Sha256Digest::parse(digest).expect("SHA-256 is lowercase hexadecimal")
    }
}

impl fmt::Debug for EffectiveCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectiveCommand")
            .field("argv_element_count", &self.argv.len())
            .field("timeout_seconds", &self.timeout_seconds)
            .finish()
    }
}

/// Canonical `OpenBox` `ActivityStarted` request for a V1 command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct ActivityStarted {
    activity_id: DispatchId,
    activity_type: &'static str,
    activity_input: ActivityInput,
}

impl ActivityStarted {
    pub(crate) fn new(activity_id: DispatchId, command: &EffectiveCommand) -> Self {
        Self {
            activity_id,
            activity_type: "openbox.command.v1",
            activity_input: ActivityInput {
                schema_version: 1,
                argv: command.argv.clone(),
                timeout_seconds: command.timeout_seconds,
            },
        }
    }

    /// Returns the dispatch ID also used as the `OpenBox` activity ID.
    pub const fn activity_id(&self) -> &DispatchId {
        &self.activity_id
    }

    /// Returns the fixed V1 activity type.
    pub const fn activity_type(&self) -> &'static str {
        self.activity_type
    }

    /// Returns the exact command argv sent for evaluation.
    pub fn argv(&self) -> &[String] {
        &self.activity_input.argv
    }

    /// Returns the effective command timeout sent for evaluation.
    pub const fn timeout_seconds(&self) -> u16 {
        self.activity_input.timeout_seconds
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivityInput {
    schema_version: u16,
    argv: Vec<String>,
    timeout_seconds: u16,
}

/// Authoritative verdicts understood by V1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceVerdict {
    /// Execute once on the host.
    Allow,
    /// Execute once in a fresh sandbox.
    Constrain,
    /// Do not execute in V1.
    RequireApproval,
    /// Do not execute.
    Block,
    /// Do not execute.
    Halt,
}

/// Why a governance response was rejected without selecting an executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceRejection {
    /// No response was returned.
    Missing,
    /// The response had an invalid shape or type.
    Malformed,
    /// The verdict is not supported by V1.
    UnknownVerdict,
    /// The activity ID does not match the current dispatch.
    MismatchedActivity,
    /// The response identified itself as stale.
    Stale,
    /// The response identified itself as synthetic.
    Synthetic,
    /// A fallback response was used.
    Fallback,
    /// Action and verdict fields disagree.
    ConflictingAction,
    /// Governance guardrails did not pass.
    FailedGuardrails,
    /// Constraints had an invalid shape.
    InvalidConstraints,
    /// V1 received a nonempty constraint directive.
    UnsupportedConstraint,
    /// V1 received command remediation or transformation instructions.
    Remediation,
    /// The response contained an unsupported field.
    UnsupportedField,
    /// The response was not explicitly authoritative.
    Unauthoritative,
}

/// Governance evidence returned as an independent result field.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum GovernanceOutcome {
    /// Validation failed before governance was called.
    NotEvaluated,
    /// The governance call failed without a decision.
    Unavailable,
    /// The response was rejected and selected no executor.
    Rejected {
        /// Stable rejection reason.
        reason: GovernanceRejection,
    },
    /// An authoritative response accepted unchanged from the governance call.
    Authoritative {
        /// Validated verdict used for routing.
        verdict: GovernanceVerdict,
        /// Unchanged direct governance response.
        response: serde_json::Value,
    },
}

impl fmt::Debug for GovernanceOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEvaluated => formatter.write_str("GovernanceOutcome::NotEvaluated"),
            Self::Unavailable => formatter.write_str("GovernanceOutcome::Unavailable"),
            Self::Rejected { reason } => formatter
                .debug_struct("GovernanceOutcome::Rejected")
                .field("reason", reason)
                .finish(),
            Self::Authoritative { verdict, .. } => formatter
                .debug_struct("GovernanceOutcome::Authoritative")
                .field("verdict", verdict)
                .field("response", &"<redacted>")
                .finish(),
        }
    }
}

/// Executor selected by governance routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedExecutor {
    /// No executor was selected.
    None,
    /// The trusted host executor was selected.
    Host,
    /// The trusted sandbox executor was selected.
    Sandbox,
}

/// Durable command dispatch state exposed to callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedDispatchState {
    /// Execution was proven not to have dispatched.
    NotDispatched,
    /// An executor may have received the command.
    PossiblyDispatched,
    /// A terminal process result was observed.
    Completed,
}

/// Timeout evidence independent from dispatch and execution outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutState {
    /// No timeout evidence was observed.
    NotObserved,
    /// Evidence is compatible with, but does not prove, timeout.
    Possible,
    /// The executor authoritatively proved timeout.
    Confirmed,
    /// Dispatch ambiguity prevents a reliable timeout claim.
    Unknown,
}

impl From<ObservedTimeout> for TimeoutState {
    fn from(value: ObservedTimeout) -> Self {
        match value {
            ObservedTimeout::NotObserved => Self::NotObserved,
            ObservedTimeout::Possible => Self::Possible,
            ObservedTimeout::Confirmed => Self::Confirmed,
        }
    }
}

impl From<FailureTimeout> for TimeoutState {
    fn from(value: FailureTimeout) -> Self {
        match value {
            FailureTimeout::NotObserved => Self::NotObserved,
            FailureTimeout::Possible => Self::Possible,
            FailureTimeout::Confirmed => Self::Confirmed,
            FailureTimeout::Unknown => Self::Unknown,
        }
    }
}

/// Cleanup status independent from the original execution result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedCleanupState {
    /// No request-owned sandbox requires cleanup.
    NotNeeded,
    /// Terminal absence was confirmed.
    ConfirmedAbsent,
    /// Durable cleanup reconciliation remains pending.
    PendingReconciliation,
}

/// Command execution evidence. Partial output bodies are impossible for indeterminate outcomes.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionOutcome {
    /// No process result exists.
    NotExecuted,
    /// A terminal result with bounded raw output was observed.
    Completed {
        /// Observed process result.
        result: ExecCompleted,
    },
    /// Execution may have occurred; only output counts are retained.
    Indeterminate {
        /// Number of stdout bytes observed before uncertainty.
        stdout_bytes_observed: u64,
        /// Number of stderr bytes observed before uncertainty.
        stderr_bytes_observed: u64,
    },
}

impl ExecutionOutcome {
    pub(crate) fn indeterminate(counts: OutputByteCounts) -> Self {
        Self::Indeterminate {
            stdout_bytes_observed: counts.stdout_bytes(),
            stderr_bytes_observed: counts.stderr_bytes(),
        }
    }
}

/// Stable error phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorPhase {
    /// Input validation.
    Validation,
    /// Governance evaluation or response validation.
    Governance,
    /// Durable dispatch-state persistence.
    DispatchPersistence,
    /// Host command dispatch.
    HostDispatch,
    /// Sandbox creation.
    SandboxCreate,
    /// Sandbox workload readiness.
    SandboxReadiness,
    /// Exact active-policy attestation.
    SandboxAttestation,
    /// Sandbox command dispatch.
    SandboxDispatch,
    /// Sandbox command execution.
    SandboxExecution,
    /// Sandbox execution transport.
    SandboxTransport,
    /// Immediate sandbox cleanup.
    SandboxCleanup,
    /// Durable cleanup reconciliation.
    SandboxReconciliation,
}

/// Stable machine-readable dispatcher error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedErrorCode {
    /// Command validation failed.
    InvalidCommand,
    /// Configured command size limits were exceeded.
    CommandTooLarge,
    /// A replay reused an identity with different command content.
    DigestMismatch,
    /// Governance evaluation was unavailable.
    GovernanceUnavailable,
    /// Governance returned a rejected response.
    GovernanceRejected,
    /// Durable state could not be read or committed.
    PersistenceFailed,
    /// A possible dispatch has no terminal result and cannot be retried.
    ReplayIndeterminate,
    /// Host execution failed.
    HostFailed,
    /// Sandbox creation failed.
    SandboxCreateFailed,
    /// Sandbox readiness failed.
    SandboxReadinessFailed,
    /// Exact sandbox policy attestation failed.
    SandboxAttestationFailed,
    /// Sandbox execution failed.
    SandboxExecutionFailed,
    /// Sandbox execution transport failed.
    SandboxTransportFailed,
    /// Terminal absence still needs reconciliation.
    CleanupPending,
}

/// Typed error with no behaviorally significant human-readable message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedError {
    code: GovernedErrorCode,
    phase: ErrorPhase,
}

impl GovernedError {
    pub(crate) const fn new(code: GovernedErrorCode, phase: ErrorPhase) -> Self {
        Self { code, phase }
    }

    /// Returns the stable code.
    pub const fn code(self) -> GovernedErrorCode {
        self.code
    }

    /// Returns the stable phase.
    pub const fn phase(self) -> ErrorPhase {
        self.phase
    }
}

/// Final authority result. Callers must never execute independently after receiving it.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedCommandResult {
    dispatch_id: DispatchId,
    governance: GovernanceOutcome,
    selected_executor: SelectedExecutor,
    dispatch_state: GovernedDispatchState,
    execution_outcome: ExecutionOutcome,
    timeout_state: TimeoutState,
    cleanup_state: GovernedCleanupState,
    error: Option<GovernedError>,
}

impl GovernedCommandResult {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        dispatch_id: DispatchId,
        governance: GovernanceOutcome,
        selected_executor: SelectedExecutor,
        dispatch_state: GovernedDispatchState,
        execution_outcome: ExecutionOutcome,
        timeout_state: TimeoutState,
        cleanup_state: GovernedCleanupState,
        error: Option<GovernedError>,
    ) -> Self {
        Self {
            dispatch_id,
            governance,
            selected_executor,
            dispatch_state,
            execution_outcome,
            timeout_state,
            cleanup_state,
            error,
        }
    }

    pub(crate) fn validation(dispatch_id: DispatchId, code: GovernedErrorCode) -> Self {
        Self::new(
            dispatch_id,
            GovernanceOutcome::NotEvaluated,
            SelectedExecutor::None,
            GovernedDispatchState::NotDispatched,
            ExecutionOutcome::NotExecuted,
            TimeoutState::NotObserved,
            GovernedCleanupState::NotNeeded,
            Some(GovernedError::new(code, ErrorPhase::Validation)),
        )
    }

    pub(crate) fn set_cleanup_state(&mut self, cleanup_state: GovernedCleanupState) {
        self.cleanup_state = cleanup_state;
    }

    pub(crate) fn set_error_if_none(&mut self, error: GovernedError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    /// Returns the stable dispatch/activity ID.
    pub const fn dispatch_id(&self) -> &DispatchId {
        &self.dispatch_id
    }
    /// Returns governance evidence.
    pub const fn governance(&self) -> &GovernanceOutcome {
        &self.governance
    }
    /// Returns the selected executor.
    pub const fn selected_executor(&self) -> SelectedExecutor {
        self.selected_executor
    }
    /// Returns whether execution did not occur, may have occurred, or completed.
    pub const fn dispatch_state(&self) -> GovernedDispatchState {
        self.dispatch_state
    }
    /// Returns execution evidence.
    pub const fn execution_outcome(&self) -> &ExecutionOutcome {
        &self.execution_outcome
    }
    /// Returns timeout evidence.
    pub const fn timeout_state(&self) -> TimeoutState {
        self.timeout_state
    }
    /// Returns cleanup evidence.
    pub const fn cleanup_state(&self) -> GovernedCleanupState {
        self.cleanup_state
    }
    /// Returns a stable typed error, when present.
    pub const fn error(&self) -> Option<GovernedError> {
        self.error
    }
}

/// Provider isolation level asserted by trusted deployment configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationSupport {
    /// All required isolation controls are enforced.
    Full,
    /// Some isolation controls are best-effort.
    Degraded,
    /// Required isolation controls are unavailable.
    Unsupported,
}

/// Trusted immutable assets used for every constrained command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxAssetBundle {
    template: TemplateIdentity,
    template_digest: Sha256Digest,
    policy: PolicyIdentity,
    policy_document: PolicyDocument,
    provider_compatibility: String,
}

impl SandboxAssetBundle {
    /// Validates deployment-pinned template and deny-network policy identities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        template: TemplateIdentity,
        template_digest: Sha256Digest,
        policy: PolicyIdentity,
        policy_document: PolicyDocument,
        provider_compatibility: impl Into<String>,
        isolation_support: IsolationSupport,
        production: bool,
        deny_network: bool,
    ) -> Result<Self, ValidationError> {
        let provider_compatibility = provider_compatibility.into();
        if provider_compatibility.is_empty() || !deny_network {
            return Err(ValidationError::new(
                "sandbox_asset_bundle",
                ValidationCode::InvalidCombination,
            ));
        }
        if production && isolation_support != IsolationSupport::Full {
            return Err(ValidationError::new(
                "isolation_support",
                ValidationCode::InvalidCombination,
            ));
        }
        let expected_template_suffix = format!("@sha256:{}", template_digest.as_str());
        if !template.as_str().ends_with(&expected_template_suffix) {
            return Err(ValidationError::new(
                "template_digest",
                ValidationCode::InvalidCombination,
            ));
        }
        let policy_digest = Sha256::digest(policy_document.as_bytes()).iter().fold(
            String::with_capacity(64),
            |mut output, byte| {
                use core::fmt::Write as _;
                write!(output, "{byte:02x}").expect("writing to String cannot fail");
                output
            },
        );
        if policy.sha256().as_str() != policy_digest {
            return Err(ValidationError::new(
                "policy.sha256",
                ValidationCode::InvalidCombination,
            ));
        }
        Ok(Self {
            template,
            template_digest,
            policy,
            policy_document,
            provider_compatibility,
        })
    }

    pub(crate) const fn template(&self) -> &TemplateIdentity {
        &self.template
    }
    /// Returns the pinned template digest.
    pub const fn template_digest(&self) -> &Sha256Digest {
        &self.template_digest
    }
    pub(crate) const fn policy(&self) -> &PolicyIdentity {
        &self.policy
    }
    pub(crate) const fn policy_document(&self) -> &PolicyDocument {
        &self.policy_document
    }
    /// Returns deployment/provider compatibility metadata.
    pub fn provider_compatibility(&self) -> &str {
        &self.provider_compatibility
    }
}

/// Dispatcher deadlines and immutable deployment assets.
#[derive(Clone, Debug)]
pub struct DispatcherConfig {
    pub(crate) state_directory: PathBuf,
    pub(crate) command_limits: CommandSizeLimits,
    pub(crate) output_limits: OutputLimits,
    pub(crate) assets: SandboxAssetBundle,
    pub(crate) create_deadline: Duration,
    pub(crate) readiness_deadline: Duration,
    pub(crate) dispatch_deadline_slack: Duration,
    pub(crate) cleanup_deadline: Duration,
}

impl DispatcherConfig {
    /// Creates production-oriented defaults around trusted deployment assets.
    pub fn new(
        state_directory: impl Into<PathBuf>,
        assets: SandboxAssetBundle,
        output_limits: OutputLimits,
    ) -> Result<Self, ValidationError> {
        let state_directory = state_directory.into();
        if state_directory.as_os_str().is_empty() {
            return Err(ValidationError::new(
                "state_directory",
                ValidationCode::Empty,
            ));
        }
        Ok(Self {
            state_directory,
            command_limits: CommandSizeLimits::default(),
            output_limits,
            assets,
            create_deadline: Duration::from_secs(120),
            readiness_deadline: Duration::from_secs(120),
            dispatch_deadline_slack: Duration::from_secs(5),
            cleanup_deadline: Duration::from_secs(60),
        })
    }

    /// Replaces command input ceilings.
    #[must_use]
    pub fn with_command_limits(mut self, limits: CommandSizeLimits) -> Self {
        self.command_limits = limits;
        self
    }

    /// Replaces independent sandbox operation deadlines.
    pub fn with_deadlines(
        mut self,
        create: Duration,
        readiness: Duration,
        dispatch_slack: Duration,
        cleanup: Duration,
    ) -> Result<Self, ValidationError> {
        if [create, readiness, dispatch_slack, cleanup]
            .iter()
            .any(Duration::is_zero)
        {
            return Err(ValidationError::new(
                "dispatcher_deadlines",
                ValidationCode::OutOfRange,
            ));
        }
        self.create_deadline = create;
        self.readiness_deadline = readiness;
        self.dispatch_deadline_slack = dispatch_slack;
        self.cleanup_deadline = cleanup;
        Ok(self)
    }
}
