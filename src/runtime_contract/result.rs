//! Terminal process results and byte-count-only ambiguity evidence.

use core::fmt;

use crate::{ObservedTimeout, ValidationCode, ValidationError};

/// A policy-proxy decision observed for one requested network target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum EgressDecisionKind {
    /// The pinned policy allowlist admitted the target.
    Allowed,
    /// The pinned policy allowlist refused the target.
    Denied,
}

/// Structured target and decision evidence emitted by the native proxy.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct EgressDecision {
    decision: EgressDecisionKind,
    host: String,
    port: u16,
}

impl EgressDecision {
    /// Creates evidence for a normalized target host and port.
    pub fn new(decision: EgressDecisionKind, host: String, port: u16) -> Self {
        Self {
            decision,
            host,
            port,
        }
    }

    /// Returns whether the target was admitted or refused.
    pub const fn decision(&self) -> EgressDecisionKind {
        self.decision
    }

    /// Returns the normalized requested host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the requested target port.
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// Stable category for an operating-system sandbox denial.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum ViolationCategory {
    /// A file write operation was denied.
    DeniedFileWrite,
    /// A file read operation was denied.
    DeniedFileRead,
    /// A network operation was denied.
    DeniedNetwork,
    /// A process operation was denied.
    DeniedProcess,
    /// A denial outside the stable categories above was observed.
    Other,
}

/// Aggregated operating-system sandbox violation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct ViolationEvidence {
    count: u64,
    categories: Vec<ViolationCategory>,
}

impl ViolationEvidence {
    /// Creates aggregated violation evidence.
    pub fn new(count: u64, categories: Vec<ViolationCategory>) -> Self {
        Self { count, categories }
    }

    /// Returns the number of observed violation records.
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Returns the distinct stable denial categories.
    pub fn categories(&self) -> &[ViolationCategory] {
        &self.categories
    }
}

/// Provider-specific isolation evidence attached to an existing terminal result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct SandboxEvidence {
    egress_decisions: Vec<EgressDecision>,
    violation: Option<ViolationEvidence>,
}

impl SandboxEvidence {
    /// Creates evidence from proxy decisions and optional OS violation records.
    pub fn new(
        egress_decisions: Vec<EgressDecision>,
        violation: Option<ViolationEvidence>,
    ) -> Self {
        Self {
            egress_decisions,
            violation,
        }
    }

    /// Returns all proxy decisions observed during the command.
    pub fn egress_decisions(&self) -> &[EgressDecision] {
        &self.egress_decisions
    }

    /// Returns aggregated OS violation evidence when the platform supplied it.
    pub const fn violation(&self) -> Option<&ViolationEvidence> {
        self.violation.as_ref()
    }

    fn is_empty(&self) -> bool {
        self.egress_decisions.is_empty() && self.violation.is_none()
    }
}

/// Immediate response to a delete request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum DeleteOutcome {
    /// The provider acknowledged deletion of an owned sandbox.
    Deleted,
    /// The retained identifier was already absent.
    AlreadyAbsent,
}

/// A real, provider-observed nonnegative process exit code.
///
/// Negative convenience sentinels such as `-1` cannot construct this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(try_from = "i32", into = "i32")
)]
pub struct ObservedExitCode(i32);

impl ObservedExitCode {
    /// Creates an observed process exit code, rejecting negative sentinels.
    pub fn new(value: i32) -> Result<Self, ValidationError> {
        if value < 0 {
            return Err(ValidationError::new(
                "exit_code",
                ValidationCode::OutOfRange,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the raw observed value, including `124` when present.
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl TryFrom<i32> for ObservedExitCode {
    type Error = ValidationError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ObservedExitCode> for i32 {
    fn from(value: ObservedExitCode) -> Self {
        value.0
    }
}

/// Counts retained after an indeterminate execution failure.
///
/// Partial output bodies are intentionally absent.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct OutputByteCounts {
    stdout_bytes: u64,
    stderr_bytes: u64,
}

impl OutputByteCounts {
    /// Creates output byte counts.
    pub const fn new(stdout_bytes: u64, stderr_bytes: u64) -> Self {
        Self {
            stdout_bytes,
            stderr_bytes,
        }
    }

    /// Returns the observed stdout byte count.
    pub const fn stdout_bytes(self) -> u64 {
        self.stdout_bytes
    }

    /// Returns the observed stderr byte count.
    pub const fn stderr_bytes(self) -> u64 {
        self.stderr_bytes
    }

    /// Returns the combined count when it fits in `u64`.
    pub const fn combined_bytes(self) -> Option<u64> {
        self.stdout_bytes.checked_add(self.stderr_bytes)
    }
}

/// A terminal execution result with raw, bounded output bytes.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(
        deny_unknown_fields,
        try_from = "ExecCompletedWire",
        into = "ExecCompletedWire"
    )
)]
pub struct ExecCompleted {
    exit_code: ObservedExitCode,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timeout: ObservedTimeout,
    sandbox_evidence: SandboxEvidence,
}

impl ExecCompleted {
    /// Creates a terminal completed result from an explicit observed exit event.
    pub const fn new(
        exit_code: ObservedExitCode,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        timeout: ObservedTimeout,
    ) -> Self {
        Self {
            exit_code,
            stdout,
            stderr,
            timeout,
            sandbox_evidence: SandboxEvidence {
                egress_decisions: Vec::new(),
                violation: None,
            },
        }
    }

    /// Attaches provider isolation evidence to this terminal result.
    #[must_use]
    pub fn with_sandbox_evidence(mut self, evidence: SandboxEvidence) -> Self {
        self.sandbox_evidence = evidence;
        self
    }

    /// Returns provider isolation evidence for this command.
    pub const fn sandbox_evidence(&self) -> &SandboxEvidence {
        &self.sandbox_evidence
    }

    /// Returns the real observed process exit.
    pub const fn exit_code(&self) -> ObservedExitCode {
        self.exit_code
    }

    /// Returns raw stdout bytes.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Returns raw stderr bytes.
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Returns provider timeout evidence for this completed process.
    pub const fn timeout(&self) -> ObservedTimeout {
        self.timeout
    }

    /// Returns stdout length without lossy conversion.
    pub fn stdout_bytes(&self) -> usize {
        self.stdout.len()
    }

    /// Returns stderr length without lossy conversion.
    pub fn stderr_bytes(&self) -> usize {
        self.stderr.len()
    }

    /// Consumes the result into its raw output bodies.
    pub fn into_output(self) -> (Vec<u8>, Vec<u8>) {
        (self.stdout, self.stderr)
    }
}

impl fmt::Debug for ExecCompleted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecCompleted")
            .field("exit_code", &self.exit_code)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("timeout", &self.timeout)
            .field("sandbox_evidence", &self.sandbox_evidence)
            .finish()
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ExecCompletedWire {
    exit_code: ObservedExitCode,
    #[serde(
        rename = "stdout_base64",
        with = "crate::runtime_contract::serde_base64"
    )]
    stdout: Vec<u8>,
    #[serde(
        rename = "stderr_base64",
        with = "crate::runtime_contract::serde_base64"
    )]
    stderr: Vec<u8>,
    timeout: ObservedTimeout,
    #[serde(default, skip_serializing_if = "SandboxEvidence::is_empty")]
    sandbox_evidence: SandboxEvidence,
}

#[cfg(feature = "serde")]
impl TryFrom<ExecCompletedWire> for ExecCompleted {
    type Error = ValidationError;

    fn try_from(value: ExecCompletedWire) -> Result<Self, Self::Error> {
        Ok(
            Self::new(value.exit_code, value.stdout, value.stderr, value.timeout)
                .with_sandbox_evidence(value.sandbox_evidence),
        )
    }
}

#[cfg(feature = "serde")]
impl From<ExecCompleted> for ExecCompletedWire {
    fn from(value: ExecCompleted) -> Self {
        Self {
            exit_code: value.exit_code,
            stdout: value.stdout,
            stderr: value.stderr,
            timeout: value.timeout,
            sandbox_evidence: value.sandbox_evidence,
        }
    }
}
