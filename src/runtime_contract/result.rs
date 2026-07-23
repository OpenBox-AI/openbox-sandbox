//! Terminal process results and byte-count-only ambiguity evidence.

use core::fmt;

use crate::{ObservedTimeout, ValidationCode, ValidationError};

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
        }
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
}

#[cfg(feature = "serde")]
impl TryFrom<ExecCompletedWire> for ExecCompleted {
    type Error = ValidationError;

    fn try_from(value: ExecCompletedWire) -> Result<Self, Self::Error> {
        Ok(Self::new(
            value.exit_code,
            value.stdout,
            value.stderr,
            value.timeout,
        ))
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
        }
    }
}
