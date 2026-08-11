//! Stable failures produced while constructing the `sbx` transport.

use core::fmt;

/// Stable failures produced while constructing the Docker Sandboxes runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SbxConnectErrorCode {
    /// Configuration was empty or internally inconsistent.
    InvalidConfiguration,
    /// The configured `sbx` binary could not be executed.
    BinaryUnavailable,
    /// The `sbx` version probe did not produce a parseable version.
    VersionProbeFailed,
    /// The installed `sbx` version is older than the supported baseline.
    UnsupportedVersion,
}

/// Redacted Docker Sandboxes transport-construction failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SbxConnectError {
    code: SbxConnectErrorCode,
}

impl SbxConnectError {
    pub(crate) const fn new(code: SbxConnectErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    pub const fn code(self) -> SbxConnectErrorCode {
        self.code
    }
}

impl fmt::Debug for SbxConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SbxConnectError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for SbxConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Docker Sandboxes connection failed: {:?}",
            self.code
        )
    }
}

impl std::error::Error for SbxConnectError {}
