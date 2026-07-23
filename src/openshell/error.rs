use core::fmt;

/// Stable failures produced while constructing the `OpenShell` transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenShellConnectErrorCode {
    /// Configuration was empty or internally inconsistent.
    InvalidConfiguration,
    /// A required mTLS asset could not be read.
    CredentialRead,
    /// The endpoint or TLS configuration was rejected locally.
    TransportConfiguration,
    /// The authenticated channel could not connect.
    Connect,
}

/// Redacted `OpenShell` transport-construction failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OpenShellConnectError {
    code: OpenShellConnectErrorCode,
}

impl OpenShellConnectError {
    pub(crate) const fn new(code: OpenShellConnectErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    pub const fn code(self) -> OpenShellConnectErrorCode {
        self.code
    }
}

impl fmt::Debug for OpenShellConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenShellConnectError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for OpenShellConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OpenShell connection failed: {:?}", self.code)
    }
}

impl std::error::Error for OpenShellConnectError {}
