//! Validated, provider-neutral request values.

use core::fmt;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use uuid::{Uuid, Variant};

use crate::{ValidationCode, ValidationError};

/// The only work directory supported by the first runtime contract.
pub const SANDBOX_WORKDIR: &str = "/sandbox";

/// A caller-generated sandbox identifier with the exact `sbx-<uuid-v4>` shape.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(try_from = "String", into = "String")
)]
pub struct RequestOwnedId(String);

impl RequestOwnedId {
    /// Generates a fresh request-owned identifier.
    pub fn generate() -> Self {
        Self(format!("sbx-{}", Uuid::new_v4()))
    }

    /// Parses and validates a request-owned identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        let suffix = value.strip_prefix("sbx-").ok_or_else(|| {
            ValidationError::new("request_owned_id", ValidationCode::InvalidFormat)
        })?;
        let uuid = Uuid::parse_str(suffix)
            .map_err(|_| ValidationError::new("request_owned_id", ValidationCode::InvalidFormat))?;
        if value.len() != 40
            || uuid.get_version_num() != 4
            || uuid.get_variant() != Variant::RFC4122
            || uuid.to_string() != suffix
        {
            return Err(ValidationError::new(
                "request_owned_id",
                ValidationCode::InvalidFormat,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the validated identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RequestOwnedId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RequestOwnedId")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for RequestOwnedId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for RequestOwnedId {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<RequestOwnedId> for String {
    fn from(value: RequestOwnedId) -> Self {
        value.0
    }
}

/// A provider-neutral, deployment-selected template identity.
///
/// Runtime adapters are responsible for applying provider-specific immutable-reference rules.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(try_from = "String", into = "String")
)]
pub struct TemplateIdentity(String);

impl TemplateIdentity {
    /// Creates a nonempty opaque template identity.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValidationError::new("template", ValidationCode::Empty));
        }
        Ok(Self(value))
    }

    /// Returns the opaque identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TemplateIdentity {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<TemplateIdentity> for String {
    fn from(value: TemplateIdentity) -> Self {
        value.0
    }
}

/// A validated lowercase SHA-256 digest without an algorithm prefix.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(try_from = "String", into = "String")
)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Validates a 64-character lowercase hexadecimal digest.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.len() != 64 {
            return Err(ValidationError::new(
                "sha256",
                ValidationCode::InvalidLength,
            ));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ValidationError::new(
                "sha256",
                ValidationCode::InvalidFormat,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the lowercase hexadecimal digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        value.0
    }
}

/// The identity that readiness must attest before execution.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(
        deny_unknown_fields,
        try_from = "PolicyIdentityWire",
        into = "PolicyIdentityWire"
    )
)]
pub struct PolicyIdentity {
    id: String,
    version: u64,
    sha256: Sha256Digest,
}

impl PolicyIdentity {
    /// Creates an expected policy identity.
    pub fn new(
        id: impl Into<String>,
        version: u64,
        sha256: Sha256Digest,
    ) -> Result<Self, ValidationError> {
        let id = id.into();
        if id.is_empty() {
            return Err(ValidationError::new("policy.id", ValidationCode::Empty));
        }
        if version == 0 {
            return Err(ValidationError::new(
                "policy.version",
                ValidationCode::OutOfRange,
            ));
        }
        Ok(Self {
            id,
            version,
            sha256,
        })
    }

    /// Returns the opaque policy identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the nonzero policy version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns the expected policy hash.
    pub const fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyIdentityWire {
    id: String,
    version: u64,
    sha256: Sha256Digest,
}

#[cfg(feature = "serde")]
impl TryFrom<PolicyIdentityWire> for PolicyIdentity {
    type Error = ValidationError;

    fn try_from(value: PolicyIdentityWire) -> Result<Self, Self::Error> {
        Self::new(value.id, value.version, value.sha256)
    }
}

#[cfg(feature = "serde")]
impl From<PolicyIdentity> for PolicyIdentityWire {
    fn from(value: PolicyIdentity) -> Self {
        Self {
            id: value.id,
            version: value.version,
            sha256: value.sha256,
        }
    }
}

/// An opaque policy document and its media type.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(
        deny_unknown_fields,
        try_from = "PolicyDocumentWire",
        into = "PolicyDocumentWire"
    )
)]
pub struct PolicyDocument {
    media_type: String,
    bytes: Vec<u8>,
}

impl PolicyDocument {
    /// Creates a nonempty opaque policy document.
    pub fn new(media_type: impl Into<String>, bytes: Vec<u8>) -> Result<Self, ValidationError> {
        let media_type = media_type.into();
        if media_type.is_empty() {
            return Err(ValidationError::new(
                "policy.media_type",
                ValidationCode::Empty,
            ));
        }
        if bytes.is_empty() {
            return Err(ValidationError::new(
                "policy.document",
                ValidationCode::Empty,
            ));
        }
        Ok(Self { media_type, bytes })
    }

    /// Returns the policy media type.
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Returns the opaque policy bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for PolicyDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyDocument")
            .field("media_type", &self.media_type)
            .field("byte_count", &self.bytes.len())
            .finish()
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocumentWire {
    media_type: String,
    #[serde(
        rename = "document_base64",
        with = "crate::runtime_contract::serde_base64"
    )]
    bytes: Vec<u8>,
}

#[cfg(feature = "serde")]
impl TryFrom<PolicyDocumentWire> for PolicyDocument {
    type Error = ValidationError;

    fn try_from(value: PolicyDocumentWire) -> Result<Self, Self::Error> {
        Self::new(value.media_type, value.bytes)
    }
}

#[cfg(feature = "serde")]
impl From<PolicyDocument> for PolicyDocumentWire {
    fn from(value: PolicyDocument) -> Self {
        Self {
            media_type: value.media_type,
            bytes: value.bytes,
        }
    }
}

/// The complete, fixed-shape sandbox creation request.
///
/// Environment, providers, GPU, secrets, and host mounts are absent by construction.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct CreateRequest {
    request_id: RequestOwnedId,
    template: TemplateIdentity,
    policy_document: PolicyDocument,
    expected_policy: PolicyIdentity,
}

impl CreateRequest {
    /// Creates a provider-neutral creation request.
    pub const fn new(
        request_id: RequestOwnedId,
        template: TemplateIdentity,
        policy_document: PolicyDocument,
        expected_policy: PolicyIdentity,
    ) -> Self {
        Self {
            request_id,
            template,
            policy_document,
            expected_policy,
        }
    }

    /// Returns the caller-owned request identifier.
    pub const fn request_id(&self) -> &RequestOwnedId {
        &self.request_id
    }

    /// Returns the deployment-selected template identity.
    pub const fn template(&self) -> &TemplateIdentity {
        &self.template
    }

    /// Returns the opaque policy document.
    pub const fn policy_document(&self) -> &PolicyDocument {
        &self.policy_document
    }

    /// Returns the policy identity that readiness must attest.
    pub const fn expected_policy(&self) -> &PolicyIdentity {
        &self.expected_policy
    }
}

/// An immutable, nonempty argv vector.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(try_from = "Vec<String>", into = "Vec<String>")
)]
pub struct Argv(Vec<String>);

impl Argv {
    /// Snapshots and validates argv. Empty elements are preserved.
    pub fn new(values: Vec<String>) -> Result<Self, ValidationError> {
        if values.is_empty() {
            return Err(ValidationError::new("argv", ValidationCode::Empty));
        }
        Ok(Self(values))
    }

    /// Returns argv element-for-element.
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// Returns the number of argv elements.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether argv contains no elements. A valid value always returns `false`.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Argv {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Argv")
            .field("element_count", &self.0.len())
            .finish()
    }
}

impl TryFrom<Vec<String>> for Argv {
    type Error = ValidationError;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Argv> for Vec<String> {
    fn from(value: Argv) -> Self {
        value.0
    }
}

/// A validated command timeout in seconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(try_from = "u16", into = "u16")
)]
pub struct CommandTimeout(u16);

impl CommandTimeout {
    /// The minimum command timeout.
    pub const MIN_SECONDS: u16 = 1;
    /// The maximum command timeout.
    pub const MAX_SECONDS: u16 = 300;
    /// The approved local default.
    pub const DEFAULT_SECONDS: u16 = 30;

    /// Creates a timeout in the inclusive range 1 through 300 seconds.
    pub fn new(seconds: u16) -> Result<Self, ValidationError> {
        if !(Self::MIN_SECONDS..=Self::MAX_SECONDS).contains(&seconds) {
            return Err(ValidationError::new(
                "command_timeout",
                ValidationCode::OutOfRange,
            ));
        }
        Ok(Self(seconds))
    }

    /// Returns the timeout in seconds.
    pub const fn seconds(self) -> u16 {
        self.0
    }
}

impl Default for CommandTimeout {
    fn default() -> Self {
        Self(Self::DEFAULT_SECONDS)
    }
}

impl TryFrom<u16> for CommandTimeout {
    type Error = ValidationError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<CommandTimeout> for u16 {
    fn from(value: CommandTimeout) -> Self {
        value.0
    }
}

/// Independent retained-output and transport-chunk ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(
        deny_unknown_fields,
        try_from = "OutputLimitsWire",
        into = "OutputLimitsWire"
    )
)]
#[allow(clippy::struct_field_names)]
pub struct OutputLimits {
    stdout_bytes: u64,
    stderr_bytes: u64,
    combined_bytes: u64,
    chunk_bytes: u64,
}

impl OutputLimits {
    /// Creates four positive byte ceilings.
    pub fn new(
        stdout_bytes: u64,
        stderr_bytes: u64,
        combined_bytes: u64,
        chunk_bytes: u64,
    ) -> Result<Self, ValidationError> {
        if [stdout_bytes, stderr_bytes, combined_bytes, chunk_bytes].contains(&0) {
            return Err(ValidationError::new(
                "output_limits",
                ValidationCode::OutOfRange,
            ));
        }
        Ok(Self {
            stdout_bytes,
            stderr_bytes,
            combined_bytes,
            chunk_bytes,
        })
    }

    /// Returns the stdout ceiling.
    pub const fn stdout_bytes(self) -> u64 {
        self.stdout_bytes
    }

    /// Returns the stderr ceiling.
    pub const fn stderr_bytes(self) -> u64 {
        self.stderr_bytes
    }

    /// Returns the combined retained-output ceiling.
    pub const fn combined_bytes(self) -> u64 {
        self.combined_bytes
    }

    /// Returns the maximum accepted transport chunk size.
    pub const fn chunk_bytes(self) -> u64 {
        self.chunk_bytes
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct OutputLimitsWire {
    stdout_bytes: u64,
    stderr_bytes: u64,
    combined_bytes: u64,
    chunk_bytes: u64,
}

#[cfg(feature = "serde")]
impl TryFrom<OutputLimitsWire> for OutputLimits {
    type Error = ValidationError;

    fn try_from(value: OutputLimitsWire) -> Result<Self, Self::Error> {
        Self::new(
            value.stdout_bytes,
            value.stderr_bytes,
            value.combined_bytes,
            value.chunk_bytes,
        )
    }
}

#[cfg(feature = "serde")]
impl From<OutputLimits> for OutputLimitsWire {
    fn from(value: OutputLimits) -> Self {
        Self {
            stdout_bytes: value.stdout_bytes,
            stderr_bytes: value.stderr_bytes,
            combined_bytes: value.combined_bytes,
            chunk_bytes: value.chunk_bytes,
        }
    }
}

/// A validated command execution request.
///
/// Workdir is always [`SANDBOX_WORKDIR`]. Environment and stdin are empty, and TTY is disabled,
/// because the contract exposes no fields capable of changing those values.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct ExecRequest {
    argv: Argv,
    timeout: CommandTimeout,
    output_limits: OutputLimits,
}

impl ExecRequest {
    /// Creates an execution request from validated values.
    pub const fn new(argv: Argv, timeout: CommandTimeout, output_limits: OutputLimits) -> Self {
        Self {
            argv,
            timeout,
            output_limits,
        }
    }

    /// Returns immutable argv.
    pub const fn argv(&self) -> &Argv {
        &self.argv
    }

    /// Returns the command timeout.
    pub const fn timeout(&self) -> CommandTimeout {
        self.timeout
    }

    /// Returns the output ceilings.
    pub const fn output_limits(&self) -> OutputLimits {
        self.output_limits
    }

    /// Returns the fixed work directory.
    pub const fn workdir(&self) -> &'static str {
        SANDBOX_WORKDIR
    }
}

impl fmt::Debug for ExecRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecRequest")
            .field("argv_element_count", &self.argv.len())
            .field("timeout", &self.timeout)
            .field("output_limits", &self.output_limits)
            .field("workdir", &SANDBOX_WORKDIR)
            .finish()
    }
}

/// A positive, relative deadline for one runtime I/O operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationDeadline(Duration);

impl OperationDeadline {
    /// Creates a positive relative deadline.
    pub fn new(duration: Duration) -> Result<Self, ValidationError> {
        if duration.is_zero() {
            return Err(ValidationError::new(
                "operation_deadline",
                ValidationCode::OutOfRange,
            ));
        }
        Ok(Self(duration))
    }

    /// Returns the duration from operation start.
    pub const fn duration(self) -> Duration {
        self.0
    }
}

/// Per-operation cancellation and deadline context.
///
/// This live value is intentionally not serializable.
#[derive(Clone)]
pub struct OperationContext {
    cancellation: CancellationToken,
    deadline: OperationDeadline,
}

impl OperationContext {
    /// Creates an operation context.
    pub const fn new(cancellation: CancellationToken, deadline: OperationDeadline) -> Self {
        Self {
            cancellation,
            deadline,
        }
    }

    /// Returns the cancellation token.
    pub const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Returns the relative operation deadline.
    pub const fn deadline(&self) -> OperationDeadline {
        self.deadline
    }
}

impl fmt::Debug for OperationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationContext")
            .field("cancelled", &self.cancellation.is_cancelled())
            .field("deadline", &self.deadline)
            .finish()
    }
}
