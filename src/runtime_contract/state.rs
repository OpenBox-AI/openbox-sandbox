//! Lifecycle state values and non-cloneable sandbox handles.

use core::fmt;

use crate::{PolicyIdentity, RequestOwnedId, ValidationCode, ValidationError};

/// The enforcement evidence a configured provider supplies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "kebab-case")
)]
pub enum ProviderCapability {
    /// A remote provider attests the active policy identity.
    Attested,
    /// A local OS sandbox enforces a deployment-pinned policy profile.
    EnforcedLocally,
}

/// The authoritative outcome class for sandbox creation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum CreationState {
    /// The runtime proved that no sandbox was created.
    NotCreated,
    /// Creation may have committed and must be reconciled by retained ID.
    PossiblyCreated,
    /// The request-owned ID already belonged to another sandbox.
    Conflict,
}

/// Whether an execution request could have reached the sandbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum DispatchState {
    /// The runtime proved that dispatch did not occur.
    NotDispatched,
    /// Dispatch may have occurred; execution is indeterminate on failure.
    PossiblyDispatched,
}

/// Timeout evidence permitted on a completed process result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum ObservedTimeout {
    /// No process-timeout signal was observed.
    NotObserved,
    /// The provider explicitly proved a process timeout.
    Confirmed,
    /// Provider evidence was compatible with, but did not prove, a process timeout.
    Possible,
}

/// Timeout state carried by an execution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum FailureTimeout {
    /// No timeout signal was observed.
    NotObserved,
    /// The provider explicitly proved a process timeout.
    Confirmed,
    /// Provider evidence indicated a possible process timeout.
    Possible,
    /// Dispatch ambiguity prevents a reliable timeout claim.
    Unknown,
}

impl From<ObservedTimeout> for FailureTimeout {
    fn from(value: ObservedTimeout) -> Self {
        match value {
            ObservedTimeout::NotObserved => Self::NotObserved,
            ObservedTimeout::Confirmed => Self::Confirmed,
            ObservedTimeout::Possible => Self::Possible,
        }
    }
}

/// Cleanup status retained alongside an execution outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum CleanupState {
    /// No owned sandbox required cleanup.
    NotNeeded,
    /// Terminal absence was confirmed.
    Deleted,
    /// Cleanup was required but terminal absence was not confirmed.
    Failed,
}

/// A cloneable cleanup key based only on the caller-owned identifier.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct CleanupTarget {
    request_id: RequestOwnedId,
}

impl CleanupTarget {
    /// Creates a cleanup key before a possibly committing create call.
    pub const fn new(request_id: RequestOwnedId) -> Self {
        Self { request_id }
    }

    /// Returns the retained request-owned identifier.
    pub const fn request_id(&self) -> &RequestOwnedId {
        &self.request_id
    }
}

/// A provider identifier wrapped without exposing a provider-specific type.
///
/// Runtime adapters create and inspect this value at the implementation trust boundary. It is
/// deliberately non-cloneable, non-serializable, and redacted in `Debug` output.
pub struct OpaqueProviderHandle(Vec<u8>);

impl OpaqueProviderHandle {
    /// Wraps a nonempty provider identifier.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ValidationError> {
        if bytes.is_empty() {
            return Err(ValidationError::new(
                "provider_handle",
                ValidationCode::Empty,
            ));
        }
        Ok(Self(bytes))
    }

    /// Exposes the opaque bytes to a runtime adapter.
    ///
    /// Application and dispatcher code should not inspect this implementation value.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for OpaqueProviderHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueProviderHandle(<redacted>)")
    }
}

/// A successfully created sandbox that has not yet attested readiness.
///
/// This handle is intentionally not `Clone`; readiness consumes it.
pub struct CreatedSandbox {
    request_id: RequestOwnedId,
    provider_handle: OpaqueProviderHandle,
    expected_policy: PolicyIdentity,
}

impl CreatedSandbox {
    /// Constructs a created handle at the runtime-adapter trust boundary.
    pub const fn from_runtime(
        request_id: RequestOwnedId,
        provider_handle: OpaqueProviderHandle,
        expected_policy: PolicyIdentity,
    ) -> Self {
        Self {
            request_id,
            provider_handle,
            expected_policy,
        }
    }

    /// Returns the caller-owned identifier.
    pub const fn request_id(&self) -> &RequestOwnedId {
        &self.request_id
    }

    /// Returns a cloneable cleanup key before a consuming transition.
    pub fn cleanup_target(&self) -> CleanupTarget {
        CleanupTarget::new(self.request_id.clone())
    }

    /// Returns the opaque implementation handle to a runtime adapter.
    pub const fn provider_handle(&self) -> &OpaqueProviderHandle {
        &self.provider_handle
    }

    /// Returns the exact policy identity supplied at creation.
    pub const fn expected_policy(&self) -> &PolicyIdentity {
        &self.expected_policy
    }

    /// Consumes the handle into provider-neutral runtime parts.
    pub fn into_runtime_parts(self) -> (RequestOwnedId, OpaqueProviderHandle, PolicyIdentity) {
        (self.request_id, self.provider_handle, self.expected_policy)
    }
}

impl fmt::Debug for CreatedSandbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedSandbox")
            .field("request_id", &self.request_id)
            .field("provider_handle", &"<redacted>")
            .field("expected_policy", &self.expected_policy)
            .finish()
    }
}

/// A sandbox whose workload and expected policy identity are attested ready.
///
/// This handle is intentionally not `Clone`; execution consumes it.
pub struct ReadySandbox {
    request_id: RequestOwnedId,
    provider_handle: OpaqueProviderHandle,
    active_policy: PolicyIdentity,
}

impl ReadySandbox {
    /// Converts a created handle only when the observed policy exactly matches the expected one.
    ///
    /// A mismatch returns the original created handle so the runtime can construct a typed
    /// readiness failure and the caller can still clean up by retained ID.
    pub fn attest(
        created: CreatedSandbox,
        expected: PolicyIdentity,
        observed: &PolicyIdentity,
    ) -> Result<Self, CreatedSandbox> {
        if created.expected_policy() != &expected || &expected != observed {
            return Err(created);
        }
        let (request_id, provider_handle, created_policy) = created.into_runtime_parts();
        Ok(Self {
            request_id,
            provider_handle,
            active_policy: created_policy,
        })
    }

    /// Returns the caller-owned identifier.
    pub const fn request_id(&self) -> &RequestOwnedId {
        &self.request_id
    }

    /// Returns a cloneable cleanup key before execution consumes this handle.
    pub fn cleanup_target(&self) -> CleanupTarget {
        CleanupTarget::new(self.request_id.clone())
    }

    /// Returns the opaque implementation handle to a runtime adapter.
    pub const fn provider_handle(&self) -> &OpaqueProviderHandle {
        &self.provider_handle
    }

    /// Returns the policy identity proven active before execution.
    pub const fn active_policy(&self) -> &PolicyIdentity {
        &self.active_policy
    }

    /// Consumes the ready handle into provider-neutral runtime parts.
    pub fn into_runtime_parts(self) -> (RequestOwnedId, OpaqueProviderHandle, PolicyIdentity) {
        (self.request_id, self.provider_handle, self.active_policy)
    }
}

impl fmt::Debug for ReadySandbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadySandbox")
            .field("request_id", &self.request_id)
            .field("provider_handle", &"<redacted>")
            .field("active_policy", &self.active_policy)
            .finish()
    }
}
