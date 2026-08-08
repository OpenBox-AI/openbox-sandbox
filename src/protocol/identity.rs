use core::fmt;
use std::time::Duration;

use crate::{PolicyIdentity, Sha256Digest, TemplateIdentity};
use uuid::{Uuid, Variant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolValidationError {
    Empty,
    InvalidFormat,
    OutOfRange,
}

impl fmt::Display for ProtocolValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid protocol value")
    }
}

impl std::error::Error for ProtocolValidationError {}

macro_rules! uuid_value {
    ($name:ident) => {
        #[derive(
            Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
        )]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn generate() -> Self {
                Self(Uuid::new_v4().to_string())
            }

            pub fn parse(value: impl Into<String>) -> Result<Self, ProtocolValidationError> {
                let value = value.into();
                let uuid =
                    Uuid::parse_str(&value).map_err(|_| ProtocolValidationError::InvalidFormat)?;
                if value.len() != 36
                    || uuid.get_version_num() != 4
                    || uuid.get_variant() != Variant::RFC4122
                    || uuid.to_string() != value
                {
                    return Err(ProtocolValidationError::InvalidFormat);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl TryFrom<String> for $name {
            type Error = ProtocolValidationError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

mod generated {
    use super::{ProtocolValidationError, Uuid, Variant, fmt};
    uuid_value!(OperationId);
    uuid_value!(CapabilityToken);
}

pub use generated::{CapabilityToken, OperationId};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct DeadlineMillis(u64);

impl DeadlineMillis {
    pub const MIN: u64 = 1;
    // Cold-boot tolerance: a fresh stack's first sandbox create (image pull +
    // rootfs build + first microVM boot) routinely exceeds 2 minutes, so the
    // protocol ceiling must cover the full cold path (20 minutes).
    pub const MAX: u64 = 1_200_000;

    pub fn new(value: u64) -> Result<Self, ProtocolValidationError> {
        if !(Self::MIN..=Self::MAX).contains(&value) {
            return Err(ProtocolValidationError::OutOfRange);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn duration(self) -> Duration {
        Duration::from_millis(self.0)
    }
}

impl TryFrom<u64> for DeadlineMillis {
    type Error = ProtocolValidationError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<DeadlineMillis> for u64 {
    fn from(value: DeadlineMillis) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(
    deny_unknown_fields,
    try_from = "AssetBundleWire",
    into = "AssetBundleWire"
)]
pub struct AssetBundleIdentity {
    runtime_contract_version: u16,
    adapter_build_sha256: Sha256Digest,
    template: TemplateIdentity,
    policy: PolicyIdentity,
    compatibility_id: String,
}

impl AssetBundleIdentity {
    pub fn new(
        runtime_contract_version: u16,
        adapter_build_sha256: Sha256Digest,
        template: TemplateIdentity,
        policy: PolicyIdentity,
        compatibility_id: impl Into<String>,
    ) -> Result<Self, ProtocolValidationError> {
        let compatibility_id = compatibility_id.into();
        if runtime_contract_version == 0 {
            return Err(ProtocolValidationError::OutOfRange);
        }
        if compatibility_id.is_empty() {
            return Err(ProtocolValidationError::Empty);
        }
        if compatibility_id.len() > 128
            || !compatibility_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(ProtocolValidationError::InvalidFormat);
        }
        Ok(Self {
            runtime_contract_version,
            adapter_build_sha256,
            template,
            policy,
            compatibility_id,
        })
    }

    pub const fn runtime_contract_version(&self) -> u16 {
        self.runtime_contract_version
    }

    pub const fn adapter_build_sha256(&self) -> &Sha256Digest {
        &self.adapter_build_sha256
    }

    pub const fn template(&self) -> &TemplateIdentity {
        &self.template
    }

    pub const fn policy(&self) -> &PolicyIdentity {
        &self.policy
    }

    pub fn compatibility_id(&self) -> &str {
        &self.compatibility_id
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AssetBundleWire {
    runtime_contract_version: u16,
    adapter_build_sha256: Sha256Digest,
    template: TemplateIdentity,
    policy: PolicyIdentity,
    compatibility_id: String,
}

impl TryFrom<AssetBundleWire> for AssetBundleIdentity {
    type Error = ProtocolValidationError;

    fn try_from(value: AssetBundleWire) -> Result<Self, Self::Error> {
        Self::new(
            value.runtime_contract_version,
            value.adapter_build_sha256,
            value.template,
            value.policy,
            value.compatibility_id,
        )
    }
}

impl From<AssetBundleIdentity> for AssetBundleWire {
    fn from(value: AssetBundleIdentity) -> Self {
        Self {
            runtime_contract_version: value.runtime_contract_version,
            adapter_build_sha256: value.adapter_build_sha256,
            template: value.template,
            policy: value.policy,
            compatibility_id: value.compatibility_id,
        }
    }
}
