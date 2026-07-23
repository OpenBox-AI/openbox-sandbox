use core::fmt;

use sha2::{Digest as _, Sha256};

#[derive(Clone, Eq, Hash, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct CallerFingerprint(String);

impl CallerFingerprint {
    pub fn from_certificate_der(der: &[u8]) -> Result<Self, AuthValueError> {
        if der.is_empty() {
            return Err(AuthValueError);
        }
        let digest = Sha256::digest(der);
        let mut value = String::with_capacity(64);
        for byte in digest {
            use core::fmt::Write as _;
            write!(value, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, AuthValueError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AuthValueError);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CallerFingerprint {
    type Error = AuthValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<CallerFingerprint> for String {
    fn from(value: CallerFingerprint) -> Self {
        value.0
    }
}

impl fmt::Debug for CallerFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CallerFingerprint(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthValueError;

impl fmt::Display for AuthValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid authentication value")
    }
}

impl std::error::Error for AuthValueError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallerRole {
    Runtime,
    Administrator,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallerIdentity {
    fingerprint: CallerFingerprint,
    role: CallerRole,
}

impl CallerIdentity {
    pub const fn new(fingerprint: CallerFingerprint, role: CallerRole) -> Self {
        Self { fingerprint, role }
    }

    pub const fn fingerprint(&self) -> &CallerFingerprint {
        &self.fingerprint
    }

    pub const fn role(&self) -> CallerRole {
        self.role
    }
}
