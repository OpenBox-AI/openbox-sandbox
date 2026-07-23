//! Input validation errors that never echo rejected values.

use core::fmt;

/// Stable reason codes for rejected contract values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum ValidationCode {
    /// A required value was empty.
    Empty,
    /// A value had an invalid representation.
    InvalidFormat,
    /// A numeric value was outside its permitted range.
    OutOfRange,
    /// A byte or text value had an invalid length.
    InvalidLength,
    /// A collection or combination of fields violated an invariant.
    InvalidCombination,
}

/// A redacted validation failure.
///
/// The rejected value is intentionally never retained, displayed, or debugged.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(deny_unknown_fields)
)]
pub struct ValidationError {
    field: String,
    code: ValidationCode,
}

impl ValidationError {
    pub(crate) fn new(field: &'static str, code: ValidationCode) -> Self {
        Self {
            field: field.to_owned(),
            code,
        }
    }

    /// Returns the stable field name that failed validation.
    pub fn field(&self) -> &str {
        &self.field
    }

    /// Returns the stable reason code.
    pub const fn code(&self) -> ValidationCode {
        self.code
    }
}

impl fmt::Debug for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidationError")
            .field("field", &self.field)
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid {}: {:?}", self.field, self.code)
    }
}

impl std::error::Error for ValidationError {}
