#![forbid(unsafe_code)]
//! Provider-neutral remote client for the authenticated sandbox service.

mod client;
mod config;
mod transport;

pub use client::SandboxRuntimeClient;
pub use config::{ClientConfigError, SandboxRuntimeClientConfig};
pub use transport::{CallFailure, CallFailureKind, ServiceTransport, SubmissionState};
