#![forbid(unsafe_code)]
//! Authenticated, durable, provider-neutral sandbox service boundary.

mod auth;
mod boundary;
mod server;
mod store;

pub use auth::{AuthValueError, CallerFingerprint, CallerIdentity, CallerRole};
pub use boundary::{ReconciliationReport, SandboxServiceBoundary};
pub use server::{SandboxTlsServer, ServerError, TlsServerConfig};
pub use store::{DurableRecord, DurableStage, DurableStore, StoreError};
