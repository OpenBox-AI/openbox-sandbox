//! `OpenShell` reference adapter for the provider-neutral sandbox runtime.
//!
//! This crate talks directly to the pinned `OpenShell` protobuf API over an authenticated tonic
//! mTLS channel. It never invokes or parses the `OpenShell` CLI.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod budget;
mod config;
#[cfg(test)]
mod conformance_tests;
mod error;
mod exec;
mod operations;
mod policy;
mod provider;
mod transport;

use core::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    CleanupFailure, CleanupTarget, CreateFailure, CreateRequest, CreatedSandbox, DeleteOutcome,
    ExecCompleted, ExecFailure, ExecRequest, OperationContext, PolicyIdentity, ReadinessFailure,
    ReadySandbox, SandboxRuntime,
};
use async_trait::async_trait;
use transport::{OpenShellTransport, TonicOpenShellTransport};

pub use config::OpenShellConfig;
pub use error::{OpenShellConnectError, OpenShellConnectErrorCode};

/// Exact `OpenShell` source commit accepted by this adapter build.
pub const OPENSHELL_SOURCE_PIN: &str = env!("OPENBOX_OPENSHELL_SOURCE_PIN");

/// Direct raw-protocol `OpenShell` implementation of [`SandboxRuntime`].
#[derive(Clone)]
pub struct OpenShellRuntime {
    transport: Arc<dyn OpenShellTransport>,
    poll_interval: Duration,
}

impl OpenShellRuntime {
    /// Establishes the authenticated mTLS channel without invoking the `OpenShell` CLI.
    pub async fn connect(config: OpenShellConfig) -> Result<Self, OpenShellConnectError> {
        let poll_interval = config.poll_interval();
        let channel = config.connect_channel().await?;
        Ok(Self {
            transport: Arc::new(TonicOpenShellTransport::new(channel)),
            poll_interval,
        })
    }

    #[cfg(test)]
    fn from_transport(transport: Arc<dyn OpenShellTransport>, poll_interval: Duration) -> Self {
        Self {
            transport,
            poll_interval,
        }
    }

    fn transport(&self) -> &dyn OpenShellTransport {
        self.transport.as_ref()
    }

    const fn poll_interval(&self) -> Duration {
        self.poll_interval
    }
}

impl fmt::Debug for OpenShellRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenShellRuntime")
            .field("transport", &"authenticated_mtls")
            .field("poll_interval", &self.poll_interval)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SandboxRuntime for OpenShellRuntime {
    async fn create(
        &self,
        request: CreateRequest,
        context: OperationContext,
    ) -> Result<CreatedSandbox, CreateFailure> {
        operations::create(self, request, context).await
    }

    async fn wait_ready(
        &self,
        sandbox: CreatedSandbox,
        expected_policy: PolicyIdentity,
        context: OperationContext,
    ) -> Result<ReadySandbox, ReadinessFailure> {
        operations::wait_ready(self, sandbox, expected_policy, context).await
    }

    async fn exec(
        &self,
        sandbox: ReadySandbox,
        request: ExecRequest,
        context: OperationContext,
    ) -> Result<ExecCompleted, ExecFailure> {
        operations::exec(self, sandbox, request, context).await
    }

    async fn delete(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<DeleteOutcome, CleanupFailure> {
        operations::delete(self, target, context).await
    }

    async fn wait_deleted(
        &self,
        target: CleanupTarget,
        context: OperationContext,
    ) -> Result<(), CleanupFailure> {
        operations::wait_deleted(self, target, context).await
    }
}
