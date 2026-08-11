//! `Docker Sandboxes` reference adapter for the provider-neutral sandbox
//! runtime.
//!
//! This adapter drives Docker's standalone `sbx` CLI (Docker Sandboxes) as a
//! sandbox execution runtime. Each sandbox is a microVM with its own Docker
//! daemon, filesystem, and network; the CLI talks to the local `sandboxd`
//! daemon, and this crate drives the CLI as a subprocess. There is no
//! documented third-party daemon API, so every lifecycle operation maps onto
//! a `sbx` command:
//!
//! - create → `sbx create --name <request-id> --template <image> shell <workspace>`
//!   with an `sbx ls --json` ownership preflight;
//! - wait-ready → poll `sbx ls --json` until `running` (and optionally a
//!   readiness probe), attesting the deployment-pinned policy identity;
//! - exec → one `sbx exec --workdir <dir> <name> <argv...>` with the exec
//!   deadline and output ceilings enforced by this adapter;
//! - delete → `sbx rm --force <name>`; wait-deleted → poll until absent.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod config;
#[cfg(test)]
mod conformance_tests;
mod error;
mod operations;
mod policy;
mod process;
mod provider;
mod runner;

use std::sync::Arc;
use std::time::Duration;

use crate::docker_sandboxes::process::{parse_sbx_version, supported_sbx_version};
use crate::{
    CleanupFailure, CleanupTarget, CreateFailure, CreateRequest, CreatedSandbox, DeleteOutcome,
    ExecCompleted, ExecFailure, ExecRequest, OperationContext, PolicyIdentity, ReadinessFailure,
    ReadySandbox, SandboxRuntime,
};
use async_trait::async_trait;
use runner::{ProcessSbxRunner, SbxRunFailure, SbxRunner};

pub use config::DockerSandboxesConfig;
pub use error::{SbxConnectError, SbxConnectErrorCode};

/// Direct `sbx` CLI implementation of [`SandboxRuntime`].
#[derive(Clone)]
pub struct DockerSandboxesRuntime {
    config: DockerSandboxesConfig,
    runner: Arc<dyn SbxRunner>,
}

impl DockerSandboxesRuntime {
    /// Probes the installed `sbx` CLI version and constructs the runtime.
    ///
    /// The probe runs `sbx version` bounded by the configured connect timeout
    /// and rejects versions older than the supported baseline. It does not
    /// require a Docker account (the version command is local); authenticated
    /// sandbox operations surface as typed failures at operation time.
    pub async fn connect(config: DockerSandboxesConfig) -> Result<Self, SbxConnectError> {
        let binary = config.sbx_binary().to_owned();
        let runner = ProcessSbxRunner::new(binary);
        let output = match runner.version(config.connect_timeout()).await {
            Ok(output) => output,
            Err(SbxRunFailure::Spawn) => {
                return Err(SbxConnectError::new(SbxConnectErrorCode::BinaryUnavailable));
            }
            Err(
                SbxRunFailure::Cancelled | SbxRunFailure::Deadline | SbxRunFailure::NonZero { .. },
            ) => {
                return Err(SbxConnectError::new(
                    SbxConnectErrorCode::VersionProbeFailed,
                ));
            }
        };
        let version = parse_sbx_version(&output)
            .ok_or_else(|| SbxConnectError::new(SbxConnectErrorCode::VersionProbeFailed))?;
        if !supported_sbx_version(version) {
            return Err(SbxConnectError::new(
                SbxConnectErrorCode::UnsupportedVersion,
            ));
        }
        Ok(Self {
            config,
            runner: Arc::new(runner),
        })
    }

    #[cfg(test)]
    fn from_runner(config: DockerSandboxesConfig, runner: Arc<dyn SbxRunner>) -> Self {
        Self { config, runner }
    }

    pub(crate) fn config(&self) -> &DockerSandboxesConfig {
        &self.config
    }

    pub(crate) fn runner(&self) -> &dyn SbxRunner {
        self.runner.as_ref()
    }

    pub(crate) const fn poll_interval(&self) -> Duration {
        self.config.poll_interval()
    }
}

impl core::fmt::Debug for DockerSandboxesRuntime {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DockerSandboxesRuntime")
            .field("config", &self.config)
            .field("runner", &"sbx_cli")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SandboxRuntime for DockerSandboxesRuntime {
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use super::*;

    fn fake_sbx(root: &Path, version: &str) -> std::path::PathBuf {
        let path = root.join("fake-sbx");
        std::fs::write(&path, format!("#!/bin/sh\necho '{version}'\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[tokio::test]
    async fn connect_accepts_a_supported_version_probe() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let binary = fake_sbx(
            &root,
            "sbx version: v0.38.0 c022b14634c4bea846ca12870d1d5e97d5868b54",
        );
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let config = DockerSandboxesConfig::new(binary.clone(), workspace)
            .unwrap()
            .with_connect_timeout(Duration::from_secs(10))
            .unwrap();
        let runtime = DockerSandboxesRuntime::connect(config).await.unwrap();
        assert_eq!(runtime.config().sbx_binary(), binary);
        assert!(!format!("{runtime:?}").contains("0.38"));
    }

    #[tokio::test]
    async fn connect_rejects_unsupported_old_versions() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let binary = fake_sbx(&root, "sbx version: v0.30.0 old");
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let config = DockerSandboxesConfig::new(binary, workspace).unwrap();
        assert_eq!(
            DockerSandboxesRuntime::connect(config)
                .await
                .unwrap_err()
                .code(),
            SbxConnectErrorCode::UnsupportedVersion
        );
    }

    #[tokio::test]
    async fn connect_reports_missing_binary_and_garbled_probes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let missing =
            DockerSandboxesConfig::new(root.join("absent-sbx"), workspace.clone()).unwrap();
        assert_eq!(
            DockerSandboxesRuntime::connect(missing)
                .await
                .unwrap_err()
                .code(),
            SbxConnectErrorCode::BinaryUnavailable
        );

        let garbled = DockerSandboxesConfig::new(fake_sbx(&root, "not a version"), workspace);
        assert_eq!(
            DockerSandboxesRuntime::connect(garbled.unwrap())
                .await
                .unwrap_err()
                .code(),
            SbxConnectErrorCode::VersionProbeFailed
        );
    }
}
