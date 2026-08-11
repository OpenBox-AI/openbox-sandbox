//! Explicit `sbx` CLI configuration for the Docker Sandboxes runtime.

use core::fmt;
use std::path::PathBuf;
use std::time::Duration;

use crate::docker_sandboxes::error::{SbxConnectError, SbxConnectErrorCode};
use crate::docker_sandboxes::policy::validate_template;
use crate::runtime_contract::TemplateIdentity;
use crate::{Argv, PolicyIdentity, SANDBOX_WORKDIR};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Explicit Docker Sandboxes runtime configuration.
///
/// The `sbx` binary may be a bare name resolved from `PATH` or an absolute
/// path; the workspace is the host directory mounted into every sandbox at
/// its host absolute path.
#[derive(Clone, Eq, PartialEq)]
pub struct DockerSandboxesConfig {
    sbx_binary: PathBuf,
    workspace: PathBuf,
    template: Option<TemplateIdentity>,
    policy: Option<PolicyIdentity>,
    exec_user: Option<String>,
    exec_workdir: String,
    readiness_probe: Option<Argv>,
    connect_timeout: Duration,
    poll_interval: Duration,
}

impl DockerSandboxesConfig {
    /// Creates a configuration from the `sbx` binary and workspace.
    pub fn new(
        sbx_binary: impl Into<PathBuf>,
        workspace: impl Into<PathBuf>,
    ) -> Result<Self, SbxConnectError> {
        let sbx_binary = sbx_binary.into();
        let workspace = workspace.into();
        if sbx_binary.as_os_str().is_empty()
            || workspace.as_os_str().is_empty()
            || !workspace.is_absolute()
            || invalid_binary_reference(&sbx_binary)
        {
            return Err(SbxConnectError::new(
                SbxConnectErrorCode::InvalidConfiguration,
            ));
        }
        Ok(Self {
            sbx_binary,
            workspace,
            template: None,
            policy: None,
            exec_user: None,
            exec_workdir: SANDBOX_WORKDIR.to_owned(),
            readiness_probe: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            poll_interval: DEFAULT_POLL_INTERVAL,
        })
    }

    /// Pins the immutable template image that every create request must carry.
    ///
    /// When set, a create request whose template differs is rejected before
    /// submission. When unset, the create request's template is used directly.
    pub fn with_template(mut self, template: impl Into<String>) -> Result<Self, SbxConnectError> {
        let template = TemplateIdentity::new(template)
            .map_err(|_| SbxConnectError::new(SbxConnectErrorCode::InvalidConfiguration))?;
        validate_template(&template)
            .map_err(|()| SbxConnectError::new(SbxConnectErrorCode::InvalidConfiguration))?;
        self.template = Some(template);
        Ok(self)
    }

    /// Pins the exact policy identity that readiness must attest.
    ///
    /// When set, readiness fails with `PolicyMismatch` unless the request's
    /// expected policy matches this deployment-pinned identity exactly.
    #[must_use]
    pub fn with_policy(mut self, policy: PolicyIdentity) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Sets the user (or `uid[:gid]`) passed to `sbx exec --user`.
    ///
    /// When unset, the sandbox image's default user is used.
    pub fn with_exec_user(mut self, user: impl Into<String>) -> Result<Self, SbxConnectError> {
        let user = user.into();
        if !valid_exec_user(&user) {
            return Err(SbxConnectError::new(
                SbxConnectErrorCode::InvalidConfiguration,
            ));
        }
        self.exec_user = Some(user);
        Ok(self)
    }

    /// Sets the working directory passed to `sbx exec --workdir`.
    ///
    /// Defaults to the runtime-contract [`SANDBOX_WORKDIR`].
    pub fn with_exec_workdir(
        mut self,
        workdir: impl Into<String>,
    ) -> Result<Self, SbxConnectError> {
        let workdir = workdir.into();
        if !workdir.starts_with('/') || workdir.contains('\0') {
            return Err(SbxConnectError::new(
                SbxConnectErrorCode::InvalidConfiguration,
            ));
        }
        self.exec_workdir = workdir;
        Ok(self)
    }

    /// Sets an optional readiness probe executed once the sandbox is running.
    ///
    /// When set, readiness is attested only after the probe exits zero.
    pub fn with_readiness_probe(mut self, probe: Option<Argv>) -> Result<Self, SbxConnectError> {
        if probe
            .as_ref()
            .is_some_and(|argv| argv.as_slice().iter().any(|element| element.contains('\0')))
        {
            return Err(SbxConnectError::new(
                SbxConnectErrorCode::InvalidConfiguration,
            ));
        }
        self.readiness_probe = probe;
        Ok(self)
    }

    /// Replaces the `sbx version` probe timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Result<Self, SbxConnectError> {
        if timeout.is_zero() {
            return Err(SbxConnectError::new(
                SbxConnectErrorCode::InvalidConfiguration,
            ));
        }
        self.connect_timeout = timeout;
        Ok(self)
    }

    /// Replaces the readiness and deletion polling interval.
    pub fn with_poll_interval(mut self, interval: Duration) -> Result<Self, SbxConnectError> {
        if interval.is_zero() {
            return Err(SbxConnectError::new(
                SbxConnectErrorCode::InvalidConfiguration,
            ));
        }
        self.poll_interval = interval;
        Ok(self)
    }

    /// Returns the configured `sbx` binary path or bare name.
    pub fn sbx_binary(&self) -> &std::path::Path {
        &self.sbx_binary
    }

    /// Returns the host workspace mounted into every sandbox.
    pub fn workspace(&self) -> &std::path::Path {
        &self.workspace
    }

    pub(crate) const fn template(&self) -> Option<&TemplateIdentity> {
        self.template.as_ref()
    }

    pub(crate) const fn policy(&self) -> Option<&PolicyIdentity> {
        self.policy.as_ref()
    }

    pub(crate) fn exec_user(&self) -> Option<&str> {
        self.exec_user.as_deref()
    }

    pub(crate) fn exec_workdir(&self) -> &str {
        &self.exec_workdir
    }

    pub(crate) const fn readiness_probe(&self) -> Option<&Argv> {
        self.readiness_probe.as_ref()
    }

    pub(crate) const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    pub(crate) const fn poll_interval(&self) -> Duration {
        self.poll_interval
    }
}

impl fmt::Debug for DockerSandboxesConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerSandboxesConfig")
            .field("sbx_binary", &self.sbx_binary)
            .field("workspace", &self.workspace)
            .field(
                "template",
                &self.template.as_ref().map(TemplateIdentity::as_str),
            )
            .field("policy", &self.policy)
            .field("exec_user", &self.exec_user)
            .field("exec_workdir", &self.exec_workdir)
            .field("has_readiness_probe", &self.readiness_probe.is_some())
            .field("connect_timeout", &self.connect_timeout)
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

fn invalid_binary_reference(path: &std::path::Path) -> bool {
    let value = path.to_string_lossy();
    value.contains('\0')
        || (!path.is_absolute()
            && value
                .chars()
                .any(|character| character == '/' || character.is_whitespace()))
}

fn valid_exec_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 128
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Sha256Digest, TemplateIdentity};

    #[test]
    fn configuration_rejects_empty_and_invalid_values() {
        assert_eq!(
            DockerSandboxesConfig::new("", "/workspace")
                .unwrap_err()
                .code(),
            SbxConnectErrorCode::InvalidConfiguration
        );
        assert_eq!(
            DockerSandboxesConfig::new("sbx", "").unwrap_err().code(),
            SbxConnectErrorCode::InvalidConfiguration
        );
        assert_eq!(
            DockerSandboxesConfig::new("sbx", "relative")
                .unwrap_err()
                .code(),
            SbxConnectErrorCode::InvalidConfiguration
        );
        assert_eq!(
            DockerSandboxesConfig::new("sb x", "/workspace")
                .unwrap_err()
                .code(),
            SbxConnectErrorCode::InvalidConfiguration
        );

        let config = DockerSandboxesConfig::new("sbx", "/workspace").unwrap();
        assert!(config.clone().with_exec_user("not valid").is_err());
        assert!(config.clone().with_exec_user("not valid").is_err());
        assert!(config.clone().with_exec_user("/abs/path").is_err());
        assert!(config.clone().with_exec_workdir("relative").is_err());
        assert!(config.clone().with_connect_timeout(Duration::ZERO).is_err());
        assert!(config.clone().with_poll_interval(Duration::ZERO).is_err());
        assert!(
            config
                .with_readiness_probe(Some(Argv::new(vec!["true".to_owned()]).unwrap()))
                .is_ok()
        );
    }

    #[test]
    fn template_pin_requires_an_immutable_reference() {
        let config = DockerSandboxesConfig::new("sbx", "/workspace").unwrap();
        assert!(
            config
                .clone()
                .with_template("example.invalid/proof:latest")
                .is_err()
        );
        let pinned = config
            .with_template(format!("example.invalid/proof@sha256:{}", "a".repeat(64)))
            .unwrap();
        let request_template =
            TemplateIdentity::new(format!("example.invalid/proof@sha256:{}", "a".repeat(64)))
                .unwrap();
        assert_eq!(pinned.template().unwrap(), &request_template);
    }

    #[test]
    fn exec_user_accepts_names_uids_and_groups() {
        let config = DockerSandboxesConfig::new("sbx", "/workspace").unwrap();
        for user in ["sandbox", "0", "1000:1000", "sandbox:sandbox", "root"] {
            assert!(config.clone().with_exec_user(user).is_ok(), "{user}");
        }
        for user in ["", "sand box", "sandbox/root", "a;rm", "\u{0}"] {
            assert!(config.clone().with_exec_user(user).is_err(), "{user:?}");
        }
    }

    #[test]
    fn policy_pin_round_trips_through_the_configuration() {
        let config = DockerSandboxesConfig::new("sbx", "/workspace").unwrap();
        let policy = PolicyIdentity::new(
            "openbox-deny-network",
            1,
            Sha256Digest::parse("a".repeat(64)).unwrap(),
        )
        .unwrap();
        let pinned = config.with_policy(policy.clone());
        assert_eq!(pinned.policy(), Some(&policy));
    }

    #[test]
    fn debug_output_does_not_include_credential_material() {
        let config = DockerSandboxesConfig::new("sbx", "/workspace").unwrap();
        let printed = format!("{config:?}");
        assert!(!printed.contains("policy_identity") || printed.contains("PolicyIdentity"));
    }
}
