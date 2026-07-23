use core::fmt;
use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{Mode, OFlags, open};
use rustix::process::geteuid;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use crate::{OpenShellConnectError, OpenShellConnectErrorCode};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Explicit local mTLS transport configuration for the pinned `OpenShell` gateway.
#[derive(Clone, Eq, PartialEq)]
pub struct OpenShellConfig {
    endpoint: String,
    mtls_directory: PathBuf,
    connect_timeout: Duration,
    poll_interval: Duration,
}

impl OpenShellConfig {
    /// Creates an explicit gateway configuration with conservative local defaults.
    pub fn new(
        endpoint: impl Into<String>,
        mtls_directory: impl Into<PathBuf>,
    ) -> Result<Self, OpenShellConnectError> {
        let endpoint = endpoint.into();
        let mtls_directory = mtls_directory.into();
        if endpoint.is_empty() || mtls_directory.as_os_str().is_empty() {
            return Err(OpenShellConnectError::new(
                OpenShellConnectErrorCode::InvalidConfiguration,
            ));
        }
        Ok(Self {
            endpoint,
            mtls_directory,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            poll_interval: DEFAULT_POLL_INTERVAL,
        })
    }

    /// Replaces the channel connection timeout.
    pub fn with_connect_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<Self, OpenShellConnectError> {
        if timeout.is_zero() {
            return Err(OpenShellConnectError::new(
                OpenShellConnectErrorCode::InvalidConfiguration,
            ));
        }
        self.connect_timeout = timeout;
        Ok(self)
    }

    /// Replaces the readiness and deletion polling interval.
    pub fn with_poll_interval(mut self, interval: Duration) -> Result<Self, OpenShellConnectError> {
        if interval.is_zero() {
            return Err(OpenShellConnectError::new(
                OpenShellConnectErrorCode::InvalidConfiguration,
            ));
        }
        self.poll_interval = interval;
        Ok(self)
    }

    /// Returns the configured endpoint without credential material.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) const fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    pub(crate) async fn connect_channel(&self) -> Result<Channel, OpenShellConnectError> {
        validate_credential_directory(&self.mtls_directory)?;
        let ca = read_credential(&self.mtls_directory, "ca.crt", false)?;
        let certificate = read_credential(&self.mtls_directory, "tls.crt", false)?;
        let key = read_credential(&self.mtls_directory, "tls.key", true)?;
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(certificate, key));
        let endpoint = Endpoint::from_shared(self.endpoint.clone())
            .map_err(|_| {
                OpenShellConnectError::new(OpenShellConnectErrorCode::TransportConfiguration)
            })?
            .connect_timeout(self.connect_timeout)
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(Duration::from_secs(10))
            .keep_alive_while_idle(true)
            .tls_config(tls)
            .map_err(|_| {
                OpenShellConnectError::new(OpenShellConnectErrorCode::TransportConfiguration)
            })?;
        endpoint
            .connect()
            .await
            .map_err(|_| OpenShellConnectError::new(OpenShellConnectErrorCode::Connect))
    }
}

impl fmt::Debug for OpenShellConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenShellConfig")
            .field("endpoint", &self.endpoint)
            .field("mtls_directory", &"<redacted>")
            .field("connect_timeout", &self.connect_timeout)
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

fn validate_credential_directory(directory: &Path) -> Result<(), OpenShellConnectError> {
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|_| OpenShellConnectError::new(OpenShellConnectErrorCode::CredentialRead))?;
    if !directory.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(OpenShellConnectError::new(
            OpenShellConnectErrorCode::CredentialRead,
        ));
    }
    Ok(())
}

fn read_credential(
    directory: &Path,
    name: &str,
    private: bool,
) -> Result<Vec<u8>, OpenShellConnectError> {
    let path = directory.join(name);
    let descriptor = open(
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| OpenShellConnectError::new(OpenShellConnectErrorCode::CredentialRead))?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| OpenShellConnectError::new(OpenShellConnectErrorCode::CredentialRead))?;
    let mode = metadata.mode() & 0o777;
    if !metadata.is_file()
        || metadata.uid() != geteuid().as_raw()
        || metadata.len() == 0
        || metadata.len() > 1024 * 1024
        || (private && mode != 0o600)
        || (!private && mode & 0o022 != 0)
    {
        return Err(OpenShellConnectError::new(
            OpenShellConnectErrorCode::CredentialRead,
        ));
    }
    let mut value = Vec::with_capacity(
        usize::try_from(metadata.len())
            .map_err(|_| OpenShellConnectError::new(OpenShellConnectErrorCode::CredentialRead))?,
    );
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut value)
        .map_err(|_| OpenShellConnectError::new(OpenShellConnectErrorCode::CredentialRead))?;
    if u64::try_from(value.len()).ok() != Some(metadata.len()) {
        return Err(OpenShellConnectError::new(
            OpenShellConnectErrorCode::CredentialRead,
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_rejects_empty_values_and_redacts_credential_path() {
        assert_eq!(
            OpenShellConfig::new("", "/credentials").unwrap_err().code(),
            OpenShellConnectErrorCode::InvalidConfiguration
        );
        assert_eq!(
            OpenShellConfig::new("https://127.0.0.1:17670", "")
                .unwrap_err()
                .code(),
            OpenShellConnectErrorCode::InvalidConfiguration
        );
        let config =
            OpenShellConfig::new("https://127.0.0.1:17670", "/sensitive/client/credentials")
                .unwrap();
        assert!(!format!("{config:?}").contains("/sensitive"));
    }

    #[test]
    fn credential_files_require_owner_only_directory_and_private_key() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().canonicalize().unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, mode) in [("ca.crt", 0o644), ("tls.crt", 0o644), ("tls.key", 0o600)] {
            let path = directory.join(name);
            std::fs::write(&path, b"credential").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        validate_credential_directory(&directory).unwrap();
        assert_eq!(
            read_credential(&directory, "tls.key", true).unwrap(),
            b"credential"
        );

        std::fs::set_permissions(
            directory.join("tls.key"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(read_credential(&directory, "tls.key", true).is_err());
    }

    #[test]
    fn configuration_rejects_zero_transport_durations() {
        let config = OpenShellConfig::new("https://127.0.0.1:17670", "/credentials").unwrap();
        assert_eq!(
            config
                .clone()
                .with_connect_timeout(Duration::ZERO)
                .unwrap_err()
                .code(),
            OpenShellConnectErrorCode::InvalidConfiguration
        );
        assert_eq!(
            config
                .with_poll_interval(Duration::ZERO)
                .unwrap_err()
                .code(),
            OpenShellConnectErrorCode::InvalidConfiguration
        );
    }
}
