use core::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::AssetBundleIdentity;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls_pki_types::pem::PemObject as _;
use tokio_rustls::TlsConnector;

#[derive(Clone)]
pub struct SandboxRuntimeClientConfig {
    endpoint: SocketAddr,
    server_name: String,
    ca_path: PathBuf,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    asset_bundle: AssetBundleIdentity,
}

impl fmt::Debug for SandboxRuntimeClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxRuntimeClientConfig")
            .field("endpoint", &self.endpoint)
            .field("server_name", &self.server_name)
            .field("credentials", &"<redacted>")
            .field("asset_bundle", &self.asset_bundle)
            .finish()
    }
}

impl SandboxRuntimeClientConfig {
    pub fn new(
        endpoint: SocketAddr,
        server_name: impl Into<String>,
        ca_path: impl Into<PathBuf>,
        certificate_path: impl Into<PathBuf>,
        private_key_path: impl Into<PathBuf>,
        asset_bundle: AssetBundleIdentity,
    ) -> Result<Self, ClientConfigError> {
        let server_name = server_name.into();
        let ca_path = ca_path.into();
        let certificate_path = certificate_path.into();
        let private_key_path = private_key_path.into();
        if !endpoint.ip().is_loopback()
            || endpoint.port() == 0
            || server_name.is_empty()
            || [&ca_path, &certificate_path, &private_key_path]
                .iter()
                .any(|path| path.as_os_str().is_empty())
            || ServerName::try_from(server_name.clone()).is_err()
        {
            return Err(ClientConfigError);
        }
        Ok(Self {
            endpoint,
            server_name,
            ca_path,
            certificate_path,
            private_key_path,
            asset_bundle,
        })
    }

    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub const fn asset_bundle(&self) -> &AssetBundleIdentity {
        &self.asset_bundle
    }

    pub(crate) fn connector(
        &self,
    ) -> Result<(TlsConnector, ServerName<'static>), ClientConfigError> {
        let roots = read_roots(&self.ca_path)?;
        let certificates = read_certificates(&self.certificate_path)?;
        let private_key = read_private_key(&self.private_key_path)?;
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ClientConfigError)?
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, private_key)
        .map_err(|_| ClientConfigError)?;
        let server_name =
            ServerName::try_from(self.server_name.clone()).map_err(|_| ClientConfigError)?;
        Ok((TlsConnector::from(Arc::new(config)), server_name))
    }
}

fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, ClientConfigError> {
    let certificates = CertificateDer::pem_file_iter(path)
        .map_err(|_| ClientConfigError)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ClientConfigError)?;
    if certificates.is_empty() {
        return Err(ClientConfigError);
    }
    Ok(certificates)
}

fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, ClientConfigError> {
    PrivateKeyDer::from_pem_file(path).map_err(|_| ClientConfigError)
}

fn read_roots(path: &Path) -> Result<RootCertStore, ClientConfigError> {
    let certificates = read_certificates(path)?;
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(|_| ClientConfigError)?;
    }
    if roots.is_empty() {
        return Err(ClientConfigError);
    }
    Ok(roots)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientConfigError;

impl fmt::Display for ClientConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sandbox runtime client configuration rejected")
    }
}

impl std::error::Error for ClientConfigError {}
