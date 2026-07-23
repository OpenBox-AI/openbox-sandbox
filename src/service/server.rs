use core::fmt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::{read_request, write_response};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject as _;
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{CallerFingerprint, CallerIdentity, CallerRole, SandboxServiceBoundary};

#[derive(Clone, Debug)]
pub struct TlsServerConfig {
    bind_address: SocketAddr,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    client_ca_path: PathBuf,
    authorized_callers: HashMap<CallerFingerprint, CallerRole>,
    maximum_connections: usize,
    drain_timeout: Duration,
}

impl TlsServerConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bind_address: SocketAddr,
        certificate_path: impl Into<PathBuf>,
        private_key_path: impl Into<PathBuf>,
        client_ca_path: impl Into<PathBuf>,
        authorized_callers: HashMap<CallerFingerprint, CallerRole>,
        maximum_connections: usize,
        drain_timeout: Duration,
    ) -> Result<Self, ServerError> {
        if !bind_address.ip().is_loopback()
            || authorized_callers.is_empty()
            || maximum_connections == 0
            || drain_timeout.is_zero()
        {
            return Err(ServerError::Configuration);
        }
        let certificate_path = certificate_path.into();
        let private_key_path = private_key_path.into();
        let client_ca_path = client_ca_path.into();
        if [&certificate_path, &private_key_path, &client_ca_path]
            .iter()
            .any(|path| path.as_os_str().is_empty())
        {
            return Err(ServerError::Configuration);
        }
        Ok(Self {
            bind_address,
            certificate_path,
            private_key_path,
            client_ca_path,
            authorized_callers,
            maximum_connections,
            drain_timeout,
        })
    }

    pub const fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }
}

pub struct SandboxTlsServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    boundary: Arc<SandboxServiceBoundary>,
    authorized_callers: Arc<HashMap<CallerFingerprint, CallerRole>>,
    maximum_connections: usize,
    drain_timeout: Duration,
}

impl SandboxTlsServer {
    pub async fn bind(
        config: TlsServerConfig,
        boundary: Arc<SandboxServiceBoundary>,
    ) -> Result<Self, ServerError> {
        let listener = TcpListener::bind(config.bind_address)
            .await
            .map_err(|_| ServerError::Bind)?;
        Self::from_listener(config, listener, boundary)
    }

    pub fn from_std_listener(
        config: TlsServerConfig,
        listener: std::net::TcpListener,
        boundary: Arc<SandboxServiceBoundary>,
    ) -> Result<Self, ServerError> {
        let address = listener.local_addr().map_err(|_| ServerError::Bind)?;
        if !address.ip().is_loopback() {
            return Err(ServerError::Configuration);
        }
        listener
            .set_nonblocking(true)
            .map_err(|_| ServerError::Bind)?;
        let listener = TcpListener::from_std(listener).map_err(|_| ServerError::Bind)?;
        Self::from_listener(config, listener, boundary)
    }

    fn from_listener(
        config: TlsServerConfig,
        listener: TcpListener,
        boundary: Arc<SandboxServiceBoundary>,
    ) -> Result<Self, ServerError> {
        let tls = load_tls_config(&config)?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            boundary,
            authorized_callers: Arc::new(config.authorized_callers),
            maximum_connections: config.maximum_connections,
            drain_timeout: config.drain_timeout,
        })
    }

    pub fn local_address(&self) -> Result<SocketAddr, ServerError> {
        self.listener.local_addr().map_err(|_| ServerError::Bind)
    }

    pub async fn run(self, shutdown: CancellationToken) -> Result<(), ServerError> {
        let semaphore = Arc::new(Semaphore::new(self.maximum_connections));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    self.boundary.start_draining();
                    break;
                }
                accepted = self.listener.accept() => {
                    let (stream, peer) = accepted.map_err(|_| ServerError::Accept)?;
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                        continue;
                    };
                    let acceptor = self.acceptor.clone();
                    let boundary = self.boundary.clone();
                    let authorized = self.authorized_callers.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ = handle_connection(stream, acceptor, boundary, authorized).await;
                    });
                }
            }
        }

        let drained = tokio::time::timeout(self.drain_timeout, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_ok();
        if !drained {
            self.boundary.cancel_all_operations().await;
            // Cancellation is an ownership-aware cleanup request, not permission
            // to abandon a possibly-created sandbox. Runtime operation budgets
            // bound this wait; durable records remain the restart backstop.
            while tasks.join_next().await.is_some() {}
        }
        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    boundary: Arc<SandboxServiceBoundary>,
    authorized: Arc<HashMap<CallerFingerprint, CallerRole>>,
) -> Result<(), ServerError> {
    let tls = acceptor
        .accept(stream)
        .await
        .map_err(|_| ServerError::Tls)?;
    let certificates = tls
        .get_ref()
        .1
        .peer_certificates()
        .ok_or(ServerError::Authentication)?;
    let leaf = certificates.first().ok_or(ServerError::Authentication)?;
    let fingerprint = CallerFingerprint::from_certificate_der(leaf.as_ref())
        .map_err(|_| ServerError::Authentication)?;
    let role = authorized
        .get(&fingerprint)
        .copied()
        .ok_or(ServerError::Authorization)?;
    let caller = CallerIdentity::new(fingerprint, role);
    let (mut reader, mut writer) = tokio::io::split(tls);
    let request = read_request(&mut reader)
        .await
        .map_err(|_| ServerError::Protocol)?;
    let operation_id = request.operation_id().clone();
    let handling = boundary.handle(&caller, request);
    tokio::pin!(handling);
    let response = tokio::select! {
        response = &mut handling => response,
        _ = reader.read_u8() => {
            boundary.cancel_operation(&operation_id).await;
            handling.await
        }
    };
    write_response(&mut writer, &response)
        .await
        .map_err(|_| ServerError::Protocol)
}

fn load_tls_config(config: &TlsServerConfig) -> Result<rustls::ServerConfig, ServerError> {
    let certificates = read_certificates(&config.certificate_path)?;
    let private_key = read_private_key(&config.private_key_path)?;
    let client_roots = read_root_store(&config.client_ca_path)?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .map_err(|_| ServerError::Configuration)?;
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ServerError::Configuration)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, private_key)
        .map_err(|_| ServerError::Configuration)
}

fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, ServerError> {
    let certificates = CertificateDer::pem_file_iter(path)
        .map_err(|_| ServerError::Configuration)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ServerError::Configuration)?;
    if certificates.is_empty() {
        return Err(ServerError::Configuration);
    }
    Ok(certificates)
}

fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, ServerError> {
    PrivateKeyDer::from_pem_file(path).map_err(|_| ServerError::Configuration)
}

fn read_root_store(path: &Path) -> Result<RootCertStore, ServerError> {
    let certificates = read_certificates(path)?;
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| ServerError::Configuration)?;
    }
    if roots.is_empty() {
        return Err(ServerError::Configuration);
    }
    Ok(roots)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerError {
    Configuration,
    Bind,
    Accept,
    Tls,
    Authentication,
    Authorization,
    Protocol,
}

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sandbox service transport failed")
    }
}

impl std::error::Error for ServerError {}
