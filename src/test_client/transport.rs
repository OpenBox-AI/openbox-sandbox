use crate::OperationContext;
use crate::{
    AssetBundleIdentity, FrameError, OperationId, PROTOCOL_VERSION, RequestEnvelope,
    ResponseEnvelope, ServiceRequest, read_response, write_request,
};
use rustls::pki_types::ServerName;
use std::future::Future;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::test_client::{ClientConfigError, SandboxRuntimeClientConfig};

#[derive(Clone)]
pub struct ServiceTransport {
    endpoint: SocketAddr,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    bundle: AssetBundleIdentity,
}

impl ServiceTransport {
    pub fn new(config: SandboxRuntimeClientConfig) -> Result<Self, ClientConfigError> {
        let (connector, server_name) = config.connector()?;
        Ok(Self {
            endpoint: config.endpoint(),
            server_name,
            connector,
            bundle: config.asset_bundle().clone(),
        })
    }

    pub const fn bundle(&self) -> &AssetBundleIdentity {
        &self.bundle
    }

    pub async fn call(
        &self,
        request: ServiceRequest,
        context: &OperationContext,
    ) -> Result<ResponseEnvelope, CallFailure> {
        let operation_id = OperationId::generate();
        let envelope = RequestEnvelope::new(operation_id.clone(), self.bundle.clone(), request);
        let cancellation = context.cancellation().clone();
        let deadline = Instant::now() + context.deadline().duration();
        if cancellation.is_cancelled() {
            return Err(CallFailure::new(
                SubmissionState::NotSubmitted,
                CallFailureKind::Cancelled,
            ));
        }
        let stream = budget(
            &cancellation,
            deadline,
            TcpStream::connect(self.endpoint),
            SubmissionState::NotSubmitted,
        )
        .await?
        .map_err(|_| CallFailure::new(SubmissionState::NotSubmitted, CallFailureKind::Transport))?;
        stream.set_nodelay(true).map_err(|_| {
            CallFailure::new(SubmissionState::NotSubmitted, CallFailureKind::Transport)
        })?;
        let mut tls = budget(
            &cancellation,
            deadline,
            self.connector.connect(self.server_name.clone(), stream),
            SubmissionState::NotSubmitted,
        )
        .await?
        .map_err(|_| {
            CallFailure::new(
                SubmissionState::NotSubmitted,
                CallFailureKind::Authentication,
            )
        })?;

        budget(
            &cancellation,
            deadline,
            write_request(&mut tls, &envelope),
            SubmissionState::PossiblySubmitted,
        )
        .await?
        .map_err(|error| frame_failure(SubmissionState::PossiblySubmitted, error))?;
        let response = budget(
            &cancellation,
            deadline,
            read_response(&mut tls),
            SubmissionState::PossiblySubmitted,
        )
        .await?
        .map_err(|error| frame_failure(SubmissionState::PossiblySubmitted, error))?;
        if response.protocol_version() != PROTOCOL_VERSION
            || response.operation_id() != &operation_id
        {
            return Err(CallFailure::new(
                SubmissionState::PossiblySubmitted,
                CallFailureKind::Protocol,
            ));
        }
        Ok(response)
    }
}

async fn budget<T, F>(
    cancellation: &CancellationToken,
    deadline: Instant,
    future: F,
    submission: SubmissionState,
) -> Result<T, CallFailure>
where
    F: Future<Output = T>,
{
    tokio::select! {
        () = cancellation.cancelled() => Err(CallFailure::new(submission, CallFailureKind::Cancelled)),
        () = tokio::time::sleep_until(deadline) => Err(CallFailure::new(submission, CallFailureKind::Deadline)),
        value = future => Ok(value),
    }
}

fn frame_failure(submission: SubmissionState, error: FrameError) -> CallFailure {
    let kind = match error {
        FrameError::Io => CallFailureKind::Transport,
        FrameError::Empty | FrameError::TooLarge | FrameError::InvalidJson => {
            CallFailureKind::Protocol
        }
    };
    CallFailure::new(submission, kind)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionState {
    NotSubmitted,
    PossiblySubmitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallFailureKind {
    Authentication,
    Transport,
    Deadline,
    Cancelled,
    Protocol,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallFailure {
    submission: SubmissionState,
    kind: CallFailureKind,
}

impl CallFailure {
    const fn new(submission: SubmissionState, kind: CallFailureKind) -> Self {
        Self { submission, kind }
    }

    pub const fn submission(self) -> SubmissionState {
        self.submission
    }

    pub const fn kind(self) -> CallFailureKind {
        self.kind
    }
}

impl core::fmt::Display for CallFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("sandbox service call failed")
    }
}

impl std::error::Error for CallFailure {}
