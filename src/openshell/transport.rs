use crate::ObservedTimeout;
use async_trait::async_trait;
use openshell_core::proto::exec_sandbox_event::Payload;
use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{
    CreateSandboxRequest, DeleteSandboxRequest, DeleteSandboxResponse, ExecSandboxEvent,
    ExecSandboxRequest, GetSandboxPolicyStatusRequest, GetSandboxPolicyStatusResponse,
    GetSandboxRequest, SandboxResponse,
};
use tonic::transport::Channel;

#[derive(Debug)]
pub enum ExecTransportEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit { code: i32, timeout: ObservedTimeout },
}

#[async_trait]
pub trait ExecEventStream: Send {
    async fn message(&mut self) -> Result<Option<ExecTransportEvent>, tonic::Status>;
}

#[allow(dead_code)]
pub enum CreateTransportError {
    Conflict,
    NotSubmitted(tonic::Status),
    PossiblySubmitted(tonic::Status),
}

#[allow(dead_code)]
pub enum ExecTransportError {
    NotSubmitted(tonic::Status),
    PossiblySubmitted(tonic::Status),
}

#[async_trait]
pub trait OpenShellTransport: Send + Sync {
    async fn create_sandbox(
        &self,
        request: CreateSandboxRequest,
    ) -> Result<SandboxResponse, CreateTransportError>;

    async fn get_sandbox(
        &self,
        request: GetSandboxRequest,
    ) -> Result<SandboxResponse, tonic::Status>;

    async fn get_sandbox_policy_status(
        &self,
        request: GetSandboxPolicyStatusRequest,
    ) -> Result<GetSandboxPolicyStatusResponse, tonic::Status>;

    async fn exec_sandbox(
        &self,
        request: ExecSandboxRequest,
    ) -> Result<Box<dyn ExecEventStream>, ExecTransportError>;

    async fn delete_sandbox(
        &self,
        request: DeleteSandboxRequest,
    ) -> Result<DeleteSandboxResponse, tonic::Status>;
}

pub struct TonicOpenShellTransport {
    channel: Channel,
}

impl TonicOpenShellTransport {
    pub const fn new(channel: Channel) -> Self {
        Self { channel }
    }

    fn client(&self) -> OpenShellClient<Channel> {
        OpenShellClient::new(self.channel.clone())
    }
}

struct TonicExecEventStream {
    inner: tonic::Streaming<ExecSandboxEvent>,
}

#[async_trait]
impl ExecEventStream for TonicExecEventStream {
    async fn message(&mut self) -> Result<Option<ExecTransportEvent>, tonic::Status> {
        let Some(event) = self.inner.message().await? else {
            return Ok(None);
        };
        let payload = event
            .payload
            .ok_or_else(|| tonic::Status::data_loss("exec event omitted payload"))?;
        let event = match payload {
            Payload::Stdout(event) => ExecTransportEvent::Stdout(event.data),
            Payload::Stderr(event) => ExecTransportEvent::Stderr(event.data),
            Payload::Exit(event) => ExecTransportEvent::Exit {
                code: event.exit_code,
                timeout: if event.exit_code == 124 {
                    ObservedTimeout::Possible
                } else {
                    ObservedTimeout::NotObserved
                },
            },
        };
        Ok(Some(event))
    }
}

#[async_trait]
impl OpenShellTransport for TonicOpenShellTransport {
    async fn create_sandbox(
        &self,
        request: CreateSandboxRequest,
    ) -> Result<SandboxResponse, CreateTransportError> {
        match self.client().create_sandbox(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) if status.code() == tonic::Code::AlreadyExists => {
                Err(CreateTransportError::Conflict)
            }
            Err(status) => Err(CreateTransportError::PossiblySubmitted(status)),
        }
    }

    async fn get_sandbox(
        &self,
        request: GetSandboxRequest,
    ) -> Result<SandboxResponse, tonic::Status> {
        self.client()
            .get_sandbox(request)
            .await
            .map(tonic::Response::into_inner)
    }

    async fn get_sandbox_policy_status(
        &self,
        request: GetSandboxPolicyStatusRequest,
    ) -> Result<GetSandboxPolicyStatusResponse, tonic::Status> {
        self.client()
            .get_sandbox_policy_status(request)
            .await
            .map(tonic::Response::into_inner)
    }

    async fn exec_sandbox(
        &self,
        request: ExecSandboxRequest,
    ) -> Result<Box<dyn ExecEventStream>, ExecTransportError> {
        let stream = self
            .client()
            .exec_sandbox(request)
            .await
            .map_err(ExecTransportError::PossiblySubmitted)?
            .into_inner();
        Ok(Box::new(TonicExecEventStream { inner: stream }))
    }

    async fn delete_sandbox(
        &self,
        request: DeleteSandboxRequest,
    ) -> Result<DeleteSandboxResponse, tonic::Status> {
        self.client()
            .delete_sandbox(request)
            .await
            .map(tonic::Response::into_inner)
    }
}
