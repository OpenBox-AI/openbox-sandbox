use crate::{OpaqueProviderHandle, ValidationError};
use openshell_core::proto::SandboxPolicy;
use prost::Message;

#[derive(Clone, PartialEq, Message)]
struct EncodedProviderState {
    #[prost(string, tag = "1")]
    sandbox_id: String,
    #[prost(bytes = "vec", tag = "2")]
    normalized_policy: Vec<u8>,
}

pub struct ProviderState {
    pub sandbox_id: String,
    pub normalized_policy: SandboxPolicy,
}

impl ProviderState {
    pub fn encode(self) -> Result<OpaqueProviderHandle, ValidationError> {
        OpaqueProviderHandle::new(
            EncodedProviderState {
                sandbox_id: self.sandbox_id,
                normalized_policy: self.normalized_policy.encode_to_vec(),
            }
            .encode_to_vec(),
        )
    }

    pub fn decode(handle: &OpaqueProviderHandle) -> Result<Self, ()> {
        let state = EncodedProviderState::decode(handle.as_bytes()).map_err(|_| ())?;
        if state.sandbox_id.is_empty() || state.normalized_policy.is_empty() {
            return Err(());
        }
        let normalized_policy =
            SandboxPolicy::decode(state.normalized_policy.as_slice()).map_err(|_| ())?;
        Ok(Self {
            sandbox_id: state.sandbox_id,
            normalized_policy,
        })
    }
}
