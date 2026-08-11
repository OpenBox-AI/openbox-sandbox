//! Opaque provider handle encoding for the Docker Sandboxes adapter.

use crate::{OpaqueProviderHandle, ValidationCode, ValidationError};
use serde::{Deserialize, Serialize};

const PROVIDER_STATE_VERSION: u32 = 1;

#[derive(Deserialize, Serialize)]
struct EncodedProviderState {
    version: u32,
    sandbox_name: String,
}

/// Implementation-side state retained across runtime operations.
pub struct SbxProviderState {
    /// The sandbox name owned by the request.
    pub sandbox_name: String,
}

impl SbxProviderState {
    /// Encodes the state into an opaque provider handle.
    pub fn encode(self) -> Result<OpaqueProviderHandle, ValidationError> {
        let bytes = serde_json::to_vec(&EncodedProviderState {
            version: PROVIDER_STATE_VERSION,
            sandbox_name: self.sandbox_name,
        })
        .map_err(|_| ValidationError::new("provider_state", ValidationCode::InvalidFormat))?;
        OpaqueProviderHandle::new(bytes)
    }

    /// Decodes an opaque provider handle produced by [`Self::encode`].
    pub fn decode(handle: &OpaqueProviderHandle) -> Result<Self, ()> {
        let state: EncodedProviderState =
            serde_json::from_slice(handle.as_bytes()).map_err(|_| ())?;
        if state.version != PROVIDER_STATE_VERSION || state.sandbox_name.is_empty() {
            return Err(());
        }
        Ok(Self {
            sandbox_name: state.sandbox_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RequestOwnedId;

    #[test]
    fn provider_state_round_trips_and_rejects_foreign_bytes() {
        let name = RequestOwnedId::parse("sbx-000000000000000").unwrap();
        let encoded = SbxProviderState {
            sandbox_name: name.to_string(),
        }
        .encode()
        .unwrap();
        let decoded = SbxProviderState::decode(&encoded).unwrap();
        assert_eq!(decoded.sandbox_name, name.as_str());

        let foreign = OpaqueProviderHandle::new(b"not json".to_vec()).unwrap();
        assert!(SbxProviderState::decode(&foreign).is_err());
    }
}
