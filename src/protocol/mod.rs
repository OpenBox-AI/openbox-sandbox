#![forbid(unsafe_code)]
//! Versioned provider-neutral protocol for the authenticated sandbox service boundary.

mod frame;
mod identity;
mod message;

pub use frame::{
    FrameError, MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES, decode_request, decode_response,
    read_request, read_response, write_request, write_response,
};
pub use identity::{
    AssetBundleIdentity, CapabilityToken, DeadlineMillis, OperationId, ProtocolValidationError,
};
pub use message::{
    BoundaryFailure, BoundaryFailureCode, HealthStatus, PROTOCOL_VERSION, RequestEnvelope,
    ResponseEnvelope, ServiceRequest, ServiceResponse,
};
