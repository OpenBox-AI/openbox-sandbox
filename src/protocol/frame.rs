use core::fmt;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{RequestEnvelope, ResponseEnvelope};

pub const MAX_REQUEST_FRAME_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_RESPONSE_FRAME_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    Io,
    Empty,
    TooLarge,
    InvalidJson,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sandbox service frame rejected")
    }
}

impl std::error::Error for FrameError {}

pub fn decode_request(bytes: &[u8]) -> Result<RequestEnvelope, FrameError> {
    decode(bytes, MAX_REQUEST_FRAME_BYTES)
}

pub fn decode_response(bytes: &[u8]) -> Result<ResponseEnvelope, FrameError> {
    decode(bytes, MAX_RESPONSE_FRAME_BYTES)
}

pub async fn read_request<R>(reader: &mut R) -> Result<RequestEnvelope, FrameError>
where
    R: AsyncRead + Unpin,
{
    let bytes = read_frame(reader, MAX_REQUEST_FRAME_BYTES).await?;
    decode_request(&bytes)
}

pub async fn read_response<R>(reader: &mut R) -> Result<ResponseEnvelope, FrameError>
where
    R: AsyncRead + Unpin,
{
    let bytes = read_frame(reader, MAX_RESPONSE_FRAME_BYTES).await?;
    decode_response(&bytes)
}

pub async fn write_request<W>(writer: &mut W, request: &RequestEnvelope) -> Result<(), FrameError>
where
    W: AsyncWrite + Send + Unpin,
{
    write_json_frame(writer, request, MAX_REQUEST_FRAME_BYTES).await
}

pub async fn write_response<W>(
    writer: &mut W,
    response: &ResponseEnvelope,
) -> Result<(), FrameError>
where
    W: AsyncWrite + Send + Unpin,
{
    write_json_frame(writer, response, MAX_RESPONSE_FRAME_BYTES).await
}

fn decode<T>(bytes: &[u8], maximum: usize) -> Result<T, FrameError>
where
    T: serde::de::DeserializeOwned,
{
    if bytes.is_empty() {
        return Err(FrameError::Empty);
    }
    if bytes.len() > maximum {
        return Err(FrameError::TooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| FrameError::InvalidJson)
}

async fn read_frame<R>(reader: &mut R, maximum: usize) -> Result<Vec<u8>, FrameError>
where
    R: AsyncRead + Unpin,
{
    let length = reader.read_u32().await.map_err(|_| FrameError::Io)?;
    let length = usize::try_from(length).map_err(|_| FrameError::TooLarge)?;
    if length == 0 {
        return Err(FrameError::Empty);
    }
    if length > maximum {
        return Err(FrameError::TooLarge);
    }
    let mut bytes = vec![0; length];
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|_| FrameError::Io)?;
    Ok(bytes)
}

async fn write_json_frame<W, T>(writer: &mut W, value: &T, maximum: usize) -> Result<(), FrameError>
where
    W: AsyncWrite + Send + Unpin,
    T: serde::Serialize + Sync,
{
    let bytes = serde_json::to_vec(value).map_err(|_| FrameError::InvalidJson)?;
    if bytes.is_empty() {
        return Err(FrameError::Empty);
    }
    if bytes.len() > maximum {
        return Err(FrameError::TooLarge);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| FrameError::TooLarge)?;
    writer.write_u32(length).await.map_err(|_| FrameError::Io)?;
    writer.write_all(&bytes).await.map_err(|_| FrameError::Io)?;
    writer.flush().await.map_err(|_| FrameError::Io)
}
