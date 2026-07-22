use std::fmt;
use std::io::{Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

pub const IPC_PROTOCOL_VERSION: u16 = 1;
pub const AUTH_FRAME_MAX_BYTES: usize = 16 * 1_024;
pub const OPS_FRAME_MAX_BYTES: usize = 256 * 1_024;

#[derive(Debug)]
pub enum FrameError {
    Empty,
    TooLarge,
    Truncated,
    InvalidJson,
    Io(std::io::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("empty frame"),
            Self::TooLarge => formatter.write_str("frame exceeds limit"),
            Self::Truncated => formatter.write_str("truncated frame"),
            Self::InvalidJson => formatter.write_str("invalid frame payload"),
            Self::Io(error) => write!(formatter, "frame I/O error: {error}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<std::io::Error> for FrameError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn encode_frame<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, FrameError> {
    let payload = serde_json::to_vec(value).map_err(|_| FrameError::InvalidJson)?;
    if payload.is_empty() {
        return Err(FrameError::Empty);
    }
    if payload.len() > maximum || payload.len() > u32::MAX as usize {
        return Err(FrameError::TooLarge);
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8], maximum: usize) -> Result<T, FrameError> {
    if frame.len() < 4 {
        return Err(FrameError::Truncated);
    }
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(FrameError::Truncated)?
        .try_into()
        .map_err(|_| FrameError::Truncated)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 {
        return Err(FrameError::Empty);
    }
    if length > maximum {
        return Err(FrameError::TooLarge);
    }
    let payload = frame.get(4..).ok_or(FrameError::Truncated)?;
    if payload.len() != length {
        return Err(FrameError::Truncated);
    }
    serde_json::from_slice(payload).map_err(|_| FrameError::InvalidJson)
}

pub fn read_frame<R: Read, T: DeserializeOwned>(
    reader: &mut R,
    maximum: usize,
) -> Result<T, FrameError> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 {
        return Err(FrameError::Empty);
    }
    if length > maximum {
        return Err(FrameError::TooLarge);
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(|_| FrameError::InvalidJson)
}

pub fn write_frame<W: Write, T: Serialize>(
    writer: &mut W,
    value: &T,
    maximum: usize,
) -> Result<(), FrameError> {
    let frame = encode_frame(value, maximum)?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::{FrameError, decode_frame, encode_frame};

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct Example {
        value: u8,
    }

    #[test]
    fn frame_round_trip() -> Result<(), FrameError> {
        let frame = encode_frame(&Example { value: 7 }, 128)?;
        let decoded: Example = decode_frame(&frame, 128)?;
        assert_eq!(decoded, Example { value: 7 });
        Ok(())
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let result = encode_frame(&Example { value: 7 }, 2);
        assert!(matches!(result, Err(FrameError::TooLarge)));
    }
}
