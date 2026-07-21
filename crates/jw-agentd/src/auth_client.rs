use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use jw_contracts::{
    AUTH_FRAME_MAX_BYTES, AuthRequest, AuthResponse, FrameError, decode_frame, encode_frame,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthBrokerError {
    Unavailable,
    Timeout,
    InvalidResponse,
}

pub type AuthFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AuthResponse, AuthBrokerError>> + Send + 'a>>;

pub trait AuthBroker: Send + Sync {
    fn authenticate<'a>(&'a self, request: AuthRequest) -> AuthFuture<'a>;

    fn platform_supported(&self) -> bool;
}

#[derive(Clone, Debug)]
pub struct UdsAuthBroker {
    socket: PathBuf,
    timeout: Duration,
}

impl UdsAuthBroker {
    #[must_use]
    pub fn new(socket: PathBuf, timeout: Duration) -> Self {
        Self { socket, timeout }
    }
}

impl AuthBroker for UdsAuthBroker {
    fn authenticate<'a>(&'a self, request: AuthRequest) -> AuthFuture<'a> {
        Box::pin(async move {
            let operation = exchange(&self.socket, request);
            tokio::time::timeout(self.timeout, operation)
                .await
                .map_err(|_| AuthBrokerError::Timeout)?
        })
    }

    fn platform_supported(&self) -> bool {
        cfg!(target_os = "linux") && self.socket.exists()
    }
}

async fn exchange(socket: &PathBuf, request: AuthRequest) -> Result<AuthResponse, AuthBrokerError> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|_| AuthBrokerError::Unavailable)?;
    let encoded = encode_frame(&request, AUTH_FRAME_MAX_BYTES).map_err(map_frame_error)?;
    let mut secret_frame = Zeroizing::new(encoded);
    stream
        .write_all(secret_frame.as_slice())
        .await
        .map_err(|_| AuthBrokerError::Unavailable)?;
    secret_frame.zeroize();
    stream
        .shutdown()
        .await
        .map_err(|_| AuthBrokerError::Unavailable)?;

    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|_| AuthBrokerError::InvalidResponse)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > AUTH_FRAME_MAX_BYTES {
        return Err(AuthBrokerError::InvalidResponse);
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&prefix);
    frame.resize(4 + length, 0);
    stream
        .read_exact(frame.get_mut(4..).ok_or(AuthBrokerError::InvalidResponse)?)
        .await
        .map_err(|_| AuthBrokerError::InvalidResponse)?;
    decode_frame(&frame, AUTH_FRAME_MAX_BYTES).map_err(map_frame_error)
}

fn map_frame_error(_error: FrameError) -> AuthBrokerError {
    AuthBrokerError::InvalidResponse
}
