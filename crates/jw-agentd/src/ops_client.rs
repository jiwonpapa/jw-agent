use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jw_contracts::{
    IPC_PROTOCOL_VERSION, OPS_FRAME_MAX_BYTES, OpsCapabilityRequest, OpsCapabilityResponse,
    decode_frame, encode_frame,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpsBrokerError {
    Unavailable,
    Timeout,
    InvalidResponse,
}

pub type OpsFuture<'a> =
    Pin<Box<dyn Future<Output = Result<OpsCapabilityResponse, OpsBrokerError>> + Send + 'a>>;

pub trait OpsBroker: Send + Sync {
    fn capabilities<'a>(&'a self) -> OpsFuture<'a>;
}

#[derive(Clone, Debug)]
pub struct UdsOpsBroker {
    socket: PathBuf,
    timeout: Duration,
}

impl UdsOpsBroker {
    #[must_use]
    pub fn new(socket: PathBuf, timeout: Duration) -> Self {
        Self { socket, timeout }
    }
}

impl OpsBroker for UdsOpsBroker {
    fn capabilities<'a>(&'a self) -> OpsFuture<'a> {
        Box::pin(async move {
            let now = unix_milliseconds()?;
            let request = OpsCapabilityRequest {
                protocol_version: IPC_PROTOCOL_VERSION,
                request_id: random_identifier()?,
                deadline_unix_ms: deadline(now, self.timeout),
            };
            let request_id = request.request_id.clone();
            let exchange = exchange(&self.socket, request);
            let response = tokio::time::timeout(self.timeout, exchange)
                .await
                .map_err(|_| OpsBrokerError::Timeout)??;
            if response.protocol_version != IPC_PROTOCOL_VERSION
                || response.request_id != request_id
                || !response.read_only
            {
                return Err(OpsBrokerError::InvalidResponse);
            }
            Ok(response)
        })
    }
}

async fn exchange(
    socket: &PathBuf,
    request: OpsCapabilityRequest,
) -> Result<OpsCapabilityResponse, OpsBrokerError> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|_| OpsBrokerError::Unavailable)?;
    let encoded =
        encode_frame(&request, OPS_FRAME_MAX_BYTES).map_err(|_| OpsBrokerError::InvalidResponse)?;
    stream
        .write_all(&encoded)
        .await
        .map_err(|_| OpsBrokerError::Unavailable)?;
    stream
        .shutdown()
        .await
        .map_err(|_| OpsBrokerError::Unavailable)?;

    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|_| OpsBrokerError::InvalidResponse)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > OPS_FRAME_MAX_BYTES {
        return Err(OpsBrokerError::InvalidResponse);
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&prefix);
    frame.resize(4 + length, 0);
    let Some(payload) = frame.get_mut(4..) else {
        return Err(OpsBrokerError::InvalidResponse);
    };
    stream
        .read_exact(payload)
        .await
        .map_err(|_| OpsBrokerError::InvalidResponse)?;
    decode_frame(&frame, OPS_FRAME_MAX_BYTES).map_err(|_| OpsBrokerError::InvalidResponse)
}

fn random_identifier() -> Result<String, OpsBrokerError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| OpsBrokerError::Unavailable)?;
    let mut output = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").map_err(|_| OpsBrokerError::Unavailable)?;
    }
    Ok(output)
}

fn unix_milliseconds() -> Result<i64, OpsBrokerError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OpsBrokerError::Unavailable)?;
    i64::try_from(duration.as_millis()).map_err(|_| OpsBrokerError::Unavailable)
}

fn deadline(now_unix_ms: i64, timeout: Duration) -> i64 {
    let timeout_ms = i64::try_from(timeout.as_millis()).map_or(i64::MAX, std::convert::identity);
    now_unix_ms.saturating_add(timeout_ms)
}
