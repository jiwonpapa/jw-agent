use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jw_contracts::{
    IPC_PROTOCOL_VERSION, NginxSiteStatePlanRequest, NginxSiteStatePlanView, OPS_FRAME_MAX_BYTES,
    OperationReceiptView, OpsCapabilityResponse, OpsRequest, OpsRequestBody, OpsResponse,
    OpsResponseBody, Subject, decode_frame, encode_frame,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpsBrokerError {
    Unavailable,
    Timeout,
    InvalidResponse,
    Rejected(String),
}

pub type OpsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, OpsBrokerError>> + Send + 'a>>;

pub trait OpsBroker: Send + Sync {
    fn capabilities<'a>(&'a self) -> OpsFuture<'a, OpsCapabilityResponse>;

    fn plan_nginx_site_state<'a>(
        &'a self,
        actor: Subject,
        plan: NginxSiteStatePlanRequest,
    ) -> OpsFuture<'a, NginxSiteStatePlanView>;

    fn approve_nginx_site_state<'a>(
        &'a self,
        actor: Subject,
        plan_id: String,
        plan_hash: String,
        idempotency_key: String,
    ) -> OpsFuture<'a, OperationReceiptView>;

    fn operation_receipt<'a>(
        &'a self,
        actor: Subject,
        operation_id: String,
    ) -> OpsFuture<'a, OperationReceiptView>;

    fn execute_operation<'a>(
        &'a self,
        actor: Subject,
        operation_id: String,
    ) -> OpsFuture<'a, OperationReceiptView>;
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

    async fn request(&self, body: OpsRequestBody) -> Result<OpsResponseBody, OpsBrokerError> {
        let now = unix_milliseconds()?;
        let request = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: random_identifier()?,
            deadline_unix_ms: deadline(now, self.timeout),
            body,
        };
        let request_id = request.request_id.clone();
        let response = tokio::time::timeout(self.timeout, exchange(&self.socket, request))
            .await
            .map_err(|_| OpsBrokerError::Timeout)??;
        if response.protocol_version != IPC_PROTOCOL_VERSION || response.request_id != request_id {
            return Err(OpsBrokerError::InvalidResponse);
        }
        match response.body {
            OpsResponseBody::Rejected(rejected) => Err(OpsBrokerError::Rejected(rejected.code)),
            body => Ok(body),
        }
    }
}

impl OpsBroker for UdsOpsBroker {
    fn capabilities<'a>(&'a self) -> OpsFuture<'a, OpsCapabilityResponse> {
        Box::pin(async move {
            let body = self.request(OpsRequestBody::Capabilities).await?;
            let OpsResponseBody::Capabilities(capabilities) = body else {
                return Err(OpsBrokerError::InvalidResponse);
            };
            Ok(capabilities)
        })
    }

    fn plan_nginx_site_state<'a>(
        &'a self,
        actor: Subject,
        plan: NginxSiteStatePlanRequest,
    ) -> OpsFuture<'a, NginxSiteStatePlanView> {
        Box::pin(async move {
            let body = self
                .request(OpsRequestBody::PlanNginxSiteState { actor, plan })
                .await?;
            let OpsResponseBody::NginxSiteStatePlan(plan) = body else {
                return Err(OpsBrokerError::InvalidResponse);
            };
            Ok(plan)
        })
    }

    fn approve_nginx_site_state<'a>(
        &'a self,
        actor: Subject,
        plan_id: String,
        plan_hash: String,
        idempotency_key: String,
    ) -> OpsFuture<'a, OperationReceiptView> {
        Box::pin(async move {
            let body = self
                .request(OpsRequestBody::ApproveNginxSiteState {
                    actor,
                    plan_id,
                    plan_hash,
                    idempotency_key,
                })
                .await?;
            let OpsResponseBody::OperationReceipt(receipt) = body else {
                return Err(OpsBrokerError::InvalidResponse);
            };
            Ok(receipt)
        })
    }

    fn operation_receipt<'a>(
        &'a self,
        actor: Subject,
        operation_id: String,
    ) -> OpsFuture<'a, OperationReceiptView> {
        Box::pin(async move {
            let body = self
                .request(OpsRequestBody::OperationReceipt {
                    actor,
                    operation_id,
                })
                .await?;
            let OpsResponseBody::OperationReceipt(receipt) = body else {
                return Err(OpsBrokerError::InvalidResponse);
            };
            Ok(receipt)
        })
    }

    fn execute_operation<'a>(
        &'a self,
        actor: Subject,
        operation_id: String,
    ) -> OpsFuture<'a, OperationReceiptView> {
        Box::pin(async move {
            let body = self
                .request(OpsRequestBody::ExecuteOperation {
                    actor,
                    operation_id,
                })
                .await?;
            let OpsResponseBody::OperationReceipt(receipt) = body else {
                return Err(OpsBrokerError::InvalidResponse);
            };
            Ok(receipt)
        })
    }
}

async fn exchange(socket: &PathBuf, request: OpsRequest) -> Result<OpsResponse, OpsBrokerError> {
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
