use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use jw_contracts::{
    CERT_FRAME_MAX_BYTES, CertbotCommand, CertbotCommandClass, CertbotCommandEvidence,
    CertbotCommandRequest, CertbotCommandResponse, CertbotCommandResult, IPC_PROTOCOL_VERSION,
    read_frame, validate_digest, write_frame,
};

use crate::error::OpsError;

pub const DEFAULT_CERTBOT_SOCKET: &str = "/run/jw-agent-certd/certd.sock";

pub trait CertbotRunner: Send + Sync {
    fn run(&self, command: CertbotCommand, now_ms: i64)
    -> Result<CertbotCommandEvidence, OpsError>;
}

#[derive(Clone, Debug)]
pub struct UdsCertbotRunner {
    socket: PathBuf,
    timeout: Duration,
}

impl UdsCertbotRunner {
    #[must_use]
    pub const fn new(socket: PathBuf, timeout: Duration) -> Self {
        Self { socket, timeout }
    }
}

impl Default for UdsCertbotRunner {
    fn default() -> Self {
        Self::new(
            PathBuf::from(DEFAULT_CERTBOT_SOCKET),
            Duration::from_secs(13 * 60),
        )
    }
}

impl CertbotRunner for UdsCertbotRunner {
    fn run(
        &self,
        command: CertbotCommand,
        now_ms: i64,
    ) -> Result<CertbotCommandEvidence, OpsError> {
        let request_id = random_identifier()?;
        let timeout_ms = i64::try_from(self.timeout.as_millis())
            .map_err(|_| OpsError::Command(String::from("certbot timeout overflow")))?;
        let request = CertbotCommandRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: request_id.clone(),
            deadline_unix_ms: now_ms.saturating_add(timeout_ms),
            command: command.clone(),
        };
        request
            .validate(now_ms)
            .map_err(|_| OpsError::Rejected("certbot_request_invalid"))?;
        let mut stream = UnixStream::connect(&self.socket)
            .map_err(|error| OpsError::Command(error.to_string()))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(10))))
            .map_err(|error| OpsError::Command(error.to_string()))?;
        write_frame(&mut stream, &request, CERT_FRAME_MAX_BYTES)
            .map_err(|error| OpsError::Command(error.to_string()))?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|error| OpsError::Command(error.to_string()))?;
        let response: CertbotCommandResponse = read_frame(&mut stream, CERT_FRAME_MAX_BYTES)
            .map_err(|error| OpsError::Command(error.to_string()))?;
        if response.protocol_version != IPC_PROTOCOL_VERSION || response.request_id != request_id {
            return Err(OpsError::Rejected("certbot_response_invalid"));
        }
        let evidence = match response.result {
            CertbotCommandResult::Completed(evidence) => evidence,
            CertbotCommandResult::Rejected { .. } => {
                return Err(OpsError::Rejected("certbot_request_rejected"));
            }
        };
        validate_evidence(&command, &evidence)?;
        Ok(evidence)
    }
}

fn validate_evidence(
    command: &CertbotCommand,
    evidence: &CertbotCommandEvidence,
) -> Result<(), OpsError> {
    let expected = match command {
        CertbotCommand::Issue { environment, .. } => match environment {
            jw_contracts::CertificateEnvironment::Staging => CertbotCommandClass::IssueStaging,
            jw_contracts::CertificateEnvironment::Production => {
                CertbotCommandClass::IssueProduction
            }
        },
        CertbotCommand::RenewDryRun => CertbotCommandClass::RenewDryRun,
    };
    if evidence.command_class != expected
        || validate_digest(&evidence.stdout_digest).is_err()
        || validate_digest(&evidence.stderr_digest).is_err()
        || (evidence.success && (evidence.timed_out || evidence.exit_code != Some(0)))
    {
        return Err(OpsError::Rejected("certbot_response_invalid"));
    }
    Ok(())
}

fn random_identifier() -> Result<String, OpsError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| OpsError::Command(format!("random identifier unavailable: {error}")))?;
    let mut output = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").map_err(|error| OpsError::Command(error.to_string()))?;
    }
    Ok(output)
}
