#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use jw_contracts::{OPS_FRAME_MAX_BYTES, OpsRequest, decode_frame, encode_frame};
#[cfg(target_os = "linux")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(target_os = "linux")]
use tokio::net::{UnixListener, UnixStream};
#[cfg(target_os = "linux")]
use tokio::sync::Semaphore;

#[cfg(target_os = "linux")]
const DEFAULT_SOCKET: &str = "/run/jw-agent/opsd.sock";
#[cfg(target_os = "linux")]
const REQUEST_TIMEOUT: Duration = Duration::from_secs(14 * 60);
#[cfg(target_os = "linux")]
const MAX_CONNECTIONS: usize = 32;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("jw-opsd: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    #[cfg(not(target_os = "linux"))]
    {
        Err(String::from("jw-opsd is supported only on Linux"))
    }

    #[cfg(target_os = "linux")]
    {
        run_linux().await
    }
}

#[cfg(target_os = "linux")]
async fn run_linux() -> Result<(), String> {
    harden_process()?;
    let expected_uid = required_uid()?;
    let paths = jw_opsd::OpsPaths::default();
    let policy = jw_opsd::OpsPolicy::default();
    let runner = Arc::new(jw_opsd::FixedCommandRunner::new(
        policy.command_timeout,
        policy.output_cap_bytes,
    ));
    let service = Arc::new(jw_opsd::OpsService::new(paths, policy, runner));
    service
        .initialize(unix_milliseconds()?)
        .map_err(|error| error.to_string())?;
    let socket = PathBuf::from(environment_or("JW_OPSD_SOCKET", DEFAULT_SOCKET));
    prepare_socket(&socket)?;
    let listener = UnixListener::bind(&socket).map_err(|error| error.to_string())?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))
        .map_err(|error| error.to_string())?;
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        let (stream, _) = listener.accept().await.map_err(|error| error.to_string())?;
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| String::from("connection limiter closed"))?;
        let request_service = service.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if handle_connection(stream, expected_uid, request_service)
                .await
                .is_err()
            {
                eprintln!("jw-opsd: request rejected");
            }
        });
    }
}

#[cfg(target_os = "linux")]
async fn handle_connection(
    mut stream: UnixStream,
    expected_uid: u32,
    service: Arc<jw_opsd::OpsService>,
) -> Result<(), String> {
    verify_peer_uid(&stream, expected_uid)?;
    let exchange = async {
        let mut prefix = [0_u8; 4];
        stream
            .read_exact(&mut prefix)
            .await
            .map_err(|_| String::from("invalid request frame"))?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length == 0 || length > OPS_FRAME_MAX_BYTES {
            return Err(String::from("invalid request frame size"));
        }
        let mut frame = Vec::with_capacity(4 + length);
        frame.extend_from_slice(&prefix);
        frame.resize(4 + length, 0);
        let Some(payload) = frame.get_mut(4..) else {
            return Err(String::from("invalid request frame"));
        };
        stream
            .read_exact(payload)
            .await
            .map_err(|_| String::from("invalid request frame"))?;
        let request: OpsRequest =
            decode_frame(&frame, OPS_FRAME_MAX_BYTES).map_err(|error| error.to_string())?;
        let response_time = unix_milliseconds()?;
        let response =
            tokio::task::spawn_blocking(move || service.response_for(&request, response_time))
                .await
                .map_err(|_| String::from("operation worker failed"))?;
        let encoded =
            encode_frame(&response, OPS_FRAME_MAX_BYTES).map_err(|error| error.to_string())?;
        stream
            .write_all(&encoded)
            .await
            .map_err(|_| String::from("response write failed"))?;
        stream
            .shutdown()
            .await
            .map_err(|_| String::from("response shutdown failed"))
    };
    tokio::time::timeout(REQUEST_TIMEOUT, exchange)
        .await
        .map_err(|_| String::from("request timed out"))?
}

#[cfg(target_os = "linux")]
fn verify_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<(), String> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let credentials = getsockopt(stream, PeerCredentials)
        .map_err(|_| String::from("peer credentials unavailable"))?;
    if credentials.uid() == expected_uid {
        Ok(())
    } else {
        Err(String::from("peer UID denied"))
    }
}

#[cfg(target_os = "linux")]
fn required_uid() -> Result<u32, String> {
    use nix::unistd::User;
    let service_user = match std::env::var("JW_AGENTD_USER") {
        Ok(value) => value,
        Err(_) => String::from("jw-agent"),
    };
    User::from_name(&service_user)
        .map_err(|_| String::from("agentd service user lookup failed"))?
        .ok_or_else(|| String::from("agentd service user does not exist"))
        .map(|user| user.uid.as_raw())
}

#[cfg(target_os = "linux")]
fn environment_or(name: &str, default: &str) -> String {
    match std::env::var(name) {
        Ok(value) => value,
        Err(_) => default.to_owned(),
    }
}

#[cfg(target_os = "linux")]
fn prepare_socket(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Err(String::from("opsd socket has no parent directory"));
    };
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(|error| error.to_string())
        }
        Ok(_) => Err(String::from("refusing to replace non-socket opsd path")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn harden_process() -> Result<(), String> {
    use nix::sys::resource::{Resource, setrlimit};
    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .map_err(|error| format!("cannot disable core dumps: {error}"))
}

#[cfg(target_os = "linux")]
fn unix_milliseconds() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| String::from("system clock is before Unix epoch"))?;
    i64::try_from(duration.as_millis()).map_err(|_| String::from("system clock overflow"))
}
