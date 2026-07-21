#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
use std::io::{self, Read};
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use jw_contracts::{AUTH_FRAME_MAX_BYTES, AuthRequest, write_frame};
#[cfg(target_os = "linux")]
use zeroize::{Zeroize, Zeroizing};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("jw-authd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    #[cfg(not(target_os = "linux"))]
    {
        Err(String::from("Linux PAM is unsupported on this platform"))
    }

    #[cfg(target_os = "linux")]
    {
        harden_process()?;
        verify_peer_uid()?;
        let request: AuthRequest = read_secret_frame(&mut io::stdin(), AUTH_FRAME_MAX_BYTES)?;
        let now = unix_milliseconds()?;
        let response = jw_authd::authenticate_request(&request, now);
        write_frame(&mut io::stdout(), &response, AUTH_FRAME_MAX_BYTES)
            .map_err(|error| error.to_string())
    }
}

#[cfg(target_os = "linux")]
fn harden_process() -> Result<(), String> {
    use nix::sys::resource::{Resource, setrlimit};
    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .map_err(|error| format!("cannot disable core dumps: {error}"))
}

#[cfg(target_os = "linux")]
fn verify_peer_uid() -> Result<(), String> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use nix::unistd::User;
    let service_user = match std::env::var("JW_AGENTD_USER") {
        Ok(value) => value,
        Err(_) => String::from("jw-agent"),
    };
    let expected = User::from_name(&service_user)
        .map_err(|_| String::from("agentd service user lookup failed"))?
        .ok_or_else(|| String::from("agentd service user does not exist"))?
        .uid
        .as_raw();
    let credentials = getsockopt(&io::stdin(), PeerCredentials)
        .map_err(|_| String::from("peer credentials unavailable"))?;
    if credentials.uid() == expected {
        Ok(())
    } else {
        Err(String::from("peer UID denied"))
    }
}

#[cfg(target_os = "linux")]
fn read_secret_frame<R: Read>(reader: &mut R, maximum: usize) -> Result<AuthRequest, String> {
    let mut prefix = [0_u8; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|_| String::from("invalid request frame"))?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > maximum {
        return Err(String::from("invalid request frame size"));
    }
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    reader
        .read_exact(payload.as_mut_slice())
        .map_err(|_| String::from("invalid request frame"))?;
    let parsed = serde_json::from_slice(payload.as_slice())
        .map_err(|_| String::from("invalid request payload"));
    payload.zeroize();
    parsed
}

#[cfg(target_os = "linux")]
fn unix_milliseconds() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| String::from("system clock is before Unix epoch"))?;
    i64::try_from(duration.as_millis()).map_err(|_| String::from("system clock overflow"))
}
