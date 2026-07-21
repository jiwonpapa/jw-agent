#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
use std::io;
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use jw_contracts::{CERT_FRAME_MAX_BYTES, CertbotCommandRequest, read_frame, write_frame};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("jw-certd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    #[cfg(not(target_os = "linux"))]
    {
        Err(String::from("jw-certd is supported only on Linux"))
    }
    #[cfg(target_os = "linux")]
    {
        harden_process()?;
        verify_root_peer()?;
        let request: CertbotCommandRequest = read_frame(&mut io::stdin(), CERT_FRAME_MAX_BYTES)
            .map_err(|error| error.to_string())?;
        let runtime = std::path::Path::new("/run/jw-agent-certd");
        let response = jw_certd::execute_request(&request, unix_milliseconds()?, runtime);
        write_frame(&mut io::stdout(), &response, CERT_FRAME_MAX_BYTES)
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
fn verify_root_peer() -> Result<(), String> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let credentials =
        getsockopt(&io::stdin(), PeerCredentials).map_err(|_| String::from("peer unavailable"))?;
    if credentials.uid() == 0 {
        Ok(())
    } else {
        Err(String::from("peer UID denied"))
    }
}

#[cfg(target_os = "linux")]
fn unix_milliseconds() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| String::from("system clock is before Unix epoch"))?;
    i64::try_from(duration.as_millis()).map_err(|_| String::from("system clock overflow"))
}
