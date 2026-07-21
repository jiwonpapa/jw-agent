#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use jw_contracts::{
    CertbotCommand, CertbotCommandClass, CertbotCommandEvidence, CertbotCommandRequest,
    CertbotCommandResponse, CertbotCommandResult, CertificateEnvironment, IPC_PROTOCOL_VERSION,
};
use sha2::{Digest, Sha256};

const CERTBOT_EXECUTABLE: &str = "/usr/bin/certbot";
const OPENSSL_EXECUTABLE: &str = "/usr/bin/openssl";
const WEBROOT: &str = "/var/lib/jw-agent/acme-webroot";
const CONFIG_DIR: &str = "/etc/letsencrypt";
const WORK_DIR: &str = "/var/lib/letsencrypt";
const LOGS_DIR: &str = "/var/log/letsencrypt";
const ISSUE_TIMEOUT: Duration = Duration::from_secs(6 * 60);
const RENEW_TIMEOUT: Duration = Duration::from_secs(12 * 60);
const OUTPUT_CAP_BYTES: usize = 64 * 1_024;
const TLS_OUTPUT_CAP_BYTES: usize = 256 * 1_024;
const TLS_TIMEOUT: Duration = Duration::from_secs(8);

pub fn execute_request(
    request: &CertbotCommandRequest,
    now_unix_ms: i64,
    runtime_directory: &Path,
) -> CertbotCommandResponse {
    let result = match request.validate(now_unix_ms) {
        Ok(()) => execute_command(&request.command, &request.request_id, runtime_directory),
        Err(code) => Err(code.to_owned()),
    };
    let result = match result {
        Ok(evidence) => CertbotCommandResult::Completed(evidence),
        Err(code) => CertbotCommandResult::Rejected { code },
    };
    CertbotCommandResponse {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        result,
    }
}

fn execute_command(
    command: &CertbotCommand,
    request_id: &str,
    runtime_directory: &Path,
) -> Result<CertbotCommandEvidence, String> {
    let config_path = runtime_directory.join(format!("request-{request_id}.ini"));
    let specification = invocation_spec(command, &config_path)?;
    let config_guard = match specification.private_config.as_deref() {
        Some(content) => Some(PrivateConfig::create(&config_path, content)?),
        None => None,
    };
    let evidence = run_bounded(&specification);
    drop(config_guard);
    evidence
}

struct InvocationSpec {
    executable: &'static str,
    class: CertbotCommandClass,
    arguments: Vec<OsString>,
    private_config: Option<String>,
    timeout: Duration,
    output_cap_bytes: usize,
    expected_fingerprint: Option<String>,
}

fn invocation_spec(command: &CertbotCommand, config_path: &Path) -> Result<InvocationSpec, String> {
    command.validate().map_err(str::to_owned)?;
    match command {
        CertbotCommand::Issue {
            primary_domain,
            domains,
            account_email,
            environment,
            ..
        } => {
            let class = match environment {
                CertificateEnvironment::Staging => CertbotCommandClass::IssueStaging,
                CertificateEnvironment::Production => CertbotCommandClass::IssueProduction,
            };
            let mut arguments = vec![
                OsString::from("certonly"),
                OsString::from("--non-interactive"),
                OsString::from("--agree-tos"),
                OsString::from("--no-eff-email"),
                OsString::from("--webroot"),
                OsString::from("--webroot-path"),
                OsString::from(WEBROOT),
                OsString::from("--config-dir"),
                OsString::from(CONFIG_DIR),
                OsString::from("--work-dir"),
                OsString::from(WORK_DIR),
                OsString::from("--logs-dir"),
                OsString::from(LOGS_DIR),
                OsString::from("--config"),
                config_path.as_os_str().to_owned(),
                OsString::from("--cert-name"),
                OsString::from(primary_domain),
            ];
            match environment {
                CertificateEnvironment::Staging => {
                    arguments.push(OsString::from("--dry-run"));
                }
                CertificateEnvironment::Production => {
                    arguments.push(OsString::from("--keep-until-expiring"));
                }
            }
            for domain in domains {
                arguments.push(OsString::from("--domain"));
                arguments.push(OsString::from(domain));
            }
            Ok(InvocationSpec {
                executable: CERTBOT_EXECUTABLE,
                class,
                arguments,
                private_config: Some(format!("email = {account_email}\n")),
                timeout: ISSUE_TIMEOUT,
                output_cap_bytes: OUTPUT_CAP_BYTES,
                expected_fingerprint: None,
            })
        }
        CertbotCommand::RenewDryRun => Ok(InvocationSpec {
            executable: CERTBOT_EXECUTABLE,
            class: CertbotCommandClass::RenewDryRun,
            arguments: vec![
                OsString::from("renew"),
                OsString::from("--dry-run"),
                OsString::from("--no-random-sleep-on-renew"),
                OsString::from("--config-dir"),
                OsString::from(CONFIG_DIR),
                OsString::from("--work-dir"),
                OsString::from(WORK_DIR),
                OsString::from("--logs-dir"),
                OsString::from(LOGS_DIR),
            ],
            private_config: None,
            timeout: RENEW_TIMEOUT,
            output_cap_bytes: OUTPUT_CAP_BYTES,
            expected_fingerprint: None,
        }),
        CertbotCommand::VerifyLocalTls {
            server_name,
            expected_fingerprint,
        } => Ok(InvocationSpec {
            executable: OPENSSL_EXECUTABLE,
            class: CertbotCommandClass::VerifyLocalTls,
            arguments: vec![
                OsString::from("s_client"),
                OsString::from("-connect"),
                OsString::from("127.0.0.1:443"),
                OsString::from("-servername"),
                OsString::from(server_name),
                OsString::from("-showcerts"),
                OsString::from("-no_ign_eof"),
            ],
            private_config: None,
            timeout: TLS_TIMEOUT,
            output_cap_bytes: TLS_OUTPUT_CAP_BYTES,
            expected_fingerprint: Some(expected_fingerprint.clone()),
        }),
    }
}

struct PrivateConfig {
    path: PathBuf,
}

impl PrivateConfig {
    fn create(path: &Path, content: &str) -> Result<Self, String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| format!("private config create failed: {error}"))?;
        #[cfg(unix)]
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("private config permission failed: {error}"))?;
        file.write_all(content.as_bytes())
            .map_err(|error| format!("private config write failed: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("private config sync failed: {error}"))?;
        Ok(Self {
            path: path.to_owned(),
        })
    }
}

impl Drop for PrivateConfig {
    fn drop(&mut self) {
        let _remove_result = std::fs::remove_file(&self.path);
        if let Some(parent) = self.path.parent() {
            let _sync_result = File::open(parent).and_then(|directory| directory.sync_all());
        }
    }
}

fn run_bounded(specification: &InvocationSpec) -> Result<CertbotCommandEvidence, String> {
    let mut command = Command::new(specification.executable);
    command
        .args(&specification.arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("certbot spawn failed: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| String::from("certbot stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| String::from("certbot stderr unavailable"))?;
    let stdout_reader = spawn_reader(stdout, specification.output_cap_bytes);
    let stderr_reader = spawn_reader(stderr, specification.output_cap_bytes);
    let (status, timed_out) = wait_bounded(&mut child, specification.timeout)?;
    close_descendants_if_readers_stuck(child.id(), &stdout_reader, &stderr_reader);
    let stdout = join_reader(stdout_reader)?;
    let stderr = join_reader(stderr_reader)?;
    let command_succeeded = status.is_some_and(|value| value.success()) && !timed_out;
    let success = match specification.expected_fingerprint.as_deref() {
        Some(expected) if command_succeeded && !stdout.truncated => {
            peer_fingerprint(&stdout.captured).is_ok_and(|observed| observed == expected)
        }
        Some(_) => false,
        None => command_succeeded,
    };
    Ok(CertbotCommandEvidence {
        command_class: specification.class,
        success,
        exit_code: status.and_then(|value| value.code()),
        timed_out,
        stdout_digest: stdout.digest,
        stdout_truncated: stdout.truncated,
        stderr_digest: stderr.digest,
        stderr_truncated: stderr.truncated,
    })
}

struct StreamEvidence {
    digest: String,
    truncated: bool,
    captured: Vec<u8>,
}

fn spawn_reader<R>(reader: R, cap: usize) -> JoinHandle<Result<StreamEvidence, String>>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || read_bounded(reader, cap))
}

fn read_bounded<R: Read>(mut reader: R, cap: usize) -> Result<StreamEvidence, String> {
    let mut hasher = Sha256::new();
    let mut captured = Vec::with_capacity(cap.min(8 * 1_024));
    let mut buffer = [0_u8; 8 * 1_024];
    let mut total = 0_usize;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total = total.saturating_add(count);
        if captured.len() < cap {
            let remaining = cap.saturating_sub(captured.len());
            captured.extend_from_slice(&buffer[..remaining.min(count)]);
        }
    }
    Ok(StreamEvidence {
        digest: format_sha256(&hasher.finalize()),
        truncated: total > cap,
        captured,
    })
}

fn peer_fingerprint(output: &[u8]) -> Result<String, String> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let begin =
        find_bytes(output, BEGIN).ok_or_else(|| String::from("peer certificate missing"))?;
    let after_begin = begin.saturating_add(BEGIN.len());
    let relative_end = find_bytes(
        output
            .get(after_begin..)
            .ok_or_else(|| String::from("peer certificate invalid"))?,
        END,
    )
    .ok_or_else(|| String::from("peer certificate incomplete"))?;
    let end = after_begin
        .saturating_add(relative_end)
        .saturating_add(END.len());
    let pem = output
        .get(begin..end)
        .ok_or_else(|| String::from("peer certificate invalid"))?;
    let der = x509_der(pem)?;
    Ok(format_sha256(&Sha256::digest(&der)))
}

fn find_bytes(value: &[u8], needle: &[u8]) -> Option<usize> {
    value
        .windows(needle.len())
        .position(|window| window == needle)
}

fn x509_der(pem: &[u8]) -> Result<Vec<u8>, String> {
    let mut command = Command::new(OPENSSL_EXECUTABLE);
    command
        .args(["x509", "-outform", "DER"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("openssl x509 spawn failed: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| String::from("openssl x509 stdin unavailable"))?;
    stdin
        .write_all(pem)
        .map_err(|error| format!("openssl x509 input failed: {error}"))?;
    drop(stdin);
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| String::from("openssl x509 stdout unavailable"))?;
    let reader = spawn_reader(stdout, TLS_OUTPUT_CAP_BYTES);
    let (status, timed_out) = wait_bounded(&mut child, TLS_TIMEOUT)?;
    let output = join_reader(reader)?;
    if timed_out || !status.is_some_and(|value| value.success()) || output.truncated {
        return Err(String::from("openssl x509 failed"));
    }
    Ok(output.captured)
}

fn format_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(7 + bytes.len().saturating_mul(2));
    output.push_str("sha256:");
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn join_reader(
    handle: JoinHandle<Result<StreamEvidence, String>>,
) -> Result<StreamEvidence, String> {
    handle
        .join()
        .map_err(|_| String::from("certbot output reader failed"))?
}

fn wait_bounded(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<(Option<ExitStatus>, bool), String> {
    let started = Instant::now();
    loop {
        match child.try_wait().map_err(|error| error.to_string())? {
            Some(status) => return Ok((Some(status), false)),
            None if started.elapsed() < timeout => std::thread::sleep(Duration::from_millis(25)),
            None => {
                terminate_process_group(child)?;
                let status = child.wait().map_err(|error| error.to_string())?;
                return Ok((Some(status), true));
            }
        }
    }
}

fn terminate_process_group(child: &mut std::process::Child) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;
        let pid = i32::try_from(child.id()).map_err(|_| String::from("child pid overflow"))?;
        let group = Pid::from_raw(pid);
        let _term_result = killpg(group, Signal::SIGTERM);
        let grace_started = Instant::now();
        while grace_started.elapsed() < Duration::from_secs(2) {
            if child
                .try_wait()
                .map_err(|error| error.to_string())?
                .is_some()
            {
                let _kill_result = killpg(group, Signal::SIGKILL);
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _kill_result = killpg(group, Signal::SIGKILL);
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        child.kill().map_err(|error| error.to_string())
    }
}

fn close_descendants_if_readers_stuck<T, U>(
    _child_id: u32,
    stdout_reader: &JoinHandle<T>,
    stderr_reader: &JoinHandle<U>,
) {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(2) {
        if stdout_reader.is_finished() && stderr_reader.is_finished() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    #[cfg(target_os = "linux")]
    if let Ok(pid) = i32::try_from(_child_id) {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;
        let _kill_result = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
}

#[must_use]
pub fn arguments_contain(specification: &CertbotCommand, needle: &OsStr) -> bool {
    invocation_spec(
        specification,
        Path::new("/run/jw-agent-certd/request-test.ini"),
    )
    .is_ok_and(|value| value.arguments.iter().any(|argument| argument == needle))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::Path;

    use jw_contracts::{CertbotCommand, CertificateEnvironment};

    use super::{arguments_contain, invocation_spec};

    #[test]
    fn issue_invocation_is_fixed_and_keeps_email_out_of_argv() -> Result<(), String> {
        let command = CertbotCommand::Issue {
            primary_domain: String::from("example.com"),
            domains: vec![String::from("example.com"), String::from("www.example.com")],
            account_email: String::from("private-owner@example.com"),
            environment: CertificateEnvironment::Staging,
            tos_agreed: true,
        };
        let specification =
            invocation_spec(&command, Path::new("/run/jw-agent-certd/request-safe.ini"))?;
        assert!(
            specification
                .arguments
                .iter()
                .any(|value| value == "--dry-run")
        );
        assert!(
            !specification
                .arguments
                .iter()
                .any(|value| value == "--test-cert" || value == "--keep-until-expiring")
        );
        assert!(
            specification
                .arguments
                .iter()
                .any(|value| value == "--webroot")
        );
        assert!(!arguments_contain(
            &command,
            OsStr::new("private-owner@example.com")
        ));
        assert_eq!(
            specification.private_config.as_deref(),
            Some("email = private-owner@example.com\n")
        );
        Ok(())
    }

    #[test]
    fn tls_probe_is_fixed_to_loopback_and_validated_sni() -> Result<(), String> {
        let command = CertbotCommand::VerifyLocalTls {
            server_name: String::from("example.com"),
            expected_fingerprint: String::from(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        };
        let specification =
            invocation_spec(&command, Path::new("/run/jw-agent-certd/request-test.ini"))?;
        assert_eq!(specification.executable, super::OPENSSL_EXECUTABLE);
        assert!(
            specification
                .arguments
                .iter()
                .any(|value| value == OsStr::new("127.0.0.1:443"))
        );
        assert!(
            specification
                .arguments
                .iter()
                .any(|value| value == OsStr::new("example.com"))
        );
        assert!(
            !specification
                .arguments
                .iter()
                .any(|value| value == OsStr::new("0.0.0.0:443"))
        );
        Ok(())
    }
}
