use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::digest::format_sha256;
use crate::error::OpsError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandClass {
    NginxConfigTest,
    NginxReload,
    NginxActive,
    CertbotTimerEnabled,
    CertbotTimerActive,
}

impl CommandClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NginxConfigTest => "nginx_config_test",
            Self::NginxReload => "nginx_reload",
            Self::NginxActive => "nginx_active",
            Self::CertbotTimerEnabled => "certbot_timer_enabled",
            Self::CertbotTimerActive => "certbot_timer_active",
        }
    }

    fn executable_and_args(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Self::NginxConfigTest => ("/usr/sbin/nginx", &["-t"]),
            Self::NginxReload => ("/usr/bin/systemctl", &["reload", "nginx.service"]),
            Self::NginxActive => (
                "/usr/bin/systemctl",
                &["is-active", "--quiet", "nginx.service"],
            ),
            Self::CertbotTimerEnabled => (
                "/usr/bin/systemctl",
                &["is-enabled", "--quiet", "certbot.timer"],
            ),
            Self::CertbotTimerActive => (
                "/usr/bin/systemctl",
                &["is-active", "--quiet", "certbot.timer"],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamEvidence {
    pub digest: String,
    pub captured: Vec<u8>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandEvidence {
    pub class: CommandClass,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: StreamEvidence,
    pub stderr: StreamEvidence,
}

pub trait OperationRunner: Send + Sync {
    fn run(&self, class: CommandClass) -> Result<CommandEvidence, OpsError>;
}

#[derive(Clone, Debug)]
pub struct FixedCommandRunner {
    timeout: Duration,
    output_cap_bytes: usize,
}

impl FixedCommandRunner {
    #[must_use]
    pub const fn new(timeout: Duration, output_cap_bytes: usize) -> Self {
        Self {
            timeout,
            output_cap_bytes,
        }
    }
}

impl OperationRunner for FixedCommandRunner {
    fn run(&self, class: CommandClass) -> Result<CommandEvidence, OpsError> {
        let (executable, arguments) = class.executable_and_args();
        let mut command = Command::new(executable);
        command
            .args(arguments)
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
            .map_err(|error| OpsError::Command(error.to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| OpsError::Command(String::from("stdout pipe unavailable")))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| OpsError::Command(String::from("stderr pipe unavailable")))?;
        let stdout_reader = spawn_reader(stdout, self.output_cap_bytes);
        let stderr_reader = spawn_reader(stderr, self.output_cap_bytes);
        let (status, timed_out) = wait_bounded(&mut child, self.timeout)?;
        close_descendants_if_readers_stuck(child.id(), &stdout_reader, &stderr_reader);
        let stdout = join_reader(stdout_reader)?;
        let stderr = join_reader(stderr_reader)?;
        Ok(CommandEvidence {
            class,
            success: status.is_some_and(|value| value.success()) && !timed_out,
            exit_code: status.and_then(|value| value.code()),
            timed_out,
            stdout,
            stderr,
        })
    }
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
            let take = remaining.min(count);
            captured.extend_from_slice(&buffer[..take]);
        }
    }
    Ok(StreamEvidence {
        digest: format_sha256(&hasher.finalize()),
        captured,
        truncated: total > cap,
    })
}

fn join_reader(
    handle: JoinHandle<Result<StreamEvidence, String>>,
) -> Result<StreamEvidence, OpsError> {
    handle
        .join()
        .map_err(|_| OpsError::Command(String::from("output reader failed")))?
        .map_err(OpsError::Command)
}

fn wait_bounded(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<(Option<ExitStatus>, bool), OpsError> {
    let started = Instant::now();
    loop {
        match child
            .try_wait()
            .map_err(|error| OpsError::Command(error.to_string()))?
        {
            Some(status) => return Ok((Some(status), false)),
            None if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(25));
            }
            None => {
                terminate_process_group(child)?;
                let status = child
                    .wait()
                    .map_err(|error| OpsError::Command(error.to_string()))?;
                return Ok((Some(status), true));
            }
        }
    }
}

fn terminate_process_group(child: &mut std::process::Child) -> Result<(), OpsError> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;

        let pid = i32::try_from(child.id())
            .map_err(|_| OpsError::Command(String::from("child pid overflow")))?;
        let group = Pid::from_raw(pid);
        let _term_result = killpg(group, Signal::SIGTERM);
        let grace_started = Instant::now();
        while grace_started.elapsed() < Duration::from_secs(2) {
            if child
                .try_wait()
                .map_err(|error| OpsError::Command(error.to_string()))?
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
        child
            .kill()
            .map_err(|error| OpsError::Command(error.to_string()))
    }
}

fn terminate_remaining_process_group(child_id: u32) {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;

        if let Ok(pid) = i32::try_from(child_id) {
            let _kill_result = killpg(Pid::from_raw(pid), Signal::SIGKILL);
        }
    }

    #[cfg(not(target_os = "linux"))]
    let _ = child_id;
}

fn close_descendants_if_readers_stuck<T, U>(
    child_id: u32,
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
    terminate_remaining_process_group(child_id);
}
