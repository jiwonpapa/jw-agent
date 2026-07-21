use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use jw_contracts::{
    TERMINAL_IDLE_TIMEOUT_SECONDS, TERMINAL_MAX_FRAME_BYTES, TERMINAL_MAX_LIFETIME_SECONDS,
    TerminalClientMessage, validate_terminal_size,
};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::pty::{Winsize, openpty};
use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, Command};
use tokio::time::{MissedTickBehavior, timeout};

use crate::{AgentConfig, SessionStore, TerminalLease};

const SSH_AUTH_TIMEOUT: Duration = Duration::from_secs(8);
const SSH_AUTH_SETTLE_TIME: Duration = Duration::from_millis(250);
const PROCESS_EXIT_TIMEOUT: Duration = Duration::from_secs(2);
const LOOPBACK_HOST: &str = "127.0.0.1";
const LOOPBACK_HOST_ALIAS: &str = "jw-agent-loopback";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalRunSummary {
    pub session_id: String,
    pub reason: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

pub async fn run_terminal(
    mut socket: WebSocket,
    mut lease: TerminalLease,
    config: AgentConfig,
    store: SessionStore,
) -> TerminalRunSummary {
    let session_id = lease.session_id.clone();
    let mut bytes_in = 0_u64;
    let mut bytes_out = 0_u64;
    let audit_started = unix_milliseconds()
        .and_then(|now| {
            store.record_terminal_start(&session_id, &lease.subject, lease.ingress, now)
        })
        .is_ok();
    let result = if audit_started {
        prepare_terminal(&mut lease, &config).await
    } else {
        Err(String::from("audit_unavailable"))
    };
    let reason = match result {
        Ok(mut terminal) => {
            let ready = format!(
                "{{\"type\":\"ready\",\"sessionId\":\"{}\",\"assurance\":\"g1_verified_action\"}}",
                lease.session_id
            );
            if socket.send(Message::text(ready)).await.is_err() {
                String::from("browser_disconnected")
            } else {
                relay_terminal(
                    &mut socket,
                    &mut terminal,
                    &mut lease,
                    &mut bytes_in,
                    &mut bytes_out,
                    &config,
                )
                .await
            }
        }
        Err(reason) => reason,
    };
    let _closed = socket
        .send(Message::Close(Some(CloseFrame {
            code: close_code(&reason),
            reason: reason.clone().into(),
        })))
        .await;
    let summary = TerminalRunSummary {
        session_id,
        reason,
        bytes_in,
        bytes_out,
    };
    if audit_started {
        let audit_result = unix_milliseconds().and_then(|now| {
            store.record_terminal_finish(
                &summary.session_id,
                &summary.reason,
                summary.bytes_in,
                summary.bytes_out,
                now,
            )
        });
        if audit_result.is_err() {
            eprintln!(
                "jw-agentd terminal audit finalize failed session={}",
                summary.session_id
            );
        }
    }
    summary
}

struct PreparedTerminal {
    io: Arc<AsyncFd<OwnedFd>>,
    slave: OwnedFd,
    child: Child,
}

async fn prepare_terminal(
    lease: &mut TerminalLease,
    config: &AgentConfig,
) -> Result<PreparedTerminal, String> {
    let winsize = Winsize {
        ws_row: lease.rows,
        ws_col: lease.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pty = openpty(Some(&winsize), None).map_err(|_| String::from("pty_unavailable"))?;
    set_nonblocking(&pty.master)?;
    let fifo_path = askpass_path(config, &lease.session_id)?;
    mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR)
        .map_err(|_| String::from("askpass_channel_failed"))?;
    let mut keeper = match OpenOptions::new().read(true).write(true).open(&fifo_path) {
        Ok(channel) => channel,
        Err(_) => {
            let _cleanup = fs::remove_file(&fifo_path);
            return Err(String::from("askpass_channel_failed"));
        }
    };
    let password = lease
        .take_password()
        .map_err(|_| String::from("credential_unavailable"))?;
    if keeper
        .write_all(password.expose().as_bytes())
        .and_then(|()| keeper.write_all(b"\n"))
        .and_then(|()| keeper.flush())
        .is_err()
    {
        let _cleanup = fs::remove_file(&fifo_path);
        return Err(String::from("askpass_channel_failed"));
    }
    drop(password);

    let mut command = match ssh_command(config, lease, &fifo_path, &pty.slave) {
        Ok(command) => command,
        Err(reason) => {
            let _cleanup = fs::remove_file(&fifo_path);
            return Err(reason);
        }
    };
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            let _cleanup = fs::remove_file(&fifo_path);
            return Err(String::from("openssh_client_unavailable"));
        }
    };
    let mut keeper_task = tokio::spawn(hold_askpass_channel(fifo_path.clone(), keeper));
    if let Err(reason) = wait_for_ssh_authentication(&fifo_path, &mut child).await {
        keeper_task.abort();
        let _joined = keeper_task.await;
        let _cleanup = fs::remove_file(&fifo_path);
        let _kill = child.start_kill();
        let _waited = timeout(PROCESS_EXIT_TIMEOUT, child.wait()).await;
        return Err(reason);
    }
    match timeout(Duration::from_secs(1), &mut keeper_task).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            let _kill = child.start_kill();
            let _waited = timeout(PROCESS_EXIT_TIMEOUT, child.wait()).await;
            return Err(String::from("askpass_channel_failed"));
        }
        Err(_) => {
            keeper_task.abort();
            let _joined = keeper_task.await;
            let _kill = child.start_kill();
            let _waited = timeout(PROCESS_EXIT_TIMEOUT, child.wait()).await;
            return Err(String::from("askpass_channel_failed"));
        }
    }
    Ok(PreparedTerminal {
        io: Arc::new(
            AsyncFd::new(pty.master).map_err(|_| String::from("pty_registration_failed"))?,
        ),
        slave: pty.slave,
        child,
    })
}

async fn wait_for_ssh_authentication(path: &Path, child: &mut Child) -> Result<(), String> {
    let deadline = Instant::now() + SSH_AUTH_TIMEOUT;
    while path.exists() {
        match child.try_wait() {
            Ok(Some(_)) => return Err(String::from("openssh_authentication_failed")),
            Ok(None) => {}
            Err(_) => return Err(String::from("openssh_wait_failed")),
        }
        if Instant::now() >= deadline {
            return Err(String::from("openssh_authentication_timeout"));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    tokio::time::sleep(SSH_AUTH_SETTLE_TIME).await;
    match child.try_wait() {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err(String::from("openssh_authentication_failed")),
        Err(_) => Err(String::from("openssh_wait_failed")),
    }
}

fn ssh_command(
    config: &AgentConfig,
    lease: &TerminalLease,
    fifo_path: &Path,
    slave: &OwnedFd,
) -> Result<Command, String> {
    let stdin = Stdio::from(
        slave
            .try_clone()
            .map_err(|_| String::from("pty_setup_failed"))?,
    );
    let stdout = Stdio::from(
        slave
            .try_clone()
            .map_err(|_| String::from("pty_setup_failed"))?,
    );
    let stderr = Stdio::from(
        slave
            .try_clone()
            .map_err(|_| String::from("pty_setup_failed"))?,
    );
    let mut command = Command::new(&config.setsid_executable);
    command
        .arg("--ctty")
        .arg("--wait")
        .arg(&config.ssh_executable)
        .arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg("BatchMode=no")
        .arg("-o")
        .arg("NumberOfPasswordPrompts=1")
        .arg("-o")
        .arg("PreferredAuthentications=password")
        .arg("-o")
        .arg("PasswordAuthentication=yes")
        .arg("-o")
        .arg("PubkeyAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
        .arg("-o")
        .arg("GSSAPIAuthentication=no")
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            config.ssh_known_hosts.to_string_lossy()
        ))
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg(format!("HostKeyAlias={LOOPBACK_HOST_ALIAS}"))
        .arg("-o")
        .arg("CheckHostIP=no")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg("-o")
        .arg("ConnectionAttempts=1")
        .arg("-o")
        .arg("ServerAliveInterval=15")
        .arg("-o")
        .arg("ServerAliveCountMax=2")
        .arg("-o")
        .arg("ClearAllForwardings=yes")
        .arg("-o")
        .arg("ForwardAgent=no")
        .arg("-o")
        .arg("PermitLocalCommand=no")
        .arg("-o")
        .arg("LocalCommand=none")
        .arg("-o")
        .arg("ControlMaster=no")
        .arg("-o")
        .arg("ControlPath=none")
        .arg("-o")
        .arg("EscapeChar=none")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-o")
        .arg("RequestTTY=force")
        .arg("-p")
        .arg("22")
        .arg("-l")
        .arg(&lease.subject.username)
        .arg(LOOPBACK_HOST)
        .env_clear()
        .env("DISPLAY", "jw-agent:0")
        .env("LANG", "C.UTF-8")
        .env("TERM", "xterm-256color")
        .env("SSH_ASKPASS", &config.askpass_executable)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("JW_AGENT_ASKPASS_MODE", "1")
        .env("JW_AGENT_ASKPASS_FIFO", fifo_path)
        .stdin(stdin)
        .stdout(stdout)
        .stderr(stderr)
        .kill_on_drop(true);
    Ok(command)
}

async fn hold_askpass_channel(path: PathBuf, keeper: fs::File) {
    let deadline = Instant::now() + SSH_AUTH_TIMEOUT;
    while Instant::now() < deadline && path.exists() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    drop(keeper);
    if path.exists() {
        let _cleanup = fs::remove_file(path);
    }
}

async fn relay_terminal(
    socket: &mut WebSocket,
    terminal: &mut PreparedTerminal,
    lease: &mut TerminalLease,
    bytes_in: &mut u64,
    bytes_out: &mut u64,
    config: &AgentConfig,
) -> String {
    let started = Instant::now();
    let mut last_activity = started;
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut buffer = vec![0_u8; TERMINAL_MAX_FRAME_BYTES];
    let reason = loop {
        tokio::select! {
            received = socket.recv() => {
                match received {
                    Some(Ok(message)) => match handle_browser_message(message, terminal, config).await {
                        Ok(InputEffect::Bytes(count)) => {
                            *bytes_in = bytes_in.saturating_add(count);
                            last_activity = Instant::now();
                        }
                        Ok(InputEffect::Control) => last_activity = Instant::now(),
                        Ok(InputEffect::Close) => break String::from("browser_closed"),
                        Err(reason) => break reason,
                    },
                    Some(Err(_)) | None => break String::from("browser_disconnected"),
                }
            }
            read = pty_read(&terminal.io, &mut buffer) => {
                match read {
                    Ok(0) => break String::from("remote_closed"),
                    Ok(count) => {
                        let count_u64 = u64::try_from(count).map_or(u64::MAX, std::convert::identity);
                        *bytes_out = bytes_out.saturating_add(count_u64);
                        if socket.send(Message::binary(buffer[..count].to_vec())).await.is_err() {
                            break String::from("browser_disconnected");
                        }
                        last_activity = Instant::now();
                    }
                    Err(_) => break String::from("pty_read_failed"),
                }
            }
            changed = lease.cancellation.changed() => {
                if changed.is_err() || *lease.cancellation.borrow() {
                    break String::from("session_revoked");
                }
            }
            _ = interval.tick() => {
                if started.elapsed() >= Duration::from_secs(TERMINAL_MAX_LIFETIME_SECONDS) {
                    break String::from("max_lifetime_reached");
                }
                if last_activity.elapsed() >= Duration::from_secs(TERMINAL_IDLE_TIMEOUT_SECONDS) {
                    break String::from("idle_timeout");
                }
                match terminal.child.try_wait() {
                    Ok(Some(_)) => break String::from("remote_exit"),
                    Ok(None) => {}
                    Err(_) => break String::from("openssh_wait_failed"),
                }
            }
        }
    };
    let _kill = terminal.child.start_kill();
    let _waited = timeout(PROCESS_EXIT_TIMEOUT, terminal.child.wait()).await;
    reason
}

enum InputEffect {
    Bytes(u64),
    Control,
    Close,
}

async fn handle_browser_message(
    message: Message,
    terminal: &mut PreparedTerminal,
    config: &AgentConfig,
) -> Result<InputEffect, String> {
    match message {
        Message::Text(text) => {
            if text.len() > TERMINAL_MAX_FRAME_BYTES {
                return Err(String::from("frame_limit_exceeded"));
            }
            let command: TerminalClientMessage = serde_json::from_str(text.as_str())
                .map_err(|_| String::from("invalid_terminal_message"))?;
            match command {
                TerminalClientMessage::Input { data } => {
                    if data.len() > TERMINAL_MAX_FRAME_BYTES {
                        return Err(String::from("input_limit_exceeded"));
                    }
                    pty_write_all(&terminal.io, data.as_bytes()).await?;
                    Ok(InputEffect::Bytes(
                        u64::try_from(data.len()).map_or(u64::MAX, std::convert::identity),
                    ))
                }
                TerminalClientMessage::Resize { rows, cols } => {
                    validate_terminal_size(rows, cols).map_err(str::to_owned)?;
                    resize_terminal(&terminal.slave, rows, cols, config).await?;
                    Ok(InputEffect::Control)
                }
            }
        }
        Message::Close(_) => Ok(InputEffect::Close),
        Message::Ping(_) | Message::Pong(_) => Ok(InputEffect::Control),
        Message::Binary(_) => Err(String::from("binary_input_rejected")),
    }
}

async fn resize_terminal(
    slave: &OwnedFd,
    rows: u16,
    cols: u16,
    config: &AgentConfig,
) -> Result<(), String> {
    let stdin = Stdio::from(
        slave
            .try_clone()
            .map_err(|_| String::from("pty_resize_failed"))?,
    );
    let mut command = Command::new(&config.stty_executable);
    let mut child = command
        .arg("rows")
        .arg(rows.to_string())
        .arg("cols")
        .arg(cols.to_string())
        .env_clear()
        .stdin(stdin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| String::from("pty_resize_failed"))?;
    match timeout(Duration::from_secs(1), child.wait()).await {
        Ok(Ok(status)) if status.success() => Ok(()),
        _ => Err(String::from("pty_resize_failed")),
    }
}

fn set_nonblocking(fd: &OwnedFd) -> Result<(), String> {
    let current = fcntl(fd, FcntlArg::F_GETFL).map_err(|_| String::from("pty_setup_failed"))?;
    let flags = OFlag::from_bits_truncate(current) | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(flags)).map_err(|_| String::from("pty_setup_failed"))?;
    Ok(())
}

async fn pty_read(fd: &AsyncFd<OwnedFd>, buffer: &mut [u8]) -> Result<usize, String> {
    loop {
        let mut guard = fd
            .readable()
            .await
            .map_err(|_| String::from("pty_read_failed"))?;
        match guard.try_io(|inner| {
            nix::unistd::read(inner.get_ref(), buffer).map_err(std::io::Error::from)
        }) {
            Ok(Ok(count)) => return Ok(count),
            Ok(Err(error)) if error.raw_os_error() == Some(nix::libc::EIO) => return Ok(0),
            Ok(Err(_)) => return Err(String::from("pty_read_failed")),
            Err(_would_block) => {}
        }
    }
}

async fn pty_write_all(fd: &AsyncFd<OwnedFd>, mut input: &[u8]) -> Result<(), String> {
    while !input.is_empty() {
        let mut guard = fd
            .writable()
            .await
            .map_err(|_| String::from("pty_write_failed"))?;
        match guard.try_io(|inner| {
            nix::unistd::write(inner.get_ref(), input).map_err(std::io::Error::from)
        }) {
            Ok(Ok(0)) => return Err(String::from("pty_write_failed")),
            Ok(Ok(count)) => input = &input[count..],
            Ok(Err(_)) => return Err(String::from("pty_write_failed")),
            Err(_would_block) => {}
        }
    }
    Ok(())
}

fn askpass_path(config: &AgentConfig, session_id: &str) -> Result<PathBuf, String> {
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(String::from("terminal_session_id_invalid"));
    }
    Ok(config
        .askpass_directory
        .join(format!("askpass-{session_id}.fifo")))
}

fn close_code(reason: &str) -> u16 {
    match reason {
        "browser_closed" | "remote_exit" | "remote_closed" => 1_000,
        "session_revoked" => 4_003,
        "idle_timeout" | "max_lifetime_reached" => 4_008,
        "frame_limit_exceeded" | "input_limit_exceeded" | "binary_input_rejected" => 1_009,
        _ => 1_011,
    }
}

fn unix_milliseconds() -> Result<i64, String> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| String::from("system clock is before Unix epoch"))?;
    i64::try_from(duration.as_millis()).map_err(|_| String::from("system clock overflow"))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use jw_contracts::{IngressChannel, Role, SecretString, Subject};
    use nix::pty::openpty;

    use crate::terminal::TerminalTicketIssue;
    use crate::{AgentConfig, TerminalBroker};

    use super::ssh_command;

    #[test]
    fn ssh_command_has_fixed_loopback_target_and_no_remote_command() -> Result<(), String> {
        let broker = TerminalBroker::default();
        let issued = broker
            .issue(TerminalTicketIssue {
                session_token: "session",
                subject: Subject {
                    uid: 1_000,
                    username: String::from("operator"),
                    role: Role::Operator,
                },
                ingress: IngressChannel::Recovery,
                origin: String::from("http://127.0.0.1:8787"),
                password: SecretString::new(String::from("secret")),
                rows: 24,
                cols: 80,
                now_unix_ms: 1_000,
            })
            .map_err(|_| String::from("ticket issue failed"))?;
        let lease = broker
            .consume(
                issued.ticket.expose(),
                "session",
                IngressChannel::Recovery,
                "http://127.0.0.1:8787",
            )
            .map_err(|_| String::from("ticket consume failed"))?;
        let config = test_config()?;
        let pty = openpty(None, None).map_err(|error| error.to_string())?;
        let command = ssh_command(
            &config,
            &lease,
            Path::new("/run/jw-agent/askpass/askpass-0123456789abcdef0123456789abcdef.fifo"),
            &pty.slave,
        )?;
        let arguments: Vec<String> = command
            .as_std()
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(arguments.last().map(String::as_str), Some("127.0.0.1"));
        assert_eq!(
            command.as_std().get_program(),
            config.setsid_executable.as_os_str()
        );
        assert!(arguments.starts_with(&[
            String::from("--ctty"),
            String::from("--wait"),
            String::from("/usr/bin/ssh"),
        ]));
        assert!(arguments.windows(2).any(|pair| pair == ["-l", "operator"]));
        assert!(!arguments.iter().any(|argument| argument.contains("secret")));
        Ok(())
    }

    fn test_config() -> Result<AgentConfig, String> {
        Ok(AgentConfig {
            recovery_address: "127.0.0.1:8787"
                .parse()
                .map_err(|_| String::from("test address invalid"))?,
            recovery_origin: String::from("http://127.0.0.1:8787"),
            public_host: None,
            public_addresses: Vec::new(),
            proxy_socket: PathBuf::new(),
            auth_socket: PathBuf::new(),
            ops_socket: PathBuf::new(),
            database: PathBuf::new(),
            web_root: PathBuf::new(),
            ssh_executable: PathBuf::from("/usr/bin/ssh"),
            ssh_known_hosts: PathBuf::new(),
            askpass_executable: PathBuf::new(),
            askpass_directory: PathBuf::from("/run/jw-agent/askpass"),
            stty_executable: PathBuf::from("/usr/bin/stty"),
            setsid_executable: PathBuf::from("/usr/bin/setsid"),
            auth_timeout: Duration::from_secs(8),
            operation_timeout: Duration::from_secs(60),
        })
    }
}
