use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jw_contracts::{
    FILE_IDLE_TIMEOUT_SECONDS, FILE_MAX_LIFETIME_SECONDS, FILE_SESSION_TOKEN_BYTES, FileListView,
    FileStatView, FileTextView, IngressChannel, SecretString, Subject,
};
use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};
use tokio::time::timeout;
use zeroize::{Zeroize, Zeroizing};

use crate::sftp_protocol::SftpProtocol;
use crate::{AgentConfig, SessionStore, terminal_runtime_available};

const TOKEN_BYTES: usize = 32;
const MAX_GLOBAL_SESSIONS: usize = 8;
const LOOPBACK_HOST: &str = "127.0.0.1";
const LOOPBACK_HOST_ALIAS: &str = "jw-agent-loopback";
const AUTH_TIMEOUT: Duration = Duration::from_secs(8);
const PROCESS_EXIT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Default)]
pub struct FileBroker {
    inner: Arc<Mutex<FileState>>,
}

#[derive(Default)]
struct FileState {
    sessions: HashMap<[u8; 32], Arc<FileSession>>,
    opening: Vec<[u8; 32]>,
}

pub struct FileSessionIssue<'a> {
    pub jw_session_token: &'a str,
    pub subject: Subject,
    pub ingress: IngressChannel,
    pub origin: String,
    pub password: SecretString,
    pub now_unix_ms: i64,
}

pub struct IssuedFileSession {
    pub token: SecretString,
    pub session_id: String,
    pub expires_at_unix_ms: i64,
}

pub struct FileLease {
    session: Arc<FileSession>,
}

struct FileSession {
    session_id: String,
    jw_session_binding: [u8; 32],
    ingress: IngressChannel,
    origin: String,
    started: Instant,
    last_activity: Mutex<Instant>,
    close_reason: Mutex<String>,
    runtime: tokio::sync::Mutex<SftpRuntime>,
    store: SessionStore,
}

struct SftpRuntime {
    protocol: SftpProtocol,
    _child: Child,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileSessionError {
    Busy,
    Expired,
    Invalid,
    Storage,
    Connection(String),
    Operation(String),
}

impl Drop for FileSession {
    fn drop(&mut self) {
        let reason = self
            .close_reason
            .lock()
            .map_or_else(|_| String::from("audit_unavailable"), |value| value.clone());
        let now = unix_milliseconds().map_or(0, std::convert::identity);
        if self
            .store
            .record_file_session_finish(&self.session_id, &reason, now)
            .is_err()
        {
            eprintln!(
                "jw-agentd file session audit finalize failed session={}",
                self.session_id
            );
        }
    }
}

impl FileBroker {
    pub async fn issue(
        &self,
        issue: FileSessionIssue<'_>,
        config: &AgentConfig,
        store: &SessionStore,
    ) -> Result<IssuedFileSession, FileSessionError> {
        terminal_runtime_available(config)
            .map_err(|reason| FileSessionError::Connection(reason.to_owned()))?;
        let binding = session_binding(issue.jw_session_token);
        let session_id = random_session_id().map_err(|_| FileSessionError::Storage)?;
        let token = random_token().map_err(|_| FileSessionError::Storage)?;
        {
            let mut state = self.inner.lock().map_err(|_| FileSessionError::Storage)?;
            cleanup_expired(&mut state);
            if state.opening.contains(&binding)
                || state
                    .sessions
                    .values()
                    .any(|session| session.jw_session_binding == binding)
                || state.sessions.len().saturating_add(state.opening.len()) >= MAX_GLOBAL_SESSIONS
            {
                return Err(FileSessionError::Busy);
            }
            state.opening.push(binding);
        }

        if store
            .record_file_session_start(
                &session_id,
                &issue.subject,
                issue.ingress,
                issue.now_unix_ms,
            )
            .is_err()
        {
            self.release_opening(&binding)?;
            return Err(FileSessionError::Storage);
        }

        let runtime = match prepare_sftp(config, &issue.subject, issue.password, &session_id).await
        {
            Ok(runtime) => runtime,
            Err(reason) => {
                let now = unix_milliseconds().map_or(issue.now_unix_ms, std::convert::identity);
                let audit_result = store.record_file_session_finish(
                    &session_id,
                    connection_close_reason(&reason),
                    now,
                );
                let release_result = self.release_opening(&binding);
                if audit_result.is_err() || release_result.is_err() {
                    return Err(FileSessionError::Storage);
                }
                return Err(FileSessionError::Connection(reason));
            }
        };
        self.release_opening(&binding)?;

        let token_digest = token_digest(token.as_bytes());
        let session = Arc::new(FileSession {
            session_id: session_id.clone(),
            jw_session_binding: binding,
            ingress: issue.ingress,
            origin: issue.origin,
            started: Instant::now(),
            last_activity: Mutex::new(Instant::now()),
            close_reason: Mutex::new(String::from("broker_dropped")),
            runtime: tokio::sync::Mutex::new(runtime),
            store: store.clone(),
        });
        {
            let mut state = self.inner.lock().map_err(|_| FileSessionError::Storage)?;
            cleanup_expired(&mut state);
            if state
                .sessions
                .values()
                .any(|active| active.jw_session_binding == binding)
                || state.sessions.len() >= MAX_GLOBAL_SESSIONS
            {
                set_close_reason(&session, "session_race_rejected");
                return Err(FileSessionError::Busy);
            }
            state.sessions.insert(token_digest, session);
        }
        self.schedule_expiry(token_digest, &session_id);
        let expires_at_unix_ms = issue.now_unix_ms.saturating_add(
            i64::try_from(FILE_MAX_LIFETIME_SECONDS.saturating_mul(1_000))
                .map_err(|_| FileSessionError::Storage)?,
        );
        Ok(IssuedFileSession {
            token: SecretString::new(token.to_string()),
            session_id,
            expires_at_unix_ms,
        })
    }

    fn release_opening(&self, binding: &[u8; 32]) -> Result<(), FileSessionError> {
        let mut state = self.inner.lock().map_err(|_| FileSessionError::Storage)?;
        state.opening.retain(|candidate| candidate != binding);
        Ok(())
    }

    pub fn acquire(
        &self,
        token: &str,
        jw_session_token: &str,
        ingress: IngressChannel,
        origin: &str,
    ) -> Result<FileLease, FileSessionError> {
        if !valid_token_shape(token) {
            return Err(FileSessionError::Invalid);
        }
        let digest = token_digest(token.as_bytes());
        let binding = session_binding(jw_session_token);
        let mut state = self.inner.lock().map_err(|_| FileSessionError::Storage)?;
        cleanup_expired(&mut state);
        let Some(session) = state.sessions.get(&digest).cloned() else {
            return Err(FileSessionError::Invalid);
        };
        if session.jw_session_binding != binding
            || session.ingress != ingress
            || session.origin != origin
        {
            return Err(FileSessionError::Invalid);
        }
        if session_expired(&session) {
            state.sessions.remove(&digest);
            set_close_reason(&session, "session_expired");
            return Err(FileSessionError::Expired);
        }
        session
            .last_activity
            .lock()
            .map_err(|_| FileSessionError::Storage)?
            .clone_from(&Instant::now());
        Ok(FileLease { session })
    }

    pub fn close(
        &self,
        token: &str,
        jw_session_token: &str,
        ingress: IngressChannel,
        origin: &str,
    ) -> Result<(), FileSessionError> {
        if !valid_token_shape(token) {
            return Err(FileSessionError::Invalid);
        }
        let digest = token_digest(token.as_bytes());
        let binding = session_binding(jw_session_token);
        let mut state = self.inner.lock().map_err(|_| FileSessionError::Storage)?;
        let Some(session) = state.sessions.get(&digest) else {
            return Err(FileSessionError::Invalid);
        };
        if session.jw_session_binding != binding
            || session.ingress != ingress
            || session.origin != origin
        {
            return Err(FileSessionError::Invalid);
        }
        let removed = state.sessions.remove(&digest);
        if let Some(session) = removed {
            set_close_reason(&session, "user_closed");
        }
        Ok(())
    }

    pub fn revoke_session(&self, jw_session_token: &str) {
        let binding = session_binding(jw_session_token);
        if let Ok(mut state) = self.inner.lock() {
            let digests: Vec<[u8; 32]> = state
                .sessions
                .iter()
                .filter_map(|(digest, session)| {
                    (session.jw_session_binding == binding).then_some(*digest)
                })
                .collect();
            for digest in digests {
                if let Some(session) = state.sessions.remove(&digest) {
                    set_close_reason(&session, "session_revoked");
                }
            }
            state.opening.retain(|candidate| candidate != &binding);
        }
    }

    pub fn revoke_all(&self) {
        if let Ok(mut state) = self.inner.lock() {
            for session in state.sessions.values() {
                set_close_reason(session, "all_sessions_revoked");
            }
            state.sessions.clear();
            state.opening.clear();
        }
    }

    fn schedule_expiry(&self, digest: [u8; 32], session_id: &str) {
        let broker = self.clone();
        let expected_id = session_id.to_owned();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(FILE_IDLE_TIMEOUT_SECONDS)).await;
                let mut state = match broker.inner.lock() {
                    Ok(state) => state,
                    Err(_) => return,
                };
                let Some(session) = state.sessions.get(&digest) else {
                    return;
                };
                if session.session_id != expected_id {
                    return;
                }
                if session_expired(session) {
                    if let Some(expired) = state.sessions.remove(&digest) {
                        set_close_reason(&expired, "session_expired");
                    }
                    return;
                }
            }
        });
    }
}

impl FileLease {
    pub fn session_id(&self) -> &str {
        &self.session.session_id
    }

    pub async fn list(&self, path: &str) -> Result<FileListView, FileSessionError> {
        let mut runtime = self.session.runtime.lock().await;
        let result = runtime.protocol.list(path).await;
        self.audit(
            "list",
            path,
            result.as_ref().map_or(0, |view| view.entries.len() as u64),
            &result,
        )?;
        result.map_err(FileSessionError::Operation)
    }

    pub async fn stat(&self, path: &str) -> Result<FileStatView, FileSessionError> {
        let mut runtime = self.session.runtime.lock().await;
        let result = runtime.protocol.stat(path).await;
        self.audit("stat", path, 0, &result)?;
        result.map_err(FileSessionError::Operation)
    }

    pub async fn read_text(&self, path: &str) -> Result<FileTextView, FileSessionError> {
        let mut runtime = self.session.runtime.lock().await;
        let result = runtime.protocol.read_text(path).await;
        let bytes = result.as_ref().map_or(0, |view| view.size_bytes);
        self.audit("read", path, bytes, &result)?;
        result.map_err(FileSessionError::Operation)
    }

    pub async fn download(&self, path: &str) -> Result<Vec<u8>, FileSessionError> {
        let mut runtime = self.session.runtime.lock().await;
        let result = runtime.protocol.download(path).await;
        let bytes = result.as_ref().map_or(0, |value| value.len() as u64);
        self.audit("download", path, bytes, &result)?;
        result.map_err(FileSessionError::Operation)
    }

    fn audit<T>(
        &self,
        action: &str,
        path: &str,
        bytes: u64,
        result: &Result<T, String>,
    ) -> Result<(), FileSessionError> {
        let result_value = match result {
            Ok(_) => "ok",
            Err(reason) if reason.len() <= 64 => reason,
            Err(_) => "internal_error",
        };
        let now = unix_milliseconds().map_or(0, std::convert::identity);
        self.session
            .store
            .record_file_access(
                &self.session.session_id,
                action,
                path,
                bytes,
                result_value,
                now,
            )
            .map_err(|_| FileSessionError::Storage)
    }
}

async fn prepare_sftp(
    config: &AgentConfig,
    subject: &Subject,
    password: SecretString,
    session_id: &str,
) -> Result<SftpRuntime, String> {
    let fifo_path = askpass_path(config, session_id)?;
    mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR)
        .map_err(|_| String::from("askpass_channel_failed"))?;
    let mut keeper = match OpenOptions::new().read(true).write(true).open(&fifo_path) {
        Ok(channel) => channel,
        Err(_) => {
            let _cleanup = fs::remove_file(&fifo_path);
            return Err(String::from("askpass_channel_failed"));
        }
    };
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

    let mut command = sftp_command(config, &subject.username, &fifo_path);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            let _cleanup = fs::remove_file(&fifo_path);
            return Err(String::from("openssh_client_unavailable"));
        }
    };
    let input = child
        .stdin
        .take()
        .ok_or_else(|| String::from("sftp_pipe_unavailable"))?;
    let output = child
        .stdout
        .take()
        .ok_or_else(|| String::from("sftp_pipe_unavailable"))?;
    let mut keeper_task = tokio::spawn(hold_askpass_channel(fifo_path.clone(), keeper));
    let protocol = match timeout(AUTH_TIMEOUT, SftpProtocol::initialize(input, output)).await {
        Ok(Ok(protocol)) => protocol,
        Ok(Err(reason)) => {
            cleanup_failed_child(&mut child, &fifo_path, &mut keeper_task).await;
            return Err(if reason == "sftp_read_failed" {
                String::from("openssh_authentication_failed")
            } else {
                reason
            });
        }
        Err(_) => {
            cleanup_failed_child(&mut child, &fifo_path, &mut keeper_task).await;
            return Err(String::from("openssh_authentication_timeout"));
        }
    };
    match timeout(Duration::from_secs(1), &mut keeper_task).await {
        Ok(Ok(())) => {}
        _ => {
            cleanup_failed_child(&mut child, &fifo_path, &mut keeper_task).await;
            return Err(String::from("askpass_channel_failed"));
        }
    }
    Ok(SftpRuntime {
        protocol,
        _child: child,
    })
}

fn sftp_command(config: &AgentConfig, username: &str, fifo_path: &Path) -> Command {
    let mut command = Command::new(&config.ssh_executable);
    command
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
        .arg("RequestTTY=no")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-s")
        .arg("-p")
        .arg("22")
        .arg("-l")
        .arg(username)
        .arg(LOOPBACK_HOST)
        .arg("sftp")
        .env_clear()
        .env("DISPLAY", "jw-agent:0")
        .env("LANG", "C.UTF-8")
        .env("SSH_ASKPASS", &config.askpass_executable)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("JW_AGENT_ASKPASS_MODE", "1")
        .env("JW_AGENT_ASKPASS_FIFO", fifo_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command
}

async fn cleanup_failed_child(
    child: &mut Child,
    fifo_path: &Path,
    keeper_task: &mut tokio::task::JoinHandle<()>,
) {
    keeper_task.abort();
    let _cleanup = fs::remove_file(fifo_path);
    let _kill = child.start_kill();
    let _waited = timeout(PROCESS_EXIT_TIMEOUT, child.wait()).await;
}

async fn hold_askpass_channel(path: PathBuf, keeper: fs::File) {
    let deadline = Instant::now() + AUTH_TIMEOUT;
    while Instant::now() < deadline && path.exists() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    drop(keeper);
    if path.exists() {
        let _cleanup = fs::remove_file(path);
    }
}

fn askpass_path(config: &AgentConfig, session_id: &str) -> Result<PathBuf, String> {
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(String::from("file_session_id_invalid"));
    }
    Ok(config
        .askpass_directory
        .join(format!("askpass-{session_id}.fifo")))
}

fn cleanup_expired(state: &mut FileState) {
    let expired: Vec<[u8; 32]> = state
        .sessions
        .iter()
        .filter_map(|(digest, session)| session_expired(session).then_some(*digest))
        .collect();
    for digest in expired {
        if let Some(session) = state.sessions.remove(&digest) {
            set_close_reason(&session, "session_expired");
        }
    }
}

fn session_expired(session: &FileSession) -> bool {
    if session.started.elapsed() >= Duration::from_secs(FILE_MAX_LIFETIME_SECONDS) {
        return true;
    }
    session.last_activity.lock().map_or(true, |last| {
        last.elapsed() >= Duration::from_secs(FILE_IDLE_TIMEOUT_SECONDS)
    })
}

fn set_close_reason(session: &FileSession, reason: &str) {
    if let Ok(mut value) = session.close_reason.lock() {
        *value = reason.to_owned();
    }
}

fn connection_close_reason(reason: &str) -> &str {
    if !reason.is_empty() && reason.len() <= 64 {
        reason
    } else {
        "openssh_connection_failed"
    }
}

fn random_token() -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new([0_u8; TOKEN_BYTES]);
    getrandom::fill(bytes.as_mut()).map_err(|_| String::from("secure random unavailable"))?;
    let encoded = URL_SAFE_NO_PAD.encode(bytes.as_ref());
    bytes.zeroize();
    Ok(Zeroizing::new(encoded))
}

fn random_session_id() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| String::from("secure random unavailable"))?;
    let mut output = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}")
            .map_err(|_| String::from("identifier encoding failed"))?;
    }
    Ok(output)
}

fn session_binding(token: &str) -> [u8; 32] {
    digest_with_domain(b"jw-agent/file-jw-session/v1\0", token.as_bytes())
}

fn token_digest(token: &[u8]) -> [u8; 32] {
    digest_with_domain(b"jw-agent/file-session-token/v1\0", token)
}

fn digest_with_domain(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().into()
}

fn valid_token_shape(token: &str) -> bool {
    token.len() == FILE_SESSION_TOKEN_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn unix_milliseconds() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| String::from("system clock is before Unix epoch"))?;
    i64::try_from(duration.as_millis()).map_err(|_| String::from("system clock overflow"))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use crate::AgentConfig;

    use super::{session_binding, sftp_command, token_digest, valid_token_shape};

    #[test]
    fn token_domain_and_shape_are_distinct() {
        let token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(valid_token_shape(token));
        assert_ne!(session_binding(token), token_digest(token.as_bytes()));
        assert!(!valid_token_shape("short"));
    }

    #[test]
    fn sftp_command_is_fixed_to_loopback_read_only_subsystem() -> Result<(), String> {
        let config = test_config()?;
        let command = sftp_command(
            &config,
            "operator",
            Path::new("/run/jw-agent/askpass/askpass-0123456789abcdef0123456789abcdef.fifo"),
        );
        let arguments: Vec<String> = command
            .as_std()
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            command.as_std().get_program(),
            config.ssh_executable.as_os_str()
        );
        assert!(arguments.windows(2).any(|pair| pair == ["-l", "operator"]));
        assert!(arguments.windows(2).any(|pair| pair == ["-s", "-p"]));
        assert_eq!(
            arguments
                .get(arguments.len().saturating_sub(2))
                .map(String::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(arguments.last().map(String::as_str), Some("sftp"));
        assert!(
            arguments
                .iter()
                .any(|value| value == "ClearAllForwardings=yes")
        );
        assert!(arguments.iter().any(|value| value == "RequestTTY=no"));
        assert!(!arguments.iter().any(|value| value.contains("secret")));
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
            ssh_known_hosts: PathBuf::from("/etc/jw-agent/ssh_known_hosts"),
            askpass_executable: PathBuf::from("/usr/lib/jw-agent/jw-agentd"),
            askpass_directory: PathBuf::from("/run/jw-agent/askpass"),
            stty_executable: PathBuf::from("/usr/bin/stty"),
            setsid_executable: PathBuf::from("/usr/bin/setsid"),
            auth_timeout: Duration::from_secs(8),
            operation_timeout: Duration::from_secs(60),
        })
    }
}
