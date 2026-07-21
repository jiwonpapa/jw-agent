use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jw_contracts::{IngressChannel, SecretString, Subject, TERMINAL_TICKET_TTL_SECONDS};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use zeroize::{Zeroize, Zeroizing};

use crate::AgentConfig;

const TOKEN_BYTES: usize = 32;
const TOKEN_TEXT_BYTES: usize = 43;
const MAX_GLOBAL_SESSIONS: usize = 8;
const LOOPBACK_HOST_ALIAS: &str = "jw-agent-loopback";

#[derive(Clone, Default)]
pub struct TerminalBroker {
    inner: Arc<Mutex<TerminalState>>,
}

#[derive(Default)]
struct TerminalState {
    tickets: HashMap<[u8; 32], TicketEntry>,
    active: HashMap<[u8; 32], ActiveEntry>,
}

struct TicketEntry {
    session_binding: [u8; 32],
    subject: Subject,
    ingress: IngressChannel,
    origin: String,
    password: SecretString,
    rows: u16,
    cols: u16,
    expires_at: Instant,
}

struct ActiveEntry {
    session_id: String,
    cancel: watch::Sender<bool>,
}

pub struct IssuedTerminalTicket {
    pub ticket: SecretString,
    pub expires_at_unix_ms: i64,
}

pub struct TerminalTicketIssue<'a> {
    pub session_token: &'a str,
    pub subject: Subject,
    pub ingress: IngressChannel,
    pub origin: String,
    pub password: SecretString,
    pub rows: u16,
    pub cols: u16,
    pub now_unix_ms: i64,
}

pub struct TerminalLease {
    broker: TerminalBroker,
    session_binding: [u8; 32],
    pub session_id: String,
    pub subject: Subject,
    pub ingress: IngressChannel,
    password: Option<SecretString>,
    pub rows: u16,
    pub cols: u16,
    pub cancellation: watch::Receiver<bool>,
}

impl Drop for TerminalLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.broker.inner.lock()
            && state
                .active
                .get(&self.session_binding)
                .is_some_and(|active| active.session_id == self.session_id)
        {
            state.active.remove(&self.session_binding);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalTicketError {
    Busy,
    Expired,
    Invalid,
    Storage,
}

impl TerminalBroker {
    pub fn issue(
        &self,
        issue: TerminalTicketIssue<'_>,
    ) -> Result<IssuedTerminalTicket, TerminalTicketError> {
        let session_binding = session_binding(issue.session_token);
        let mut state = self
            .inner
            .lock()
            .map_err(|_| TerminalTicketError::Storage)?;
        cleanup_expired(&mut state);
        if state.active.contains_key(&session_binding)
            || state
                .tickets
                .values()
                .any(|ticket| ticket.session_binding == session_binding)
            || state.tickets.len() >= MAX_GLOBAL_SESSIONS
            || state.active.len() >= MAX_GLOBAL_SESSIONS
        {
            return Err(TerminalTicketError::Busy);
        }
        let ticket = random_token().map_err(|_| TerminalTicketError::Storage)?;
        let digest = ticket_digest(ticket.as_bytes());
        let expires_at_unix_ms = issue.now_unix_ms.saturating_add(
            i64::try_from(TERMINAL_TICKET_TTL_SECONDS.saturating_mul(1_000))
                .map_err(|_| TerminalTicketError::Storage)?,
        );
        state.tickets.insert(
            digest,
            TicketEntry {
                session_binding,
                subject: issue.subject,
                ingress: issue.ingress,
                origin: issue.origin,
                password: issue.password,
                rows: issue.rows,
                cols: issue.cols,
                expires_at: Instant::now() + Duration::from_secs(TERMINAL_TICKET_TTL_SECONDS),
            },
        );
        Ok(IssuedTerminalTicket {
            ticket: SecretString::new(ticket.to_string()),
            expires_at_unix_ms,
        })
    }

    pub fn consume(
        &self,
        ticket: &str,
        session_token: &str,
        ingress: IngressChannel,
        origin: &str,
    ) -> Result<TerminalLease, TerminalTicketError> {
        if !valid_token_shape(ticket) {
            return Err(TerminalTicketError::Invalid);
        }
        let binding = session_binding(session_token);
        let mut state = self
            .inner
            .lock()
            .map_err(|_| TerminalTicketError::Storage)?;
        let Some(entry) = state.tickets.remove(&ticket_digest(ticket.as_bytes())) else {
            cleanup_expired(&mut state);
            return Err(TerminalTicketError::Invalid);
        };
        cleanup_expired(&mut state);
        if entry.expires_at <= Instant::now() {
            return Err(TerminalTicketError::Expired);
        }
        if entry.session_binding != binding || entry.ingress != ingress || entry.origin != origin {
            return Err(TerminalTicketError::Invalid);
        }
        if state.active.contains_key(&binding) || state.active.len() >= MAX_GLOBAL_SESSIONS {
            return Err(TerminalTicketError::Busy);
        }
        let session_id = random_session_id().map_err(|_| TerminalTicketError::Storage)?;
        let (cancel, cancellation) = watch::channel(false);
        state.active.insert(
            binding,
            ActiveEntry {
                session_id: session_id.clone(),
                cancel,
            },
        );
        Ok(TerminalLease {
            broker: self.clone(),
            session_binding: binding,
            session_id,
            subject: entry.subject,
            ingress: entry.ingress,
            password: Some(entry.password),
            rows: entry.rows,
            cols: entry.cols,
            cancellation,
        })
    }

    pub fn revoke_session(&self, session_token: &str) {
        let binding = session_binding(session_token);
        if let Ok(mut state) = self.inner.lock() {
            state
                .tickets
                .retain(|_, ticket| ticket.session_binding != binding);
            if let Some(active) = state.active.get(&binding) {
                let _notified = active.cancel.send(true);
            }
        }
    }

    pub fn revoke_all(&self) {
        if let Ok(mut state) = self.inner.lock() {
            state.tickets.clear();
            for active in state.active.values() {
                let _notified = active.cancel.send(true);
            }
        }
    }

    pub fn schedule_expiry(&self, ticket: &str) -> Result<(), TerminalTicketError> {
        self.schedule_expiry_after(ticket, Duration::from_secs(TERMINAL_TICKET_TTL_SECONDS))
    }

    fn schedule_expiry_after(
        &self,
        ticket: &str,
        delay: Duration,
    ) -> Result<(), TerminalTicketError> {
        if !valid_token_shape(ticket) {
            return Err(TerminalTicketError::Invalid);
        }
        let digest = ticket_digest(ticket.as_bytes());
        let broker = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            if let Ok(mut state) = broker.inner.lock() {
                state.tickets.remove(&digest);
            }
        });
        Ok(())
    }
}

impl TerminalLease {
    pub fn take_password(&mut self) -> Result<SecretString, TerminalTicketError> {
        self.password.take().ok_or(TerminalTicketError::Invalid)
    }
}

pub fn terminal_runtime_available(config: &AgentConfig) -> Result<(), &'static str> {
    validate_root_executable(&config.ssh_executable).map_err(|_| "openssh_client_unavailable")?;
    validate_known_hosts(&config.ssh_known_hosts).map_err(|_| "ssh_known_hosts_unavailable")?;
    validate_root_executable(&config.askpass_executable).map_err(|_| "askpass_unavailable")?;
    validate_root_executable(&config.stty_executable).map_err(|_| "stty_unavailable")?;
    validate_root_executable(&config.setsid_executable).map_err(|_| "setsid_unavailable")?;
    validate_agent_directory(&config.askpass_directory).map_err(|_| "askpass_runtime_unavailable")
}

fn validate_root_executable(path: &Path) -> Result<(), ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    let mode = metadata.permissions().mode();
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || mode & 0o022 != 0
        || mode & 0o111 == 0
    {
        return Err(());
    }
    Ok(())
}

fn validate_known_hosts(path: &Path) -> Result<(), ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > 64 * 1_024
    {
        return Err(());
    }
    let content = fs::read_to_string(path).map_err(|_| ())?;
    if content.lines().any(valid_known_host_line) {
        Ok(())
    } else {
        Err(())
    }
}

fn valid_known_host_line(line: &str) -> bool {
    let mut fields = line.split_ascii_whitespace();
    let hosts = fields.next();
    let key_type = fields.next();
    let key = fields.next();
    hosts.is_some_and(|value| value.split(',').any(|host| host == LOOPBACK_HOST_ALIAS))
        && key_type
            .is_some_and(|value| matches!(value, "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ssh-rsa"))
        && key.is_some_and(|value| !value.is_empty() && value.len() <= 16 * 1_024)
}

fn validate_agent_directory(path: &Path) -> Result<(), ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_dir()
        || metadata.uid() == 0
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(());
    }
    Ok(())
}

fn cleanup_expired(state: &mut TerminalState) {
    let now = Instant::now();
    state.tickets.retain(|_, ticket| ticket.expires_at > now);
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
    digest_with_domain(b"jw-agent/terminal-session/v1\0", token.as_bytes())
}

fn ticket_digest(token: &[u8]) -> [u8; 32] {
    digest_with_domain(b"jw-agent/terminal-ticket/v1\0", token)
}

fn digest_with_domain(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().into()
}

fn valid_token_shape(token: &str) -> bool {
    token.len() == TOKEN_TEXT_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use jw_contracts::{IngressChannel, Role, SecretString, Subject};

    use super::{TerminalBroker, TerminalTicketError, TerminalTicketIssue};

    fn subject() -> Subject {
        Subject {
            uid: 1_000,
            username: String::from("operator"),
            role: Role::Operator,
        }
    }

    #[test]
    fn ticket_is_single_use_and_bound_to_session_origin_and_ingress() -> Result<(), String> {
        let broker = TerminalBroker::default();
        let issued = broker
            .issue(TerminalTicketIssue {
                session_token: "session-one",
                subject: subject(),
                ingress: IngressChannel::Public,
                origin: String::from("https://server.example.com"),
                password: SecretString::new(String::from("secret")),
                rows: 24,
                cols: 80,
                now_unix_ms: 1_000,
            })
            .map_err(|_| String::from("ticket issue failed"))?;
        assert_eq!(
            broker
                .consume(
                    issued.ticket.expose(),
                    "wrong-session",
                    IngressChannel::Public,
                    "https://server.example.com",
                )
                .err(),
            Some(TerminalTicketError::Invalid)
        );
        assert_eq!(
            broker
                .consume(
                    issued.ticket.expose(),
                    "session-one",
                    IngressChannel::Public,
                    "https://server.example.com",
                )
                .err(),
            Some(TerminalTicketError::Invalid)
        );
        Ok(())
    }

    #[test]
    fn revoke_notifies_active_lease_and_releases_quota() -> Result<(), String> {
        let broker = TerminalBroker::default();
        let issued = broker
            .issue(TerminalTicketIssue {
                session_token: "session-one",
                subject: subject(),
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
                "session-one",
                IngressChannel::Recovery,
                "http://127.0.0.1:8787",
            )
            .map_err(|_| String::from("ticket consume failed"))?;
        broker.revoke_session("session-one");
        assert!(*lease.cancellation.borrow());
        drop(lease);
        thread::sleep(Duration::from_millis(1));
        assert!(
            broker
                .issue(TerminalTicketIssue {
                    session_token: "session-one",
                    subject: subject(),
                    ingress: IngressChannel::Recovery,
                    origin: String::from("http://127.0.0.1:8787"),
                    password: SecretString::new(String::from("secret")),
                    rows: 24,
                    cols: 80,
                    now_unix_ms: 2_000,
                })
                .is_ok()
        );
        Ok(())
    }

    #[tokio::test]
    async fn scheduled_expiry_removes_password_ticket_without_another_request() -> Result<(), String>
    {
        let broker = TerminalBroker::default();
        let issued = broker
            .issue(TerminalTicketIssue {
                session_token: "expiring-session",
                subject: subject(),
                ingress: IngressChannel::Public,
                origin: String::from("https://server.example.com"),
                password: SecretString::new(String::from("secret")),
                rows: 24,
                cols: 80,
                now_unix_ms: 1_000,
            })
            .map_err(|_| String::from("ticket issue failed"))?;
        broker
            .schedule_expiry_after(issued.ticket.expose(), Duration::from_millis(5))
            .map_err(|_| String::from("ticket expiry scheduling failed"))?;
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            broker
                .consume(
                    issued.ticket.expose(),
                    "expiring-session",
                    IngressChannel::Public,
                    "https://server.example.com",
                )
                .err(),
            Some(TerminalTicketError::Invalid)
        );
        Ok(())
    }
}
