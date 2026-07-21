use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jw_contracts::{
    AdditionalAuthPolicy, IngressChannel, ReauthPurpose, Role, SessionView, Subject,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const MIGRATION_1: &str = include_str!("../migrations/0001_initial.sql");
const MIGRATION_2: &str = include_str!("../migrations/0002_terminal_audit.sql");
const TOKEN_BYTES: usize = 32;
const TOKEN_TEXT_BYTES: usize = 43;
const PUBLIC_IDLE_MS: i64 = 15 * 60 * 1_000;
const PUBLIC_ABSOLUTE_MS: i64 = 8 * 60 * 60 * 1_000;
const RECOVERY_IDLE_MS: i64 = 10 * 60 * 1_000;
const RECOVERY_ABSOLUTE_MS: i64 = 2 * 60 * 60 * 1_000;
const REAUTH_CLAIM_MS: i64 = 5 * 60 * 1_000;
const SESSION_TOUCH_INTERVAL_MS: i64 = 60 * 1_000;

#[derive(Clone, Debug)]
pub struct SessionStore {
    path: PathBuf,
}

pub struct IssuedSession {
    token: Zeroizing<String>,
    pub view: SessionView,
}

impl IssuedSession {
    #[must_use]
    pub fn token(&self) -> &str {
        self.token.as_str()
    }
}

pub struct ReauthClaim {
    token: Zeroizing<String>,
    pub expires_at: String,
}

impl ReauthClaim {
    #[must_use]
    pub fn token(&self) -> &str {
        self.token.as_str()
    }
}

impl SessionStore {
    pub fn open(path: PathBuf, now_unix_ms: i64) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        migrate(&path, now_unix_ms)?;
        Ok(Self { path })
    }

    pub fn issue_session(
        &self,
        subject: &Subject,
        ingress: IngressChannel,
        now_unix_ms: i64,
    ) -> Result<IssuedSession, String> {
        if subject.uid == 0 {
            return Err(String::from("root session is forbidden"));
        }
        let policy = self.additional_auth_policy()?;
        let token = random_token()?;
        let token_digest = session_digest(token.as_bytes());
        let (idle_duration, absolute_duration) = session_durations(ingress);
        let idle_expires_at = now_unix_ms.saturating_add(idle_duration);
        let absolute_expires_at = now_unix_ms.saturating_add(absolute_duration);
        let connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO sessions(\
                    token_digest, ingress, subject_uid, subject_username, subject_role, \
                    authenticated_at_unix_ms, last_seen_at_unix_ms, idle_expires_at_unix_ms, \
                    absolute_expires_at_unix_ms, revoked_at_unix_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8, NULL)",
                params![
                    token_digest.as_slice(),
                    ingress_value(ingress),
                    subject.uid,
                    subject.username,
                    role_value(subject.role),
                    now_unix_ms,
                    idle_expires_at,
                    absolute_expires_at,
                ],
            )
            .map_err(|error| error.to_string())?;
        let view = session_view(
            subject.clone(),
            ingress,
            now_unix_ms,
            idle_expires_at,
            absolute_expires_at,
            token.as_str(),
            policy,
        )?;
        Ok(IssuedSession { token, view })
    }

    pub fn authenticate_session(
        &self,
        token: &str,
        ingress: IngressChannel,
        now_unix_ms: i64,
    ) -> Result<Option<SessionView>, String> {
        if !valid_token_shape(token) {
            return Ok(None);
        }
        let digest = session_digest(token.as_bytes());
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let record = load_session(&transaction, &digest)?;
        let Some(record) = record else {
            return Ok(None);
        };
        if record.ingress != ingress
            || record.revoked_at.is_some()
            || record.idle_expires_at <= now_unix_ms
            || record.absolute_expires_at <= now_unix_ms
        {
            return Ok(None);
        }
        let should_touch =
            now_unix_ms.saturating_sub(record.last_seen_at) >= SESSION_TOUCH_INTERVAL_MS;
        let idle_expires_at = if should_touch {
            let (idle_duration, _) = session_durations(ingress);
            let next_idle = now_unix_ms
                .saturating_add(idle_duration)
                .min(record.absolute_expires_at);
            transaction
                .execute(
                    "UPDATE sessions SET last_seen_at_unix_ms = ?1, idle_expires_at_unix_ms = ?2 \
                     WHERE token_digest = ?3 AND revoked_at_unix_ms IS NULL",
                    params![now_unix_ms, next_idle, digest.as_slice()],
                )
                .map_err(|error| error.to_string())?;
            next_idle
        } else {
            record.idle_expires_at
        };
        let policy = policy_in_transaction(&transaction)?;
        transaction.commit().map_err(|error| error.to_string())?;
        session_view(
            record.subject,
            ingress,
            record.authenticated_at,
            idle_expires_at,
            record.absolute_expires_at,
            token,
            policy,
        )
        .map(Some)
    }

    pub fn revoke_session(&self, token: &str, now_unix_ms: i64) -> Result<(), String> {
        if !valid_token_shape(token) {
            return Ok(());
        }
        let digest = session_digest(token.as_bytes());
        self.connection()?
            .execute(
                "UPDATE sessions SET revoked_at_unix_ms = ?1 WHERE token_digest = ?2",
                params![now_unix_ms, digest.as_slice()],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn revoke_all(&self, now_unix_ms: i64) -> Result<usize, String> {
        self.connection()?
            .execute(
                "UPDATE sessions SET revoked_at_unix_ms = ?1 WHERE revoked_at_unix_ms IS NULL",
                [now_unix_ms],
            )
            .map_err(|error| error.to_string())
    }

    pub fn record_terminal_start(
        &self,
        session_id: &str,
        subject: &Subject,
        ingress: IngressChannel,
        now_unix_ms: i64,
    ) -> Result<(), String> {
        if session_id.len() != 32 || subject.uid == 0 {
            return Err(String::from("terminal audit identity is invalid"));
        }
        let changed = self
            .connection()?
            .execute(
                "INSERT INTO terminal_sessions(\
                    session_id, actor_uid, actor_username, ingress, remote_host, \
                    started_at_unix_ms, ended_at_unix_ms, close_reason, bytes_in, bytes_out, state\
                 ) VALUES (?1, ?2, ?3, ?4, '127.0.0.1', ?5, NULL, NULL, 0, 0, 'active')",
                params![
                    session_id,
                    subject.uid,
                    subject.username,
                    ingress_value(ingress),
                    now_unix_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 1 {
            Ok(())
        } else {
            Err(String::from("terminal audit start was not recorded"))
        }
    }

    pub fn record_terminal_finish(
        &self,
        session_id: &str,
        reason: &str,
        bytes_in: u64,
        bytes_out: u64,
        now_unix_ms: i64,
    ) -> Result<(), String> {
        if reason.is_empty() || reason.len() > 64 {
            return Err(String::from("terminal audit reason is invalid"));
        }
        let stored_in = i64::try_from(bytes_in).map_or(i64::MAX, std::convert::identity);
        let stored_out = i64::try_from(bytes_out).map_or(i64::MAX, std::convert::identity);
        let changed = self
            .connection()?
            .execute(
                "UPDATE terminal_sessions \
                 SET ended_at_unix_ms = ?1, close_reason = ?2, bytes_in = ?3, bytes_out = ?4, \
                     state = 'closed' \
                 WHERE session_id = ?5 AND state = 'active'",
                params![now_unix_ms, reason, stored_in, stored_out, session_id],
            )
            .map_err(|error| error.to_string())?;
        if changed == 1 {
            Ok(())
        } else {
            Err(String::from("terminal audit finish was not recorded"))
        }
    }

    pub fn additional_auth_policy(&self) -> Result<AdditionalAuthPolicy, String> {
        let connection = self.connection()?;
        policy_in_connection(&connection)
    }

    pub fn issue_reauth_claim(
        &self,
        session_token: &str,
        subject: &Subject,
        purpose: &ReauthPurpose,
        now_unix_ms: i64,
    ) -> Result<ReauthClaim, String> {
        let session_digest = session_digest(session_token.as_bytes());
        let token = random_token()?;
        let digest = claim_digest(token.as_bytes());
        let (purpose_value, context) = reauth_context(purpose);
        let expires_at = now_unix_ms.saturating_add(REAUTH_CLAIM_MS);
        self.connection()?
            .execute(
                "INSERT INTO reauth_claims(\
                    token_digest, session_digest, subject_uid, purpose, context_digest, \
                    expires_at_unix_ms, consumed_at_unix_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                params![
                    digest.as_slice(),
                    session_digest.as_slice(),
                    subject.uid,
                    purpose_value,
                    context,
                    expires_at,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(ReauthClaim {
            token,
            expires_at: format_rfc3339(expires_at)?,
        })
    }

    pub fn update_additional_auth_policy(
        &self,
        session_token: &str,
        subject: &Subject,
        target: AdditionalAuthPolicy,
        reauth_token: Option<&str>,
        now_unix_ms: i64,
    ) -> Result<(), PolicyUpdateError> {
        if subject.role != Role::Admin {
            return Err(PolicyUpdateError::Denied);
        }
        let mut connection = self.connection().map_err(PolicyUpdateError::Storage)?;
        let transaction = connection
            .transaction()
            .map_err(|error| PolicyUpdateError::Storage(error.to_string()))?;
        let _current = policy_in_transaction(&transaction).map_err(PolicyUpdateError::Storage)?;
        let token = reauth_token.ok_or(PolicyUpdateError::ReauthRequired)?;
        consume_policy_claim(
            &transaction,
            session_token,
            subject.uid,
            target,
            token,
            now_unix_ms,
        )?;
        transaction
            .execute(
                "UPDATE settings SET value = ?1, updated_at_unix_ms = ?2 \
                 WHERE key = 'additional_auth_policy'",
                params![target.as_storage_value(), now_unix_ms],
            )
            .map_err(|error| PolicyUpdateError::Storage(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| PolicyUpdateError::Storage(error.to_string()))
    }

    pub fn consume_operation_claim(
        &self,
        session_token: &str,
        subject: &Subject,
        plan_hash: &str,
        reauth_token: &str,
        now_unix_ms: i64,
    ) -> Result<(), OperationClaimError> {
        if !valid_token_shape(reauth_token) || plan_hash.is_empty() || plan_hash.len() > 128 {
            return Err(OperationClaimError::Invalid);
        }
        let digest = claim_digest(reauth_token.as_bytes());
        let session_digest = session_digest(session_token.as_bytes());
        let changed = self
            .connection()
            .map_err(OperationClaimError::Storage)?
            .execute(
                "UPDATE reauth_claims SET consumed_at_unix_ms = ?1 \
                 WHERE token_digest = ?2 AND session_digest = ?3 AND subject_uid = ?4 \
                   AND purpose = 'operation' AND context_digest = ?5 \
                   AND expires_at_unix_ms > ?1 AND consumed_at_unix_ms IS NULL",
                params![
                    now_unix_ms,
                    digest.as_slice(),
                    session_digest.as_slice(),
                    subject.uid,
                    plan_hash,
                ],
            )
            .map_err(|error| OperationClaimError::Storage(error.to_string()))?;
        if changed == 1 {
            Ok(())
        } else {
            Err(OperationClaimError::Invalid)
        }
    }

    fn connection(&self) -> Result<Connection, String> {
        configure(Connection::open(&self.path).map_err(|error| error.to_string())?)
    }
}

#[derive(Debug)]
pub enum PolicyUpdateError {
    Denied,
    ReauthRequired,
    InvalidReauth,
    Storage(String),
}

#[derive(Debug)]
pub enum OperationClaimError {
    Invalid,
    Storage(String),
}

struct SessionRecord {
    ingress: IngressChannel,
    subject: Subject,
    authenticated_at: i64,
    last_seen_at: i64,
    idle_expires_at: i64,
    absolute_expires_at: i64,
    revoked_at: Option<i64>,
}

fn load_session(
    transaction: &Transaction<'_>,
    digest: &[u8; 32],
) -> Result<Option<SessionRecord>, String> {
    transaction
        .query_row(
            "SELECT ingress, subject_uid, subject_username, subject_role, \
                    authenticated_at_unix_ms, last_seen_at_unix_ms, \
                    idle_expires_at_unix_ms, absolute_expires_at_unix_ms, revoked_at_unix_ms \
             FROM sessions WHERE token_digest = ?1",
            [digest.as_slice()],
            |row| {
                let ingress_text: String = row.get(0)?;
                let uid: u32 = row.get(1)?;
                let username: String = row.get(2)?;
                let role_text: String = row.get(3)?;
                Ok((
                    ingress_text,
                    uid,
                    username,
                    role_text,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(
            |(
                ingress_text,
                uid,
                username,
                role_text,
                authenticated_at,
                last_seen_at,
                idle_expires_at,
                absolute_expires_at,
                revoked_at,
            )| {
                Ok(SessionRecord {
                    ingress: parse_ingress(&ingress_text)?,
                    subject: Subject {
                        uid,
                        username,
                        role: parse_role(&role_text)?,
                    },
                    authenticated_at,
                    last_seen_at,
                    idle_expires_at,
                    absolute_expires_at,
                    revoked_at,
                })
            },
        )
        .transpose()
}

fn consume_policy_claim(
    transaction: &Transaction<'_>,
    session_token: &str,
    uid: u32,
    target: AdditionalAuthPolicy,
    reauth_token: &str,
    now_unix_ms: i64,
) -> Result<(), PolicyUpdateError> {
    if !valid_token_shape(reauth_token) {
        return Err(PolicyUpdateError::InvalidReauth);
    }
    let digest = claim_digest(reauth_token.as_bytes());
    let session_digest = session_digest(session_token.as_bytes());
    let changed = transaction
        .execute(
            "UPDATE reauth_claims SET consumed_at_unix_ms = ?1 \
             WHERE token_digest = ?2 AND session_digest = ?3 AND subject_uid = ?4 \
               AND purpose = 'security_policy_change' AND context_digest = ?5 \
               AND expires_at_unix_ms > ?1 AND consumed_at_unix_ms IS NULL",
            params![
                now_unix_ms,
                digest.as_slice(),
                session_digest.as_slice(),
                uid,
                target.as_storage_value(),
            ],
        )
        .map_err(|error| PolicyUpdateError::Storage(error.to_string()))?;
    if changed == 1 {
        Ok(())
    } else {
        Err(PolicyUpdateError::InvalidReauth)
    }
}

fn migrate(path: &Path, now_unix_ms: i64) -> Result<(), String> {
    let mut connection = configure(Connection::open(path).map_err(|error| error.to_string())?)?;
    let transaction = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    transaction
        .execute_batch(MIGRATION_1)
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at_unix_ms) VALUES (1, ?1)",
            [now_unix_ms],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute_batch(MIGRATION_2)
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at_unix_ms) VALUES (2, ?1)",
            [now_unix_ms],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "UPDATE terminal_sessions \
             SET ended_at_unix_ms = ?1, close_reason = 'daemon_restart', state = 'closed' \
             WHERE state = 'active'",
            [now_unix_ms],
        )
        .map_err(|error| error.to_string())?;
    transaction.commit().map_err(|error| error.to_string())
}

fn configure(connection: Connection) -> Result<Connection, String> {
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| error.to_string())?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|error| error.to_string())?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|error| error.to_string())?;
    connection
        .pragma_update(None, "secure_delete", true)
        .map_err(|error| error.to_string())?;
    Ok(connection)
}

fn random_token() -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new([0_u8; TOKEN_BYTES]);
    getrandom::fill(bytes.as_mut()).map_err(|_| String::from("secure random unavailable"))?;
    let encoded = URL_SAFE_NO_PAD.encode(bytes.as_ref());
    bytes.zeroize();
    Ok(Zeroizing::new(encoded))
}

fn session_digest(token: &[u8]) -> [u8; 32] {
    digest_with_domain(b"jw-agent/session/v1\0", token)
}

fn claim_digest(token: &[u8]) -> [u8; 32] {
    digest_with_domain(b"jw-agent/reauth/v1\0", token)
}

fn csrf_token(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest_with_domain(b"jw-agent/csrf/v1\0", token.as_bytes()))
}

fn digest_with_domain(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().into()
}

#[must_use]
pub fn csrf_matches(session_token: &str, provided: &str) -> bool {
    let expected = csrf_token(session_token);
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

fn valid_token_shape(token: &str) -> bool {
    token.len() == TOKEN_TEXT_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn session_durations(ingress: IngressChannel) -> (i64, i64) {
    match ingress {
        IngressChannel::Public => (PUBLIC_IDLE_MS, PUBLIC_ABSOLUTE_MS),
        IngressChannel::Recovery => (RECOVERY_IDLE_MS, RECOVERY_ABSOLUTE_MS),
    }
}

fn session_view(
    subject: Subject,
    ingress: IngressChannel,
    authenticated_at: i64,
    idle_expires_at: i64,
    absolute_expires_at: i64,
    token: &str,
    policy: AdditionalAuthPolicy,
) -> Result<SessionView, String> {
    Ok(SessionView {
        subject,
        ingress,
        authenticated_at: format_rfc3339(authenticated_at)?,
        idle_expires_at: format_rfc3339(idle_expires_at)?,
        absolute_expires_at: format_rfc3339(absolute_expires_at)?,
        csrf_token: csrf_token(token),
        additional_auth_policy: policy,
    })
}

fn format_rfc3339(unix_ms: i64) -> Result<String, String> {
    let nanos = i128::from(unix_ms).saturating_mul(1_000_000);
    let time = time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| String::from("timestamp is out of range"))?;
    time.format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| String::from("timestamp formatting failed"))
}

fn policy_in_connection(connection: &Connection) -> Result<AdditionalAuthPolicy, String> {
    let value: String = connection
        .query_row(
            "SELECT value FROM settings WHERE key = 'additional_auth_policy'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    AdditionalAuthPolicy::from_storage_value(&value).map_err(str::to_owned)
}

fn policy_in_transaction(transaction: &Transaction<'_>) -> Result<AdditionalAuthPolicy, String> {
    let value: String = transaction
        .query_row(
            "SELECT value FROM settings WHERE key = 'additional_auth_policy'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    AdditionalAuthPolicy::from_storage_value(&value).map_err(str::to_owned)
}

fn ingress_value(ingress: IngressChannel) -> &'static str {
    match ingress {
        IngressChannel::Public => "public",
        IngressChannel::Recovery => "recovery",
    }
}

fn parse_ingress(value: &str) -> Result<IngressChannel, String> {
    match value {
        "public" => Ok(IngressChannel::Public),
        "recovery" => Ok(IngressChannel::Recovery),
        _ => Err(String::from("invalid stored ingress")),
    }
}

fn role_value(role: Role) -> &'static str {
    match role {
        Role::Admin => "admin",
        Role::Operator => "operator",
        Role::Viewer => "viewer",
    }
}

fn parse_role(value: &str) -> Result<Role, String> {
    match value {
        "admin" => Ok(Role::Admin),
        "operator" => Ok(Role::Operator),
        "viewer" => Ok(Role::Viewer),
        _ => Err(String::from("invalid stored role")),
    }
}

fn reauth_context(purpose: &ReauthPurpose) -> (&'static str, String) {
    match purpose {
        ReauthPurpose::Operation { plan_hash } => ("operation", plan_hash.clone()),
        ReauthPurpose::SecurityPolicyChange { target_policy } => (
            "security_policy_change",
            target_policy.as_storage_value().to_owned(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use jw_contracts::{AdditionalAuthPolicy, IngressChannel, ReauthPurpose, Role, Subject};

    use super::{OperationClaimError, PolicyUpdateError, SessionStore};

    fn test_path() -> Result<PathBuf, String> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|_| String::from("random unavailable"))?;
        Ok(std::env::temp_dir().join(format!("jw-agent-session-{:02x?}.sqlite3", random)))
    }

    #[test]
    fn stores_only_session_digest_and_rejects_cross_channel() -> Result<(), String> {
        let path = test_path()?;
        let store = SessionStore::open(path.clone(), 1_000)?;
        assert_eq!(
            store.additional_auth_policy()?,
            AdditionalAuthPolicy::Disabled
        );
        let issued = store.issue_session(
            &Subject {
                uid: 1_000,
                username: String::from("admin"),
                role: Role::Admin,
            },
            IngressChannel::Public,
            1_000,
        )?;
        let token = issued.token().to_owned();
        assert!(
            store
                .authenticate_session(&token, IngressChannel::Public, 2_000)?
                .is_some()
        );
        assert!(
            store
                .authenticate_session(&token, IngressChannel::Recovery, 2_000)?
                .is_none()
        );
        let database = fs::read(&path).map_err(|error| error.to_string())?;
        assert!(
            !database
                .windows(token.len())
                .any(|window| window == token.as_bytes())
        );
        drop(issued);
        fs::remove_file(&path).map_err(|error| error.to_string())?;
        let wal = path.with_extension("sqlite3-wal");
        if wal.exists() {
            fs::remove_file(wal).map_err(|error| error.to_string())?;
        }
        let shm = path.with_extension("sqlite3-shm");
        if shm.exists() {
            fs::remove_file(shm).map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    #[test]
    fn terminal_audit_is_metadata_only_and_restart_closes_active_session() -> Result<(), String> {
        let path = test_path()?;
        let store = SessionStore::open(path.clone(), 1_000)?;
        let subject = Subject {
            uid: 1_000,
            username: String::from("operator"),
            role: Role::Operator,
        };
        store.record_terminal_start(
            "0123456789abcdef0123456789abcdef",
            &subject,
            IngressChannel::Recovery,
            2_000,
        )?;
        drop(store);

        let reopened = SessionStore::open(path.clone(), 3_000)?;
        let record: (String, String, i64, i64) = reopened
            .connection()?
            .query_row(
                "SELECT state, close_reason, bytes_in, bytes_out \
                 FROM terminal_sessions WHERE session_id = ?1",
                ["0123456789abcdef0123456789abcdef"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(
            record,
            (String::from("closed"), String::from("daemon_restart"), 0, 0,)
        );
        let columns: i64 = reopened
            .connection()?
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('terminal_sessions') \
                 WHERE name IN ('command', 'input', 'output', 'password', 'ticket')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(columns, 0);
        drop(reopened);
        cleanup_test_database(&path)
    }

    #[test]
    fn policy_update_requires_admin_reauth_and_consumes_claim_once() -> Result<(), String> {
        let path = test_path()?;
        let store = SessionStore::open(path.clone(), 1_000)?;
        let admin = Subject {
            uid: 1_000,
            username: String::from("admin"),
            role: Role::Admin,
        };
        let issued = store.issue_session(&admin, IngressChannel::Recovery, 1_000)?;
        let target = AdditionalAuthPolicy::RiskyOperations;
        assert!(matches!(
            store.update_additional_auth_policy(issued.token(), &admin, target, None, 2_000,),
            Err(PolicyUpdateError::ReauthRequired)
        ));

        let claim = store.issue_reauth_claim(
            issued.token(),
            &admin,
            &ReauthPurpose::SecurityPolicyChange {
                target_policy: target,
            },
            2_000,
        )?;
        store
            .update_additional_auth_policy(
                issued.token(),
                &admin,
                target,
                Some(claim.token()),
                2_001,
            )
            .map_err(|error| format!("first policy update failed: {error:?}"))?;
        assert_eq!(store.additional_auth_policy()?, target);
        assert!(matches!(
            store.update_additional_auth_policy(
                issued.token(),
                &admin,
                AdditionalAuthPolicy::Disabled,
                Some(claim.token()),
                2_002,
            ),
            Err(PolicyUpdateError::InvalidReauth)
        ));

        drop(claim);
        drop(issued);
        cleanup_test_database(&path)
    }

    #[test]
    fn operation_claim_is_bound_to_rotated_session_uid_and_plan() -> Result<(), String> {
        let path = test_path()?;
        let store = SessionStore::open(path.clone(), 1_000)?;
        let subject = Subject {
            uid: 1_000,
            username: String::from("admin"),
            role: Role::Admin,
        };
        let session = store.issue_session(&subject, IngressChannel::Public, 1_000)?;
        let purpose = ReauthPurpose::Operation {
            plan_hash: String::from(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
        };
        let claim = store.issue_reauth_claim(session.token(), &subject, &purpose, 1_100)?;
        store
            .consume_operation_claim(
                session.token(),
                &subject,
                match &purpose {
                    ReauthPurpose::Operation { plan_hash } => plan_hash,
                    ReauthPurpose::SecurityPolicyChange { .. } => "",
                },
                claim.token(),
                1_200,
            )
            .map_err(|error| format!("{error:?}"))?;
        assert!(matches!(
            store.consume_operation_claim(
                session.token(),
                &subject,
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                claim.token(),
                1_300,
            ),
            Err(OperationClaimError::Invalid)
        ));
        drop(claim);
        drop(session);
        cleanup_test_database(&path)
    }

    fn cleanup_test_database(path: &PathBuf) -> Result<(), String> {
        if path.exists() {
            fs::remove_file(path).map_err(|error| error.to_string())?;
        }
        let wal = path.with_extension("sqlite3-wal");
        if wal.exists() {
            fs::remove_file(wal).map_err(|error| error.to_string())?;
        }
        let shm = path.with_extension("sqlite3-shm");
        if shm.exists() {
            fs::remove_file(shm).map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}
