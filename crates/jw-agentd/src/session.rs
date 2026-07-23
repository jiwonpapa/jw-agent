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

use crate::totp::{TotpService, additional_claim_digest};

mod lifecycle;

const MIGRATION_1: &str = include_str!("../migrations/0001_initial.sql");
const MIGRATION_2: &str = include_str!("../migrations/0002_terminal_audit.sql");
const MIGRATION_3: &str = include_str!("../migrations/0003_file_audit.sql");
const MIGRATION_4: &str = include_str!("../migrations/0004_file_upload_audit.sql");
const MIGRATION_5: &str = include_str!("../migrations/0005_totp.sql");
const MIGRATION_6: &str = include_str!("../migrations/0006_administrative_access.sql");
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
    totp: TotpService,
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

pub struct FileUploadPlanAudit<'a> {
    pub upload_id: &'a str,
    pub session_id: &'a str,
    pub path: &'a str,
    pub target_state: &'a str,
    pub before_digest: Option<&'a str>,
    pub after_digest: &'a str,
    pub byte_count: u64,
    pub now_unix_ms: i64,
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
        let totp = TotpService::new(path.clone());
        Ok(Self { path, totp })
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

    pub fn record_file_session_start(
        &self,
        session_id: &str,
        subject: &Subject,
        ingress: IngressChannel,
        now_unix_ms: i64,
    ) -> Result<(), String> {
        if session_id.len() != 32 || subject.uid == 0 {
            return Err(String::from("file session audit identity is invalid"));
        }
        let changed = self
            .connection()?
            .execute(
                "INSERT INTO file_sessions(\
                session_id, actor_uid, actor_username, ingress, remote_host, \
                started_at_unix_ms, ended_at_unix_ms, close_reason, state\
             ) VALUES (?1, ?2, ?3, ?4, '127.0.0.1', ?5, NULL, NULL, 'active')",
                params![
                    session_id,
                    subject.uid,
                    subject.username,
                    ingress_value(ingress),
                    now_unix_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 1 {
            Ok(())
        } else {
            Err(String::from("file session audit start was not recorded"))
        }
    }

    pub fn record_file_session_finish(
        &self,
        session_id: &str,
        reason: &str,
        now_unix_ms: i64,
    ) -> Result<(), String> {
        if reason.is_empty() || reason.len() > 64 {
            return Err(String::from("file session audit reason is invalid"));
        }
        let changed = self.connection()?.execute(
            "UPDATE file_sessions SET ended_at_unix_ms = ?1, close_reason = ?2, state = 'closed' \
             WHERE session_id = ?3 AND state = 'active'",
            params![now_unix_ms, reason, session_id],
        ).map_err(|error| error.to_string())?;
        if changed == 1 {
            Ok(())
        } else {
            Err(String::from("file session audit finish was not recorded"))
        }
    }

    pub fn record_file_access(
        &self,
        session_id: &str,
        action: &str,
        path: &str,
        byte_count: u64,
        result: &str,
        now_unix_ms: i64,
    ) -> Result<(), String> {
        if !matches!(action, "list" | "stat" | "read" | "download")
            || result.is_empty()
            || result.len() > 64
        {
            return Err(String::from("file access audit value is invalid"));
        }
        let stored_bytes = i64::try_from(byte_count).map_or(i64::MAX, std::convert::identity);
        let path_digest = digest_with_domain(b"jw-agent/file-path/v1\0", path.as_bytes());
        self.connection()?
            .execute(
                "INSERT INTO file_access_events(\
                session_id, action, path_digest, byte_count, result, occurred_at_unix_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    session_id,
                    action,
                    path_digest.as_slice(),
                    stored_bytes,
                    result,
                    now_unix_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn record_file_upload_plan(&self, audit: &FileUploadPlanAudit<'_>) -> Result<(), String> {
        if audit.upload_id.len() != 32
            || audit.session_id.len() != 32
            || !matches!(audit.target_state, "create" | "replace")
            || audit
                .before_digest
                .is_some_and(|value| jw_contracts::validate_digest(value).is_err())
            || jw_contracts::validate_digest(audit.after_digest).is_err()
        {
            return Err(String::from("file upload audit plan is invalid"));
        }
        let path_digest = digest_with_domain(b"jw-agent/file-path/v1\0", audit.path.as_bytes());
        let stored_bytes = i64::try_from(audit.byte_count)
            .map_err(|_| String::from("file upload size overflow"))?;
        let changed = self
            .connection()?
            .execute(
                "INSERT INTO file_uploads(\
                upload_id, session_id, path_digest, target_state, before_digest, after_digest, \
                byte_count, state, result, planned_at_unix_ms, started_at_unix_ms, ended_at_unix_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'planned', NULL, ?8, NULL, NULL)",
                params![
                    audit.upload_id,
                    audit.session_id,
                    path_digest.as_slice(),
                    audit.target_state,
                    audit.before_digest,
                    audit.after_digest,
                    stored_bytes,
                    audit.now_unix_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 1 {
            Ok(())
        } else {
            Err(String::from("file upload audit plan was not recorded"))
        }
    }

    pub fn record_file_upload_start(
        &self,
        upload_id: &str,
        now_unix_ms: i64,
    ) -> Result<(), String> {
        let changed = self
            .connection()?
            .execute(
                "UPDATE file_uploads SET state = 'applying', started_at_unix_ms = ?1 \
             WHERE upload_id = ?2 AND state = 'planned'",
                params![now_unix_ms, upload_id],
            )
            .map_err(|error| error.to_string())?;
        if changed == 1 {
            Ok(())
        } else {
            Err(String::from("file upload audit start was not recorded"))
        }
    }

    pub fn record_file_upload_finish(
        &self,
        upload_id: &str,
        state: &str,
        result: &str,
        now_unix_ms: i64,
    ) -> Result<(), String> {
        if !matches!(state, "verified" | "failed" | "manual_check")
            || result.is_empty()
            || result.len() > 64
        {
            return Err(String::from("file upload audit result is invalid"));
        }
        let changed = self
            .connection()?
            .execute(
                "UPDATE file_uploads SET state = ?1, result = ?2, ended_at_unix_ms = ?3 \
             WHERE upload_id = ?4 AND state IN ('planned', 'applying')",
                params![state, result, now_unix_ms, upload_id],
            )
            .map_err(|error| error.to_string())?;
        if changed == 1 {
            Ok(())
        } else {
            Err(String::from("file upload audit finish was not recorded"))
        }
    }

    pub fn additional_auth_policy(&self) -> Result<AdditionalAuthPolicy, String> {
        let connection = self.connection()?;
        policy_in_connection(&connection)
    }

    #[must_use]
    pub fn totp(&self) -> &TotpService {
        &self.totp
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
        if target != AdditionalAuthPolicy::Disabled
            && self
                .totp
                .provider_status(subject.uid)
                .map_err(|_| PolicyUpdateError::ProviderUnavailable)?
                != jw_contracts::AdditionalAuthProviderStatus::Ready
        {
            return Err(PolicyUpdateError::ProviderUnavailable);
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
        self.consume_operation_claims(OperationAuthorization {
            session_token,
            subject,
            plan_hash,
            reauth_token,
            additional_auth_claim: None,
            additional_auth_required: false,
            now_unix_ms,
        })
    }

    pub fn consume_operation_claims(
        &self,
        authorization: OperationAuthorization<'_>,
    ) -> Result<(), OperationClaimError> {
        let OperationAuthorization {
            session_token,
            subject,
            plan_hash,
            reauth_token,
            additional_auth_claim,
            additional_auth_required,
            now_unix_ms,
        } = authorization;
        if !valid_token_shape(reauth_token) || plan_hash.is_empty() || plan_hash.len() > 128 {
            return Err(OperationClaimError::Invalid);
        }
        let digest = claim_digest(reauth_token.as_bytes());
        let session_digest = session_digest(session_token.as_bytes());
        let mut connection = self.connection().map_err(OperationClaimError::Storage)?;
        let transaction = connection
            .transaction()
            .map_err(|error| OperationClaimError::Storage(error.to_string()))?;
        let changed = transaction
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
        if changed != 1 {
            return Err(OperationClaimError::Invalid);
        }
        match (additional_auth_required, additional_auth_claim) {
            (false, None) => {}
            (false, Some(_)) | (true, None) => return Err(OperationClaimError::InvalidAdditional),
            (true, Some(claim)) => {
                if !valid_token_shape(claim) {
                    return Err(OperationClaimError::InvalidAdditional);
                }
                let claim_digest = additional_claim_digest(claim.as_bytes());
                let consumed = transaction
                    .execute(
                        "UPDATE additional_auth_claims SET consumed_at_unix_ms = ?1 \
                         WHERE token_digest = ?2 AND reauth_digest = ?3 AND session_digest = ?4 \
                           AND subject_uid = ?5 AND context_digest = ?6 \
                           AND expires_at_unix_ms > ?1 AND consumed_at_unix_ms IS NULL",
                        params![
                            now_unix_ms,
                            claim_digest.as_slice(),
                            digest.as_slice(),
                            session_digest.as_slice(),
                            subject.uid,
                            plan_hash,
                        ],
                    )
                    .map_err(|error| OperationClaimError::Storage(error.to_string()))?;
                if consumed != 1 {
                    return Err(OperationClaimError::InvalidAdditional);
                }
            }
        }
        transaction
            .commit()
            .map_err(|error| OperationClaimError::Storage(error.to_string()))
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
    ProviderUnavailable,
    Storage(String),
}

#[derive(Debug)]
pub enum OperationClaimError {
    Invalid,
    InvalidAdditional,
    Storage(String),
}

pub struct OperationAuthorization<'a> {
    pub session_token: &'a str,
    pub subject: &'a Subject,
    pub plan_hash: &'a str,
    pub reauth_token: &'a str,
    pub additional_auth_claim: Option<&'a str>,
    pub additional_auth_required: bool,
    pub now_unix_ms: i64,
}

struct SessionRecord {
    ingress: IngressChannel,
    subject: Subject,
    authenticated_at: i64,
    last_seen_at: i64,
    idle_expires_at: i64,
    absolute_expires_at: i64,
    revoked_at: Option<i64>,
    administrative_until: Option<i64>,
}

fn load_session(
    transaction: &Transaction<'_>,
    digest: &[u8; 32],
) -> Result<Option<SessionRecord>, String> {
    transaction
        .query_row(
            "SELECT sessions.ingress, sessions.subject_uid, sessions.subject_username, \
                    sessions.subject_role, sessions.authenticated_at_unix_ms, \
                    sessions.last_seen_at_unix_ms, sessions.idle_expires_at_unix_ms, \
                    sessions.absolute_expires_at_unix_ms, sessions.revoked_at_unix_ms, \
                    administrative_access.expires_at_unix_ms, \
                    administrative_access.revoked_at_unix_ms \
             FROM sessions LEFT JOIN administrative_access \
               ON administrative_access.session_digest = sessions.token_digest \
             WHERE sessions.token_digest = ?1",
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
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
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
                administrative_until,
                administrative_revoked_at,
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
                    administrative_until: administrative_until
                        .filter(|_| administrative_revoked_at.is_none()),
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
        .execute_batch(MIGRATION_3)
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at_unix_ms) VALUES (3, ?1)",
            [now_unix_ms],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute_batch(MIGRATION_4)
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at_unix_ms) VALUES (4, ?1)",
            [now_unix_ms],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "UPDATE file_uploads SET state = 'manual_check', result = 'interrupted_manual_check', \
             ended_at_unix_ms = ?1 WHERE state = 'applying'",
            [now_unix_ms],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "UPDATE file_uploads SET state = 'failed', result = 'daemon_restart_before_apply', \
             ended_at_unix_ms = ?1 WHERE state = 'planned'",
            [now_unix_ms],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "UPDATE file_sessions \
             SET ended_at_unix_ms = ?1, close_reason = 'daemon_restart', state = 'closed' \
             WHERE state = 'active'",
            [now_unix_ms],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute_batch(MIGRATION_2)
        .map_err(|error| error.to_string())?;
    transaction
        .execute_batch(MIGRATION_5)
        .map_err(|error| error.to_string())?;
    transaction
        .execute_batch(MIGRATION_6)
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at_unix_ms) VALUES (6, ?1)",
            [now_unix_ms],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at_unix_ms) VALUES (5, ?1)",
            [now_unix_ms],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "DELETE FROM additional_auth_claims \
             WHERE expires_at_unix_ms <= ?1 OR consumed_at_unix_ms IS NOT NULL",
            [now_unix_ms],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "DELETE FROM totp_enrollments WHERE state = 'pending' AND expires_at_unix_ms <= ?1",
            [now_unix_ms],
        )
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

pub(crate) fn configure(connection: Connection) -> Result<Connection, String> {
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

pub(crate) fn session_digest(token: &[u8]) -> [u8; 32] {
    digest_with_domain(b"jw-agent/session/v1\0", token)
}

pub(crate) fn claim_digest(token: &[u8]) -> [u8; 32] {
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

fn record_administrative_event(
    transaction: &Transaction<'_>,
    subject_uid: u32,
    ingress: IngressChannel,
    event_type: &str,
    result: &str,
    now_unix_ms: i64,
) -> Result<(), String> {
    if subject_uid == 0 || result.is_empty() || result.len() > 64 {
        return Err(String::from("administrative access audit value is invalid"));
    }
    transaction
        .execute(
            "INSERT INTO administrative_access_events(\
                subject_uid, ingress, event_type, result, occurred_at_unix_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                subject_uid,
                ingress_value(ingress),
                event_type,
                result,
                now_unix_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub(crate) fn format_rfc3339(unix_ms: i64) -> Result<String, String> {
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
        ReauthPurpose::TotpEnrollment => ("totp_enrollment", String::from("totp/v1")),
        ReauthPurpose::TotpRecoveryReset => ("totp_recovery_reset", String::from("totp/v1")),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use jw_contracts::{
        AdditionalAuthPolicy, AdministrativeAccessState, IngressChannel, Role, Subject,
    };
    use rusqlite::Connection;

    use super::{FileUploadPlanAudit, SessionStore};

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
    fn administrative_access_is_bounded_preserved_and_audited() -> Result<(), String> {
        let path = test_path()?;
        let store = SessionStore::open(path.clone(), 1_000)?;
        let admin = Subject {
            uid: 1_000,
            username: String::from("admin"),
            role: Role::Admin,
        };
        let standard = store.issue_session(&admin, IngressChannel::Public, 2_000)?;
        assert_eq!(
            standard.view.administrative_access,
            AdministrativeAccessState::Standard
        );
        let elevated = store.issue_administrative_session(&admin, IngressChannel::Public, 3_000)?;
        assert_eq!(
            elevated.view.administrative_access,
            AdministrativeAccessState::Administrative
        );
        assert!(elevated.view.administrative_expires_at.is_some());
        let rotated = store.issue_reauthenticated_session(
            elevated.token(),
            &admin,
            IngressChannel::Public,
            4_000,
        )?;
        assert_eq!(
            rotated.view.administrative_access,
            AdministrativeAccessState::Administrative
        );
        store.revoke_administrative_access(
            rotated.token(),
            IngressChannel::Public,
            &admin,
            5_000,
        )?;
        let after_revoke = store
            .authenticate_session(rotated.token(), IngressChannel::Public, 6_000)?
            .ok_or_else(|| String::from("rotated session missing"))?;
        assert_eq!(
            after_revoke.administrative_access,
            AdministrativeAccessState::Standard
        );
        let audit_count: i64 = Connection::open(&path)
            .map_err(|error| error.to_string())?
            .query_row(
                "SELECT COUNT(*) FROM administrative_access_events \
                 WHERE subject_uid = 1000 AND event_type IN ('grant', 'revoke')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(audit_count, 2);
        assert!(
            store
                .issue_administrative_session(
                    &Subject {
                        uid: 1_001,
                        username: String::from("operator"),
                        role: Role::Operator,
                    },
                    IngressChannel::Public,
                    7_000,
                )
                .is_err()
        );
        drop((standard, elevated, rotated, store));
        fs::remove_file(&path).map_err(|error| error.to_string())?;
        for extension in ["sqlite3-wal", "sqlite3-shm"] {
            let sidecar = path.with_extension(extension);
            if sidecar.exists() {
                fs::remove_file(sidecar).map_err(|error| error.to_string())?;
            }
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
    fn file_audit_hashes_paths_and_restart_closes_active_session() -> Result<(), String> {
        let path = test_path()?;
        let store = SessionStore::open(path.clone(), 1_000)?;
        let subject = Subject {
            uid: 1_000,
            username: String::from("operator"),
            role: Role::Operator,
        };
        let session_id = "abcdef0123456789abcdef0123456789";
        let upload_id = "fedcba9876543210fedcba9876543210";
        let sensitive_path = "private/customer-secret.txt";
        store.record_file_session_start(session_id, &subject, IngressChannel::Recovery, 2_000)?;
        store.record_file_access(session_id, "read", sensitive_path, 42, "ok", 2_001)?;
        let before_digest = jw_contracts::sha256_digest(b"before");
        let after_digest = jw_contracts::sha256_digest(b"after");
        store.record_file_upload_plan(&FileUploadPlanAudit {
            upload_id,
            session_id,
            path: sensitive_path,
            target_state: "replace",
            before_digest: Some(&before_digest),
            after_digest: &after_digest,
            byte_count: 5,
            now_unix_ms: 2_002,
        })?;
        store.record_file_upload_start(upload_id, 2_003)?;
        drop(store);

        let database = fs::read(&path).map_err(|error| error.to_string())?;
        assert!(
            !database
                .windows(sensitive_path.len())
                .any(|window| window == sensitive_path.as_bytes())
        );
        let reopened = SessionStore::open(path.clone(), 3_000)?;
        let record: (String, String) = reopened
            .connection()?
            .query_row(
                "SELECT state, close_reason FROM file_sessions WHERE session_id = ?1",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(
            record,
            (String::from("closed"), String::from("daemon_restart"))
        );
        let forbidden_columns: i64 = reopened
            .connection()?
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('file_access_events') \
                 WHERE name IN ('path', 'content', 'password', 'token')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(forbidden_columns, 0);
        let upload_record: (String, String) = reopened
            .connection()?
            .query_row(
                "SELECT state, result FROM file_uploads WHERE upload_id = ?1",
                [upload_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(
            upload_record,
            (
                String::from("manual_check"),
                String::from("interrupted_manual_check")
            )
        );
        let upload_forbidden_columns: i64 = reopened
            .connection()?
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('file_uploads') \
                 WHERE name IN ('path', 'content', 'password', 'token', 'temporary_name')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(upload_forbidden_columns, 0);
        drop(reopened);
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
