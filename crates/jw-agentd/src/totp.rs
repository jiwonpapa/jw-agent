use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, Mac};
use jw_contracts::{
    AdditionalAuthProviderStatus, IngressChannel, Role, SecretString, Subject, TOTP_PROVIDER_ID,
    TotpEnrollmentConfirmView, TotpEnrollmentStartView, TotpEnrollmentState, TotpVerificationView,
    validate_enrollment_id, validate_totp_code,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::session::{claim_digest, configure, format_rfc3339, session_digest};

const SECRET_BYTES: usize = 20;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const RECOVERY_CODE_BYTES: usize = 16;
const RECOVERY_CODE_COUNT: usize = 10;
const ENROLLMENT_TTL_MS: i64 = 10 * 60 * 1_000;
const CLAIM_TTL_MS: i64 = 5 * 60 * 1_000;
const TOTP_PERIOD_MS: i64 = 30 * 1_000;
const MAX_CLOCK_ROLLBACK_STEPS: i64 = 1;

#[derive(Clone, Debug)]
pub struct TotpService {
    database: PathBuf,
    key_path: PathBuf,
}

pub struct TotpEnrollmentIssue {
    pub view: TotpEnrollmentStartView,
}

#[derive(Debug)]
pub enum TotpError {
    Denied,
    NotConfigured,
    AlreadyConfigured,
    InvalidClaim,
    InvalidCode,
    Replay,
    ClockRollback,
    EnrollmentExpired,
    KeyUnavailable,
    Storage,
}

impl TotpService {
    #[must_use]
    pub fn new(database: PathBuf) -> Self {
        let key_path = database.with_extension("totp.key");
        Self { database, key_path }
    }

    pub fn provider_status(
        &self,
        subject_uid: u32,
    ) -> Result<AdditionalAuthProviderStatus, TotpError> {
        let connection = self.connection()?;
        let encrypted = connection
            .query_row(
                "SELECT secret_nonce, secret_ciphertext FROM totp_enrollments \
                 WHERE subject_uid = ?1 AND state = 'active'",
                [subject_uid],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|_| TotpError::Storage)?;
        let Some((nonce, ciphertext)) = encrypted else {
            return Ok(AdditionalAuthProviderStatus::NotConfigured);
        };
        Ok(
            match self.decrypt_secret(subject_uid, &nonce, &ciphertext) {
                Ok(_) => AdditionalAuthProviderStatus::Ready,
                Err(_) => AdditionalAuthProviderStatus::Unavailable,
            },
        )
    }

    pub fn begin_enrollment(
        &self,
        session_token: &str,
        subject: &Subject,
        ingress: IngressChannel,
        reauth_token: &str,
        server_label: &str,
        now_unix_ms: i64,
    ) -> Result<TotpEnrollmentIssue, TotpError> {
        if ingress != IngressChannel::Recovery || subject.role != Role::Admin || subject.uid == 0 {
            return Err(TotpError::Denied);
        }
        let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
        getrandom::fill(secret.as_mut()).map_err(|_| TotpError::KeyUnavailable)?;
        let key = self.load_or_create_key()?;
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| TotpError::KeyUnavailable)?;
        let ciphertext = encrypt_secret(&key, subject.uid, &nonce, secret.as_ref())?;
        let enrollment_id = random_hex_identifier()?;
        let manual_key = base32(secret.as_ref());
        let otpauth_uri = otpauth_uri(&subject.username, server_label, &manual_key);
        let recovery_codes = recovery_codes()?;
        let expires_at = now_unix_ms.saturating_add(ENROLLMENT_TTL_MS);

        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(|_| TotpError::Storage)?;
        if active_enrollment_exists(&transaction, subject.uid)? {
            return Err(TotpError::AlreadyConfigured);
        }
        consume_reauth_claim(
            &transaction,
            session_token,
            subject.uid,
            "totp_enrollment",
            "totp/v1",
            reauth_token,
            now_unix_ms,
        )?;
        transaction
            .execute(
                "DELETE FROM totp_enrollments WHERE subject_uid = ?1 AND state = 'pending'",
                [subject.uid],
            )
            .map_err(|_| TotpError::Storage)?;
        transaction
            .execute(
                "INSERT INTO totp_enrollments(\
                    subject_uid, enrollment_id, secret_nonce, secret_ciphertext, state, \
                    first_confirmed_step, last_observed_step, created_at_unix_ms, \
                    expires_at_unix_ms, activated_at_unix_ms\
                 ) VALUES (?1, ?2, ?3, ?4, 'pending', NULL, NULL, ?5, ?6, NULL)",
                params![
                    subject.uid,
                    enrollment_id,
                    nonce.as_slice(),
                    ciphertext,
                    now_unix_ms,
                    expires_at,
                ],
            )
            .map_err(|_| TotpError::Storage)?;
        for code in &recovery_codes {
            let digest = recovery_digest(subject.uid, code.expose());
            transaction
                .execute(
                    "INSERT INTO totp_recovery_codes(subject_uid, code_digest, consumed_at_unix_ms) \
                     VALUES (?1, ?2, NULL)",
                    params![subject.uid, digest.as_slice()],
                )
                .map_err(|_| TotpError::Storage)?;
        }
        audit(
            &transaction,
            subject.uid,
            "enroll_begin",
            "pending",
            "totp/v1",
            now_unix_ms,
        )?;
        transaction.commit().map_err(|_| TotpError::Storage)?;
        secret.zeroize();

        Ok(TotpEnrollmentIssue {
            view: TotpEnrollmentStartView {
                enrollment_id,
                provider_id: String::from(TOTP_PROVIDER_ID),
                manual_key: SecretString::new(manual_key),
                otpauth_uri: SecretString::new(otpauth_uri),
                recovery_codes,
                expires_at: format_rfc3339(expires_at).map_err(|_| TotpError::Storage)?,
            },
        })
    }

    pub fn confirm_enrollment(
        &self,
        subject: &Subject,
        ingress: IngressChannel,
        enrollment_id: &str,
        code: &str,
        now_unix_ms: i64,
    ) -> Result<TotpEnrollmentConfirmView, TotpError> {
        if ingress != IngressChannel::Recovery || subject.role != Role::Admin {
            return Err(TotpError::Denied);
        }
        validate_enrollment_id(enrollment_id).map_err(|_| TotpError::InvalidCode)?;
        validate_totp_code(code).map_err(|_| TotpError::InvalidCode)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(|_| TotpError::Storage)?;
        let record = load_pending_enrollment(&transaction, subject.uid, enrollment_id)?;
        if record.expires_at_unix_ms <= now_unix_ms {
            return Err(TotpError::EnrollmentExpired);
        }
        let secret = self.decrypt_secret(subject.uid, &record.nonce, &record.ciphertext)?;
        let step = match_and_reserve_step(
            &transaction,
            subject.uid,
            secret.as_ref(),
            code,
            now_unix_ms,
            record.last_observed_step,
        )?;
        let state = match record.first_confirmed_step {
            None => {
                transaction
                    .execute(
                        "UPDATE totp_enrollments SET first_confirmed_step = ?1, \
                         last_observed_step = MAX(COALESCE(last_observed_step, ?1), ?1) \
                         WHERE subject_uid = ?2 AND enrollment_id = ?3 AND state = 'pending'",
                        params![step, subject.uid, enrollment_id],
                    )
                    .map_err(|_| TotpError::Storage)?;
                TotpEnrollmentState::AwaitingNextCode
            }
            Some(first) if step == first.saturating_add(1) => {
                transaction
                    .execute(
                        "UPDATE totp_enrollments SET state = 'active', activated_at_unix_ms = ?1, \
                         last_observed_step = MAX(COALESCE(last_observed_step, ?2), ?2) \
                         WHERE subject_uid = ?3 AND enrollment_id = ?4 AND state = 'pending'",
                        params![now_unix_ms, step, subject.uid, enrollment_id],
                    )
                    .map_err(|_| TotpError::Storage)?;
                TotpEnrollmentState::Ready
            }
            Some(_) => return Err(TotpError::InvalidCode),
        };
        audit(
            &transaction,
            subject.uid,
            "enroll_confirm",
            match state {
                TotpEnrollmentState::AwaitingNextCode => "first_code_verified",
                TotpEnrollmentState::Ready => "ready",
            },
            "totp/v1",
            now_unix_ms,
        )?;
        transaction.commit().map_err(|_| TotpError::Storage)?;
        Ok(TotpEnrollmentConfirmView {
            state,
            provider_id: String::from(TOTP_PROVIDER_ID),
        })
    }

    pub fn issue_operation_claim(
        &self,
        session_token: &str,
        subject: &Subject,
        reauth_token: &str,
        plan_hash: &str,
        code: &str,
        now_unix_ms: i64,
    ) -> Result<TotpVerificationView, TotpError> {
        validate_totp_code(code).map_err(|_| TotpError::InvalidCode)?;
        if plan_hash.is_empty() || plan_hash.len() > 128 {
            return Err(TotpError::InvalidClaim);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(|_| TotpError::Storage)?;
        validate_operation_reauth_claim(
            &transaction,
            session_token,
            subject.uid,
            reauth_token,
            plan_hash,
            now_unix_ms,
        )?;
        let record = load_active_enrollment(&transaction, subject.uid)?;
        let secret = self.decrypt_secret(subject.uid, &record.nonce, &record.ciphertext)?;
        let step = match_and_reserve_step(
            &transaction,
            subject.uid,
            secret.as_ref(),
            code,
            now_unix_ms,
            record.last_observed_step,
        )?;
        update_observed_step(&transaction, subject.uid, step)?;
        let claim = random_token()?;
        let token_digest = additional_claim_digest(claim.as_bytes());
        let reauth_digest = claim_digest(reauth_token.as_bytes());
        let session_digest = session_digest(session_token.as_bytes());
        let expires_at = now_unix_ms.saturating_add(CLAIM_TTL_MS);
        transaction
            .execute(
                "INSERT INTO additional_auth_claims(\
                    token_digest, reauth_digest, session_digest, subject_uid, context_digest, \
                    expires_at_unix_ms, consumed_at_unix_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                params![
                    token_digest.as_slice(),
                    reauth_digest.as_slice(),
                    session_digest.as_slice(),
                    subject.uid,
                    plan_hash,
                    expires_at,
                ],
            )
            .map_err(|_| TotpError::Storage)?;
        audit(
            &transaction,
            subject.uid,
            "verify",
            "claim_issued",
            plan_hash,
            now_unix_ms,
        )?;
        transaction.commit().map_err(|_| TotpError::Storage)?;
        Ok(TotpVerificationView {
            additional_auth_claim: SecretString::new(claim.to_string()),
            expires_at: format_rfc3339(expires_at).map_err(|_| TotpError::Storage)?,
        })
    }

    pub fn verify_direct_context(
        &self,
        subject: &Subject,
        context_digest: &str,
        code: &str,
        now_unix_ms: i64,
    ) -> Result<(), TotpError> {
        validate_totp_code(code).map_err(|_| TotpError::InvalidCode)?;
        if context_digest.is_empty() || context_digest.len() > 128 {
            return Err(TotpError::InvalidClaim);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(|_| TotpError::Storage)?;
        let record = load_active_enrollment(&transaction, subject.uid)?;
        let secret = self.decrypt_secret(subject.uid, &record.nonce, &record.ciphertext)?;
        let step = match_and_reserve_step(
            &transaction,
            subject.uid,
            secret.as_ref(),
            code,
            now_unix_ms,
            record.last_observed_step,
        )?;
        update_observed_step(&transaction, subject.uid, step)?;
        audit(
            &transaction,
            subject.uid,
            "verify",
            "direct_verified",
            context_digest,
            now_unix_ms,
        )?;
        transaction.commit().map_err(|_| TotpError::Storage)
    }

    pub fn recovery_reset(
        &self,
        session_token: &str,
        subject: &Subject,
        ingress: IngressChannel,
        reauth_token: &str,
        recovery_code: &str,
        now_unix_ms: i64,
    ) -> Result<(), TotpError> {
        if ingress != IngressChannel::Recovery || subject.role != Role::Admin {
            return Err(TotpError::Denied);
        }
        let digest = recovery_digest(subject.uid, recovery_code);
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(|_| TotpError::Storage)?;
        consume_reauth_claim(
            &transaction,
            session_token,
            subject.uid,
            "totp_recovery_reset",
            "totp/v1",
            reauth_token,
            now_unix_ms,
        )?;
        let changed = transaction
            .execute(
                "UPDATE totp_recovery_codes SET consumed_at_unix_ms = ?1 \
                 WHERE subject_uid = ?2 AND code_digest = ?3 AND consumed_at_unix_ms IS NULL",
                params![now_unix_ms, subject.uid, digest.as_slice()],
            )
            .map_err(|_| TotpError::Storage)?;
        if changed != 1 {
            return Err(TotpError::InvalidCode);
        }
        audit(
            &transaction,
            subject.uid,
            "recovery_reset",
            "provider_removed",
            "totp/v1",
            now_unix_ms,
        )?;
        transaction
            .execute(
                "DELETE FROM additional_auth_claims WHERE subject_uid = ?1",
                [subject.uid],
            )
            .map_err(|_| TotpError::Storage)?;
        transaction
            .execute(
                "DELETE FROM totp_enrollments WHERE subject_uid = ?1",
                [subject.uid],
            )
            .map_err(|_| TotpError::Storage)?;
        transaction
            .execute(
                "UPDATE settings SET value = 'disabled', updated_at_unix_ms = ?1 \
                 WHERE key = 'additional_auth_policy'",
                [now_unix_ms],
            )
            .map_err(|_| TotpError::Storage)?;
        transaction
            .execute(
                "UPDATE sessions SET revoked_at_unix_ms = ?1 \
                 WHERE subject_uid = ?2 AND revoked_at_unix_ms IS NULL",
                params![now_unix_ms, subject.uid],
            )
            .map_err(|_| TotpError::Storage)?;
        transaction.commit().map_err(|_| TotpError::Storage)
    }

    fn connection(&self) -> Result<Connection, TotpError> {
        let connection = Connection::open(&self.database).map_err(|_| TotpError::Storage)?;
        configure(connection).map_err(|_| TotpError::Storage)
    }

    fn decrypt_secret(
        &self,
        subject_uid: u32,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, TotpError> {
        if nonce.len() != NONCE_BYTES || ciphertext.len() != SECRET_BYTES + 16 {
            return Err(TotpError::Storage);
        }
        let key = self.load_existing_key()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &encryption_aad(subject_uid),
                },
            )
            .map_err(|_| TotpError::KeyUnavailable)?;
        if plaintext.len() != SECRET_BYTES {
            return Err(TotpError::Storage);
        }
        Ok(Zeroizing::new(plaintext))
    }

    fn load_or_create_key(&self) -> Result<Zeroizing<[u8; KEY_BYTES]>, TotpError> {
        match self.load_existing_key() {
            Ok(key) => Ok(key),
            Err(TotpError::KeyUnavailable) if !self.key_path.exists() => {
                let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
                getrandom::fill(key.as_mut()).map_err(|_| TotpError::KeyUnavailable)?;
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&self.key_path)
                {
                    Ok(mut file) => {
                        file.write_all(key.as_ref())
                            .map_err(|_| TotpError::KeyUnavailable)?;
                        file.sync_all().map_err(|_| TotpError::KeyUnavailable)?;
                        validate_key_metadata(&file)?;
                        Ok(key)
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        self.load_existing_key()
                    }
                    Err(_) => Err(TotpError::KeyUnavailable),
                }
            }
            Err(error) => Err(error),
        }
    }

    fn load_existing_key(&self) -> Result<Zeroizing<[u8; KEY_BYTES]>, TotpError> {
        let mut file = File::open(&self.key_path).map_err(|_| TotpError::KeyUnavailable)?;
        validate_key_metadata(&file)?;
        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        file.read_exact(key.as_mut())
            .map_err(|_| TotpError::KeyUnavailable)?;
        let mut trailing = [0_u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| TotpError::KeyUnavailable)?
            != 0
        {
            return Err(TotpError::KeyUnavailable);
        }
        Ok(key)
    }
}

struct EnrollmentRecord {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    first_confirmed_step: Option<i64>,
    last_observed_step: Option<i64>,
    expires_at_unix_ms: i64,
}

fn load_pending_enrollment(
    transaction: &Transaction<'_>,
    subject_uid: u32,
    enrollment_id: &str,
) -> Result<EnrollmentRecord, TotpError> {
    transaction
        .query_row(
            "SELECT secret_nonce, secret_ciphertext, first_confirmed_step, \
                    last_observed_step, expires_at_unix_ms \
             FROM totp_enrollments WHERE subject_uid = ?1 AND enrollment_id = ?2 \
               AND state = 'pending'",
            params![subject_uid, enrollment_id],
            |row| {
                Ok(EnrollmentRecord {
                    nonce: row.get(0)?,
                    ciphertext: row.get(1)?,
                    first_confirmed_step: row.get(2)?,
                    last_observed_step: row.get(3)?,
                    expires_at_unix_ms: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|_| TotpError::Storage)?
        .ok_or(TotpError::NotConfigured)
}

fn load_active_enrollment(
    transaction: &Transaction<'_>,
    subject_uid: u32,
) -> Result<EnrollmentRecord, TotpError> {
    transaction
        .query_row(
            "SELECT secret_nonce, secret_ciphertext, first_confirmed_step, \
                    last_observed_step, expires_at_unix_ms \
             FROM totp_enrollments WHERE subject_uid = ?1 AND state = 'active'",
            [subject_uid],
            |row| {
                Ok(EnrollmentRecord {
                    nonce: row.get(0)?,
                    ciphertext: row.get(1)?,
                    first_confirmed_step: row.get(2)?,
                    last_observed_step: row.get(3)?,
                    expires_at_unix_ms: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|_| TotpError::Storage)?
        .ok_or(TotpError::NotConfigured)
}

fn active_enrollment_exists(
    transaction: &Transaction<'_>,
    subject_uid: u32,
) -> Result<bool, TotpError> {
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM totp_enrollments \
             WHERE subject_uid = ?1 AND state = 'active')",
            [subject_uid],
            |row| row.get(0),
        )
        .map_err(|_| TotpError::Storage)
}

fn validate_operation_reauth_claim(
    transaction: &Transaction<'_>,
    session_token: &str,
    subject_uid: u32,
    reauth_token: &str,
    plan_hash: &str,
    now_unix_ms: i64,
) -> Result<(), TotpError> {
    let reauth_digest = claim_digest(reauth_token.as_bytes());
    let session_digest = session_digest(session_token.as_bytes());
    let exists = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM reauth_claims \
             WHERE token_digest = ?1 AND session_digest = ?2 AND subject_uid = ?3 \
               AND purpose = 'operation' AND context_digest = ?4 \
               AND expires_at_unix_ms > ?5 AND consumed_at_unix_ms IS NULL)",
            params![
                reauth_digest.as_slice(),
                session_digest.as_slice(),
                subject_uid,
                plan_hash,
                now_unix_ms,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| TotpError::Storage)?;
    if exists {
        Ok(())
    } else {
        Err(TotpError::InvalidClaim)
    }
}

fn consume_reauth_claim(
    transaction: &Transaction<'_>,
    session_token: &str,
    subject_uid: u32,
    purpose: &str,
    context_digest: &str,
    reauth_token: &str,
    now_unix_ms: i64,
) -> Result<(), TotpError> {
    let reauth_digest = claim_digest(reauth_token.as_bytes());
    let session_digest = session_digest(session_token.as_bytes());
    let changed = transaction
        .execute(
            "UPDATE reauth_claims SET consumed_at_unix_ms = ?1 \
             WHERE token_digest = ?2 AND session_digest = ?3 AND subject_uid = ?4 \
               AND purpose = ?5 AND context_digest = ?6 \
               AND expires_at_unix_ms > ?1 AND consumed_at_unix_ms IS NULL",
            params![
                now_unix_ms,
                reauth_digest.as_slice(),
                session_digest.as_slice(),
                subject_uid,
                purpose,
                context_digest,
            ],
        )
        .map_err(|_| TotpError::Storage)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(TotpError::InvalidClaim)
    }
}

fn match_and_reserve_step(
    transaction: &Transaction<'_>,
    subject_uid: u32,
    secret: &[u8],
    provided_code: &str,
    now_unix_ms: i64,
    last_observed_step: Option<i64>,
) -> Result<i64, TotpError> {
    let current_step = time_step(now_unix_ms)?;
    if last_observed_step
        .is_some_and(|last| current_step.saturating_add(MAX_CLOCK_ROLLBACK_STEPS) < last)
    {
        return Err(TotpError::ClockRollback);
    }
    let candidates = [
        current_step,
        current_step.saturating_sub(1),
        current_step.saturating_add(1),
    ];
    let mut matched = None;
    for candidate in candidates {
        let expected = totp_code(secret, candidate)?;
        if expected.as_bytes().ct_eq(provided_code.as_bytes()).into() {
            matched = Some(candidate);
        }
    }
    let step = matched.ok_or(TotpError::InvalidCode)?;
    let inserted = transaction
        .execute(
            "INSERT OR IGNORE INTO totp_used_steps(subject_uid, time_step, used_at_unix_ms) \
             VALUES (?1, ?2, ?3)",
            params![subject_uid, step, now_unix_ms],
        )
        .map_err(|_| TotpError::Storage)?;
    if inserted == 1 {
        Ok(step)
    } else {
        Err(TotpError::Replay)
    }
}

fn update_observed_step(
    transaction: &Transaction<'_>,
    subject_uid: u32,
    step: i64,
) -> Result<(), TotpError> {
    transaction
        .execute(
            "UPDATE totp_enrollments SET \
             last_observed_step = MAX(COALESCE(last_observed_step, ?1), ?1) \
             WHERE subject_uid = ?2 AND state = 'active'",
            params![step, subject_uid],
        )
        .map_err(|_| TotpError::Storage)?;
    Ok(())
}

fn audit(
    transaction: &Transaction<'_>,
    subject_uid: u32,
    action: &str,
    result: &str,
    context_digest: &str,
    now_unix_ms: i64,
) -> Result<(), TotpError> {
    let safe_context = if context_digest.len() <= 128 {
        context_digest.to_owned()
    } else {
        let mut hasher = Sha256::new();
        hasher.update(b"jw-agent/totp-context/v1\0");
        hasher.update(context_digest.as_bytes());
        let digest = hasher.finalize();
        let encoded: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        format!("sha256:{encoded}")
    };
    transaction
        .execute(
            "INSERT INTO totp_audit_events(\
                subject_uid, action, result, context_digest, occurred_at_unix_ms\
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![subject_uid, action, result, safe_context, now_unix_ms],
        )
        .map_err(|_| TotpError::Storage)?;
    Ok(())
}

fn encrypt_secret(
    key: &[u8; KEY_BYTES],
    subject_uid: u32,
    nonce: &[u8; NONCE_BYTES],
    secret: &[u8],
) -> Result<Vec<u8>, TotpError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: secret,
                aad: &encryption_aad(subject_uid),
            },
        )
        .map_err(|_| TotpError::KeyUnavailable)
}

fn encryption_aad(subject_uid: u32) -> Vec<u8> {
    let mut aad = Vec::from(&b"jw-agent/totp-secret/v1\0"[..]);
    aad.extend_from_slice(&subject_uid.to_be_bytes());
    aad
}

fn validate_key_metadata(file: &File) -> Result<(), TotpError> {
    let metadata = file.metadata().map_err(|_| TotpError::KeyUnavailable)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() != KEY_BYTES as u64
    {
        return Err(TotpError::KeyUnavailable);
    }
    Ok(())
}

fn recovery_codes() -> Result<Vec<SecretString>, TotpError> {
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut random = Zeroizing::new([0_u8; RECOVERY_CODE_BYTES]);
        getrandom::fill(random.as_mut()).map_err(|_| TotpError::KeyUnavailable)?;
        let raw = base32(random.as_ref());
        let grouped = raw
            .as_bytes()
            .chunks(5)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join("-");
        codes.push(SecretString::new(grouped));
    }
    Ok(codes)
}

fn recovery_digest(subject_uid: u32, code: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"jw-agent/totp-recovery/v1\0");
    hasher.update(subject_uid.to_be_bytes());
    for byte in code.bytes() {
        if byte != b'-' && !byte.is_ascii_whitespace() {
            hasher.update([byte.to_ascii_uppercase()]);
        }
    }
    hasher.finalize().into()
}

pub(crate) fn additional_claim_digest(token: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"jw-agent/additional-auth-claim/v1\0");
    hasher.update(token);
    hasher.finalize().into()
}

fn time_step(now_unix_ms: i64) -> Result<i64, TotpError> {
    if now_unix_ms < 0 {
        Err(TotpError::ClockRollback)
    } else {
        Ok(now_unix_ms / TOTP_PERIOD_MS)
    }
}

fn totp_code(secret: &[u8], step: i64) -> Result<Zeroizing<String>, TotpError> {
    let counter = u64::try_from(step).map_err(|_| TotpError::ClockRollback)?;
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).map_err(|_| TotpError::Storage)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(Zeroizing::new(format!("{:06}", binary % 1_000_000)))
}

fn base32(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in input {
        buffer = (buffer << 8) | u32::from(*byte);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits -= 5;
            output.push(char::from(ALPHABET[((buffer >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        output.push(char::from(
            ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
    }
    output
}

fn otpauth_uri(username: &str, server_label: &str, secret: &str) -> String {
    let label = percent_encode(&format!("JW Agent:{username}@{server_label}"));
    format!(
        "otpauth://totp/{label}?secret={secret}&issuer=JW%20Agent&algorithm=SHA1&digits=6&period=30"
    )
}

fn percent_encode(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn random_hex_identifier() -> Result<String, TotpError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| TotpError::KeyUnavailable)?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn random_token() -> Result<Zeroizing<String>, TotpError> {
    let mut random = Zeroizing::new([0_u8; 32]);
    getrandom::fill(random.as_mut()).map_err(|_| TotpError::KeyUnavailable)?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(random.as_ref())))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use jw_contracts::{
        AdditionalAuthPolicy, IngressChannel, ReauthPurpose, Role, Subject, TotpEnrollmentState,
    };

    use crate::SessionStore;
    use crate::session::OperationAuthorization;

    use super::{base32, percent_encode, recovery_digest, totp_code};

    #[test]
    fn rfc6238_sha1_six_digit_vector_matches() -> Result<(), String> {
        let code = totp_code(b"12345678901234567890", 1).map_err(|error| format!("{error:?}"))?;
        assert_eq!(code.as_str(), "287082");
        Ok(())
    }

    #[test]
    fn base32_and_uri_encoding_are_stable() {
        assert_eq!(base32(b"foo"), "MZXW6");
        assert_eq!(percent_encode("a b/한"), "a%20b%2F%ED%95%9C");
    }

    #[test]
    fn recovery_digest_ignores_display_grouping() {
        assert_eq!(
            recovery_digest(1000, "abcde-fghij"),
            recovery_digest(1000, "ABCDEFGHIJ")
        );
    }

    #[test]
    fn enrollment_claim_replay_and_recovery_reset_are_atomic() -> Result<(), String> {
        let path = test_path()?;
        let store = SessionStore::open(path.clone(), 1_000)?;
        let subject = Subject {
            uid: 1_000,
            username: String::from("admin"),
            role: Role::Admin,
        };
        let session = store.issue_session(&subject, IngressChannel::Recovery, 1_000)?;
        let enrollment_reauth = store.issue_reauth_claim(
            session.token(),
            &subject,
            &ReauthPurpose::TotpEnrollment,
            1_499_000,
        )?;
        let issue = store
            .totp()
            .begin_enrollment(
                session.token(),
                &subject,
                IngressChannel::Recovery,
                enrollment_reauth.token(),
                "test-server",
                1_500_000,
            )
            .map_err(|error| format!("{error:?}"))?;
        let secret = decode_base32(issue.view.manual_key.expose())?;
        let recovery_code = issue
            .view
            .recovery_codes
            .first()
            .ok_or_else(|| String::from("missing recovery code"))?
            .expose()
            .to_owned();
        let first = totp_code(&secret, 50).map_err(|error| format!("{error:?}"))?;
        let progress = store
            .totp()
            .confirm_enrollment(
                &subject,
                IngressChannel::Recovery,
                &issue.view.enrollment_id,
                first.as_str(),
                1_500_000,
            )
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(progress.state, TotpEnrollmentState::AwaitingNextCode);
        let second = totp_code(&secret, 51).map_err(|error| format!("{error:?}"))?;
        let ready = store
            .totp()
            .confirm_enrollment(
                &subject,
                IngressChannel::Recovery,
                &issue.view.enrollment_id,
                second.as_str(),
                1_530_000,
            )
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(ready.state, TotpEnrollmentState::Ready);

        let policy_reauth = store.issue_reauth_claim(
            session.token(),
            &subject,
            &ReauthPurpose::SecurityPolicyChange {
                target_policy: AdditionalAuthPolicy::RiskyOperations,
            },
            1_540_000,
        )?;
        store
            .update_additional_auth_policy(
                session.token(),
                &subject,
                AdditionalAuthPolicy::RiskyOperations,
                Some(policy_reauth.token()),
                1_540_001,
            )
            .map_err(|error| format!("{error:?}"))?;

        let plan_hash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let operation_reauth = store.issue_reauth_claim(
            session.token(),
            &subject,
            &ReauthPurpose::Operation {
                plan_hash: String::from(plan_hash),
            },
            1_550_000,
        )?;
        let operation_code = totp_code(&secret, 52).map_err(|error| format!("{error:?}"))?;
        let additional = store
            .totp()
            .issue_operation_claim(
                session.token(),
                &subject,
                operation_reauth.token(),
                plan_hash,
                operation_code.as_str(),
                1_560_000,
            )
            .map_err(|error| format!("{error:?}"))?;
        store
            .consume_operation_claims(OperationAuthorization {
                session_token: session.token(),
                subject: &subject,
                plan_hash,
                reauth_token: operation_reauth.token(),
                additional_auth_claim: Some(additional.additional_auth_claim.expose()),
                additional_auth_required: true,
                now_unix_ms: 1_560_001,
            })
            .map_err(|error| format!("{error:?}"))?;
        assert!(
            store
                .consume_operation_claims(OperationAuthorization {
                    session_token: session.token(),
                    subject: &subject,
                    plan_hash,
                    reauth_token: operation_reauth.token(),
                    additional_auth_claim: Some(additional.additional_auth_claim.expose()),
                    additional_auth_required: true,
                    now_unix_ms: 1_560_002,
                })
                .is_err()
        );

        let reset_reauth = store.issue_reauth_claim(
            session.token(),
            &subject,
            &ReauthPurpose::TotpRecoveryReset,
            1_570_000,
        )?;
        store
            .totp()
            .recovery_reset(
                session.token(),
                &subject,
                IngressChannel::Recovery,
                reset_reauth.token(),
                &recovery_code,
                1_570_001,
            )
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            store.additional_auth_policy()?,
            AdditionalAuthPolicy::Disabled
        );
        assert!(
            store
                .authenticate_session(session.token(), IngressChannel::Recovery, 1_570_002)?
                .is_none()
        );
        cleanup_test_database(&path)
    }

    fn decode_base32(value: &str) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();
        let mut buffer = 0_u32;
        let mut bits = 0_u8;
        for byte in value.bytes() {
            let index = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'2'..=b'7' => byte - b'2' + 26,
                _ => return Err(String::from("invalid base32 test value")),
            };
            buffer = (buffer << 5) | u32::from(index);
            bits = bits.saturating_add(5);
            if bits >= 8 {
                bits -= 8;
                output.push(((buffer >> bits) & 0xff) as u8);
            }
        }
        Ok(output)
    }

    fn test_path() -> Result<PathBuf, String> {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        Ok(std::env::temp_dir().join(format!("jw-agent-totp-{suffix}.sqlite3")))
    }

    fn cleanup_test_database(path: &Path) -> Result<(), String> {
        for candidate in [
            path.to_path_buf(),
            path.with_extension("totp.key"),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            match std::fs::remove_file(&candidate) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }
}
