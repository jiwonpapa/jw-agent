use jw_contracts::{
    AdditionalAuthPolicy, AdministrativeAccessState, IngressChannel, Role, SessionView, Subject,
};
use rusqlite::{OptionalExtension, params};

use super::{
    IssuedSession, SESSION_TOUCH_INTERVAL_MS, SessionStore, csrf_token, format_rfc3339,
    ingress_value, load_session, policy_in_transaction, random_token, record_administrative_event,
    role_value, session_digest, session_durations, valid_token_shape,
};

const ADMINISTRATIVE_ACCESS_MS: i64 = 15 * 60 * 1_000;

struct SessionViewInput<'a> {
    subject: Subject,
    ingress: IngressChannel,
    authenticated_at: i64,
    idle_expires_at: i64,
    absolute_expires_at: i64,
    token: &'a str,
    policy: AdditionalAuthPolicy,
    administrative_until: Option<i64>,
    now_unix_ms: i64,
}

fn session_view(input: SessionViewInput<'_>) -> Result<SessionView, String> {
    let administrative_until = input
        .administrative_until
        .filter(|expiry| *expiry > input.now_unix_ms);
    Ok(SessionView {
        subject: input.subject,
        ingress: input.ingress,
        authenticated_at: format_rfc3339(input.authenticated_at)?,
        idle_expires_at: format_rfc3339(input.idle_expires_at)?,
        absolute_expires_at: format_rfc3339(input.absolute_expires_at)?,
        csrf_token: csrf_token(input.token),
        additional_auth_policy: input.policy,
        administrative_access: if administrative_until.is_some() {
            AdministrativeAccessState::Administrative
        } else {
            AdministrativeAccessState::Standard
        },
        administrative_expires_at: administrative_until.map(format_rfc3339).transpose()?,
    })
}

impl SessionStore {
    pub fn issue_session(
        &self,
        subject: &Subject,
        ingress: IngressChannel,
        now: i64,
    ) -> Result<IssuedSession, String> {
        self.issue_session_with_administrative_access(subject, ingress, now, None, false)
    }

    pub fn issue_administrative_session(
        &self,
        subject: &Subject,
        ingress: IngressChannel,
        now: i64,
    ) -> Result<IssuedSession, String> {
        if subject.role != Role::Admin {
            return Err(String::from("administrative access requires admin role"));
        }
        self.issue_session_with_administrative_access(
            subject,
            ingress,
            now,
            Some(now.saturating_add(ADMINISTRATIVE_ACCESS_MS)),
            true,
        )
    }

    pub fn issue_reauthenticated_session(
        &self,
        prior_token: &str,
        subject: &Subject,
        ingress: IngressChannel,
        now: i64,
    ) -> Result<IssuedSession, String> {
        let administrative_until = self.administrative_expiry(prior_token, now)?;
        self.issue_session_with_administrative_access(
            subject,
            ingress,
            now,
            administrative_until,
            false,
        )
    }

    fn issue_session_with_administrative_access(
        &self,
        subject: &Subject,
        ingress: IngressChannel,
        now: i64,
        administrative_until: Option<i64>,
        audit_grant: bool,
    ) -> Result<IssuedSession, String> {
        if subject.uid == 0 {
            return Err(String::from("root session is forbidden"));
        }
        let policy = self.additional_auth_policy()?;
        let token = random_token()?;
        let token_digest = session_digest(token.as_bytes());
        let (idle_duration, absolute_duration) = session_durations(ingress);
        let idle_expires_at = now.saturating_add(idle_duration);
        let absolute_expires_at = now.saturating_add(absolute_duration);
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
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
                    now,
                    idle_expires_at,
                    absolute_expires_at
                ],
            )
            .map_err(|error| error.to_string())?;
        let administrative_until = administrative_until
            .filter(|expiry| subject.role == Role::Admin && *expiry > now)
            .map(|expiry| expiry.min(absolute_expires_at));
        if let Some(expires_at) = administrative_until {
            transaction.execute(
                "INSERT INTO administrative_access(\
                    session_digest, subject_uid, granted_at_unix_ms, expires_at_unix_ms, revoked_at_unix_ms\
                 ) VALUES (?1, ?2, ?3, ?4, NULL)",
                params![token_digest.as_slice(), subject.uid, now, expires_at],
            ).map_err(|error| error.to_string())?;
            if audit_grant {
                record_administrative_event(
                    &transaction,
                    subject.uid,
                    ingress,
                    "grant",
                    "granted",
                    now,
                )?;
            }
        }
        transaction.commit().map_err(|error| error.to_string())?;
        let view = session_view(SessionViewInput {
            subject: subject.clone(),
            ingress,
            authenticated_at: now,
            idle_expires_at,
            absolute_expires_at,
            token: token.as_str(),
            policy,
            administrative_until,
            now_unix_ms: now,
        })?;
        Ok(IssuedSession { token, view })
    }

    pub fn revoke_administrative_access(
        &self,
        session_token: &str,
        ingress: IngressChannel,
        subject: &Subject,
        now: i64,
    ) -> Result<(), String> {
        if !valid_token_shape(session_token) || subject.uid == 0 {
            return Err(String::from("administrative session identity is invalid"));
        }
        let digest = session_digest(session_token.as_bytes());
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "UPDATE administrative_access SET revoked_at_unix_ms = ?1 \
             WHERE session_digest = ?2 AND subject_uid = ?3 AND revoked_at_unix_ms IS NULL",
                params![now, digest.as_slice(), subject.uid],
            )
            .map_err(|error| error.to_string())?;
        record_administrative_event(&transaction, subject.uid, ingress, "revoke", "revoked", now)?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn record_administrative_denial(
        &self,
        subject: &Subject,
        ingress: IngressChannel,
        result: &str,
        now: i64,
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        record_administrative_event(&transaction, subject.uid, ingress, "denied", result, now)?;
        transaction.commit().map_err(|error| error.to_string())
    }

    fn administrative_expiry(&self, token: &str, now: i64) -> Result<Option<i64>, String> {
        if !valid_token_shape(token) {
            return Ok(None);
        }
        let digest = session_digest(token.as_bytes());
        self.connection()?
            .query_row(
                "SELECT expires_at_unix_ms FROM administrative_access \
             WHERE session_digest = ?1 AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms > ?2",
                params![digest.as_slice(), now],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn authenticate_session(
        &self,
        token: &str,
        ingress: IngressChannel,
        now: i64,
    ) -> Result<Option<SessionView>, String> {
        if !valid_token_shape(token) {
            return Ok(None);
        }
        let digest = session_digest(token.as_bytes());
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let Some(record) = load_session(&transaction, &digest)? else {
            return Ok(None);
        };
        if record.ingress != ingress
            || record.revoked_at.is_some()
            || record.idle_expires_at <= now
            || record.absolute_expires_at <= now
        {
            return Ok(None);
        }
        let idle_expires_at =
            if now.saturating_sub(record.last_seen_at) >= SESSION_TOUCH_INTERVAL_MS {
                let (idle_duration, _) = session_durations(ingress);
                let next_idle = now
                    .saturating_add(idle_duration)
                    .min(record.absolute_expires_at);
                transaction.execute(
                "UPDATE sessions SET last_seen_at_unix_ms = ?1, idle_expires_at_unix_ms = ?2 \
                 WHERE token_digest = ?3 AND revoked_at_unix_ms IS NULL",
                params![now, next_idle, digest.as_slice()],
            ).map_err(|error| error.to_string())?;
                next_idle
            } else {
                record.idle_expires_at
            };
        let policy = policy_in_transaction(&transaction)?;
        transaction.commit().map_err(|error| error.to_string())?;
        session_view(SessionViewInput {
            subject: record.subject,
            ingress,
            authenticated_at: record.authenticated_at,
            idle_expires_at,
            absolute_expires_at: record.absolute_expires_at,
            token,
            policy,
            administrative_until: record.administrative_until,
            now_unix_ms: now,
        })
        .map(Some)
    }

    pub fn revoke_session(&self, token: &str, now: i64) -> Result<(), String> {
        if !valid_token_shape(token) {
            return Ok(());
        }
        let digest = session_digest(token.as_bytes());
        self.connection()?
            .execute(
                "UPDATE sessions SET revoked_at_unix_ms = ?1 WHERE token_digest = ?2",
                params![now, digest.as_slice()],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn revoke_all(&self, now: i64) -> Result<usize, String> {
        self.connection()?
            .execute(
                "UPDATE sessions SET revoked_at_unix_ms = ?1 WHERE revoked_at_unix_ms IS NULL",
                [now],
            )
            .map_err(|error| error.to_string())
    }
}
