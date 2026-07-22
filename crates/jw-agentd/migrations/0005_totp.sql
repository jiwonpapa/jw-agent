CREATE TABLE IF NOT EXISTS totp_enrollments (
    subject_uid INTEGER PRIMARY KEY CHECK (subject_uid > 0),
    enrollment_id TEXT NOT NULL UNIQUE CHECK (length(enrollment_id) = 32),
    secret_nonce BLOB NOT NULL CHECK (length(secret_nonce) = 12),
    secret_ciphertext BLOB NOT NULL CHECK (length(secret_ciphertext) = 36),
    state TEXT NOT NULL CHECK (state IN ('pending', 'active')),
    first_confirmed_step INTEGER,
    last_observed_step INTEGER,
    created_at_unix_ms INTEGER NOT NULL,
    expires_at_unix_ms INTEGER NOT NULL,
    activated_at_unix_ms INTEGER,
    CHECK (
        (state = 'pending' AND activated_at_unix_ms IS NULL)
        OR (state = 'active' AND activated_at_unix_ms IS NOT NULL)
    )
) STRICT;

CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    subject_uid INTEGER NOT NULL CHECK (subject_uid > 0),
    code_digest BLOB NOT NULL CHECK (length(code_digest) = 32),
    consumed_at_unix_ms INTEGER,
    PRIMARY KEY (subject_uid, code_digest),
    FOREIGN KEY (subject_uid) REFERENCES totp_enrollments(subject_uid) ON DELETE CASCADE
) STRICT;

CREATE TABLE IF NOT EXISTS totp_used_steps (
    subject_uid INTEGER NOT NULL CHECK (subject_uid > 0),
    time_step INTEGER NOT NULL CHECK (time_step >= 0),
    used_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (subject_uid, time_step),
    FOREIGN KEY (subject_uid) REFERENCES totp_enrollments(subject_uid) ON DELETE CASCADE
) STRICT;

CREATE TABLE IF NOT EXISTS additional_auth_claims (
    token_digest BLOB PRIMARY KEY CHECK (length(token_digest) = 32),
    reauth_digest BLOB NOT NULL CHECK (length(reauth_digest) = 32),
    session_digest BLOB NOT NULL CHECK (length(session_digest) = 32),
    subject_uid INTEGER NOT NULL CHECK (subject_uid > 0),
    context_digest TEXT NOT NULL CHECK (length(context_digest) BETWEEN 1 AND 128),
    expires_at_unix_ms INTEGER NOT NULL,
    consumed_at_unix_ms INTEGER,
    FOREIGN KEY (session_digest) REFERENCES sessions(token_digest)
) STRICT;

CREATE TABLE IF NOT EXISTS totp_audit_events (
    event_id INTEGER PRIMARY KEY,
    subject_uid INTEGER NOT NULL CHECK (subject_uid > 0),
    action TEXT NOT NULL CHECK (action IN ('enroll_begin', 'enroll_confirm', 'verify', 'recovery_reset')),
    result TEXT NOT NULL CHECK (length(result) BETWEEN 1 AND 64),
    context_digest TEXT NOT NULL CHECK (length(context_digest) BETWEEN 1 AND 128),
    occurred_at_unix_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS additional_auth_claims_expiry_idx
ON additional_auth_claims(expires_at_unix_ms, consumed_at_unix_ms);

CREATE INDEX IF NOT EXISTS totp_audit_events_subject_idx
ON totp_audit_events(subject_uid, occurred_at_unix_ms DESC);
