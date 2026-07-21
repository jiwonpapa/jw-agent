PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS sessions (
    token_digest BLOB PRIMARY KEY CHECK (length(token_digest) = 32),
    ingress TEXT NOT NULL CHECK (ingress IN ('public', 'recovery')),
    subject_uid INTEGER NOT NULL CHECK (subject_uid > 0),
    subject_username TEXT NOT NULL CHECK (length(subject_username) BETWEEN 1 AND 64),
    subject_role TEXT NOT NULL CHECK (subject_role IN ('admin', 'operator', 'viewer')),
    authenticated_at_unix_ms INTEGER NOT NULL,
    last_seen_at_unix_ms INTEGER NOT NULL,
    idle_expires_at_unix_ms INTEGER NOT NULL,
    absolute_expires_at_unix_ms INTEGER NOT NULL,
    revoked_at_unix_ms INTEGER,
    CHECK (idle_expires_at_unix_ms <= absolute_expires_at_unix_ms)
) STRICT;

CREATE INDEX IF NOT EXISTS sessions_expiry_idx
ON sessions(absolute_expires_at_unix_ms, idle_expires_at_unix_ms);

CREATE TABLE IF NOT EXISTS reauth_claims (
    token_digest BLOB PRIMARY KEY CHECK (length(token_digest) = 32),
    session_digest BLOB NOT NULL CHECK (length(session_digest) = 32),
    subject_uid INTEGER NOT NULL CHECK (subject_uid > 0),
    purpose TEXT NOT NULL,
    context_digest TEXT NOT NULL,
    expires_at_unix_ms INTEGER NOT NULL,
    consumed_at_unix_ms INTEGER,
    FOREIGN KEY (session_digest) REFERENCES sessions(token_digest)
) STRICT;

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL
) STRICT;

INSERT OR IGNORE INTO settings(key, value, updated_at_unix_ms)
VALUES ('additional_auth_policy', 'disabled', 0);
