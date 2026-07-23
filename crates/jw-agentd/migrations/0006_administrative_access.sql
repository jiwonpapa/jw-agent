CREATE TABLE IF NOT EXISTS administrative_access (
    session_digest BLOB PRIMARY KEY CHECK (length(session_digest) = 32),
    subject_uid INTEGER NOT NULL CHECK (subject_uid > 0),
    granted_at_unix_ms INTEGER NOT NULL,
    expires_at_unix_ms INTEGER NOT NULL,
    revoked_at_unix_ms INTEGER,
    CHECK (expires_at_unix_ms > granted_at_unix_ms),
    FOREIGN KEY (session_digest) REFERENCES sessions(token_digest)
) STRICT;

CREATE TABLE IF NOT EXISTS administrative_access_events (
    event_id INTEGER PRIMARY KEY,
    subject_uid INTEGER NOT NULL CHECK (subject_uid > 0),
    ingress TEXT NOT NULL CHECK (ingress IN ('public', 'recovery')),
    event_type TEXT NOT NULL CHECK (event_type IN ('grant', 'revoke', 'denied')),
    result TEXT NOT NULL CHECK (length(result) BETWEEN 1 AND 64),
    occurred_at_unix_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS administrative_access_expiry_idx
ON administrative_access(expires_at_unix_ms, revoked_at_unix_ms);
