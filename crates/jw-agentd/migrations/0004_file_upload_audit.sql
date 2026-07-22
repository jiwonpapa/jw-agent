CREATE TABLE IF NOT EXISTS file_uploads (
    upload_id TEXT PRIMARY KEY CHECK (length(upload_id) = 32),
    session_id TEXT NOT NULL,
    path_digest BLOB NOT NULL CHECK (length(path_digest) = 32),
    target_state TEXT NOT NULL CHECK (target_state IN ('create', 'replace')),
    before_digest TEXT CHECK (before_digest IS NULL OR length(before_digest) = 71),
    after_digest TEXT NOT NULL CHECK (length(after_digest) = 71),
    byte_count INTEGER NOT NULL CHECK (byte_count >= 0),
    state TEXT NOT NULL CHECK (state IN ('planned', 'applying', 'verified', 'failed', 'manual_check')),
    result TEXT CHECK (result IS NULL OR length(result) BETWEEN 1 AND 64),
    planned_at_unix_ms INTEGER NOT NULL,
    started_at_unix_ms INTEGER,
    ended_at_unix_ms INTEGER,
    FOREIGN KEY (session_id) REFERENCES file_sessions(session_id),
    CHECK (
        (state = 'planned' AND started_at_unix_ms IS NULL AND ended_at_unix_ms IS NULL AND result IS NULL)
        OR (state = 'applying' AND started_at_unix_ms IS NOT NULL AND ended_at_unix_ms IS NULL AND result IS NULL)
        OR (state IN ('verified', 'failed', 'manual_check') AND ended_at_unix_ms IS NOT NULL AND result IS NOT NULL)
    )
) STRICT;

CREATE INDEX IF NOT EXISTS file_uploads_session_idx
ON file_uploads(session_id, planned_at_unix_ms DESC);
