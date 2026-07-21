CREATE TABLE IF NOT EXISTS file_sessions (
    session_id TEXT PRIMARY KEY CHECK (length(session_id) = 32),
    actor_uid INTEGER NOT NULL CHECK (actor_uid > 0),
    actor_username TEXT NOT NULL CHECK (length(actor_username) BETWEEN 1 AND 64),
    ingress TEXT NOT NULL CHECK (ingress IN ('public', 'recovery')),
    remote_host TEXT NOT NULL CHECK (remote_host = '127.0.0.1'),
    started_at_unix_ms INTEGER NOT NULL,
    ended_at_unix_ms INTEGER,
    close_reason TEXT CHECK (close_reason IS NULL OR length(close_reason) BETWEEN 1 AND 64),
    state TEXT NOT NULL CHECK (state IN ('active', 'closed')),
    CHECK (
        (state = 'active' AND ended_at_unix_ms IS NULL AND close_reason IS NULL)
        OR (state = 'closed' AND ended_at_unix_ms IS NOT NULL AND close_reason IS NOT NULL)
    )
) STRICT;

CREATE INDEX IF NOT EXISTS file_sessions_started_idx
ON file_sessions(started_at_unix_ms DESC);

CREATE TABLE IF NOT EXISTS file_access_events (
    event_id INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('list', 'stat', 'read', 'download')),
    path_digest BLOB NOT NULL CHECK (length(path_digest) = 32),
    byte_count INTEGER NOT NULL CHECK (byte_count >= 0),
    result TEXT NOT NULL CHECK (length(result) BETWEEN 1 AND 64),
    occurred_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES file_sessions(session_id)
) STRICT;

CREATE INDEX IF NOT EXISTS file_access_events_session_idx
ON file_access_events(session_id, occurred_at_unix_ms DESC);
