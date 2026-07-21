CREATE TABLE IF NOT EXISTS terminal_sessions (
    session_id TEXT PRIMARY KEY CHECK (length(session_id) = 32),
    actor_uid INTEGER NOT NULL CHECK (actor_uid > 0),
    actor_username TEXT NOT NULL CHECK (length(actor_username) BETWEEN 1 AND 64),
    ingress TEXT NOT NULL CHECK (ingress IN ('public', 'recovery')),
    remote_host TEXT NOT NULL CHECK (remote_host = '127.0.0.1'),
    started_at_unix_ms INTEGER NOT NULL,
    ended_at_unix_ms INTEGER,
    close_reason TEXT CHECK (close_reason IS NULL OR length(close_reason) BETWEEN 1 AND 64),
    bytes_in INTEGER NOT NULL DEFAULT 0 CHECK (bytes_in >= 0),
    bytes_out INTEGER NOT NULL DEFAULT 0 CHECK (bytes_out >= 0),
    state TEXT NOT NULL CHECK (state IN ('active', 'closed')),
    CHECK (
        (state = 'active' AND ended_at_unix_ms IS NULL AND close_reason IS NULL)
        OR (state = 'closed' AND ended_at_unix_ms IS NOT NULL AND close_reason IS NOT NULL)
    )
) STRICT;

CREATE INDEX IF NOT EXISTS terminal_sessions_started_idx
ON terminal_sessions(started_at_unix_ms DESC);
