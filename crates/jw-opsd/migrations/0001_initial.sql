PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plans (
    plan_id TEXT PRIMARY KEY NOT NULL,
    operation_type TEXT NOT NULL,
    plan_hash TEXT UNIQUE NOT NULL,
    actor_uid INTEGER NOT NULL,
    actor_username TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    site_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    current_state TEXT NOT NULL,
    target_state TEXT NOT NULL,
    available_digest TEXT NOT NULL,
    enabled_state_digest TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    idempotency_key TEXT UNIQUE NOT NULL,
    request_digest TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    assurance_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    plan_id TEXT UNIQUE NOT NULL REFERENCES plans(plan_id),
    stage TEXT NOT NULL,
    before_digest TEXT NOT NULL,
    after_digest TEXT NOT NULL,
    rollback_result TEXT,
    snapshot_relative_path TEXT,
    snapshot_digest TEXT,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency (
    idempotency_key TEXT PRIMARY KEY NOT NULL,
    request_digest TEXT NOT NULL,
    plan_id TEXT NOT NULL REFERENCES plans(plan_id),
    operation_id TEXT REFERENCES operations(operation_id)
);

CREATE TABLE IF NOT EXISTS resource_locks (
    resource_key TEXT PRIMARY KEY NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    acquired_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger_events (
    sequence INTEGER PRIMARY KEY NOT NULL,
    operation_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    result_code TEXT NOT NULL,
    recorded_at_ms INTEGER NOT NULL,
    evidence_digest TEXT NOT NULL,
    previous_digest TEXT NOT NULL,
    event_digest TEXT UNIQUE NOT NULL
);

CREATE INDEX IF NOT EXISTS ledger_events_operation_sequence
ON ledger_events(operation_id, sequence);

PRAGMA user_version = 1;
