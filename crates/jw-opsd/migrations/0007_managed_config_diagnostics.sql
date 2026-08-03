CREATE TABLE managed_config_diagnostics (
    sequence INTEGER PRIMARY KEY NOT NULL REFERENCES ledger_events(sequence) ON DELETE CASCADE,
    diagnostics_json TEXT NOT NULL,
    diagnostics_digest TEXT NOT NULL,
    validator_evidence_digest TEXT NOT NULL
);
