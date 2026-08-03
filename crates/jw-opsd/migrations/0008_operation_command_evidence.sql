CREATE TABLE operation_command_evidence (
    sequence INTEGER PRIMARY KEY NOT NULL REFERENCES ledger_events(sequence) ON DELETE CASCADE,
    command_json TEXT NOT NULL
);
