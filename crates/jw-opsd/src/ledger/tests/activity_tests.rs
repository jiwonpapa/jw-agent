use super::*;

#[test]
fn older_checkpoint_completion_cannot_clear_newer_pending_sequence() -> Result<(), String> {
    let connection = Connection::open_in_memory().map_err(|error| error.to_string())?;
    connection
        .execute_batch(
            "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);\n\
             INSERT INTO metadata (key, value) VALUES ('checkpoint_required_sequence', '42');",
        )
        .map_err(|error| error.to_string())?;
    clear_completed_checkpoint(&connection, 41).map_err(|error| error.to_string())?;
    let pending: String = connection
        .query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            [CHECKPOINT_PENDING_KEY],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if pending != "42" {
        return Err(String::from(
            "older checkpoint completion cleared the newer pending sequence",
        ));
    }
    clear_completed_checkpoint(&connection, 42).map_err(|error| error.to_string())?;
    let remaining: i64 = connection
        .query_row("SELECT COUNT(*) FROM metadata", [], |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if remaining != 0 {
        return Err(String::from(
            "matching checkpoint completion did not clear its pending sequence",
        ));
    }
    Ok(())
}

#[test]
fn recent_receipts_are_scoped_to_the_canonical_actor_uid() -> Result<(), String> {
    let root = test_root("recent-receipts")?;
    let paths = OpsPaths::for_test(&root);
    let mut ledger = Ledger::open(&paths).map_err(|error| error.to_string())?;
    let first = ledger
        .create_or_reuse_plan(&fixture_plan())
        .map_err(|error| error.to_string())?;
    let first_operation = ledger
        .begin_operation(
            "op-actor-1000",
            &first.plan_id,
            &first.plan_hash,
            &first.idempotency_key,
            &first.actor,
            1_500,
        )
        .map_err(|error| error.to_string())?;
    ledger
        .transition(
            &first_operation.operation_id,
            Transition {
                expected: &[OperationStage::Approved],
                next: OperationStage::CancelledBeforeApply,
                result_code: "test_cancel",
                evidence_digest: &sha256_digest(b"test_cancel"),
                after_digest: None,
                rollback_result: None,
                now_ms: 1_501,
            },
        )
        .map_err(|error| error.to_string())?;

    let mut other_plan = fixture_plan();
    other_plan.plan_id = String::from("plan-2");
    other_plan.plan_hash = sha256_digest(b"plan-2");
    other_plan.actor.uid = 2_000;
    other_plan.actor.username = String::from("other");
    other_plan.idempotency_key = String::from("fedcba9876543210");
    other_plan.request_digest = sha256_digest(b"request-2");
    other_plan.resource_key = String::from("nginx/site/other");
    let second = ledger
        .create_or_reuse_plan(&other_plan)
        .map_err(|error| error.to_string())?;
    ledger
        .begin_operation(
            "op-actor-2000",
            &second.plan_id,
            &second.plan_hash,
            &second.idempotency_key,
            &second.actor,
            1_600,
        )
        .map_err(|error| error.to_string())?;

    let recent = ledger
        .recent_receipts(1_000, 8)
        .map_err(|error| error.to_string())?;
    assert_eq!(recent.operations.len(), 1);
    assert_eq!(recent.operations[0].operation_id, "op-actor-1000");
    assert_eq!(recent.operations[0].display_name, "example.com");
    assert_eq!(recent.operations[0].actor.uid, 1_000);
    std::fs::remove_dir_all(root).map_err(|error| error.to_string())
}
