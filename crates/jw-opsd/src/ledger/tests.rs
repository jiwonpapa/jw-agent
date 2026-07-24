use jw_contracts::{
    AssuranceLevel, AssuranceView, NGINX_SITE_STATE_OPERATION, NginxSiteState, OperationStage,
    Role, RollbackSupport, Subject, sha256_digest,
};

use crate::config::OpsPaths;

use super::{
    CHECKPOINT_PENDING_KEY, Connection, Ledger, StoredPlan, Transition, clear_completed_checkpoint,
};

mod activity_tests;

#[test]
fn idempotency_reuses_same_plan_and_rejects_different_meaning() -> Result<(), String> {
    let root = test_root("idempotency")?;
    let paths = OpsPaths::for_test(&root);
    let mut ledger = Ledger::open(&paths).map_err(|error| error.to_string())?;
    let plan = fixture_plan();
    let first = ledger
        .create_or_reuse_plan(&plan)
        .map_err(|error| error.to_string())?;
    let second = ledger
        .create_or_reuse_plan(&plan)
        .map_err(|error| error.to_string())?;
    assert_eq!(first.plan_id, second.plan_id);
    let mut conflict = plan;
    conflict.plan_id = String::from("plan-other");
    conflict.request_digest = sha256_digest(b"different");
    assert!(matches!(
        ledger.create_or_reuse_plan(&conflict),
        Err(crate::error::OpsError::Rejected("idempotency_conflict"))
    ));
    std::fs::remove_dir_all(root).map_err(|error| error.to_string())
}

#[test]
fn tampered_event_enters_forensic_lockdown() -> Result<(), String> {
    let root = test_root("tamper")?;
    let paths = OpsPaths::for_test(&root);
    let mut ledger = Ledger::open(&paths).map_err(|error| error.to_string())?;
    ledger
        .create_or_reuse_plan(&fixture_plan())
        .map_err(|error| error.to_string())?;
    drop(ledger);
    let connection =
        rusqlite::Connection::open(&paths.database).map_err(|error| error.to_string())?;
    connection
        .execute(
            "UPDATE ledger_events SET result_code = 'forged' WHERE sequence = 1",
            [],
        )
        .map_err(|error| error.to_string())?;
    drop(connection);
    assert!(matches!(
        Ledger::open(&paths),
        Err(crate::error::OpsError::ForensicLockdown)
    ));
    std::fs::remove_dir_all(root).map_err(|error| error.to_string())
}

#[test]
fn deleting_required_checkpoint_enters_forensic_lockdown() -> Result<(), String> {
    let root = test_root("checkpoint-delete")?;
    let paths = OpsPaths::for_test(&root);
    let mut ledger = Ledger::open(&paths).map_err(|error| error.to_string())?;
    let plan = ledger
        .create_or_reuse_plan(&fixture_plan())
        .map_err(|error| error.to_string())?;
    let operation = ledger
        .begin_operation(
            "op-1",
            &plan.plan_id,
            &plan.plan_hash,
            &plan.idempotency_key,
            &plan.actor,
            1_500,
        )
        .map_err(|error| error.to_string())?;
    ledger
        .transition(
            &operation.operation_id,
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
    drop(ledger);
    std::fs::remove_file(&paths.checkpoint).map_err(|error| error.to_string())?;
    assert!(matches!(
        Ledger::open(&paths),
        Err(crate::error::OpsError::ForensicLockdown)
    ));
    std::fs::remove_dir_all(root).map_err(|error| error.to_string())
}

#[test]
fn missing_operation_has_a_typed_error() -> Result<(), String> {
    let root = test_root("missing-operation")?;
    let paths = OpsPaths::for_test(&root);
    let ledger = Ledger::open(&paths).map_err(|error| error.to_string())?;
    assert!(matches!(
        ledger.load_operation("missing"),
        Err(crate::error::OpsError::Rejected("operation_missing"))
    ));
    std::fs::remove_dir_all(root).map_err(|error| error.to_string())
}

fn fixture_plan() -> StoredPlan {
    StoredPlan {
        operation_type: String::from(NGINX_SITE_STATE_OPERATION),
        plan_id: String::from("plan-1"),
        plan_hash: sha256_digest(b"plan"),
        actor: Subject {
            uid: 1_000,
            username: String::from("operator"),
            role: Role::Admin,
        },
        site_id: String::from("ngs_tQ9Xog5xTe1fh8OsTIdiw6xr"),
        display_name: String::from("example.com"),
        current_state: NginxSiteState::Disabled,
        target_state: NginxSiteState::Enabled,
        available_digest: sha256_digest(b"server {}\n"),
        enabled_state_digest: sha256_digest(b"disabled"),
        created_at_ms: 1_000,
        expires_at_ms: 2_000,
        idempotency_key: String::from("0123456789abcdef"),
        request_digest: sha256_digest(b"request"),
        resource_key: String::from("nginx/site/example"),
        assurance: AssuranceView {
            level: AssuranceLevel::G2ReversibleConfig,
            rollback_support: RollbackSupport::AutomaticBounded,
            operation_available: true,
            scope: vec![String::from("enabled link")],
            excluded_effects: vec![String::from("connections")],
            apply_verifier: vec![String::from("read back")],
            rollback_verifier: vec![String::from("restore")],
            reason: None,
        },
        managed_config: None,
        certbot_renew: None,
        certbot_issue: None,
        certbot_attach: None,
        ufw_rule: None,
    }
}

fn test_root(label: &str) -> Result<std::path::PathBuf, String> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|error| error.to_string())?;
    Ok(std::env::temp_dir().join(format!(
        "jw-opsd-ledger-{label}-{}-{}",
        std::process::id(),
        u64::from_le_bytes(random)
    )))
}
