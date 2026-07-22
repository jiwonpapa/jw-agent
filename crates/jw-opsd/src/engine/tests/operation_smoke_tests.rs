use super::*;

#[test]
fn successful_enable_reaches_verified_terminal_receipt() -> Result<(), String> {
    let root = test_root("success")?;
    let service = fixture_service(&root, Arc::new(FakeRunner::all_success()))?;
    let plan = plan(&service, 1_000)?;
    let receipt = approve(&service, &plan, 1_001)?;
    assert_eq!(
        receipt.terminal_state,
        jw_contracts::OperationStage::Succeeded
    );
    assert_eq!(receipt.after_digest, enabled_state_digest(true));
    fs::remove_dir_all(root).map_err(|error| error.to_string())
}
