use super::*;

#[test]
fn config_save_uses_php_validator_reload_and_read_back() -> Result<(), String> {
    let root = test_root("php-fpm-managed-success")?;
    let service = fixture_service(&root, Arc::new(FakeRunner::php_fpm_success()))?;
    prepare_php_fpm(&service, "memory_limit = 128M\n")?;
    let plan = managed_php_fpm_plan(
        &service,
        1_000,
        "memory_limit = 256M\n",
        "php-managed-key01",
    )?;
    assert_eq!(plan.adapter_id, PHP_FPM_CONFIG_ADAPTER_ID);
    assert_eq!(plan.masked_path, "…/php/8.3/fpm/php.ini");
    let receipt = approve_managed(&service, &plan, 1_001, "php-managed-key01", true)?;
    assert_eq!(receipt.terminal_state, OperationStage::Succeeded);
    assert!(receipt.stages.iter().any(|stage| {
        stage.result_code == "php_fpm_config_valid" && stage.stage == OperationStage::Reloading
    }));
    let content =
        fs::read_to_string(&service.paths.php_fpm_ini).map_err(|error| error.to_string())?;
    assert_eq!(content, "memory_limit = 256M\n");
    fs::remove_dir_all(root).map_err(|error| error.to_string())
}

#[test]
fn syntax_failure_restores_exact_php_ini() -> Result<(), String> {
    let root = test_root("php-fpm-managed-rollback")?;
    let service = fixture_service(
        &root,
        Arc::new(FakeRunner::php_fpm_syntax_failure_then_rollback()),
    )?;
    prepare_php_fpm(&service, "memory_limit = 128M\n")?;
    let plan = managed_php_fpm_plan(
        &service,
        1_000,
        "memory_limit == broken\n",
        "php-managed-key02",
    )?;
    let receipt = approve_managed(&service, &plan, 1_001, "php-managed-key02", true)?;
    assert_eq!(receipt.terminal_state, OperationStage::RolledBack);
    assert_eq!(receipt.rollback_result.as_deref(), Some("verified"));
    let content =
        fs::read_to_string(&service.paths.php_fpm_ini).map_err(|error| error.to_string())?;
    assert_eq!(content, "memory_limit = 128M\n");
    fs::remove_dir_all(root).map_err(|error| error.to_string())
}

fn prepare_php_fpm(service: &OpsService, content: &str) -> Result<(), String> {
    let parent = service
        .paths
        .php_fpm_ini
        .parent()
        .ok_or_else(|| String::from("php-fpm parent missing"))?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    fs::write(&service.paths.php_fpm_ini, content).map_err(|error| error.to_string())
}

fn managed_php_fpm_plan(
    service: &OpsService,
    now_ms: i64,
    proposed_content: &str,
    idempotency_key: &str,
) -> Result<jw_contracts::ManagedConfigPlanView, String> {
    let resource_id = php_fpm_config_resource_id(PHP_FPM_CONFIG_ADAPTER_ID);
    let resource = crate::managed_config::discover_managed_config(&service.paths, &resource_id)
        .map_err(|error| error.to_string())?;
    let request = OpsRequest {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: String::from("request-php-managed-plan"),
        deadline_unix_ms: now_ms.saturating_add(1_000),
        body: OpsRequestBody::PlanManagedConfig {
            actor: actor(),
            plan: ManagedConfigPlanRequest {
                schema_version: 1,
                operation_type: String::from(MANAGED_CONFIG_OPERATION),
                resource_id,
                expected_content_digest: resource.content_digest,
                expected_metadata_digest: resource.metadata_digest,
                proposed_content: proposed_content.to_owned(),
                service_action: ServiceAction::Reload,
                idempotency_key: idempotency_key.to_owned(),
            },
        },
    };
    let response = service.response_for(&request, now_ms);
    let OpsResponseBody::ManagedConfigPlan(plan) = response.body else {
        return Err(String::from("PHP-FPM managed plan response rejected"));
    };
    Ok(plan)
}
