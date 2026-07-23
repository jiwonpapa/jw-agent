use super::*;

#[test]
fn nginx_stop_is_rejected_without_independent_management_edge() -> Result<(), String> {
    let root = test_root("nginx-stop-edge-guard")?;
    let service = fixture_service(
        &root,
        Arc::new(FakeRunner::sequence([
            (crate::runner::CommandClass::NginxActive, true),
            (crate::runner::CommandClass::JwEdgeActive, false),
        ])),
    )?;
    let unit = "nginx.service";
    let request = jw_contracts::OpsRequest {
        protocol_version: jw_contracts::IPC_PROTOCOL_VERSION,
        request_id: String::from("request-nginx-stop-edge-guard"),
        deadline_unix_ms: 2_000,
        body: jw_contracts::OpsRequestBody::PlanServiceControl {
            actor: actor(),
            plan: jw_contracts::ServiceControlPlanRequest {
                schema_version: jw_contracts::OPERATION_SCHEMA_VERSION,
                operation_type: String::from(jw_contracts::SERVICE_CONTROL_OPERATION),
                service_id: jw_contracts::service_id(unit),
                action: jw_contracts::ManagedServiceAction::Stop,
                expected_state_digest: jw_contracts::service_state_digest(unit, true),
                idempotency_key: String::from("nginx-stop-edge-guard-01"),
            },
        },
    };
    let response = service.response_for(&request, 1_000);
    let jw_contracts::OpsResponseBody::Rejected(rejected) = response.body else {
        return Err(String::from("Nginx stop plan bypassed the edge guard"));
    };
    assert_eq!(rejected.code, "management_ingress_dependency");
    fs::remove_dir_all(root).map_err(|error| error.to_string())
}

#[test]
fn nginx_stop_is_cancelled_if_edge_disappears_after_plan() -> Result<(), String> {
    let root = test_root("nginx-stop-edge-recheck")?;
    let service = fixture_service(
        &root,
        Arc::new(FakeRunner::sequence([
            (crate::runner::CommandClass::NginxActive, true),
            (crate::runner::CommandClass::JwEdgeActive, true),
            (crate::runner::CommandClass::JwEdgeReady, true),
            (crate::runner::CommandClass::JwEdgeActive, false),
        ])),
    )?;
    let unit = "nginx.service";
    let idempotency_key = String::from("nginx-stop-edge-recheck-01");
    let plan_request = jw_contracts::OpsRequest {
        protocol_version: jw_contracts::IPC_PROTOCOL_VERSION,
        request_id: String::from("request-nginx-stop-edge-plan"),
        deadline_unix_ms: 2_000,
        body: jw_contracts::OpsRequestBody::PlanServiceControl {
            actor: actor(),
            plan: jw_contracts::ServiceControlPlanRequest {
                schema_version: jw_contracts::OPERATION_SCHEMA_VERSION,
                operation_type: String::from(jw_contracts::SERVICE_CONTROL_OPERATION),
                service_id: jw_contracts::service_id(unit),
                action: jw_contracts::ManagedServiceAction::Stop,
                expected_state_digest: jw_contracts::service_state_digest(unit, true),
                idempotency_key: idempotency_key.clone(),
            },
        },
    };
    let plan_response = service.response_for(&plan_request, 1_000);
    let jw_contracts::OpsResponseBody::ServiceControlPlan(plan) = plan_response.body else {
        return Err(String::from(
            "Nginx stop plan was rejected while edge was ready",
        ));
    };
    let approval = jw_contracts::OpsRequest {
        protocol_version: jw_contracts::IPC_PROTOCOL_VERSION,
        request_id: String::from("request-nginx-stop-edge-approve"),
        deadline_unix_ms: 2_100,
        body: jw_contracts::OpsRequestBody::ApproveServiceControl {
            actor: actor(),
            plan_id: plan.plan_id,
            plan_hash: plan.plan_hash,
            idempotency_key,
            impact_confirmed: true,
        },
    };
    let accepted = service.response_for(&approval, 1_001);
    let jw_contracts::OpsResponseBody::OperationReceipt(accepted) = accepted.body else {
        return Err(String::from("Nginx stop approval was rejected"));
    };
    let execute = jw_contracts::OpsRequest {
        protocol_version: jw_contracts::IPC_PROTOCOL_VERSION,
        request_id: String::from("request-nginx-stop-edge-execute"),
        deadline_unix_ms: 2_200,
        body: jw_contracts::OpsRequestBody::ExecuteOperation {
            actor: actor(),
            operation_id: accepted.operation_id,
        },
    };
    let executed = service.response_for(&execute, 1_002);
    let jw_contracts::OpsResponseBody::OperationReceipt(receipt) = executed.body else {
        return Err(String::from(
            "Nginx stop execution did not return a receipt",
        ));
    };
    assert_eq!(
        receipt.terminal_state,
        jw_contracts::OperationStage::CancelledBeforeApply
    );
    assert!(
        receipt
            .stages
            .iter()
            .any(|stage| stage.result_code == "management_ingress_dependency")
    );
    fs::remove_dir_all(root).map_err(|error| error.to_string())
}

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
