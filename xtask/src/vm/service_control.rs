#![forbid(unsafe_code)]

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use super::{
    P2ApiSession, VmConfig, expect_http, json_string, json_string_field, json_unsigned_field,
    operation_idempotency_key, public_api_request, read_secret, require_success, require_terminal,
    restart_edge_and_agentd_and_wait,
};

pub(crate) fn gate_p2_service_control(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    let prepared = config.ssh(
        "sudo systemctl start nginx.service php8.3-fpm.service\nsudo systemctl restart jw-opsd.service jw-agentd.service",
        None,
        timeout,
    )?;
    require_success(&prepared, "service control fixture preparation", false)?;
    restart_edge_and_agentd_and_wait(&config, timeout)?;

    let result = run_scenarios(&config, &password, timeout);
    let cleanup = config.ssh(
        "sudo systemctl start nginx.service php8.3-fpm.service\nsudo systemctl restart jw-opsd.service jw-agentd.service",
        None,
        timeout,
    );
    match (result, cleanup) {
        (Ok(()), Ok(output)) => require_success(&output, "service control fixture cleanup", false),
        (Err(error), Ok(output)) => {
            match require_success(&output, "service control fixture cleanup", false) {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!(
                    "{error}; service control cleanup also failed: {cleanup_error}"
                )),
            }
        }
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; service control cleanup also failed: {cleanup_error}"
        )),
    }
}

fn run_scenarios(config: &VmConfig, password: &str, timeout: Duration) -> Result<(), String> {
    let mut session = P2ApiSession::login(config, password, timeout)?;
    session.enter_administrative(config, password, timeout)?;

    for (unit_name, action) in [
        ("nginx.service", "reload"),
        ("php8.3-fpm.service", "restart"),
        ("php8.3-fpm.service", "stop"),
        ("php8.3-fpm.service", "start"),
    ] {
        let receipt = operate(&session, config, unit_name, action, timeout)?;
        require_terminal(&receipt, "SUCCEEDED", &format!("{unit_name} {action}"))?;
        if !receipt.contains("\"operationType\":\"service.lifecycle.set/v1\"")
            || !receipt.contains("\"resultCode\":\"service_state_verified\"")
        {
            return Err(format!(
                "{unit_name} {action} receipt omitted lifecycle verification evidence"
            ));
        }
        let health = session.get(config, "/api/v1/services", timeout)?;
        expect_http(&health, 200, "post-operation management continuity")?;
    }

    let runtime = config.ssh(
        "systemctl is-active --quiet nginx.service\nsystemctl is-active --quiet php8.3-fpm.service\nsudo nginx -t\nsudo php-fpm8.3 -t",
        None,
        timeout,
    )?;
    require_success(&runtime, "service control final runtime state", false)
}

fn operate(
    session: &P2ApiSession,
    config: &VmConfig,
    unit_name: &str,
    action: &str,
    timeout: Duration,
) -> Result<String, String> {
    let services = session.get(config, "/api/v1/services", timeout)?;
    expect_http(&services, 200, "service control inventory")?;
    let object = service_object(&services.body, unit_name)?;
    let schema_version = u16::try_from(json_unsigned_field(object, "operationSchemaVersion")?)
        .map_err(|_| String::from("service operation schema overflow"))?;
    let service_id = json_string_field(object, "serviceId")?;
    let state_digest = json_string_field(object, "stateDigest")?;
    let operation_type = json_string_field(object, "operationType")?;
    if operation_type != "service.lifecycle.set/v1"
        || !object.contains("\"allowedActions\":[")
        || !object.contains(&json_string(action))
    {
        return Err(format!(
            "{unit_name} did not advertise the bounded {action} lifecycle action"
        ));
    }

    let idempotency_key = operation_idempotency_key()?;
    let body = format!(
        "{{\"schemaVersion\":{schema_version},\"operationType\":{},\"serviceId\":{},\"action\":{},\"expectedStateDigest\":{},\"idempotencyKey\":{}}}",
        json_string(&operation_type),
        json_string(&service_id),
        json_string(action),
        json_string(&state_digest),
        json_string(&idempotency_key),
    );
    let plan = public_api_request(
        config,
        "POST",
        "/api/v1/operations/service/lifecycle/plans",
        &session.cookie_jar.path,
        Some(&session.csrf_token),
        Some(body.as_bytes()),
        timeout,
    )?;
    expect_http(&plan, 200, "service lifecycle plan")?;
    if !plan.body.contains("\"level\":\"g2_reversible_config\"")
        || !plan
            .body
            .contains("\"rollbackSupport\":\"automatic_bounded\"")
    {
        return Err(String::from(
            "service lifecycle plan omitted its bounded rollback contract",
        ));
    }
    let plan_id = json_string_field(&plan.body, "planId")?;
    let plan_hash = json_string_field(&plan.body, "planHash")?;
    let approval = format!(
        "{{\"schemaVersion\":{schema_version},\"planId\":{},\"planHash\":{},\"idempotencyKey\":{},\"impactConfirmed\":true}}",
        json_string(&plan_id),
        json_string(&plan_hash),
        json_string(&idempotency_key),
    );
    let accepted = public_api_request(
        config,
        "POST",
        "/api/v1/operations/service/lifecycle/approvals",
        &session.cookie_jar.path,
        Some(&session.csrf_token),
        Some(approval.as_bytes()),
        timeout,
    )?;
    expect_http(&accepted, 202, "service lifecycle approval")?;
    let operation_id = json_string_field(&accepted.body, "operationId")?;
    let operation_path = format!("/api/v1/operations/{operation_id}");
    let started = Instant::now();
    loop {
        let current = session.get(config, &operation_path, timeout)?;
        expect_http(&current, 200, "service lifecycle receipt")?;
        let stage = json_string_field(&current.body, "terminalState")?;
        if matches!(
            stage.as_str(),
            "SUCCEEDED"
                | "ROLLED_BACK"
                | "RECOVERY_REQUIRED"
                | "REJECTED"
                | "EXPIRED"
                | "CANCELLED_BEFORE_APPLY"
        ) {
            return Ok(current.body);
        }
        if started.elapsed() >= timeout {
            return Err(format!(
                "{unit_name} {action} did not reach a terminal receipt"
            ));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

pub(super) fn service_object<'a>(body: &'a str, unit_name: &str) -> Result<&'a str, String> {
    let marker = format!("\"unitName\":{}", json_string(unit_name));
    let marker_index = body
        .find(&marker)
        .ok_or_else(|| format!("service `{unit_name}` was not observed"))?;
    let start = body[..marker_index]
        .rfind('{')
        .ok_or_else(|| format!("service `{unit_name}` object start is missing"))?;
    let remainder = &body[start..];
    let end = remainder
        .find('}')
        .ok_or_else(|| format!("service `{unit_name}` object end is missing"))?;
    Ok(&remainder[..=end])
}
