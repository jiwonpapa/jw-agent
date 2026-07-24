#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Duration;

use super::{
    ManagedConfigPlanFields, P2ApiSession, VmConfig, expect_http, json_string, json_string_field,
    json_unsigned_field, operation_idempotency_key, public_api_request, read_secret,
    require_success, require_terminal, restart_edge_and_agentd_and_wait, text,
};

const PHP_FPM_API: &str = "/api/v1/services/php-fpm";
const PHP_INI: &str = "/etc/php/8.3/fpm/php.ini";
const PHP_INI_BACKUP: &str = "/var/tmp/jw-agent-vm-php.ini.backup";

pub fn gate_p2_php_fpm(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    restart_edge_and_agentd_and_wait(&config, timeout)?;
    prepare_fixture(&config, timeout)?;
    let result = run_scenarios(&config, &password, timeout);
    let cleanup = cleanup_fixture(&config, timeout);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; PHP-FPM fixture cleanup also failed: {cleanup_error}"
        )),
    }
}

fn run_scenarios(config: &VmConfig, password: &str, timeout: Duration) -> Result<(), String> {
    let baseline_result = config.ssh(&format!("sudo cat {PHP_INI}"), None, timeout)?;
    require_success(&baseline_result, "PHP-FPM baseline read", false)?;
    if baseline_result.stdout_truncated {
        return Err(String::from(
            "PHP-FPM baseline exceeded the 128 KiB harness bound",
        ));
    }
    let baseline = text(&baseline_result.stdout)?.to_owned();
    if baseline.len() > 128 * 1_024 {
        return Err(String::from(
            "PHP-FPM php.ini exceeded the supported 128 KiB bound",
        ));
    }

    let mut session = P2ApiSession::login(config, password, timeout)?;
    session.enter_administrative(config, password, timeout)?;
    let inventory = session.get(config, PHP_FPM_API, timeout)?;
    expect_http(&inventory, 200, "PHP-FPM observation")?;
    require_inventory_contract(&inventory.body)?;

    let resource_id = json_string_field(&inventory.body, "managedConfigResourceId")?;
    let operation_type = json_string_field(&inventory.body, "managedConfigOperationType")?;
    let schema_version = u16::try_from(json_unsigned_field(
        &inventory.body,
        "managedConfigSchemaVersion",
    )?)
    .map_err(|_| String::from("PHP-FPM managed config schema overflow"))?;
    let resource_path = format!("/api/v1/config-resources/{resource_id}");
    let resource = session.get(config, &resource_path, timeout)?;
    expect_http(&resource, 200, "PHP-FPM managed resource")?;
    require_resource_contract(&resource.body)?;

    let valid_content = format!("{baseline}\n; JW Agent VM PFC-02\nmemory_limit = 129M\n");
    let valid_plan = plan(
        &session,
        config,
        PlanInput {
            resource_id: &resource_id,
            operation_type: &operation_type,
            schema_version,
            proposed_content: &valid_content,
        },
        timeout,
    )?;
    let saved = session.approve_managed_config(config, &valid_plan, timeout)?;
    require_php_terminal(&saved, "SUCCEEDED", "PHP-FPM config save")?;
    for evidence in [
        "\"resultCode\":\"php_fpm_config_valid\"",
        "\"resultCode\":\"php_fpm_reloaded\"",
        "\"resultCode\":\"config_verified\"",
    ] {
        if !saved.contains(evidence) {
            return Err(format!("PHP-FPM save receipt omitted {evidence}"));
        }
    }
    require_php_ini_equals(config, valid_content.as_bytes(), timeout)?;

    let restore_plan = plan_restore(
        &session,
        config,
        &resource_id,
        &json_string_field(&saved, "operationId")?,
        timeout,
    )?;
    let restored = session.approve_managed_config(config, &restore_plan, timeout)?;
    require_php_terminal(&restored, "SUCCEEDED", "PHP-FPM manual restore")?;
    if !restored.contains("\"operationType\":\"service.config_file.restore/v1\"")
        || !restored.contains("\"restoreAvailable\":true")
        || !restored.contains("\"resultCode\":\"config_verified\"")
    {
        return Err(String::from(
            "PHP-FPM restore receipt omitted immutable restore evidence",
        ));
    }
    require_php_ini_equals(config, baseline.as_bytes(), timeout)?;

    let invalid_content = format!("{valid_content}\nmemory_limit == broken\n");
    let invalid_plan = plan(
        &session,
        config,
        PlanInput {
            resource_id: &resource_id,
            operation_type: &operation_type,
            schema_version,
            proposed_content: &invalid_content,
        },
        timeout,
    )?;
    let rolled_back = session.approve_managed_config(config, &invalid_plan, timeout)?;
    require_php_terminal(&rolled_back, "ROLLED_BACK", "PHP-FPM syntax rollback")?;
    if !rolled_back.contains("\"resultCode\":\"php_fpm_config_syntax_line_")
        || !rolled_back.contains("\"rollbackResult\":\"verified\"")
    {
        return Err(String::from(
            "PHP-FPM syntax receipt omitted bounded line or verified rollback evidence",
        ));
    }
    require_php_ini_equals(config, baseline.as_bytes(), timeout)
}

struct PlanInput<'a> {
    resource_id: &'a str,
    operation_type: &'a str,
    schema_version: u16,
    proposed_content: &'a str,
}

fn plan(
    session: &P2ApiSession,
    config: &VmConfig,
    input: PlanInput<'_>,
    timeout: Duration,
) -> Result<ManagedConfigPlanFields, String> {
    let resource = session.get(
        config,
        &format!("/api/v1/config-resources/{}", input.resource_id),
        timeout,
    )?;
    expect_http(&resource, 200, "PHP-FPM managed resource refresh")?;
    let idempotency_key = operation_idempotency_key()?;
    let body = format!(
        "{{\"schemaVersion\":{},\"operationType\":{},\"resourceId\":{},\"expectedContentDigest\":{},\"expectedMetadataDigest\":{},\"proposedContent\":{},\"serviceAction\":\"reload\",\"idempotencyKey\":{}}}",
        input.schema_version,
        json_string(input.operation_type),
        json_string(input.resource_id),
        json_string(&json_string_field(&resource.body, "contentDigest")?),
        json_string(&json_string_field(&resource.body, "metadataDigest")?),
        json_string(input.proposed_content),
        json_string(&idempotency_key),
    );
    let response = public_api_request(
        config,
        "POST",
        "/api/v1/operations/service/config-file/plans",
        &session.cookie_jar.path,
        Some(&session.csrf_token),
        Some(body.as_bytes()),
        timeout,
    )?;
    expect_http(&response, 200, "PHP-FPM managed config plan")?;
    if !response
        .body
        .contains("\"adapterId\":\"php-fpm/ubuntu-24.04-8.3-v1\"")
        || !response
            .body
            .contains("\"maskedPath\":\"…/php/8.3/fpm/php.ini\"")
        || !response.body.contains("\"level\":\"g2_reversible_config\"")
    {
        return Err(String::from(
            "PHP-FPM plan omitted adapter, masked path, or recovery assurance",
        ));
    }
    Ok(ManagedConfigPlanFields {
        schema_version: input.schema_version,
        plan_id: json_string_field(&response.body, "planId")?,
        plan_hash: json_string_field(&response.body, "planHash")?,
        idempotency_key,
    })
}

fn plan_restore(
    session: &P2ApiSession,
    config: &VmConfig,
    resource_id: &str,
    source_operation_id: &str,
    timeout: Duration,
) -> Result<ManagedConfigPlanFields, String> {
    let resource = session.get(
        config,
        &format!("/api/v1/config-resources/{resource_id}"),
        timeout,
    )?;
    expect_http(&resource, 200, "PHP-FPM restore resource refresh")?;
    let idempotency_key = operation_idempotency_key()?;
    let body = format!(
        "{{\"schemaVersion\":1,\"operationType\":\"service.config_file.restore/v1\",\"sourceOperationId\":{},\"expectedContentDigest\":{},\"expectedMetadataDigest\":{},\"idempotencyKey\":{}}}",
        json_string(source_operation_id),
        json_string(&json_string_field(&resource.body, "contentDigest")?),
        json_string(&json_string_field(&resource.body, "metadataDigest")?),
        json_string(&idempotency_key),
    );
    let response = public_api_request(
        config,
        "POST",
        "/api/v1/operations/service/config-file/restore/plans",
        &session.cookie_jar.path,
        Some(&session.csrf_token),
        Some(body.as_bytes()),
        timeout,
    )?;
    expect_http(&response, 200, "PHP-FPM restore plan")?;
    if !response
        .body
        .contains("\"operationType\":\"service.config_file.restore/v1\"")
        || !response
            .body
            .contains("\"rollbackSupport\":\"automatic_bounded\"")
    {
        return Err(String::from(
            "PHP-FPM restore plan omitted the restore type or bounded rollback contract",
        ));
    }
    Ok(ManagedConfigPlanFields {
        schema_version: 1,
        plan_id: json_string_field(&response.body, "planId")?,
        plan_hash: json_string_field(&response.body, "planHash")?,
        idempotency_key,
    })
}

fn require_inventory_contract(body: &str) -> Result<(), String> {
    if body.contains("\"status\":\"observed\"")
        && body.contains("\"version\":\"8.3\"")
        && body.contains("\"unitName\":\"php8.3-fpm.service\"")
        && body.contains("\"runtimeState\":\"running\"")
        && body.contains("\"phpIniMaskedPath\":\"/etc/php/8.3/fpm/php.ini\"")
        && body.contains("\"extensions\":[")
        && body.contains("\"operationAvailable\":true")
        && !body.to_ascii_lowercase().contains("phpinfo")
    {
        Ok(())
    } else {
        Err(String::from(
            "PHP-FPM inventory omitted runtime, extension, path, or mutation contract",
        ))
    }
}

fn require_resource_contract(body: &str) -> Result<(), String> {
    if json_unsigned_field(body, "maxBytes")? == 131_072
        && body.contains("\"adapterId\":\"php-fpm/ubuntu-24.04-8.3-v1\"")
        && body.contains("\"reload\"")
        && body.contains("\"validate_only\"")
        && body.contains("\"level\":\"g2_reversible_config\"")
        && body.contains("\"rollbackSupport\":\"automatic_bounded\"")
    {
        Ok(())
    } else {
        Err(String::from(
            "PHP-FPM resource omitted its 128 KiB bounded validation and recovery contract",
        ))
    }
}

fn prepare_fixture(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let result = config.ssh(
        &format!(
            "sudo sh -eu -c 'test -x /usr/sbin/php-fpm8.3; test -f {PHP_INI}; systemctl is-active --quiet php8.3-fpm.service; rm -f {PHP_INI_BACKUP}; cp -a {PHP_INI} {PHP_INI_BACKUP}'"
        ),
        None,
        timeout,
    )?;
    require_success(&result, "PHP-FPM fixture preparation", false)
}

fn cleanup_fixture(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let result = config.ssh(
        &format!(
            "sudo sh -eu -c 'if test -f {PHP_INI_BACKUP}; then cp -a --remove-destination {PHP_INI_BACKUP} {PHP_INI}; rm -f {PHP_INI_BACKUP}; /usr/sbin/php-fpm8.3 -t; systemctl reload php8.3-fpm.service; fi; systemctl is-active --quiet php8.3-fpm.service'"
        ),
        None,
        timeout,
    )?;
    require_success(&result, "PHP-FPM fixture cleanup", false)
}

fn require_php_ini_equals(
    config: &VmConfig,
    expected: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    let result = config.ssh(
        &format!(
            "sudo cmp -s /dev/stdin {PHP_INI} && sudo /usr/sbin/php-fpm8.3 -t && sudo systemctl is-active --quiet php8.3-fpm.service"
        ),
        Some(expected),
        timeout,
    )?;
    require_success(
        &result,
        "exact PHP-FPM config and service continuity",
        false,
    )
}

fn require_php_terminal(body: &str, expected: &str, label: &str) -> Result<(), String> {
    if let Err(error) = require_terminal(body, expected, label) {
        return Err(format!("{error}; result codes={}", result_codes(body)));
    }
    Ok(())
}

fn result_codes(body: &str) -> String {
    let marker = "\"resultCode\":\"";
    let mut remaining = body;
    let mut values = Vec::new();
    while values.len() < 16 {
        let Some(start) = remaining.find(marker).map(|index| index + marker.len()) else {
            break;
        };
        remaining = &remaining[start..];
        let Some(end) = remaining.find('"') else {
            break;
        };
        let value = &remaining[..end];
        if value.len() <= 128
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'=')
            })
        {
            values.push(value);
        }
        remaining = &remaining[end.saturating_add(1)..];
    }
    if values.is_empty() {
        String::from("none")
    } else {
        values.join(",")
    }
}
