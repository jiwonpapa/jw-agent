#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Duration;

use super::{
    ManagedConfigPlanFields, P2ApiSession, VmConfig, expect_http, json_string, json_string_field,
    json_unsigned_field, operation_idempotency_key, public_api_request, read_secret,
    require_success, require_terminal, restart_edge_and_agentd_and_wait, text,
};

const APACHE_CONFIG_API: &str = "/api/v1/services/apache/configurations";
const APACHE_SITE: &str = "/etc/apache2/sites-available/jw-agent-test.conf";
const APACHE_FIXTURE_ROOT: &str = "/var/tmp/jw-agent-vm-apache";
const BASELINE: &str = "<VirtualHost 127.0.0.1:18081>\n    ServerName jw-agent-apache.test\n    DocumentRoot /var/www/html\n</VirtualHost>\n";

pub(crate) fn gate_p2_apache_managed_config(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    restart_edge_and_agentd_and_wait(&config, timeout)?;
    prepare_fixture(&config, timeout)?;
    let result = run_managed_config_scenarios(&config, &password, timeout);
    let cleanup = cleanup_fixture(&config, timeout);
    combine_with_cleanup(result, cleanup, "Apache managed config")
}

pub(super) fn prepare_fixture(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    cleanup_fixture(config, timeout)?;
    let script = format!(
        r#"sudo sh -eu -c '
test -x /usr/sbin/apache2ctl
mkdir -p {APACHE_FIXTURE_ROOT}
cp -a /etc/apache2/ports.conf {APACHE_FIXTURE_ROOT}/ports.conf
if systemctl is-active --quiet apache2.service; then
    printf active > {APACHE_FIXTURE_ROOT}/original-state
else
    printf inactive > {APACHE_FIXTURE_ROOT}/original-state
fi
systemctl stop apache2.service || true
printf "%s\n" "Listen 127.0.0.1:18081" > /etc/apache2/ports.conf
cat > {APACHE_SITE} <<'"'"'JW_AGENT_APACHE'"'"'
{BASELINE}JW_AGENT_APACHE
ln -sfn ../sites-available/jw-agent-test.conf /etc/apache2/sites-enabled/jw-agent-test.conf
apache2ctl configtest
systemctl start apache2.service
systemctl is-active --quiet apache2.service
'"#
    );
    let prepared = config.ssh(&script, None, timeout)?;
    require_success(&prepared, "Apache fixture preparation", false)
}

pub(super) fn cleanup_fixture(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let script = format!(
        r#"sudo sh -eu -c '
if test -d {APACHE_FIXTURE_ROOT}; then
    original_state=inactive
    if test -f {APACHE_FIXTURE_ROOT}/original-state; then
        original_state=$(cat {APACHE_FIXTURE_ROOT}/original-state)
    fi
    systemctl stop apache2.service || true
    rm -f /etc/apache2/sites-enabled/jw-agent-test.conf {APACHE_SITE}
    if test -f {APACHE_FIXTURE_ROOT}/ports.conf; then
        cp -a {APACHE_FIXTURE_ROOT}/ports.conf /etc/apache2/ports.conf
    fi
    apache2ctl configtest
    if test "$original_state" = active; then
        systemctl start apache2.service
    fi
    rm -rf {APACHE_FIXTURE_ROOT}
fi
'"#
    );
    let cleaned = config.ssh(&script, None, timeout)?;
    require_success(&cleaned, "Apache fixture cleanup", false)
}

fn run_managed_config_scenarios(
    config: &VmConfig,
    password: &str,
    timeout: Duration,
) -> Result<(), String> {
    let baseline = read_site(config, timeout)?;
    if baseline != BASELINE {
        return Err(String::from(
            "Apache fixture content did not match its expected baseline",
        ));
    }

    let mut session = P2ApiSession::login(config, password, timeout)?;
    session.enter_administrative(config, password, timeout)?;
    let inventory = session.get(config, APACHE_CONFIG_API, timeout)?;
    expect_http(&inventory, 200, "Apache configuration inventory")?;
    if !inventory.body.contains("\"status\":\"observed\"")
        || !inventory
            .body
            .contains("\"maskedPath\":\"/etc/apache2/sites-available/jw-agent-test.conf\"")
    {
        return Err(String::from(
            "Apache fixture was not exposed as an active managed configuration",
        ));
    }
    let object = configuration_object(
        &inventory.body,
        "/etc/apache2/sites-available/jw-agent-test.conf",
    )?;
    if !object.contains("\"available\":true") {
        return Err(String::from(
            "Apache fixture did not advertise an editable active configuration",
        ));
    }
    let resource_id = json_string_field(object, "resourceId")?;
    let operation_type = json_string_field(object, "operationType")?;
    let schema_version = u16::try_from(json_unsigned_field(object, "schemaVersion")?)
        .map_err(|_| String::from("Apache managed config schema overflow"))?;

    let valid_content = format!("{BASELINE}# JW Agent VM Apache managed config\n");
    let valid_plan = plan(
        &session,
        config,
        &resource_id,
        &operation_type,
        schema_version,
        &valid_content,
        timeout,
    )?;
    let saved = session.approve_managed_config(config, &valid_plan, timeout)?;
    require_terminal(&saved, "SUCCEEDED", "Apache managed config save")?;
    for evidence in [
        "\"resultCode\":\"apache_config_valid\"",
        "\"resultCode\":\"apache_reloaded\"",
        "\"resultCode\":\"config_verified\"",
    ] {
        if !saved.contains(evidence) {
            return Err(format!("Apache save receipt omitted {evidence}"));
        }
    }
    require_site_equals(config, &valid_content, timeout)?;

    let invalid_content = format!("{valid_content}JWAgentInvalidDirective on\n");
    let invalid_plan = plan(
        &session,
        config,
        &resource_id,
        &operation_type,
        schema_version,
        &invalid_content,
        timeout,
    )?;
    let rolled_back = session.approve_managed_config(config, &invalid_plan, timeout)?;
    require_terminal(
        &rolled_back,
        "ROLLED_BACK",
        "Apache managed config syntax rollback",
    )?;
    if !rolled_back.contains("\"resultCode\":\"apache_config_invalid\"")
        || !rolled_back.contains("\"rollbackResult\":\"verified\"")
    {
        return Err(String::from(
            "Apache syntax receipt omitted invalid-config or verified rollback evidence",
        ));
    }
    require_site_equals(config, &valid_content, timeout)?;

    let runtime = config.ssh(
        "sudo apache2ctl configtest\nsystemctl is-active --quiet apache2.service",
        None,
        timeout,
    )?;
    require_success(&runtime, "Apache managed config final runtime", false)
}

fn configuration_object<'a>(body: &'a str, masked_path: &str) -> Result<&'a str, String> {
    let marker = format!("\"maskedPath\":{}", json_string(masked_path));
    let marker_index = body
        .find(&marker)
        .ok_or_else(|| format!("managed Apache config `{masked_path}` was not observed"))?;
    let start = body[..marker_index]
        .rfind('{')
        .ok_or_else(|| String::from("Apache configuration object start is missing"))?;
    Ok(&body[start..])
}

fn plan(
    session: &P2ApiSession,
    config: &VmConfig,
    resource_id: &str,
    operation_type: &str,
    schema_version: u16,
    proposed_content: &str,
    timeout: Duration,
) -> Result<ManagedConfigPlanFields, String> {
    let resource = session.get(
        config,
        &format!("/api/v1/config-resources/{resource_id}"),
        timeout,
    )?;
    expect_http(&resource, 200, "Apache managed resource refresh")?;
    let idempotency_key = operation_idempotency_key()?;
    let body = format!(
        "{{\"schemaVersion\":{schema_version},\"operationType\":{},\"resourceId\":{},\"expectedContentDigest\":{},\"expectedMetadataDigest\":{},\"proposedContent\":{},\"serviceAction\":\"reload\",\"idempotencyKey\":{}}}",
        json_string(operation_type),
        json_string(resource_id),
        json_string(&json_string_field(&resource.body, "contentDigest")?),
        json_string(&json_string_field(&resource.body, "metadataDigest")?),
        json_string(proposed_content),
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
    expect_http(&response, 200, "Apache managed config plan")?;
    let has_adapter = response
        .body
        .contains("\"adapterId\":\"apache/ubuntu-24.04-site-enabled-v1\"");
    let has_masked_path = response
        .body
        .contains("\"maskedPath\":\"…/apache2/sites-available/jw-agent-test.conf\"");
    let has_assurance = response.body.contains("\"level\":\"g2_reversible_config\"");
    if !(has_adapter && has_masked_path && has_assurance) {
        return Err(format!(
            "Apache plan evidence mismatch: adapter={has_adapter}, masked_path={has_masked_path}, assurance={has_assurance}"
        ));
    }
    Ok(ManagedConfigPlanFields {
        schema_version,
        plan_id: json_string_field(&response.body, "planId")?,
        plan_hash: json_string_field(&response.body, "planHash")?,
        idempotency_key,
    })
}

fn read_site(config: &VmConfig, timeout: Duration) -> Result<String, String> {
    let result = config.ssh(&format!("sudo cat {APACHE_SITE}"), None, timeout)?;
    require_success(&result, "Apache fixture read", false)?;
    text(&result.stdout).map(str::to_owned)
}

fn require_site_equals(config: &VmConfig, expected: &str, timeout: Duration) -> Result<(), String> {
    if read_site(config, timeout)? == expected {
        Ok(())
    } else {
        Err(String::from(
            "Apache managed configuration did not match the expected exact content",
        ))
    }
}

fn combine_with_cleanup(
    result: Result<(), String>,
    cleanup: Result<(), String>,
    label: &str,
) -> Result<(), String> {
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; {label} fixture cleanup also failed: {cleanup_error}"
        )),
    }
}
