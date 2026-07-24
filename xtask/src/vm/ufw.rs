#![forbid(unsafe_code)]

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use super::{
    P2ApiSession, VmConfig, expect_http, json_string, json_string_field, operation_idempotency_key,
    public_api_request, read_secret, require_success, require_terminal,
    restart_edge_and_agentd_and_wait,
};

const UFW_API: &str = "/api/v1/firewall/ufw";
const UFW_PLAN_API: &str = "/api/v1/operations/ufw/rules/plans";
const UFW_APPROVAL_API: &str = "/api/v1/operations/ufw/rules/approvals";
const FIXTURE_ROOT: &str = "/var/tmp/jw-agent-vm-ufw";
const TEST_SOURCE: &str = "203.0.113.0/24";

struct UfwPlan {
    plan_id: String,
    plan_hash: String,
    idempotency_key: String,
    rule_id: String,
}

pub(crate) fn gate_p2_ufw_rule(_root: &Path, timeout: Duration) -> Result<(), String> {
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
            "{error}; UFW fixture cleanup also failed: {cleanup_error}"
        )),
    }
}

fn prepare_fixture(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    cleanup_fixture(config, timeout)?;
    let script = format!(
        r#"sudo sh -eu -c '
test -x /usr/sbin/ufw
mkdir -p {FIXTURE_ROOT}
cp -a /etc/ufw {FIXTURE_ROOT}/etc-ufw
if ufw status | grep -q "^Status: active$"; then
    printf active > {FIXTURE_ROOT}/original-state
else
    printf inactive > {FIXTURE_ROOT}/original-state
fi
ufw --force reset
ufw allow 22/tcp
ufw allow 443/tcp
ufw allow 9443/tcp
ufw --force enable
ufw status | grep -q "^Status: active$"
'"#
    );
    let prepared = config.ssh(&script, None, timeout)?;
    require_success(&prepared, "UFW fixture preparation", false)
}

fn cleanup_fixture(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let script = format!(
        r#"sudo sh -eu -c '
if test -d {FIXTURE_ROOT}; then
    original_state=inactive
    if test -f {FIXTURE_ROOT}/original-state; then
        original_state=$(cat {FIXTURE_ROOT}/original-state)
    fi
    ufw --force disable || true
    find /etc/ufw -mindepth 1 -delete
    cp -a {FIXTURE_ROOT}/etc-ufw/. /etc/ufw/
    if test "$original_state" = active; then
        ufw --force enable
    else
        ufw --force disable
    fi
    rm -rf {FIXTURE_ROOT}
fi
'"#
    );
    let cleaned = config.ssh(&script, None, timeout)?;
    require_success(&cleaned, "UFW fixture cleanup", false)
}

fn run_scenarios(config: &VmConfig, password: &str, timeout: Duration) -> Result<(), String> {
    let mut session = P2ApiSession::login(config, password, timeout)?;
    session.enter_administrative(config, password, timeout)?;

    let baseline = inventory(&session, config, timeout)?;
    require_active_inventory(&baseline)?;
    let baseline_digest = json_string_field(&baseline, "stateDigest")?;

    let allow_plan = plan_rule(
        &session,
        config,
        "allow",
        Some("tcp"),
        Some(18_080),
        Some(TEST_SOURCE),
        None,
        &baseline_digest,
        timeout,
    )?;
    let added = approve_rule(&session, config, &allow_plan, timeout)?;
    require_terminal(&added, "SUCCEEDED", "UFW allow rule").map_err(|error| {
        format!(
            "{error}; result_codes={}",
            receipt_result_codes(&added).join(",")
        )
    })?;
    if !added.contains("\"resultCode\":\"ufw_rule_verified\"") {
        return Err(String::from(
            "UFW allow receipt omitted verified rule evidence",
        ));
    }
    let after_add = inventory(&session, config, timeout)?;
    require_owned_rule(&after_add, &allow_plan.rule_id, 18_080, true)?;

    let delete_plan = plan_rule(
        &session,
        config,
        "delete",
        None,
        None,
        None,
        Some(&allow_plan.rule_id),
        &json_string_field(&after_add, "stateDigest")?,
        timeout,
    )?;
    let deleted = approve_rule(&session, config, &delete_plan, timeout)?;
    require_terminal(&deleted, "SUCCEEDED", "UFW delete rule")?;
    let after_delete = inventory(&session, config, timeout)?;
    require_owned_rule(&after_delete, &allow_plan.rule_id, 18_080, false)?;

    let protected = plan_response(
        &session,
        config,
        "deny",
        Some("tcp"),
        Some(22),
        None,
        None,
        &json_string_field(&after_delete, "stateDigest")?,
        timeout,
    )?;
    expect_http(&protected, 400, "UFW protected management port rejection")?;
    if !protected.body.contains("protected_management_rule") {
        return Err(String::from(
            "UFW protected management port rejection omitted its typed reason",
        ));
    }

    let stale_plan = plan_rule(
        &session,
        config,
        "allow",
        Some("tcp"),
        Some(18_081),
        Some(TEST_SOURCE),
        None,
        &json_string_field(&after_delete, "stateDigest")?,
        timeout,
    )?;
    let external = config.ssh(
        "sudo ufw allow from 203.0.113.0/24 to any port 18082 proto tcp comment jw-agent-vm-external",
        None,
        timeout,
    )?;
    require_success(&external, "external UFW fixture mutation", false)?;
    let stale = approve_rule(&session, config, &stale_plan, timeout)?;
    require_terminal(
        &stale,
        "CANCELLED_BEFORE_APPLY",
        "UFW external drift cancellation",
    )?;
    if !stale.contains("\"resultCode\":\"precondition_changed\"") {
        return Err(String::from(
            "UFW stale receipt omitted precondition_changed evidence",
        ));
    }
    let after_stale = inventory(&session, config, timeout)?;
    require_owned_rule(&after_stale, &stale_plan.rule_id, 18_081, false)?;

    let continuity = config.ssh(
        "systemctl is-active --quiet jw-edge.service\nsudo ufw status | grep -q '^Status: active$'",
        None,
        timeout,
    )?;
    require_success(&continuity, "UFW management continuity", false)
}

fn inventory(
    session: &P2ApiSession,
    config: &VmConfig,
    timeout: Duration,
) -> Result<String, String> {
    let response = session.get(config, UFW_API, timeout)?;
    expect_http(&response, 200, "UFW inventory")?;
    Ok(response.body)
}

fn require_active_inventory(body: &str) -> Result<(), String> {
    if body.contains("\"status\":\"active\"")
        && body.contains("\"mutationAvailable\":true")
        && body.contains("\"level\":\"g2_reversible_config\"")
    {
        Ok(())
    } else {
        Err(String::from(
            "UFW inventory was not active, mutable, and G2 bounded",
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn plan_rule(
    session: &P2ApiSession,
    config: &VmConfig,
    mutation: &str,
    protocol: Option<&str>,
    port: Option<u16>,
    source: Option<&str>,
    rule_id: Option<&str>,
    expected_state_digest: &str,
    timeout: Duration,
) -> Result<UfwPlan, String> {
    let idempotency_key = operation_idempotency_key()?;
    let response = plan_response_with_key(
        session,
        config,
        mutation,
        protocol,
        port,
        source,
        rule_id,
        expected_state_digest,
        &idempotency_key,
        timeout,
    )?;
    expect_http(&response, 200, "UFW typed rule plan")?;
    if !response
        .body
        .contains("\"operationType\":\"ufw.rule.set/v1\"")
        || !response.body.contains("\"level\":\"g2_reversible_config\"")
    {
        return Err(String::from(
            "UFW plan omitted operation type or G2 assurance",
        ));
    }
    Ok(UfwPlan {
        plan_id: json_string_field(&response.body, "planId")?,
        plan_hash: json_string_field(&response.body, "planHash")?,
        idempotency_key,
        rule_id: json_string_field(&response.body, "ruleId")?,
    })
}

#[allow(clippy::too_many_arguments)]
fn plan_response(
    session: &P2ApiSession,
    config: &VmConfig,
    mutation: &str,
    protocol: Option<&str>,
    port: Option<u16>,
    source: Option<&str>,
    rule_id: Option<&str>,
    expected_state_digest: &str,
    timeout: Duration,
) -> Result<super::HttpResponse, String> {
    let idempotency_key = operation_idempotency_key()?;
    plan_response_with_key(
        session,
        config,
        mutation,
        protocol,
        port,
        source,
        rule_id,
        expected_state_digest,
        &idempotency_key,
        timeout,
    )
}

#[allow(clippy::too_many_arguments)]
fn plan_response_with_key(
    session: &P2ApiSession,
    config: &VmConfig,
    mutation: &str,
    protocol: Option<&str>,
    port: Option<u16>,
    source: Option<&str>,
    rule_id: Option<&str>,
    expected_state_digest: &str,
    idempotency_key: &str,
    timeout: Duration,
) -> Result<super::HttpResponse, String> {
    let protocol = protocol.map_or(String::from("null"), json_string);
    let port = port.map_or(String::from("null"), |value| value.to_string());
    let source = source.map_or(String::from("null"), json_string);
    let rule_id = rule_id.map_or(String::from("null"), json_string);
    let body = format!(
        "{{\"schemaVersion\":1,\"operationType\":\"ufw.rule.set/v1\",\"mutation\":{},\"protocol\":{protocol},\"port\":{port},\"source\":{source},\"ruleId\":{rule_id},\"expectedStateDigest\":{},\"idempotencyKey\":{}}}",
        json_string(mutation),
        json_string(expected_state_digest),
        json_string(idempotency_key),
    );
    public_api_request(
        config,
        "POST",
        UFW_PLAN_API,
        &session.cookie_jar.path,
        Some(&session.csrf_token),
        Some(body.as_bytes()),
        timeout,
    )
}

fn approve_rule(
    session: &P2ApiSession,
    config: &VmConfig,
    plan: &UfwPlan,
    timeout: Duration,
) -> Result<String, String> {
    let body = format!(
        "{{\"schemaVersion\":1,\"planId\":{},\"planHash\":{},\"idempotencyKey\":{},\"impactConfirmed\":true}}",
        json_string(&plan.plan_id),
        json_string(&plan.plan_hash),
        json_string(&plan.idempotency_key),
    );
    let accepted = public_api_request(
        config,
        "POST",
        UFW_APPROVAL_API,
        &session.cookie_jar.path,
        Some(&session.csrf_token),
        Some(body.as_bytes()),
        timeout,
    )?;
    expect_http(&accepted, 202, "UFW rule approval")?;
    let operation_id = json_string_field(&accepted.body, "operationId")?;
    let path = format!("/api/v1/operations/{operation_id}");
    let started = Instant::now();
    loop {
        let response = session.get(config, &path, timeout)?;
        expect_http(&response, 200, "UFW rule receipt")?;
        let terminal = json_string_field(&response.body, "terminalState")?;
        if matches!(
            terminal.as_str(),
            "SUCCEEDED"
                | "ROLLED_BACK"
                | "RECOVERY_REQUIRED"
                | "REJECTED"
                | "EXPIRED"
                | "CANCELLED_BEFORE_APPLY"
        ) {
            return Ok(response.body);
        }
        if started.elapsed() >= timeout {
            return Err(String::from(
                "UFW rule operation did not reach a terminal receipt",
            ));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn require_owned_rule(
    body: &str,
    rule_id: &str,
    port: u16,
    expected_present: bool,
) -> Result<(), String> {
    let marker = format!("\"ruleId\":{}", json_string(rule_id));
    let present = body.contains(&marker)
        && body.contains(&format!("\"port\":{port}"))
        && body.contains("\"owned\":true");
    if present == expected_present {
        Ok(())
    } else if expected_present {
        Err(format!("UFW owned rule `{rule_id}` was not observed"))
    } else {
        Err(format!("UFW owned rule `{rule_id}` remained after removal"))
    }
}

fn receipt_result_codes(body: &str) -> Vec<String> {
    let marker = "\"resultCode\":\"";
    let mut remainder = body;
    let mut codes = Vec::new();
    while let Some(start) = remainder.find(marker) {
        let value = &remainder[start + marker.len()..];
        let Some(end) = value.find('"') else {
            break;
        };
        codes.push(value[..end].to_owned());
        remainder = &value[end + 1..];
    }
    codes
}
