#![forbid(unsafe_code)]

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use super::service_control::service_object;
use super::{
    P2ApiSession, TemporarySecretFile, VmConfig, expect_http, independent_edge_api_request,
    json_string, json_string_field, json_unsigned_field, operation_idempotency_key, read_secret,
    require_success, require_terminal, text,
};

pub(crate) fn gate_p2_independent_edge(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    let setup = config.ssh(
        r#"set -eu
sudo install -d -o root -g jw-agent -m 0750 /etc/jw-agent/edge
sudo install -o root -g jw-agent -m 0644 /etc/jw-agent/tls/server.crt /etc/jw-agent/edge/server.crt
sudo install -o root -g jw-agent -m 0640 /etc/jw-agent/tls/server.key /etc/jw-agent/edge/server.key
sudo systemctl daemon-reload
sudo systemctl enable jw-edge.service
sudo systemctl start nginx.service jw-agentd.service jw-opsd.service
sudo systemctl restart jw-edge.service
sudo systemctl is-active --quiet jw-edge.service
for attempt in $(seq 1 30); do
  sudo test -f /run/jw-agent-edge/ready && break
  sleep 0.1
done
sudo test -f /run/jw-agent-edge/ready
"#,
        None,
        timeout,
    )?;
    require_success(&setup, "independent edge fixture preparation", false)?;

    let result = run_scenarios(&config, &password, timeout);
    let cleanup = config.ssh(
        "sudo systemctl start nginx.service\nsudo systemctl restart jw-edge.service\nsudo nginx -t",
        None,
        timeout,
    );
    match (result, cleanup) {
        (Ok(()), Ok(output)) => require_success(&output, "independent edge cleanup", false),
        (Err(error), Ok(output)) => {
            match require_success(&output, "independent edge cleanup", false) {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!(
                    "{error}; independent edge cleanup also failed: {cleanup_error}"
                )),
            }
        }
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; independent edge cleanup also failed: {cleanup_error}"
        )),
    }
}

fn run_scenarios(config: &VmConfig, password: &str, timeout: Duration) -> Result<(), String> {
    verify_missing_edge_guard(config, password, timeout)?;
    let started = config.ssh(
        "sudo systemctl start jw-edge.service\nsudo systemctl is-active --quiet jw-edge.service\nfor attempt in $(seq 1 30); do sudo test -f /run/jw-agent-edge/ready && break; sleep 0.1; done\nsudo test -f /run/jw-agent-edge/ready",
        None,
        timeout,
    )?;
    require_success(&started, "independent edge start", false)?;
    wait_for_edge(config, timeout)?;

    let mut session = EdgeSession::login(config, password, timeout)?;
    session.enter_administrative(config, password, timeout)?;
    let services = session.get(config, "/api/v1/services", timeout)?;
    expect_http(&services, 200, "independent edge service inventory")?;
    let nginx = service_object(&services.body, "nginx.service")?;
    if !nginx.contains("\"allowedActions\":[") || !nginx.contains("\"stop\"") {
        return Err(String::from(
            "Nginx stop was not advertised after the independent edge became ready",
        ));
    }
    let receipt = session.stop_nginx(config, nginx, timeout)?;
    require_terminal(&receipt, "SUCCEEDED", "Nginx stop through independent edge")?;

    let stopped = config.ssh(
        r#"set -eu
test "$(systemctl is-active nginx.service)" = inactive
systemctl is-active --quiet jw-edge.service
sudo test -f /run/jw-agent-edge/ready
test "$(systemctl show -p User --value jw-edge.service)" = jw-agent
edge_pid=$(systemctl show -p MainPID --value jw-edge.service)
test "$edge_pid" -gt 1
test "$(awk '/^CapEff:/{print $2}' "/proc/$edge_pid/status")" = 0000000000000000
test "$(ss -H -ltn 'sport = :9443' | awk '{print $4}')" = 0.0.0.0:9443
test "$(ss -H -ltn 'sport = :8787' | awk '{print $4}')" = 127.0.0.1:8787
"#,
        None,
        timeout,
    )?;
    require_success(&stopped, "Nginx-independent edge runtime", false)?;

    let deep_link = config.independent_edge_curl(
        &["--fail", "--output", "-", "/services"],
        None,
        Duration::from_secs(15),
    )?;
    require_success(&deep_link, "Nginx-independent /services UI", false)?;
    if !text(&deep_link.stdout)?.contains("<!doctype html>") {
        return Err(String::from(
            "independent edge did not return the SPA services route",
        ));
    }
    let continuity = session.get(config, "/api/v1/services", timeout)?;
    expect_http(
        &continuity,
        200,
        "authenticated edge continuity after Nginx stop",
    )?;
    let legacy = config.public_curl(
        &["--fail", "--output", "-", "/api/v1/health"],
        None,
        Duration::from_secs(3),
    )?;
    if legacy.status.success() {
        return Err(String::from(
            "Nginx compatibility ingress unexpectedly remained reachable",
        ));
    }
    Ok(())
}

fn verify_missing_edge_guard(
    config: &VmConfig,
    password: &str,
    timeout: Duration,
) -> Result<(), String> {
    let stopped = config.ssh(
        "sudo systemctl stop jw-edge.service\nsudo test ! -e /run/jw-agent-edge/ready\nsudo test ! -e /run/jw-agent-edge/ready.sock\nsudo systemctl is-active --quiet nginx.service",
        None,
        timeout,
    )?;
    require_success(&stopped, "missing edge guard fixture", false)?;
    let mut session = P2ApiSession::login(config, password, timeout)?;
    session.enter_administrative(config, password, timeout)?;
    let services = session.get(config, "/api/v1/services", timeout)?;
    expect_http(&services, 200, "missing edge service inventory")?;
    let nginx = service_object(&services.body, "nginx.service")?;
    if nginx.contains("\"stop\"") {
        return Err(String::from(
            "Nginx stop was advertised without an independent management edge",
        ));
    }
    let plan = plan_body(nginx, "stop")?;
    let rejected = super::public_api_request(
        config,
        "POST",
        "/api/v1/operations/service/lifecycle/plans",
        &session.cookie_jar.path,
        Some(&session.csrf_token),
        Some(plan.as_bytes()),
        timeout,
    )?;
    expect_http(&rejected, 409, "missing edge Nginx stop rejection")?;
    if !rejected
        .body
        .contains("\"code\":\"management_ingress_dependency\"")
    {
        return Err(String::from(
            "missing edge Nginx stop did not return the dependency guard",
        ));
    }
    Ok(())
}

struct EdgeSession {
    cookie_jar: TemporarySecretFile,
    csrf_token: String,
}

impl EdgeSession {
    fn login(config: &VmConfig, password: &str, timeout: Duration) -> Result<Self, String> {
        let cookie_jar = TemporarySecretFile::create("jw-agent-edge-cookie")?;
        let body = format!(
            "{{\"username\":{},\"password\":{}}}",
            json_string(&config.admin_user),
            json_string(password),
        );
        let response = independent_edge_api_request(
            config,
            "POST",
            "/api/v1/auth/login",
            &cookie_jar.path,
            None,
            Some(body.as_bytes()),
            timeout,
        )?;
        expect_http(&response, 200, "independent edge login")?;
        Ok(Self {
            cookie_jar,
            csrf_token: json_string_field(&response.body, "csrfToken")?,
        })
    }

    fn enter_administrative(
        &mut self,
        config: &VmConfig,
        password: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let body = format!(
            "{{\"password\":{},\"additionalAuthCode\":null}}",
            json_string(password),
        );
        let response = independent_edge_api_request(
            config,
            "POST",
            "/api/v1/auth/administrative-access",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(body.as_bytes()),
            timeout,
        )?;
        expect_http(&response, 200, "independent edge administrative access")?;
        self.csrf_token = json_string_field(&response.body, "csrfToken")?;
        Ok(())
    }

    fn get(
        &self,
        config: &VmConfig,
        path: &str,
        timeout: Duration,
    ) -> Result<super::HttpResponse, String> {
        independent_edge_api_request(
            config,
            "GET",
            path,
            &self.cookie_jar.path,
            None,
            None,
            timeout,
        )
    }

    fn stop_nginx(
        &self,
        config: &VmConfig,
        nginx: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let body = plan_body(nginx, "stop")?;
        let plan = independent_edge_api_request(
            config,
            "POST",
            "/api/v1/operations/service/lifecycle/plans",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(body.as_bytes()),
            timeout,
        )?;
        if plan.status != 200 {
            let code = match json_string_field(&plan.body, "code") {
                Ok(value) => value,
                Err(_) => String::from("unknown"),
            };
            return Err(format!(
                "independent edge Nginx stop plan returned HTTP {} code={code}",
                plan.status
            ));
        }
        let schema_version = json_unsigned_field(&plan.body, "schemaVersion")?;
        let plan_id = json_string_field(&plan.body, "planId")?;
        let plan_hash = json_string_field(&plan.body, "planHash")?;
        let idempotency_key = json_string_field(&body, "idempotencyKey")?;
        let approval = format!(
            "{{\"schemaVersion\":{schema_version},\"planId\":{},\"planHash\":{},\"idempotencyKey\":{},\"impactConfirmed\":true}}",
            json_string(&plan_id),
            json_string(&plan_hash),
            json_string(&idempotency_key),
        );
        let accepted = independent_edge_api_request(
            config,
            "POST",
            "/api/v1/operations/service/lifecycle/approvals",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(approval.as_bytes()),
            timeout,
        )?;
        expect_http(&accepted, 202, "independent edge Nginx stop approval")?;
        let operation_id = json_string_field(&accepted.body, "operationId")?;
        let path = format!("/api/v1/operations/{operation_id}");
        let started = Instant::now();
        loop {
            let current = self.get(config, &path, timeout)?;
            expect_http(&current, 200, "independent edge Nginx stop receipt")?;
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
                return Err(String::from("Nginx stop did not reach a terminal receipt"));
            }
            thread::sleep(Duration::from_millis(250));
        }
    }
}

fn plan_body(service: &str, action: &str) -> Result<String, String> {
    let schema_version = json_unsigned_field(service, "operationSchemaVersion")?;
    let operation_type = json_string_field(service, "operationType")?;
    let service_id = json_string_field(service, "serviceId")?;
    let state_digest = json_string_field(service, "stateDigest")?;
    let idempotency_key = operation_idempotency_key()?;
    Ok(format!(
        "{{\"schemaVersion\":{schema_version},\"operationType\":{},\"serviceId\":{},\"action\":{},\"expectedStateDigest\":{},\"idempotencyKey\":{}}}",
        json_string(&operation_type),
        json_string(&service_id),
        json_string(action),
        json_string(&state_digest),
        json_string(&idempotency_key),
    ))
}

fn wait_for_edge(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    loop {
        let health = config.independent_edge_curl(
            &["--fail", "--output", "-", "/api/v1/health"],
            None,
            Duration::from_secs(3),
        );
        if let Ok(result) = health
            && result.status.success()
            && text(&result.stdout)?.contains("\"status\":\"ok\"")
        {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(String::from(
                "independent edge did not become ready before timeout",
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}
