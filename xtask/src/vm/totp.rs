#![forbid(unsafe_code)]

use std::time::Duration;

use crate::process::safe_output;

use super::{VmConfig, read_secret, require_success, text};

const TOTP_VM_PROBE: &str = r#"
import base64
import hashlib
import hmac
import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8787"
ORIGIN = "http://127.0.0.1:8787"
cfg = json.load(sys.stdin)
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
csrf = None

def fail(label):
    raise RuntimeError(label)

def call(method, path, body=None, expected=200):
    global csrf
    encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {"Origin": ORIGIN, "Accept": "application/json"}
    if encoded is not None:
        headers["Content-Type"] = "application/json"
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    request = urllib.request.Request(BASE + path, data=encoded, headers=headers, method=method)
    try:
        with opener.open(request, timeout=12) as response:
            status = response.status
            payload = response.read(1048576)
    except urllib.error.HTTPError as error:
        status = error.code
        payload = error.read(1048576)
    except Exception as error:
        fail("http_transport_" + path.replace("/", "_") + "_" + type(error).__name__)
    if status != expected:
        fail("http_status_" + str(status) + "_for_" + path)
    if not payload:
        return None
    try:
        return json.loads(payload)
    except Exception:
        fail("invalid_json_for_" + path)

def login():
    global csrf
    session = call("POST", "/api/v1/auth/login", {
        "username": cfg["username"],
        "password": cfg["password"],
    })
    if session.get("ingress") != "recovery" or session.get("subject", {}).get("role") != "admin":
        fail("recovery_admin_required")
    csrf = session.get("csrfToken")
    if not csrf:
        fail("csrf_missing")

def reauth(purpose):
    global csrf
    result = call("POST", "/api/v1/auth/reauth", {
        "password": cfg["password"],
        "purpose": purpose,
    })
    csrf = result.get("session", {}).get("csrfToken")
    token = result.get("reauthToken")
    if not csrf or not token:
        fail("reauth_claim_missing")
    return token

def enter_administrative():
    global csrf
    session = call("POST", "/api/v1/auth/administrative-access", {
        "password": cfg["password"],
        "additionalAuthCode": None,
    })
    if session.get("administrativeAccess") != "administrative":
        fail("administrative_access_missing")
    csrf = session.get("csrfToken")
    if not csrf:
        fail("administrative_csrf_missing")

def totp(secret, step):
    try:
        key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    except Exception:
        fail("invalid_enrollment_secret")
    counter = int(step).to_bytes(8, "big")
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
    return str(value % 1000000).zfill(6)

def wait_for_safe_window():
    deadline = time.monotonic() + 24
    while int(time.time()) % 30 > 12:
        if time.monotonic() >= deadline:
            fail("totp_window_timeout")
        time.sleep(0.2)
    return int(time.time()) // 30

def mutable_site():
    inventory = call("GET", "/api/v1/services/nginx/sites")
    for site in inventory.get("sites", []):
        required = (
            site.get("siteId"),
            site.get("availableDigest"),
            site.get("enabledStateDigest"),
            site.get("operationType"),
            site.get("operationSchemaVersion"),
        )
        if not site.get("protected") and all(value is not None for value in required):
            return site
    fail("mutable_nginx_fixture_missing")

def operation_plan(site):
    nonce = hashlib.sha256(str(time.time_ns()).encode("ascii")).hexdigest()[:24]
    idempotency = "vm-totp-" + nonce
    plan = call("POST", "/api/v1/operations/nginx/site-state/plans", {
        "schemaVersion": site["operationSchemaVersion"],
        "operationType": site["operationType"],
        "siteId": site["siteId"],
        "targetState": "enabled" if site["enabled"] else "disabled",
        "expectedAvailableDigest": site["availableDigest"],
        "expectedEnabledStateDigest": site["enabledStateDigest"],
        "idempotencyKey": idempotency,
    })
    return plan, idempotency

def wait_for_success(operation_id):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        receipt = call("GET", "/api/v1/operations/" + operation_id)
        terminal = receipt.get("terminalState")
        if terminal == "SUCCEEDED":
            return
        if terminal in ("ROLLED_BACK", "RECOVERY_REQUIRED", "REJECTED", "EXPIRED", "CANCELLED_BEFORE_APPLY"):
            fail("operation_terminal_" + str(terminal))
        time.sleep(0.15)
    fail("operation_timeout")

def main():
    login()
    enter_administrative()
    enrollment_claim = reauth({"kind": "totp_enrollment"})
    enrollment = call("POST", "/api/v1/settings/access/totp/enrollment", {
        "reauthToken": enrollment_claim,
    }, 201)
    recovery_codes = enrollment.get("recoveryCodes", [])
    if len(recovery_codes) != 10:
        fail("recovery_code_count")
    step = wait_for_safe_window()
    first = call("POST", "/api/v1/settings/access/totp/enrollment/confirm", {
        "enrollmentId": enrollment["enrollmentId"],
        "code": totp(enrollment["manualKey"], step - 1),
    })
    if first.get("state") != "awaiting_next_code":
        fail("first_enrollment_state")
    second = call("POST", "/api/v1/settings/access/totp/enrollment/confirm", {
        "enrollmentId": enrollment["enrollmentId"],
        "code": totp(enrollment["manualKey"], step),
    })
    if second.get("state") != "ready":
        fail("second_enrollment_state")

    policy_claim = reauth({"kind": "security_policy_change", "targetPolicy": "risky_operations"})
    settings = call("PUT", "/api/v1/settings/access/additional-auth", {
        "policy": "risky_operations",
        "reauthToken": policy_claim,
    })
    if settings.get("additionalAuthProvider") != "ready" or settings.get("additionalAuthPolicy") != "risky_operations":
        fail("policy_not_active")

    site = mutable_site()
    plan, idempotency = operation_plan(site)
    operation_claim = reauth({"kind": "operation", "planHash": plan["planHash"]})
    verified = call("POST", "/api/v1/auth/totp/verify", {
        "reauthToken": operation_claim,
        "planHash": plan["planHash"],
        "code": totp(enrollment["manualKey"], step + 1),
    })
    approval = {
        "schemaVersion": plan["schemaVersion"],
        "planId": plan["planId"],
        "planHash": plan["planHash"],
        "idempotencyKey": idempotency,
        "reauthToken": operation_claim,
        "additionalAuthClaim": verified["additionalAuthClaim"],
    }
    accepted = call("POST", "/api/v1/operations/nginx/site-state/approvals", approval, 202)
    call("POST", "/api/v1/operations/nginx/site-state/approvals", approval, 403)
    wait_for_success(accepted["operationId"])

    reset_claim = reauth({"kind": "totp_recovery_reset"})
    call("POST", "/api/v1/settings/access/totp/reset", {
        "reauthToken": reset_claim,
        "recoveryCode": recovery_codes[0],
    }, 204)
    login()
    settings = call("GET", "/api/v1/settings/access")
    if settings.get("additionalAuthProvider") != "not_configured" or settings.get("additionalAuthPolicy") != "disabled":
        fail("reset_state_mismatch")
    print("TOTP_VM_PASS")

try:
    main()
except Exception as error:
    message = str(error)
    if not message or len(message) > 160 or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_/-" for character in message):
        message = "unexpected_probe_failure"
    sys.stderr.write("totp probe: " + message + "\n")
    sys.exit(1)
"#;

const RESET_FIXTURE: &str = r#"set -eu
sudo systemctl stop jw-agentd.service
sudo python3 -c "import sqlite3; connection=sqlite3.connect('/var/lib/jw-agent/agentd/agentd.sqlite3'); connection.executescript(\"PRAGMA foreign_keys=ON; UPDATE settings SET value='disabled' WHERE key='additional_auth_policy'; DELETE FROM additional_auth_claims; DELETE FROM totp_enrollments; DELETE FROM reauth_claims; DELETE FROM administrative_access; DELETE FROM sessions;\"); connection.commit(); connection.close()"
sudo systemctl reset-failed jw-agentd.service
sudo systemctl start jw-agentd.service
for attempt in $(seq 1 40); do
  if curl --silent --fail --max-time 2 --header 'Host: 127.0.0.1:8787' http://127.0.0.1:8787/api/v1/health >/dev/null; then
    sleep 1
    exit 0
  fi
  sleep 0.25
done
exit 1"#;

const STORAGE_PROOF: &str = r#"sudo test "$(stat -c '%a:%U:%G:%s' /var/lib/jw-agent/agentd/agentd.totp.key)" = '600:jw-agent:jw-agent:32'
result=$(sudo python3 -c "import sqlite3; connection=sqlite3.connect('/var/lib/jw-agent/agentd/agentd.sqlite3'); checks=(connection.execute('SELECT count(*) FROM totp_enrollments').fetchone()[0] == 0, connection.execute('SELECT count(*) FROM totp_recovery_codes').fetchone()[0] == 0, connection.execute('SELECT count(*) FROM totp_used_steps').fetchone()[0] == 0, connection.execute('SELECT count(*) FROM additional_auth_claims').fetchone()[0] == 0, connection.execute('SELECT count(*) FROM totp_audit_events').fetchone()[0] >= 5, connection.execute(\"SELECT value FROM settings WHERE key='additional_auth_policy'\").fetchone()[0] == 'disabled'); connection.close(); print('TOTP_STORAGE_PASS' if all(checks) else 'TOTP_STORAGE_FAIL')")
test "$result" = 'TOTP_STORAGE_PASS'
printf '%s\n' "$result""#;

pub(crate) fn gate_p2_totp_step_up(_: &std::path::Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    reset_fixture(&config, timeout)?;
    let result = run_probe(&config, timeout);
    if let Err(error) = result {
        let cleanup = reset_fixture(&config, timeout);
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(format!(
                "{error}; TOTP fixture cleanup failed: {cleanup_error}"
            )),
        };
    }
    let storage = config.ssh(STORAGE_PROOF, None, timeout)?;
    require_success(&storage, "TOTP encrypted-storage proof", false)?;
    if text(&storage.stdout)?.trim() != "TOTP_STORAGE_PASS" {
        return Err(String::from(
            "TOTP encrypted-storage proof returned unexpected evidence",
        ));
    }
    Ok(())
}

fn run_probe(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let password = read_secret(&config.password_file)?;
    let input = format!(
        "{{\"username\":{},\"password\":{}}}",
        super::json_string(&config.admin_user),
        super::json_string(&password),
    );
    let command = format!("python3 -c {}", shell_single_quote(TOTP_VM_PROBE));
    let result = config.ssh(&command, Some(input.as_bytes()), timeout)?;
    require_success(&result, "bounded TOTP VM probe", false)?;
    if text(&result.stdout)?.trim() != "TOTP_VM_PASS" {
        return Err(String::from(
            "bounded TOTP VM probe returned unexpected evidence",
        ));
    }
    Ok(())
}

fn shell_single_quote(value: &str) -> String {
    let mut quoted = String::from("'");
    for character in value.chars() {
        if character == '\'' {
            quoted.push_str("'\"'\"'");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

fn reset_fixture(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let result = config.ssh(RESET_FIXTURE, None, timeout)?;
    if result.status.success() && !result.stdout_truncated && !result.stderr_truncated {
        Ok(())
    } else {
        Err(format!(
            "TOTP fixture reset failed with {}; stdout={}; stderr={}",
            result.status,
            safe_output(&result.stdout, result.stdout_truncated),
            safe_output(&result.stderr, result.stderr_truncated),
        ))
    }
}
