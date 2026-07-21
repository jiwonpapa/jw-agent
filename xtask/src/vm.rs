#![forbid(unsafe_code)]

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT_LIMIT_BYTES: usize = 128 * 1_024;
const RECOVERY_HOST: &str = "127.0.0.1:8787";
const RECOVERY_ORIGIN: &str = "http://127.0.0.1:8787";

pub fn gate_preflight(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let script = r#"set -eu
test -f /var/tmp/jw-agent-vm-ready
. /etc/os-release
test "$ID" = ubuntu
test "$VERSION_ID" = 24.04
test "$(systemd-detect-virt)" = kvm
test "$(hostname)" = jw-agent-p1
for account in jwvmadmin jwvmoperator jwvmviewer jwvmdenied jwvmmulti jwvmlocked jwvmexpired; do
    getent passwd "$account" >/dev/null
done
id -nG jwvmadmin | tr ' ' '\n' | grep -Fxq jw-agent-admin
id -nG jwvmoperator | tr ' ' '\n' | grep -Fxq jw-agent-operator
id -nG jwvmviewer | tr ' ' '\n' | grep -Fxq jw-agent-viewer
id -nG jwvmmulti | tr ' ' '\n' | grep -Fxq jw-agent-admin
id -nG jwvmmulti | tr ' ' '\n' | grep -Fxq jw-agent-viewer
sudo passwd -S jwvmlocked | grep -Eq '^jwvmlocked[[:space:]]+L'
"#;
    let result = config.ssh(script, None, timeout)?;
    require_success(&result, "VM preflight", false)
}

pub fn gate_package_runtime(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let version = config.ssh(
        "dpkg-query -W -f='${Version}' jw-agent",
        None,
        Duration::from_secs(15),
    )?;
    require_success(&version, "installed package version", false)?;
    if text(&version.stdout)?.trim() != config.expected_version {
        return Err(String::from(
            "installed jw-agent version differs from JW_VM_EXPECTED_VERSION",
        ));
    }

    let package_path = shell_safe_path(&config.remote_package)?;
    let checksum = config.ssh(
        &format!("sha256sum -- {package_path}"),
        None,
        Duration::from_secs(20),
    )?;
    require_success(&checksum, "remote package checksum", false)?;
    let checksum_output = text(&checksum.stdout)?;
    let Some(actual_checksum) = checksum_output.split_whitespace().next() else {
        return Err(String::from("remote package checksum was empty"));
    };
    if actual_checksum != config.expected_package_sha256 {
        return Err(String::from(
            "remote package checksum differs from expected artifact",
        ));
    }

    let native_script = format!(
        r#"set -eu
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM
dpkg-deb -x -- {package_path} "$tmpdir"
cmp -s "$tmpdir/etc/pam.d/jw-agent" /etc/pam.d/jw-agent
! grep -Eq '^[[:space:]]*(auth|account)[[:space:]].*pam_faillock' /etc/pam.d/jw-agent
dpkg-query -W -f='${{db:Status-Abbrev}}' libpam0g | grep -q '^ii'
dpkg-query -W -f='${{db:Status-Abbrev}}' libsqlite3-0 | grep -q '^ii'
dpkg-query -W -f='${{db:Status-Abbrev}}' certbot | grep -q '^ii'
ldd /usr/lib/jw-agent/jw-authd | grep -q 'libpam\.so\.0'
ldd /usr/lib/jw-agent/jw-agentd | grep -q 'libsqlite3\.so\.0'
test -x /usr/lib/jw-agent/jw-certd
grep -Fq 'client_max_body_size 64k;' "$tmpdir/usr/share/jw-agent/nginx/jw-agent-management.conf.template"
"#
    );
    let native = config.ssh(&native_script, None, Duration::from_secs(20))?;
    require_success(&native, "native link and PAM package fixture", false)?;

    let script = r#"set -eu
for unit in jw-agentd.service jw-opsd.service jw-authd.socket jw-certd.socket; do
    test "$(systemctl is-enabled "$unit")" = enabled
    test "$(systemctl is-active "$unit")" = active
done
test "$(systemctl show -p User --value jw-agentd.service)" = jw-agent
test "$(systemctl show -p User --value jw-opsd.service)" = root
test "$(systemctl show -p Group --value jw-opsd.service)" = root
test "$(systemctl show -p NoNewPrivileges --value jw-agentd.service)" = yes
test "$(systemctl show -p NoNewPrivileges --value jw-opsd.service)" = yes
test "$(systemctl show -p ProtectSystem --value jw-agentd.service)" = strict
test "$(systemctl show -p ProtectSystem --value jw-opsd.service)" = strict
test "$(systemctl show -p MemoryDenyWriteExecute --value jw-agentd.service)" = yes
test "$(systemctl show -p MemoryDenyWriteExecute --value jw-opsd.service)" = yes
systemctl cat jw-opsd.service | grep -Fq 'IPAddressDeny=any'
systemctl cat jw-certd@.service | grep -Fq 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
! systemctl cat jw-certd@.service | grep -Fq 'IPAddressDeny=any'
sudo test -S /run/jw-agent/authd.sock
sudo test -S /run/jw-agent-certd/certd.sock
sudo test -S /run/jw-agent/opsd.sock
sudo test -S /run/jw-agent-proxy/agentd.sock
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent/authd.sock)" = jw-agent:jw-agent:600
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent-certd/certd.sock)" = root:root:600
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent/opsd.sock)" = root:jw-agent:660
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent)" = root:jw-agent:2750
test "$(sudo stat -c '%U:%G:%a' /var/lib/jw-agent/opsd)" = root:root:700
test "$(sudo stat -c '%U:%G:%a' /var/lib/jw-agent/opsd/snapshots)" = root:root:700
test "$(sudo stat -c '%U:%G:%a' /var/lib/jw-agent/opsd/opsd.sqlite3)" = root:jw-agent:600
test "$(stat -c '%U:%G:%a' /run/jw-agent-proxy)" = jw-agent:jw-agent-proxy:2750
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent-proxy/agentd.sock)" = jw-agent:jw-agent-proxy:660
id -nG jw-agent | tr ' ' '\n' | grep -Fxq jw-agent-proxy
id -nG www-data | tr ' ' '\n' | grep -Fxq jw-agent-proxy
agent_pid=$(systemctl show -p MainPID --value jw-agentd.service)
ops_pid=$(systemctl show -p MainPID --value jw-opsd.service)
test "$agent_pid" -gt 1
test "$ops_pid" -gt 1
test "$(awk '/^CapEff:/{print $2}' "/proc/$agent_pid/status")" = 0000000000000000
test "$(awk '/^CapEff:/{print $2}' "/proc/$ops_pid/status")" = 0000000000000400
test "$(systemctl show -p PrivateNetwork --value jw-opsd.service)" = yes
test -z "$(sudo nsenter --target "$ops_pid" --net ss -H -ltnup)"
test "$(ss -H -ltn 'sport = :8787' | awk '{print $4}')" = 127.0.0.1:8787
test "$(find /proc -maxdepth 2 -name comm -readable -exec grep -l '^jw-authd$' {} + 2>/dev/null | wc -l)" -eq 0
test "$(find /proc -maxdepth 2 -name comm -readable -exec grep -l '^jw-certd$' {} + 2>/dev/null | wc -l)" -eq 0
"#;
    let result = config.ssh(script, None, timeout)?;
    require_success(&result, "package runtime boundary", false)
}

pub fn gate_pam_matrix(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;

    let reset = config.ssh("sudo systemctl restart jw-agentd", None, timeout)?;
    require_success(&reset, "authentication limiter reset", false)?;
    let account_before = config.ssh(
        &format!("sudo passwd -S -- {}", config.admin_user),
        None,
        timeout,
    )?;
    require_success(&account_before, "PAM account state before limiter", false)?;
    for _attempt in 0..6 {
        let response = recovery_login(
            &config,
            &config.admin_user,
            "jw-agent-intentionally-wrong",
            timeout,
        )?;
        expect_http(&response, 401, "bounded PAM failure")?;
    }
    let limited = recovery_login(
        &config,
        &config.admin_user,
        "jw-agent-intentionally-wrong",
        timeout,
    )?;
    expect_http(&limited, 429, "PAM subject budget")?;
    let account_after = config.ssh(
        &format!("sudo passwd -S -- {}", config.admin_user),
        None,
        timeout,
    )?;
    require_success(&account_after, "PAM account state after limiter", false)?;
    if account_before.stdout != account_after.stdout {
        return Err(String::from(
            "agentd authentication budget changed the Linux password state",
        ));
    }
    let ssh_after_limit = config.ssh("true", None, timeout)?;
    require_success(&ssh_after_limit, "OpenSSH after PAM limiter", false)?;
    let reset = config.ssh("sudo systemctl restart jw-agentd", None, timeout)?;
    require_success(&reset, "authentication limiter cleanup", false)?;

    let admin = recovery_login(&config, &config.admin_user, &password, timeout)?;
    expect_http(&admin, 200, "admin PAM login")?;
    if !admin
        .body
        .contains(&format!("\"username\":\"{}\"", config.admin_user))
        || !admin.body.contains("\"role\":\"admin\"")
        || !admin.body.contains("\"ingress\":\"recovery\"")
    {
        return Err(String::from(
            "admin PAM login returned the wrong subject or ingress",
        ));
    }

    for (username, expected_role) in [("jwvmoperator", "operator"), ("jwvmviewer", "viewer")] {
        let response = recovery_login(&config, username, &password, timeout)?;
        expect_http(&response, 200, "role PAM login")?;
        if !response
            .body
            .contains(&format!("\"username\":\"{username}\""))
            || !response
                .body
                .contains(&format!("\"role\":\"{expected_role}\""))
        {
            return Err(format!("PAM role mismatch for {username}"));
        }
    }

    let denied = [
        (config.admin_user.as_str(), "jw-agent-intentionally-wrong"),
        ("jwvmunknown", password.as_str()),
        ("jwvmlocked", password.as_str()),
        ("jwvmexpired", password.as_str()),
        ("jwvmdenied", password.as_str()),
        ("jwvmmulti", password.as_str()),
        ("root", password.as_str()),
    ];
    let mut generic_body: Option<String> = None;
    for (username, candidate) in denied {
        let response = recovery_login(&config, username, candidate, timeout)?;
        expect_http(&response, 401, "denied PAM login")?;
        if !response.body.contains("\"code\":\"invalid_credentials\"") {
            return Err(format!(
                "denied PAM login leaked a distinct result for {username}"
            ));
        }
        if let Some(expected) = &generic_body {
            if expected != &response.body {
                return Err(String::from("denied PAM responses are distinguishable"));
            }
        } else {
            generic_body = Some(response.body);
        }
    }
    Ok(())
}

pub fn gate_public_recovery(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let edge_profile = config.ssh(
        "sudo nginx -T 2>/dev/null | grep -Fq 'client_max_body_size 64k;'",
        None,
        timeout,
    )?;
    require_success(
        &edge_profile,
        "public edge managed-config body envelope",
        false,
    )?;
    let public_health = config.public_curl(
        &["--fail", "--output", "-", "/api/v1/health"],
        None,
        Duration::from_secs(15),
    )?;
    require_success(&public_health, "public TLS health", false)?;
    let health = text(&public_health.stdout)?;
    if !health.contains("\"status\":\"ok\"") || !health.contains("\"ingress\":\"public\"") {
        return Err(String::from(
            "public health did not report a healthy public ingress",
        ));
    }

    let deep_link = config.public_curl(
        &[
            "--dump-header",
            "-",
            "--output",
            "/dev/null",
            "/integrations",
        ],
        None,
        Duration::from_secs(15),
    )?;
    require_success(&deep_link, "public SPA deep link", false)?;
    let headers = text(&deep_link.stdout)?.to_ascii_lowercase();
    for required in [
        " 200",
        "strict-transport-security: max-age=31536000",
        "cache-control: no-store",
        "content-security-policy:",
        "x-content-type-options: nosniff",
    ] {
        if !headers.contains(required) {
            return Err(format!("public deep link is missing `{required}`"));
        }
    }

    let favicon = config.public_curl(
        &["--fail", "--output", "/dev/null", "/favicon.svg"],
        None,
        Duration::from_secs(15),
    )?;
    require_success(&favicon, "public favicon", false)?;

    let redirect = config.plain_http_curl(
        &["--dump-header", "-", "--output", "/dev/null", "/login"],
        Duration::from_secs(15),
    )?;
    require_success(&redirect, "HTTP redirect", false)?;
    let redirect_headers = text(&redirect.stdout)?.to_ascii_lowercase();
    if !redirect_headers.contains("http/1.1 308")
        || !redirect_headers.contains(&format!("location: https://{}/login", config.public_host))
    {
        return Err(String::from(
            "public HTTP did not redirect exactly to HTTPS",
        ));
    }

    let invalid_origin = config.public_curl(
        &[
            "--output",
            "-",
            "--write-out",
            "\n%{http_code}",
            "--header",
            "Content-Type: application/json",
            "--header",
            "Origin: https://attacker.invalid",
            "--data-binary",
            "@-",
            "/api/v1/auth/login",
        ],
        Some(b"{}"),
        Duration::from_secs(15),
    )?;
    require_success(&invalid_origin, "invalid Origin request", false)?;
    let rejected = parse_http_response(&invalid_origin.stdout)?;
    expect_http(&rejected, 403, "invalid Origin request")?;
    if !rejected.body.contains("\"code\":\"origin_rejected\"") {
        return Err(String::from(
            "invalid Origin did not return origin_rejected",
        ));
    }

    let recovery = config.ssh(
        &format!(
            "curl --silent --show-error --fail --max-time 10 --header 'Host: {RECOVERY_HOST}' http://127.0.0.1:8787/api/v1/health"
        ),
        None,
        timeout,
    )?;
    require_success(&recovery, "loopback recovery health", false)?;
    if !text(&recovery.stdout)?.contains("\"ingress\":\"recovery\"") {
        return Err(String::from("recovery health reported the wrong ingress"));
    }

    let exposed_recovery = run_capture(
        OsStr::new("curl"),
        &[
            OsString::from("--silent"),
            OsString::from("--show-error"),
            OsString::from("--connect-timeout"),
            OsString::from("2"),
            OsString::from("--max-time"),
            OsString::from("3"),
            OsString::from(format!(
                "http://{}:8787/api/v1/health",
                config.public_address
            )),
        ],
        None,
        Duration::from_secs(5),
    )?;
    if exposed_recovery.status.success() {
        return Err(String::from(
            "recovery listener is reachable on the VM LAN address",
        ));
    }

    let invalid_tls = run_capture(
        OsStr::new("curl"),
        &config.public_curl_arguments(
            &["--fail", "--output", "/dev/null", "/api/v1/health"],
            false,
        ),
        None,
        Duration::from_secs(15),
    )?;
    if invalid_tls.status.success() {
        return Err(String::from(
            "test-only TLS certificate was unexpectedly system-trusted",
        ));
    }
    Ok(())
}

pub fn gate_secret_scan(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    let mut secret_input = password.into_bytes();
    secret_input.push(b'\n');
    let script = r#"sudo sh -eu -c '
pattern=$(mktemp /dev/shm/jw-agent-secret.XXXXXX)
trap "rm -f $pattern" EXIT HUP INT TERM
chmod 600 "$pattern"
IFS= read -r secret
printf "%s" "$secret" > "$pattern"
found=0
journalctl -u jw-agentd.service --no-pager -o cat | grep -F -q -f "$pattern" && found=1 || true
journalctl -u jw-opsd.service --no-pager -o cat | grep -F -q -f "$pattern" && found=1 || true
find /var/lib/jw-agent -type f -print0 | xargs -0 -r strings | grep -F -q -f "$pattern" && found=1 || true
ps -eo args= | grep -F -q -f "$pattern" && found=1 || true
grep -F -q -f "$pattern" /var/log/dpkg.log /var/log/apt/term.log 2>/dev/null && found=1 || true
test "$found" -eq 0
'"#;
    let result = config.ssh(script, Some(&secret_input), timeout)?;
    require_success(&result, "fixture secret scan", true)
}

const P2_VALID_SITE: &str = "jw-agent-vm-operation.conf";
const P2_INVALID_SITE: &str = "jw-agent-vm-invalid.conf";
const P2_MANAGED_SITE: &str = "jw-agent-vm-managed.conf";
const P2_INTERNAL_TEMP: &str = ".jw-agent-0123456789abcdef.tmp";
const P2_MANAGED_BASELINE: &[u8] =
    b"server { listen 127.0.0.1:18082; server_name jw-agent-vm-managed.invalid; return 204; }\n";
const P2_MANAGED_RELOAD_CHANGE: &str = "server { listen 127.0.0.1:18082; server_name jw-agent-vm-managed.invalid; add_header X-JW-Agent-VM config-v2 always; return 204; }\n";
const P2_MANAGED_EXTERNAL: &[u8] = b"server { listen 127.0.0.1:18082; server_name jw-agent-vm-managed.invalid; add_header X-JW-Agent-VM external-owner always; return 204; }\n";

fn managed_config_large_saved() -> String {
    format!(
        "{}server {{ listen 127.0.0.1:18082; server_name jw-agent-vm-managed.invalid; add_header X-JW-Agent-VM config-v1 always; return 204; }}\n",
        "# jw-agent-vm-padding\n".repeat(850)
    )
}

pub fn gate_p2_nginx_operation(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    restart_edge_and_agentd_and_wait(&config, timeout)?;
    cleanup_p2_fixtures(&config, timeout)?;
    let result = (|| {
        install_nginx_fixture(
        &config,
        P2_VALID_SITE,
        b"server { listen 127.0.0.1:18081; server_name jw-agent-vm-operation.invalid; return 204; }\n",
        timeout,
        )?;
        install_nginx_fixture(
            &config,
            P2_INVALID_SITE,
            b"server { this_is_not_valid_nginx_syntax; }\n",
            timeout,
        )?;
        let syntax = config.ssh("sudo nginx -t", None, timeout)?;
        require_success(&syntax, "baseline Nginx syntax", false)?;

        let mut session = P2ApiSession::login(&config, &password, timeout)?;
        session.require_management_site_protected(&config, timeout)?;
        let enabled = session.operate(&config, &password, P2_VALID_SITE, "enabled", timeout)?;
        require_terminal(&enabled, "SUCCEEDED", "valid site enable")?;
        let runtime = config.ssh(
        "sudo test -L /etc/nginx/sites-enabled/jw-agent-vm-operation.conf && sudo systemctl is-active --quiet nginx.service",
        None,
        timeout,
        )?;
        require_success(&runtime, "enabled Nginx fixture", false)?;

        let noop = session.operate(&config, &password, P2_VALID_SITE, "enabled", timeout)?;
        require_terminal(&noop, "SUCCEEDED", "already-target no-op")?;
        if !noop.contains("\"resultCode\":\"verified_noop\"") {
            return Err(String::from("no-op receipt omitted verified_noop evidence"));
        }

        let disabled = session.operate(&config, &password, P2_VALID_SITE, "disabled", timeout)?;
        require_terminal(&disabled, "SUCCEEDED", "valid site disable")?;
        require_link_absent(&config, P2_VALID_SITE, timeout)?;
        restart_edge_and_agentd_and_wait(&config, timeout)?;

        let syntax_rollback =
            session.operate(&config, &password, P2_INVALID_SITE, "enabled", timeout)?;
        require_terminal(&syntax_rollback, "ROLLED_BACK", "syntax failure rollback")?;
        require_link_absent(&config, P2_INVALID_SITE, timeout)?;

        install_reload_fail_once(&config, timeout)?;
        let reload_rollback =
            session.operate(&config, &password, P2_VALID_SITE, "enabled", timeout)?;
        require_terminal(&reload_rollback, "ROLLED_BACK", "reload failure rollback")?;
        if !reload_rollback.contains("\"resultCode\":\"nginx_reload_failed\"") {
            return Err(String::from(
                "reload failure receipt omitted failure evidence",
            ));
        }
        require_link_absent(&config, P2_VALID_SITE, timeout)?;
        remove_reload_fixture(&config, timeout)?;

        mount_small_snapshot_filesystem(&config, timeout)?;
        session.wait_for_operation_available(&config, timeout)?;
        let disk_guard = session.operate(&config, &password, P2_VALID_SITE, "enabled", timeout)?;
        require_terminal(&disk_guard, "CANCELLED_BEFORE_APPLY", "snapshot disk guard")?;
        if !disk_guard.contains("\"resultCode\":\"snapshot_space_insufficient\"") {
            return Err(String::from(
                "disk guard receipt omitted snapshot_space_insufficient",
            ));
        }
        require_link_absent(&config, P2_VALID_SITE, timeout)?;
        unmount_small_snapshot_filesystem(&config, timeout)
    })();
    let cleanup = cleanup_p2_fixtures(&config, timeout);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; fixture cleanup also failed: {cleanup_error}"
        )),
    }
}

pub fn gate_p2_certd_boundary(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let script = r#"set -eu
if sudo -u jw-agent python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/jw-agent-certd/certd.sock")' 2>/dev/null; then
    exit 1
fi
expired=$(sudo python3 -c 'import json,socket,struct; r={"protocolVersion":1,"requestId":"expired-request","deadlineUnixMs":1,"command":{"kind":"renew_dry_run"}}; p=json.dumps(r,separators=(",",":")).encode(); s=socket.socket(socket.AF_UNIX); s.connect("/run/jw-agent-certd/certd.sock"); s.sendall(struct.pack(">I",len(p))+p); f=s.makefile("rb"); h=f.read(4); print(f.read(struct.unpack(">I",h)[0]).decode())')
printf '%s' "$expired" | grep -Fq '"kind":"rejected"'
printf '%s' "$expired" | grep -Fq '"code":"deadline_expired"'
renew=$(sudo python3 -c 'import json,socket,struct,time; r={"protocolVersion":1,"requestId":"renew-dry-run","deadlineUnixMs":int(time.time()*1000)+60000,"command":{"kind":"renew_dry_run"}}; p=json.dumps(r,separators=(",",":")).encode(); s=socket.socket(socket.AF_UNIX); s.connect("/run/jw-agent-certd/certd.sock"); s.sendall(struct.pack(">I",len(p))+p); f=s.makefile("rb"); h=f.read(4); print(f.read(struct.unpack(">I",h)[0]).decode())')
printf '%s' "$renew" | grep -Fq '"kind":"completed"'
printf '%s' "$renew" | grep -Fq '"commandClass":"renew_dry_run"'
printf '%s' "$renew" | grep -Fq '"stdoutDigest":"sha256:'
printf '%s' "$renew" | grep -Fq '"stderrDigest":"sha256:'
! printf '%s' "$renew" | grep -Fq 'No renewals were attempted'
! pgrep -x jw-certd >/dev/null
! find /run/jw-agent-certd -maxdepth 1 -type f -name 'request-*.ini' | grep -q .
"#;
    let result = config.ssh(script, None, timeout)?;
    require_success(&result, "Certbot runner boundary", false)
}

pub fn gate_p2_managed_config(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    restart_edge_and_agentd_and_wait(&config, timeout)?;
    cleanup_managed_config_fixture(&config, timeout)?;
    let result = (|| {
        let managed_saved = managed_config_large_saved();
        if managed_saved.len() <= 16 * 1_024 || managed_saved.len() > 24 * 1_024 {
            return Err(format!(
                "managed config envelope fixture must be >16 KiB and <=24 KiB, got {} bytes",
                managed_saved.len()
            ));
        }
        install_active_nginx_fixture(&config, P2_MANAGED_SITE, P2_MANAGED_BASELINE, timeout)?;
        let mut session = P2ApiSession::login(&config, &password, timeout)?;
        install_nginx_fixture(
            &config,
            P2_INTERNAL_TEMP,
            b"not an operator resource\n",
            timeout,
        )?;
        let inventory = session.get(&config, "/api/v1/services/nginx/sites", timeout)?;
        expect_http(&inventory, 200, "internal temporary inventory exclusion")?;
        if inventory.body.contains(P2_INTERNAL_TEMP) {
            return Err(String::from(
                "internal managed-config temporary file was exposed as a site",
            ));
        }
        let restarted = config.ssh("sudo systemctl restart jw-opsd.service", None, timeout)?;
        require_success(&restarted, "internal temporary startup cleanup", false)?;
        session.wait_for_operation_available(&config, timeout)?;
        let removed = config.ssh(
            &format!("sudo test ! -e /etc/nginx/sites-available/{P2_INTERNAL_TEMP}"),
            None,
            timeout,
        )?;
        require_success(&removed, "internal temporary removal", false)?;

        let saved = session.operate_managed_config(
            &config,
            &password,
            P2_MANAGED_SITE,
            &managed_saved,
            timeout,
        )?;
        require_terminal(&saved, "SUCCEEDED", "managed config save")?;
        if !saved.contains("\"resultCode\":\"config_verified\"") {
            return Err(String::from(
                "managed config receipt omitted config_verified evidence",
            ));
        }
        require_file_equals(&config, P2_MANAGED_SITE, managed_saved.as_bytes(), timeout)?;

        let noop = session.operate_managed_config(
            &config,
            &password,
            P2_MANAGED_SITE,
            &managed_saved,
            timeout,
        )?;
        require_terminal(&noop, "SUCCEEDED", "managed config no-op")?;
        if !noop.contains("\"resultCode\":\"verified_noop\"") {
            return Err(String::from(
                "managed config no-op omitted verified_noop evidence",
            ));
        }

        let syntax_rollback = session.operate_managed_config(
            &config,
            &password,
            P2_MANAGED_SITE,
            "server { this_is_not_valid_nginx_syntax; }\n",
            timeout,
        )?;
        require_terminal(
            &syntax_rollback,
            "ROLLED_BACK",
            "managed config syntax rollback",
        )?;
        if !syntax_rollback.contains("\"resultCode\":\"nginx_config_test_failed\"") {
            return Err(String::from(
                "managed config syntax receipt omitted failure evidence",
            ));
        }
        require_file_equals(&config, P2_MANAGED_SITE, managed_saved.as_bytes(), timeout)?;

        install_reload_fail_once(&config, timeout)?;
        let reload_rollback = session.operate_managed_config(
            &config,
            &password,
            P2_MANAGED_SITE,
            P2_MANAGED_RELOAD_CHANGE,
            timeout,
        )?;
        require_terminal(
            &reload_rollback,
            "ROLLED_BACK",
            "managed config reload rollback",
        )?;
        if !reload_rollback.contains("\"resultCode\":\"nginx_reload_failed\"") {
            return Err(String::from(
                "managed config reload receipt omitted failure evidence",
            ));
        }
        require_file_equals(&config, P2_MANAGED_SITE, managed_saved.as_bytes(), timeout)?;
        remove_reload_fixture(&config, timeout)?;

        let stale_plan = session.plan_managed_config(
            &config,
            P2_MANAGED_SITE,
            P2_MANAGED_RELOAD_CHANGE,
            timeout,
        )?;
        install_nginx_fixture(&config, P2_MANAGED_SITE, P2_MANAGED_EXTERNAL, timeout)?;
        let syntax = config.ssh("sudo nginx -t", None, timeout)?;
        require_success(&syntax, "external managed config edit syntax", false)?;
        let stale = session.approve_managed_config(&config, &password, &stale_plan, timeout)?;
        require_terminal(
            &stale,
            "CANCELLED_BEFORE_APPLY",
            "managed config external drift",
        )?;
        if !stale.contains("\"resultCode\":\"stale_resource\"") {
            return Err(String::from(
                "managed config stale receipt omitted stale_resource evidence",
            ));
        }
        require_file_equals(&config, P2_MANAGED_SITE, P2_MANAGED_EXTERNAL, timeout)?;

        let resource_id = session.managed_resource_id(&config, P2_MANAGED_SITE, timeout)?;
        disable_nginx_fixture(&config, P2_MANAGED_SITE, timeout)?;
        session.require_managed_config_unavailable(&config, P2_MANAGED_SITE, timeout)?;
        let inactive = session.get(
            &config,
            &format!("/api/v1/config-resources/{resource_id}"),
            timeout,
        )?;
        expect_http(&inactive, 409, "inactive managed config resource")?;
        if !inactive.body.contains("\"code\":\"resource_not_active\"") {
            return Err(String::from(
                "inactive managed config denial omitted resource_not_active",
            ));
        }
        let proposals = config.ssh(
            "sudo test -d /var/lib/jw-agent/opsd/proposals && sudo test -z \"$(sudo find /var/lib/jw-agent/opsd/proposals -mindepth 1 -maxdepth 1 -type d -print -quit)\"",
            None,
            timeout,
        )?;
        require_success(&proposals, "managed config proposal cleanup", false)
    })();
    let cleanup = cleanup_managed_config_fixture(&config, timeout);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; managed config cleanup also failed: {cleanup_error}"
        )),
    }
}

pub fn gate_p2_forensic_lockdown(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    restart_edge_and_agentd_and_wait(&config, timeout)?;
    let backup = "/var/tmp/jw-agent-ledger.checkpoint.backup";
    let remove_checkpoint = config.ssh(
        &format!(
            "sudo systemctl stop jw-opsd.service\nsudo install -o root -g root -m 0600 /var/lib/jw-agent/opsd/ledger.checkpoint {backup}\nsudo rm -f /var/lib/jw-agent/opsd/ledger.checkpoint\nsudo systemctl start jw-opsd.service"
        ),
        None,
        timeout,
    )?;
    require_success(&remove_checkpoint, "checkpoint deletion fixture", false)?;

    let locked_result = (|| {
        let session = P2ApiSession::login(&config, &password, timeout)?;
        session.wait_for_forensic_lockdown(&config, timeout)
    })();

    let restore = config.ssh(
        &format!(
            "sudo systemctl stop jw-opsd.service\nsudo install -o root -g root -m 0600 {backup} /var/lib/jw-agent/opsd/ledger.checkpoint\nsudo rm -f {backup}\nsudo systemctl start jw-opsd.service"
        ),
        None,
        timeout,
    )?;
    require_success(&restore, "checkpoint restoration", false)?;
    locked_result?;
    let session = P2ApiSession::login(&config, &password, timeout)?;
    session.wait_for_operation_available(&config, timeout)
}

struct P2ApiSession {
    cookie_jar: TemporarySecretFile,
    csrf_token: String,
}

impl P2ApiSession {
    fn login(config: &VmConfig, password: &str, timeout: Duration) -> Result<Self, String> {
        let cookie_jar = TemporarySecretFile::create("jw-agent-p2-cookie")?;
        let body = format!(
            "{{\"username\":{},\"password\":{}}}",
            json_string(&config.admin_user),
            json_string(password)
        );
        let response = public_api_request(
            config,
            "POST",
            "/api/v1/auth/login",
            &cookie_jar.path,
            None,
            Some(body.as_bytes()),
            timeout,
        )?;
        expect_http(&response, 200, "P2 API login")?;
        let csrf_token = json_string_field(&response.body, "csrfToken")?;
        Ok(Self {
            cookie_jar,
            csrf_token,
        })
    }

    fn get(
        &self,
        config: &VmConfig,
        path: &str,
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        public_api_request(
            config,
            "GET",
            path,
            &self.cookie_jar.path,
            None,
            None,
            timeout,
        )
    }

    fn wait_for_operation_available(
        &self,
        config: &VmConfig,
        timeout: Duration,
    ) -> Result<(), String> {
        self.wait_for_capability(
            config,
            timeout,
            |body| {
                !body.contains("\"forensicLockdown\":true")
                    && body.contains("nginx.site_state.set/v1")
            },
            "typed operation capability",
        )
    }

    fn require_management_site_protected(
        &self,
        config: &VmConfig,
        timeout: Duration,
    ) -> Result<(), String> {
        let sites = self.get(config, "/api/v1/services/nginx/sites", timeout)?;
        expect_http(&sites, 200, "Nginx protected management observation")?;
        let Some((_, after_protected)) = sites.body.split_once("\"protected\":true") else {
            return Err(String::from(
                "public management vhost was not classified as protected",
            ));
        };
        let before_assurance = after_protected
            .split_once("\"assurance\":")
            .map_or(after_protected, |(before, _)| before);
        if !before_assurance.contains("\"operationType\":null")
            || !before_assurance.contains("\"operationSchemaVersion\":null")
            || !before_assurance.contains("\"managedConfigResourceId\":null")
            || !before_assurance.contains("\"managedConfigOperationType\":null")
            || !before_assurance.contains("\"managedConfigSchemaVersion\":null")
        {
            return Err(String::from(
                "protected public management vhost exposed a mutation contract",
            ));
        }
        Ok(())
    }

    fn wait_for_forensic_lockdown(
        &self,
        config: &VmConfig,
        timeout: Duration,
    ) -> Result<(), String> {
        self.wait_for_capability(
            config,
            timeout,
            |body| {
                body.contains("\"forensicLockdown\":true")
                    && body.contains("\"readOnly\":true")
                    && body.contains("\"supportedOperations\":[]")
            },
            "forensic lockdown capability",
        )
    }

    fn wait_for_capability(
        &self,
        config: &VmConfig,
        timeout: Duration,
        accepted: impl Fn(&str) -> bool,
        label: &str,
    ) -> Result<(), String> {
        let started = Instant::now();
        loop {
            if let Ok(response) = self.get(config, "/api/v1/capabilities", timeout)
                && response.status == 200
                && accepted(&response.body)
            {
                return Ok(());
            }
            if started.elapsed() >= timeout {
                return Err(format!("{label} did not become ready before timeout"));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn operate(
        &mut self,
        config: &VmConfig,
        password: &str,
        site_name: &str,
        target_state: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let sites = self.get(config, "/api/v1/services/nginx/sites", timeout)?;
        expect_http(&sites, 200, "Nginx site observation")?;
        let site = json_site_fields(&sites.body, site_name)?;
        let idempotency_key = operation_idempotency_key()?;
        let plan_body = format!(
            "{{\"schemaVersion\":{},\"operationType\":{},\"siteId\":{},\"targetState\":{},\"expectedAvailableDigest\":{},\"expectedEnabledStateDigest\":{},\"idempotencyKey\":{}}}",
            site.schema_version,
            json_string(&site.operation_type),
            json_string(&site.site_id),
            json_string(target_state),
            json_string(&site.available_digest),
            json_string(&site.enabled_state_digest),
            json_string(&idempotency_key),
        );
        let plan = public_api_request(
            config,
            "POST",
            "/api/v1/operations/nginx/site-state/plans",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(plan_body.as_bytes()),
            timeout,
        )?;
        expect_http(&plan, 200, "Nginx operation plan")?;
        let plan_id = json_string_field(&plan.body, "planId")?;
        let plan_hash = json_string_field(&plan.body, "planHash")?;
        let reauth_body = format!(
            "{{\"password\":{},\"purpose\":{{\"kind\":\"operation\",\"planHash\":{}}}}}",
            json_string(password),
            json_string(&plan_hash),
        );
        let reauth = public_api_request(
            config,
            "POST",
            "/api/v1/auth/reauth",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(reauth_body.as_bytes()),
            timeout,
        )?;
        expect_http(&reauth, 200, "exact-plan PAM reauthentication")?;
        self.csrf_token = json_string_field(&reauth.body, "csrfToken")?;
        let reauth_token = json_string_field(&reauth.body, "reauthToken")?;
        let approval_body = format!(
            "{{\"schemaVersion\":{},\"planId\":{},\"planHash\":{},\"idempotencyKey\":{},\"reauthToken\":{}}}",
            site.schema_version,
            json_string(&plan_id),
            json_string(&plan_hash),
            json_string(&idempotency_key),
            json_string(&reauth_token),
        );
        let accepted = public_api_request(
            config,
            "POST",
            "/api/v1/operations/nginx/site-state/approvals",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(approval_body.as_bytes()),
            timeout,
        )?;
        expect_http(&accepted, 202, "Nginx operation approval")?;
        let operation_id = json_string_field(&accepted.body, "operationId")?;
        let event_stream = json_string_field(&accepted.body, "eventStream")?;
        let expected_stream = format!("/api/v1/operations/{operation_id}/events");
        if event_stream != expected_stream {
            return Err(String::from(
                "Nginx operation returned a non-canonical event stream",
            ));
        }
        let operation_path = format!("/api/v1/operations/{operation_id}");
        let started = Instant::now();
        let receipt = loop {
            let current = self.get(config, &operation_path, timeout)?;
            expect_http(&current, 200, "Nginx operation receipt")?;
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
                break current;
            }
            if started.elapsed() >= timeout {
                return Err(String::from(
                    "Nginx operation did not reach a terminal receipt before timeout",
                ));
            }
            thread::sleep(Duration::from_millis(250));
        };
        let events = self.get(config, &event_stream, timeout)?;
        expect_http(&events, 200, "Nginx operation event stream")?;
        if !events.body.contains("event:operation-stage")
            && !events.body.contains("event: operation-stage")
        {
            return Err(String::from(
                "Nginx operation event stream did not replay durable stage evidence",
            ));
        }
        Ok(receipt.body)
    }

    fn managed_resource_id(
        &self,
        config: &VmConfig,
        site_name: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let sites = self.get(config, "/api/v1/services/nginx/sites", timeout)?;
        expect_http(&sites, 200, "managed config Nginx observation")?;
        Ok(json_managed_config_site_fields(&sites.body, site_name)?.resource_id)
    }

    fn require_managed_config_unavailable(
        &self,
        config: &VmConfig,
        site_name: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let sites = self.get(config, "/api/v1/services/nginx/sites", timeout)?;
        expect_http(&sites, 200, "inactive managed config observation")?;
        let object = json_site_object(&sites.body, site_name)?;
        if object.contains("\"managedConfigResourceId\":null")
            && object.contains("\"managedConfigOperationType\":null")
            && object.contains("\"managedConfigSchemaVersion\":null")
        {
            Ok(())
        } else {
            Err(String::from(
                "inactive Nginx site exposed a managed config mutation contract",
            ))
        }
    }

    fn plan_managed_config(
        &self,
        config: &VmConfig,
        site_name: &str,
        proposed_content: &str,
        timeout: Duration,
    ) -> Result<ManagedConfigPlanFields, String> {
        let sites = self.get(config, "/api/v1/services/nginx/sites", timeout)?;
        expect_http(&sites, 200, "managed config Nginx observation")?;
        let site = json_managed_config_site_fields(&sites.body, site_name)?;
        let resource = self.get(
            config,
            &format!("/api/v1/config-resources/{}", site.resource_id),
            timeout,
        )?;
        expect_http(&resource, 200, "managed config resource")?;
        if json_unsigned_field(&resource.body, "maxBytes")? != 24_576
            || !resource
                .body
                .contains("\"allowedServiceActions\":[\"reload\"]")
            || !resource.body.contains("\"level\":\"g2_reversible_config\"")
        {
            return Err(String::from(
                "managed config resource omitted its bounded G2 contract",
            ));
        }
        let idempotency_key = operation_idempotency_key()?;
        let plan_body = format!(
            "{{\"schemaVersion\":{},\"operationType\":{},\"resourceId\":{},\"expectedContentDigest\":{},\"expectedMetadataDigest\":{},\"proposedContent\":{},\"serviceAction\":\"reload\",\"idempotencyKey\":{}}}",
            site.schema_version,
            json_string(&site.operation_type),
            json_string(&site.resource_id),
            json_string(&json_string_field(&resource.body, "contentDigest")?),
            json_string(&json_string_field(&resource.body, "metadataDigest")?),
            json_string(proposed_content),
            json_string(&idempotency_key),
        );
        let plan = public_api_request(
            config,
            "POST",
            "/api/v1/operations/service/config-file/plans",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(plan_body.as_bytes()),
            timeout,
        )?;
        expect_http(&plan, 200, "managed config plan")?;
        if !plan.body.contains("\"serviceAction\":\"reload\"")
            || !plan.body.contains("\"level\":\"g2_reversible_config\"")
            || !plan.body.contains("\"maskedPath\":\"…/sites-available/")
        {
            return Err(String::from(
                "managed config plan omitted action, assurance, or masked path",
            ));
        }
        Ok(ManagedConfigPlanFields {
            schema_version: site.schema_version,
            plan_id: json_string_field(&plan.body, "planId")?,
            plan_hash: json_string_field(&plan.body, "planHash")?,
            idempotency_key,
        })
    }

    fn approve_managed_config(
        &mut self,
        config: &VmConfig,
        password: &str,
        plan: &ManagedConfigPlanFields,
        timeout: Duration,
    ) -> Result<String, String> {
        let reauth_body = format!(
            "{{\"password\":{},\"purpose\":{{\"kind\":\"operation\",\"planHash\":{}}}}}",
            json_string(password),
            json_string(&plan.plan_hash),
        );
        let reauth = public_api_request(
            config,
            "POST",
            "/api/v1/auth/reauth",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(reauth_body.as_bytes()),
            timeout,
        )?;
        expect_http(
            &reauth,
            200,
            "managed config exact-plan PAM reauthentication",
        )?;
        self.csrf_token = json_string_field(&reauth.body, "csrfToken")?;
        let reauth_token = json_string_field(&reauth.body, "reauthToken")?;
        let approval_body = format!(
            "{{\"schemaVersion\":{},\"planId\":{},\"planHash\":{},\"idempotencyKey\":{},\"reauthToken\":{},\"approvalIntent\":{{\"validationConfirmed\":true,\"serviceActionConfirmed\":true}}}}",
            plan.schema_version,
            json_string(&plan.plan_id),
            json_string(&plan.plan_hash),
            json_string(&plan.idempotency_key),
            json_string(&reauth_token),
        );
        let accepted = public_api_request(
            config,
            "POST",
            "/api/v1/operations/service/config-file/approvals",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(approval_body.as_bytes()),
            timeout,
        )?;
        expect_http(&accepted, 202, "managed config approval")?;
        let operation_id = json_string_field(&accepted.body, "operationId")?;
        let event_stream = json_string_field(&accepted.body, "eventStream")?;
        let expected_stream = format!("/api/v1/operations/{operation_id}/events");
        if event_stream != expected_stream {
            return Err(String::from(
                "managed config returned a non-canonical event stream",
            ));
        }
        let operation_path = format!("/api/v1/operations/{operation_id}");
        let started = Instant::now();
        let receipt = loop {
            let current = self.get(config, &operation_path, timeout)?;
            expect_http(&current, 200, "managed config receipt")?;
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
                break current;
            }
            if started.elapsed() >= timeout {
                return Err(String::from(
                    "managed config did not reach a terminal receipt before timeout",
                ));
            }
            thread::sleep(Duration::from_millis(250));
        };
        let events = self.get(config, &event_stream, timeout)?;
        expect_http(&events, 200, "managed config event stream")?;
        if !events.body.contains("event:operation-stage")
            && !events.body.contains("event: operation-stage")
        {
            return Err(String::from(
                "managed config event stream omitted durable stage evidence",
            ));
        }
        Ok(receipt.body)
    }

    fn operate_managed_config(
        &mut self,
        config: &VmConfig,
        password: &str,
        site_name: &str,
        proposed_content: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let plan = self.plan_managed_config(config, site_name, proposed_content, timeout)?;
        self.approve_managed_config(config, password, &plan, timeout)
    }
}

fn restart_edge_and_agentd_and_wait(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let restarted = config.ssh(
        "sudo systemctl restart nginx.service jw-agentd.service",
        None,
        timeout,
    )?;
    require_success(&restarted, "public edge and agentd restart", false)?;
    wait_for_public_agent(config, timeout)
}

fn wait_for_public_agent(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    loop {
        let health = config.public_curl(
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
            return Err(String::from("agentd did not become ready before timeout"));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

struct NginxSiteFields {
    schema_version: u16,
    operation_type: String,
    site_id: String,
    available_digest: String,
    enabled_state_digest: String,
}

struct ManagedConfigSiteFields {
    schema_version: u16,
    operation_type: String,
    resource_id: String,
}

struct ManagedConfigPlanFields {
    schema_version: u16,
    plan_id: String,
    plan_hash: String,
    idempotency_key: String,
}

fn json_site_object<'a>(body: &'a str, site_name: &str) -> Result<&'a str, String> {
    let marker = format!("\"name\":{}", json_string(site_name));
    let Some(marker_index) = body.find(&marker) else {
        return Err(format!("Nginx fixture `{site_name}` was not observed"));
    };
    let start = body[..marker_index]
        .rfind('{')
        .map_or(marker_index, std::convert::identity);
    let remainder = &body[start..];
    let end = remainder
        .find("\"assurance\":")
        .map_or(remainder.len(), std::convert::identity);
    Ok(&remainder[..end])
}

fn json_site_fields(body: &str, site_name: &str) -> Result<NginxSiteFields, String> {
    let object = json_site_object(body, site_name)?;
    let schema = json_unsigned_field(object, "operationSchemaVersion")?;
    Ok(NginxSiteFields {
        schema_version: u16::try_from(schema)
            .map_err(|_| String::from("operation schema version overflow"))?,
        operation_type: json_string_field(object, "operationType")?,
        site_id: json_string_field(object, "siteId")?,
        available_digest: json_string_field(object, "availableDigest")?,
        enabled_state_digest: json_string_field(object, "enabledStateDigest")?,
    })
}

fn json_managed_config_site_fields(
    body: &str,
    site_name: &str,
) -> Result<ManagedConfigSiteFields, String> {
    let object = json_site_object(body, site_name)?;
    let schema = json_unsigned_field(object, "managedConfigSchemaVersion")?;
    Ok(ManagedConfigSiteFields {
        schema_version: u16::try_from(schema)
            .map_err(|_| String::from("managed config schema version overflow"))?,
        operation_type: json_string_field(object, "managedConfigOperationType")?,
        resource_id: json_string_field(object, "managedConfigResourceId")?,
    })
}

fn json_string_field(body: &str, field: &str) -> Result<String, String> {
    let marker = format!("\"{field}\":\"");
    let Some(start) = body.find(&marker).map(|index| index + marker.len()) else {
        return Err(format!("JSON field `{field}` is missing"));
    };
    let remainder = &body[start..];
    let Some(end) = remainder.find('"') else {
        return Err(format!("JSON field `{field}` is unterminated"));
    };
    let value = &remainder[..end];
    if value.contains('\\') || value.is_empty() {
        return Err(format!("JSON field `{field}` has an unsupported value"));
    }
    Ok(value.to_owned())
}

fn json_unsigned_field(body: &str, field: &str) -> Result<u64, String> {
    let marker = format!("\"{field}\":");
    let Some(start) = body.find(&marker).map(|index| index + marker.len()) else {
        return Err(format!("JSON field `{field}` is missing"));
    };
    let digits: String = body[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    if digits.is_empty() {
        return Err(format!("JSON field `{field}` is not unsigned"));
    }
    digits
        .parse::<u64>()
        .map_err(|_| format!("JSON field `{field}` overflowed"))
}

fn public_api_request(
    config: &VmConfig,
    method: &str,
    path: &str,
    cookie_jar: &Path,
    csrf_token: Option<&str>,
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    if !path.starts_with("/api/") || !matches!(method, "GET" | "POST") {
        return Err(String::from("P2 API request rejected an unsupported shape"));
    }
    let csrf_header = match csrf_token {
        Some(token) => Some(TemporarySecretFile::create_with_contents(
            "jw-agent-p2-csrf",
            format!("X-CSRF-Token: {token}\n").as_bytes(),
        )?),
        None => None,
    };
    let mut arguments = vec![
        OsString::from("--silent"),
        OsString::from("--show-error"),
        OsString::from("--max-time"),
        OsString::from(timeout.as_secs().min(295).to_string()),
        OsString::from("--resolve"),
        OsString::from(format!(
            "{}:443:{}",
            config.public_host, config.public_address
        )),
        OsString::from("--cacert"),
        config.ca_certificate.as_os_str().to_owned(),
        OsString::from("--output"),
        OsString::from("-"),
        OsString::from("--write-out"),
        OsString::from("\n%{http_code}"),
        OsString::from("--cookie"),
        cookie_jar.as_os_str().to_owned(),
        OsString::from("--cookie-jar"),
        cookie_jar.as_os_str().to_owned(),
        OsString::from("--header"),
        OsString::from(format!("Origin: https://{}", config.public_host)),
    ];
    if let Some(header) = &csrf_header {
        arguments.push(OsString::from("--header"));
        arguments.push(OsString::from(format!("@{}", header.path.display())));
    }
    if method == "POST" {
        arguments.push(OsString::from("--header"));
        arguments.push(OsString::from("Content-Type: application/json"));
        arguments.push(OsString::from("--data-binary"));
        arguments.push(OsString::from("@-"));
    }
    arguments.push(OsString::from(format!(
        "https://{}{}",
        config.public_host, path
    )));
    let result = run_capture(OsStr::new("curl"), &arguments, body, timeout)?;
    if !result.status.success() || result.stdout_truncated || result.stderr_truncated {
        return Err(format!(
            "P2 API transport failed with {} (response and credentials redacted)",
            result.status
        ));
    }
    parse_http_response(&result.stdout)
}

fn operation_idempotency_key() -> Result<String, String> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| String::from("system clock is before Unix epoch"))?;
    Ok(format!(
        "vm-{}-{:x}",
        std::process::id(),
        elapsed.as_nanos()
    ))
}

fn require_terminal(body: &str, expected: &str, label: &str) -> Result<(), String> {
    if json_string_field(body, "terminalState")? == expected {
        Ok(())
    } else {
        Err(format!("{label} returned the wrong terminal state"))
    }
}

fn install_nginx_fixture(
    config: &VmConfig,
    name: &str,
    contents: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    validate_atom(name, "Nginx fixture name", ".-_")?;
    let command = format!(
        "sudo install -o root -g root -m 0644 /dev/stdin /etc/nginx/sites-available/{name}"
    );
    let result = config.ssh(&command, Some(contents), timeout)?;
    require_success(&result, "Nginx fixture install", false)
}

fn install_active_nginx_fixture(
    config: &VmConfig,
    name: &str,
    contents: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    install_nginx_fixture(config, name, contents, timeout)?;
    validate_atom(name, "Nginx fixture name", ".-_")?;
    let result = config.ssh(
        &format!(
            "sudo ln -s ../sites-available/{name} /etc/nginx/sites-enabled/{name}\nsudo nginx -t\nsudo systemctl reload nginx.service"
        ),
        None,
        timeout,
    )?;
    require_success(&result, "active Nginx fixture install", false)
}

fn disable_nginx_fixture(config: &VmConfig, name: &str, timeout: Duration) -> Result<(), String> {
    validate_atom(name, "Nginx fixture name", ".-_")?;
    let result = config.ssh(
        &format!(
            "sudo rm -f /etc/nginx/sites-enabled/{name}\nsudo nginx -t\nsudo systemctl reload nginx.service"
        ),
        None,
        timeout,
    )?;
    require_success(&result, "inactive Nginx fixture", false)
}

fn require_file_equals(
    config: &VmConfig,
    name: &str,
    expected: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    validate_atom(name, "Nginx fixture name", ".-_")?;
    let result = config.ssh(
        &format!("sudo cmp -s /dev/stdin /etc/nginx/sites-available/{name}"),
        Some(expected),
        timeout,
    )?;
    require_success(&result, "exact managed config bytes", false)
}

fn require_link_absent(config: &VmConfig, name: &str, timeout: Duration) -> Result<(), String> {
    validate_atom(name, "Nginx fixture name", ".-_")?;
    let result = config.ssh(
        &format!(
            "sudo test ! -e /etc/nginx/sites-enabled/{name} && sudo test ! -L /etc/nginx/sites-enabled/{name} && sudo systemctl is-active --quiet nginx.service"
        ),
        None,
        timeout,
    )?;
    require_success(&result, "rolled-back Nginx fixture", false)
}

fn install_reload_fail_once(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let script = r#"set -eu
sudo install -d -o root -g root -m 0755 /etc/systemd/system/nginx.service.d
sudo install -o root -g root -m 0644 /dev/stdin /etc/systemd/system/nginx.service.d/90-jw-agent-vm.conf
sudo touch /run/jw-agent-vm-reload-fail-once
sudo systemctl daemon-reload
"#;
    let drop_in = b"[Service]\nExecReload=\nExecReload=/bin/sh -c 'if test -e /run/jw-agent-vm-reload-fail-once; then rm -f /run/jw-agent-vm-reload-fail-once; exit 1; fi; exec /usr/sbin/nginx -s reload'\n";
    let result = config.ssh(script, Some(drop_in), timeout)?;
    require_success(&result, "reload failure fixture", false)
}

fn remove_reload_fixture(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let result = config.ssh(
        "sudo rm -f /etc/systemd/system/nginx.service.d/90-jw-agent-vm.conf /run/jw-agent-vm-reload-fail-once\nsudo systemctl daemon-reload\nsudo systemctl is-active --quiet nginx.service",
        None,
        timeout,
    )?;
    require_success(&result, "reload failure fixture cleanup", false)
}

fn mount_small_snapshot_filesystem(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let result = config.ssh(
        "sudo systemctl stop jw-opsd.service\nsudo mount -t tmpfs -o size=1m,mode=0700,uid=0,gid=0 tmpfs /var/lib/jw-agent/opsd/snapshots\nsudo systemctl start jw-opsd.service",
        None,
        timeout,
    )?;
    require_success(&result, "small snapshot filesystem fixture", false)
}

fn unmount_small_snapshot_filesystem(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let result = config.ssh(
        "sudo systemctl stop jw-opsd.service\nsudo umount /var/lib/jw-agent/opsd/snapshots\nsudo systemctl start jw-opsd.service",
        None,
        timeout,
    )?;
    require_success(&result, "small snapshot filesystem cleanup", false)
}

fn cleanup_p2_fixtures(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let result = config.ssh(
        "sudo systemctl stop jw-opsd.service\nsudo umount /var/lib/jw-agent/opsd/snapshots 2>/dev/null || true\nsudo rm -f /etc/nginx/sites-enabled/jw-agent-vm-operation.conf /etc/nginx/sites-enabled/jw-agent-vm-invalid.conf\nsudo rm -f /etc/nginx/sites-available/jw-agent-vm-operation.conf /etc/nginx/sites-available/jw-agent-vm-invalid.conf\nsudo rm -f /etc/systemd/system/nginx.service.d/90-jw-agent-vm.conf /run/jw-agent-vm-reload-fail-once\nsudo systemctl daemon-reload\nsudo systemctl start jw-opsd.service\nsudo nginx -t\nsudo systemctl reload nginx.service",
        None,
        timeout,
    )?;
    require_success(&result, "P2 VM fixture cleanup", false)
}

fn cleanup_managed_config_fixture(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let result = config.ssh(
        "sudo rm -f /etc/nginx/sites-enabled/jw-agent-vm-managed.conf\nsudo rm -f /etc/nginx/sites-available/jw-agent-vm-managed.conf /etc/nginx/sites-available/.jw-agent-0123456789abcdef.tmp\nsudo rm -f /etc/systemd/system/nginx.service.d/90-jw-agent-vm.conf /run/jw-agent-vm-reload-fail-once\nsudo systemctl daemon-reload\nsudo nginx -t\nsudo systemctl reload nginx.service",
        None,
        timeout,
    )?;
    require_success(&result, "managed config VM fixture cleanup", false)
}

struct TemporarySecretFile {
    path: PathBuf,
}

impl TemporarySecretFile {
    fn create(prefix: &str) -> Result<Self, String> {
        let path = env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| String::from("system clock is before Unix epoch"))?
                .as_nanos()
        ));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| format!("cannot create temporary cookie jar: {error}"))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot secure temporary cookie jar: {error}"))?;
        Ok(Self { path })
    }

    fn create_with_contents(prefix: &str, contents: &[u8]) -> Result<Self, String> {
        let file = Self::create(prefix)?;
        fs::write(&file.path, contents)
            .map_err(|error| format!("cannot write temporary secret file: {error}"))?;
        Ok(file)
    }
}

impl Drop for TemporarySecretFile {
    fn drop(&mut self) {
        let _remove_result = fs::remove_file(&self.path);
    }
}

struct VmConfig {
    ssh_target: String,
    ssh_known_hosts: PathBuf,
    public_host: String,
    public_address: IpAddr,
    ca_certificate: PathBuf,
    admin_user: String,
    password_file: PathBuf,
    remote_package: String,
    expected_package_sha256: String,
    expected_version: String,
}

impl VmConfig {
    fn load() -> Result<Self, String> {
        let ssh_target = required_environment("JW_VM_SSH_TARGET")?;
        validate_atom(&ssh_target, "JW_VM_SSH_TARGET", "@._-")?;
        let ssh_known_hosts = readable_file("JW_VM_SSH_KNOWN_HOSTS")?;
        let public_host = required_environment("JW_VM_PUBLIC_HOST")?;
        validate_host(&public_host)?;
        let public_address = required_environment("JW_VM_PUBLIC_ADDRESS")?
            .parse::<IpAddr>()
            .map_err(|_| String::from("JW_VM_PUBLIC_ADDRESS must be an IP address"))?;
        let ca_certificate = readable_file("JW_VM_CA_CERT")?;
        let admin_user = required_environment("JW_VM_ADMIN_USER")?;
        validate_atom(&admin_user, "JW_VM_ADMIN_USER", "_-")?;
        let password_file = secret_file("JW_VM_PASSWORD_FILE")?;
        let remote_package = required_environment("JW_VM_REMOTE_PACKAGE")?;
        let expected_package_sha256 = required_environment("JW_VM_EXPECTED_PACKAGE_SHA256")?;
        if expected_package_sha256.len() != 64
            || !expected_package_sha256
                .bytes()
                .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
        {
            return Err(String::from(
                "JW_VM_EXPECTED_PACKAGE_SHA256 must be lowercase SHA-256",
            ));
        }
        let expected_version = required_environment("JW_VM_EXPECTED_VERSION")?;
        validate_atom(&expected_version, "JW_VM_EXPECTED_VERSION", ".~+-")?;
        Ok(Self {
            ssh_target,
            ssh_known_hosts,
            public_host,
            public_address,
            ca_certificate,
            admin_user,
            password_file,
            remote_package,
            expected_package_sha256,
            expected_version,
        })
    }

    fn ssh(
        &self,
        remote_command: &str,
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Captured, String> {
        let arguments = [
            OsString::from("-o"),
            OsString::from("BatchMode=yes"),
            OsString::from("-o"),
            OsString::from("ConnectTimeout=8"),
            OsString::from("-o"),
            OsString::from("StrictHostKeyChecking=yes"),
            OsString::from("-o"),
            OsString::from(format!(
                "UserKnownHostsFile={}",
                self.ssh_known_hosts.display()
            )),
            OsString::from(&self.ssh_target),
            OsString::from(remote_command),
        ];
        run_capture(OsStr::new("ssh"), &arguments, input, timeout)
    }

    fn public_curl(
        &self,
        suffix: &[&str],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Captured, String> {
        let arguments = self.public_curl_arguments(suffix, true);
        run_capture(OsStr::new("curl"), &arguments, input, timeout)
    }

    fn public_curl_arguments(&self, suffix: &[&str], trust_fixture_ca: bool) -> Vec<OsString> {
        let mut arguments = vec![
            OsString::from("--silent"),
            OsString::from("--show-error"),
            OsString::from("--max-time"),
            OsString::from("12"),
            OsString::from("--resolve"),
            OsString::from(format!("{}:443:{}", self.public_host, self.public_address)),
        ];
        if trust_fixture_ca {
            arguments.push(OsString::from("--cacert"));
            arguments.push(self.ca_certificate.as_os_str().to_owned());
        }
        for argument in suffix {
            if is_http_endpoint(argument) {
                arguments.push(OsString::from(format!(
                    "https://{}{}",
                    self.public_host, argument
                )));
            } else {
                arguments.push(OsString::from(argument));
            }
        }
        arguments
    }

    fn plain_http_curl(&self, suffix: &[&str], timeout: Duration) -> Result<Captured, String> {
        let mut arguments = vec![
            OsString::from("--silent"),
            OsString::from("--show-error"),
            OsString::from("--max-time"),
            OsString::from("12"),
            OsString::from("--resolve"),
            OsString::from(format!("{}:80:{}", self.public_host, self.public_address)),
        ];
        for argument in suffix {
            if is_http_endpoint(argument) {
                arguments.push(OsString::from(format!(
                    "http://{}{}",
                    self.public_host, argument
                )));
            } else {
                arguments.push(OsString::from(argument));
            }
        }
        run_capture(OsStr::new("curl"), &arguments, None, timeout)
    }
}

fn recovery_login(
    config: &VmConfig,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    let body = format!(
        "{{\"username\":{},\"password\":{}}}",
        json_string(username),
        json_string(password)
    );
    let command = format!(
        "curl --silent --show-error --max-time 12 --output - --write-out '\\n%{{http_code}}' --header 'Host: {RECOVERY_HOST}' --header 'Origin: {RECOVERY_ORIGIN}' --header 'Content-Type: application/json' --data-binary @- http://127.0.0.1:8787/api/v1/auth/login"
    );
    let result = config.ssh(&command, Some(body.as_bytes()), timeout)?;
    if !result.status.success() {
        return Err(format!(
            "recovery login transport failed with {}; stderr={}",
            result.status,
            safe_output(&result.stderr, result.stderr_truncated)
        ));
    }
    parse_http_response(&result.stdout)
}

fn parse_http_response(output: &[u8]) -> Result<HttpResponse, String> {
    let encoded = text(output)?;
    let Some((body, status)) = encoded.rsplit_once('\n') else {
        return Err(String::from("HTTP response is missing the status trailer"));
    };
    let status = status
        .trim()
        .parse::<u16>()
        .map_err(|_| String::from("HTTP response status is invalid"))?;
    Ok(HttpResponse {
        status,
        body: body.to_owned(),
    })
}

fn expect_http(response: &HttpResponse, expected: u16, label: &str) -> Result<(), String> {
    if response.status == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} returned HTTP {}, expected {expected}",
            response.status
        ))
    }
}

struct HttpResponse {
    status: u16,
    body: String,
}

struct Captured {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

fn run_capture(
    program: &OsStr,
    arguments: &[OsString],
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<Captured, String> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot start {}: {error}", program.to_string_lossy()))?;

    if let Some(bytes) = input {
        let Some(mut stdin) = child.stdin.take() else {
            return Err(String::from("child stdin is unavailable"));
        };
        stdin
            .write_all(bytes)
            .map_err(|error| format!("cannot write child stdin: {error}"))?;
    }

    let Some(stdout) = child.stdout.take() else {
        return Err(String::from("child stdout is unavailable"));
    };
    let Some(stderr) = child.stderr.take() else {
        return Err(String::from("child stderr is unavailable"));
    };
    let stdout_reader = thread::spawn(move || read_capped(stdout));
    let stderr_reader = thread::spawn(move || read_capped(stderr));

    let started = Instant::now();
    let status = loop {
        match child
            .try_wait()
            .map_err(|error| format!("cannot wait for {}: {error}", program.to_string_lossy()))?
        {
            Some(status) => break status,
            None if started.elapsed() >= timeout => {
                child
                    .kill()
                    .map_err(|error| format!("cannot stop timed-out process: {error}"))?;
                let status = child
                    .wait()
                    .map_err(|error| format!("cannot reap timed-out process: {error}"))?;
                let _stdout = stdout_reader.join();
                let _stderr = stderr_reader.join();
                return Err(format!(
                    "{} exceeded {} seconds and exited with {status}",
                    program.to_string_lossy(),
                    timeout.as_secs()
                ));
            }
            None => thread::sleep(Duration::from_millis(25)),
        }
    };
    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| String::from("stdout reader failed"))??;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| String::from("stderr reader failed"))??;
    Ok(Captured {
        status,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

fn read_capped<R: Read>(mut reader: R) -> Result<(Vec<u8>, bool), String> {
    let mut kept = Vec::new();
    let mut buffer = [0_u8; 8 * 1_024];
    let mut truncated = false;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| format!("cannot read child output: {error}"))?;
        if count == 0 {
            return Ok((kept, truncated));
        }
        let remaining = OUTPUT_LIMIT_BYTES.saturating_sub(kept.len());
        let take = remaining.min(count);
        kept.extend_from_slice(&buffer[..take]);
        if take < count {
            truncated = true;
        }
    }
}

fn require_success(result: &Captured, label: &str, sensitive: bool) -> Result<(), String> {
    if result.status.success() && !result.stdout_truncated && !result.stderr_truncated {
        return Ok(());
    }
    if sensitive {
        Err(format!(
            "{label} failed with {} (sensitive output redacted)",
            result.status
        ))
    } else {
        Err(format!(
            "{label} failed with {}; stdout={}; stderr={}",
            result.status,
            safe_output(&result.stdout, result.stdout_truncated),
            safe_output(&result.stderr, result.stderr_truncated)
        ))
    }
}

fn safe_output(bytes: &[u8], truncated: bool) -> String {
    let mut value = String::from_utf8_lossy(bytes).trim().to_owned();
    if value.len() > 2_048 {
        value.truncate(2_048);
        value.push_str("...[display capped]");
    }
    if truncated {
        value.push_str("...[capture capped]");
    }
    value
}

fn text(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|_| String::from("command output is not UTF-8"))
}

fn required_environment(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required for p1-vm"))
}

fn readable_file(name: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(required_environment(name)?);
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!("{name} does not name a readable file"))
    }
}

fn secret_file(name: &str) -> Result<PathBuf, String> {
    let path = readable_file(name)?;
    let mode = fs::metadata(&path)
        .map_err(|error| format!("cannot inspect {name}: {error}"))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(format!("{name} must have mode 0600"));
    }
    Ok(path)
}

fn read_secret(path: &Path) -> Result<String, String> {
    let encoded =
        fs::read_to_string(path).map_err(|_| String::from("cannot read VM password file"))?;
    let secret = encoded.trim_end_matches(['\r', '\n']).to_owned();
    if secret.is_empty() || secret.len() > 1_024 || secret.bytes().any(|value| value == 0) {
        return Err(String::from(
            "VM password fixture has an invalid length or value",
        ));
    }
    Ok(secret)
}

fn validate_atom(value: &str, name: &str, punctuation: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || punctuation.contains(character))
    {
        Err(format!("{name} contains unsupported characters"))
    } else {
        Ok(())
    }
}

fn validate_host(value: &str) -> Result<(), String> {
    validate_atom(value, "JW_VM_PUBLIC_HOST", ".-")?;
    if !value.contains('.') || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Err(String::from("JW_VM_PUBLIC_HOST must be a lowercase FQDN"))
    } else {
        Ok(())
    }
}

fn shell_safe_path(value: &str) -> Result<&str, String> {
    if value.starts_with('/')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/._~+-".contains(character))
    {
        Ok(value)
    } else {
        Err(String::from(
            "JW_VM_REMOTE_PACKAGE is not a safe absolute path",
        ))
    }
}

fn is_http_endpoint(value: &str) -> bool {
    value.starts_with("/api/")
        || value == "/integrations"
        || value == "/favicon.svg"
        || value == "/login"
}

fn json_string(value: &str) -> String {
    let mut encoded = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            value if value.is_control() => encoded.push_str(&format!("\\u{:04x}", value as u32)),
            value => encoded.push(value),
        }
    }
    encoded.push('"');
    encoded
}

#[cfg(test)]
mod tests {
    use super::json_string;

    #[test]
    fn json_string_escapes_secret_without_debug_output() {
        assert_eq!(json_string("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
    }
}
