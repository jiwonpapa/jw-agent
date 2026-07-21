#![forbid(unsafe_code)]

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
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
ldd /usr/lib/jw-agent/jw-authd | grep -q 'libpam\.so\.0'
ldd /usr/lib/jw-agent/jw-agentd | grep -q 'libsqlite3\.so\.0'
"#
    );
    let native = config.ssh(&native_script, None, Duration::from_secs(20))?;
    require_success(&native, "native link and PAM package fixture", false)?;

    let script = r#"set -eu
for unit in jw-agentd.service jw-opsd.service jw-authd.socket; do
    test "$(systemctl is-enabled "$unit")" = enabled
    test "$(systemctl is-active "$unit")" = active
done
test "$(systemctl show -p User --value jw-agentd.service)" = jw-agent
test "$(systemctl show -p User --value jw-opsd.service)" = root
test "$(systemctl show -p NoNewPrivileges --value jw-agentd.service)" = yes
test "$(systemctl show -p NoNewPrivileges --value jw-opsd.service)" = yes
test "$(systemctl show -p ProtectSystem --value jw-agentd.service)" = strict
test "$(systemctl show -p ProtectSystem --value jw-opsd.service)" = strict
test "$(systemctl show -p MemoryDenyWriteExecute --value jw-agentd.service)" = yes
test "$(systemctl show -p MemoryDenyWriteExecute --value jw-opsd.service)" = yes
sudo test -S /run/jw-agent/authd.sock
sudo test -S /run/jw-agent/opsd.sock
sudo test -S /run/jw-agent-proxy/agentd.sock
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent/authd.sock)" = jw-agent:jw-agent:600
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent/opsd.sock)" = root:jw-agent:660
test "$(stat -c '%U:%G:%a' /run/jw-agent-proxy)" = jw-agent:jw-agent-proxy:2750
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent-proxy/agentd.sock)" = jw-agent:jw-agent-proxy:660
id -nG jw-agent | tr ' ' '\n' | grep -Fxq jw-agent-proxy
id -nG www-data | tr ' ' '\n' | grep -Fxq jw-agent-proxy
agent_pid=$(systemctl show -p MainPID --value jw-agentd.service)
ops_pid=$(systemctl show -p MainPID --value jw-opsd.service)
test "$agent_pid" -gt 1
test "$ops_pid" -gt 1
test "$(awk '/^CapEff:/{print $2}' "/proc/$agent_pid/status")" = 0000000000000000
test "$(awk '/^CapEff:/{print $2}' "/proc/$ops_pid/status")" = 0000000000000000
test "$(ss -H -ltn 'sport = :8787' | awk '{print $4}')" = 127.0.0.1:8787
test "$(find /proc -maxdepth 2 -name comm -readable -exec grep -l '^jw-authd$' {} + 2>/dev/null | wc -l)" -eq 0
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
find /var/lib/jw-agent/agentd -maxdepth 1 -type f -print0 | xargs -0 -r strings | grep -F -q -f "$pattern" && found=1 || true
ps -eo args= | grep -F -q -f "$pattern" && found=1 || true
grep -F -q -f "$pattern" /var/log/dpkg.log /var/log/apt/term.log 2>/dev/null && found=1 || true
test "$found" -eq 0
'"#;
    let result = config.ssh(script, Some(&secret_input), timeout)?;
    require_success(&result, "fixture secret scan", true)
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
