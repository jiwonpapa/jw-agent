#![forbid(unsafe_code)]

pub(crate) mod apache;
pub(crate) mod independent_edge;
pub(crate) mod php_fpm;
pub(crate) mod public_recovery;
mod receipt;
pub(crate) mod service_control;
pub(crate) mod service_inventory;
pub(crate) mod totp;
pub(crate) mod ufw;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::process::{Captured, run_capture, safe_output};
use receipt::contains_nginx_config_failure_result;

const RECOVERY_HOST: &str = "127.0.0.1:8787";
const RECOVERY_ORIGIN: &str = "http://127.0.0.1:8787";
const RESTART_AGENTD_READY: &str = "sudo systemctl restart jw-agentd && sleep 1";
const TERMINAL_WS_PROBE: &str = r#"
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time

cfg = json.load(sys.stdin)

def report_probe_error(exception_type, value, traceback):
    message = str(value)
    allowed = (
        "websocket ",
        "HTTP ",
        "server websocket ",
        "unsupported websocket ",
        "terminal ",
        "logout ",
        "valid terminal ",
        "consumed terminal ",
        "wrong Origin ",
        "revocation terminal ",
        "unsupported terminal ",
    )
    if not message.startswith(allowed):
        message = "unexpected probe failure (" + exception_type.__name__ + ")"
    sys.stderr.write("terminal probe: " + message + "\n")

sys.excepthook = report_probe_error

class Ws:
    def __init__(self, stream, buffered=b""):
        self.stream = stream
        self.buffered = bytearray(buffered)

    def read_exact(self, count, deadline):
        while len(self.buffered) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("websocket receive deadline exceeded")
            self.stream.settimeout(min(remaining, 2.0))
            try:
                chunk = self.stream.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise RuntimeError("websocket closed without a close frame")
            self.buffered.extend(chunk)
        value = bytes(self.buffered[:count])
        del self.buffered[:count]
        return value

    def send(self, opcode, payload=b""):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        first = 0x80 | opcode
        size = len(payload)
        mask = os.urandom(4)
        if size < 126:
            header = bytes((first, 0x80 | size))
        elif size <= 65535:
            header = bytes((first, 0x80 | 126)) + struct.pack("!H", size)
        else:
            header = bytes((first, 0x80 | 127)) + struct.pack("!Q", size)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.stream.sendall(header + mask + masked)

    def receive(self, deadline):
        first, second = self.read_exact(2, deadline)
        if first & 0x70:
            raise RuntimeError("websocket RSV bits were set")
        opcode = first & 0x0F
        size = second & 0x7F
        if second & 0x80:
            raise RuntimeError("server websocket frame was masked")
        if size == 126:
            size = struct.unpack("!H", self.read_exact(2, deadline))[0]
        elif size == 127:
            size = struct.unpack("!Q", self.read_exact(8, deadline))[0]
        if size > 262144:
            raise RuntimeError("server websocket frame exceeded probe bound")
        payload = self.read_exact(size, deadline)
        if opcode == 0x9:
            self.send(0xA, payload)
            return self.receive(deadline)
        if opcode == 0xA:
            return self.receive(deadline)
        if opcode not in (0x1, 0x2, 0x8):
            raise RuntimeError("unsupported websocket frame opcode")
        return opcode, payload

    def close(self):
        try:
            self.send(0x8, struct.pack("!H", 1000))
        except Exception:
            pass
        self.stream.close()

def tls_stream():
    raw = socket.create_connection((cfg["address"], 443), timeout=10)
    context = ssl.create_default_context(cafile=cfg["ca"])
    return context.wrap_socket(raw, server_hostname=cfg["host"])

def read_http(stream):
    buffered = bytearray()
    while b"\r\n\r\n" not in buffered:
        chunk = stream.recv(4096)
        if not chunk:
            raise RuntimeError("HTTP response ended before headers")
        buffered.extend(chunk)
        if len(buffered) > 65536:
            raise RuntimeError("HTTP response headers exceeded probe bound")
    head, body = bytes(buffered).split(b"\r\n\r\n", 1)
    lines = head.decode("ascii").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise RuntimeError("HTTP response status was invalid")
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            raise RuntimeError("HTTP response header was invalid")
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return int(parts[1]), headers, body


def websocket(origin):
    stream = tls_stream()
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        "GET /api/v1/terminal/connect HTTP/1.1\r\n"
        + "Host: " + cfg["host"] + "\r\n"
        + "Origin: " + origin + "\r\n"
        + "Cookie: " + cfg["cookie"] + "\r\n"
        + "Upgrade: websocket\r\n"
        + "Connection: Upgrade\r\n"
        + "Sec-WebSocket-Version: 13\r\n"
        + "Sec-WebSocket-Key: " + key + "\r\n"
        + "Sec-WebSocket-Protocol: jw-terminal-v1, ticket." + cfg["ticket"] + "\r\n\r\n"
    )
    stream.sendall(request.encode("ascii"))
    status, headers, buffered = read_http(stream)
    if status == 101:
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        if headers.get("sec-websocket-accept") != expected:
            raise RuntimeError("websocket accept proof did not match")
        if headers.get("sec-websocket-protocol") != "jw-terminal-v1":
            raise RuntimeError("websocket subprotocol was not constrained")
        return status, Ws(stream, buffered)
    stream.close()
    return status, None


def require_ready(ws):
    deadline = time.monotonic() + 12
    while True:
        opcode, payload = ws.receive(deadline)
        if opcode == 0x8:
            reason = payload[2:].decode("utf-8", "replace") if len(payload) >= 2 else ""
            raise RuntimeError("terminal closed before ready: " + reason)
        if opcode == 0x1:
            message = json.loads(payload.decode("utf-8"))
            if message.get("type") == "ready" and message.get("assurance") == "g1_verified_action":
                return


def logout():
    stream = tls_stream()
    request = (
        "POST /api/v1/auth/logout HTTP/1.1\r\n"
        + "Host: " + cfg["host"] + "\r\n"
        + "Origin: https://" + cfg["host"] + "\r\n"
        + "Cookie: " + cfg["cookie"] + "\r\n"
        + "X-CSRF-Token: " + cfg["csrf"] + "\r\n"
        + "Content-Length: 0\r\n"
        + "Connection: close\r\n\r\n"
    )
    stream.sendall(request.encode("ascii"))
    status, _, _ = read_http(stream)
    stream.close()
    if status != 204:
        raise RuntimeError("logout did not return HTTP 204")


mode = cfg["mode"]
origin = "https://" + cfg["host"]
if mode == "success_replay":
    status, ws = websocket(origin)
    if status != 101:
        raise RuntimeError("valid terminal ticket did not upgrade")
    require_ready(ws)
    time.sleep(1.0)
    ws.send(0x1, json.dumps({"type": "input", "data": "\r"}, separators=(",", ":")))
    time.sleep(1.0)
    ws.send(0x1, json.dumps({"type": "resize", "rows": 40, "cols": 100}, separators=(",", ":")))
    ws.send(0x1, json.dumps({"type": "input", "data": "printf 'JW_TERMINAL_%s\\n' 'VM_OK'; stty size; exit\r"}, separators=(",", ":")))
    deadline = time.monotonic() + 15
    output = bytearray()
    while time.monotonic() < deadline:
        try:
            opcode, payload = ws.receive(deadline)
        except RuntimeError as error:
            if str(error) == "websocket receive deadline exceeded":
                break
            raise
        if opcode in (0x1, 0x2):
            output.extend(payload)
            if len(output) > 262144:
                raise RuntimeError("terminal output exceeded probe bound")
        if b"JW_TERMINAL_VM_OK" in output and b"40 100" in output:
            break
        if opcode == 0x8:
            break
    ws.close()
    if b"JW_TERMINAL_VM_OK" not in output or b"40 100" not in output:
        raise RuntimeError(
            "terminal evidence was missing command="
            + str(b"JW_TERMINAL_VM_OK" in output).lower()
            + " resize="
            + str(b"40 100" in output).lower()
        )
    replay_status, replay_ws = websocket(origin)
    if replay_ws is not None:
        replay_ws.close()
    if replay_status != 401:
        raise RuntimeError("consumed terminal ticket was reusable")
elif mode == "wrong_origin":
    rejected_status, rejected_ws = websocket("https://attacker.example")
    if rejected_ws is not None:
        rejected_ws.close()
    if rejected_status != 403:
        raise RuntimeError("wrong Origin was not rejected")
    status, ws = websocket(origin)
    if status != 101:
        raise RuntimeError("wrong Origin consumed the valid ticket")
    require_ready(ws)
    time.sleep(1.0)
    ws.send(0x1, json.dumps({"type": "input", "data": "exit\r"}, separators=(",", ":")))
    deadline = time.monotonic() + 12
    while True:
        opcode, _ = ws.receive(deadline)
        if opcode == 0x8:
            break
    ws.stream.close()
elif mode == "logout_revoke":
    status, ws = websocket(origin)
    if status != 101:
        raise RuntimeError("revocation terminal ticket did not upgrade")
    require_ready(ws)
    logout()
    deadline = time.monotonic() + 12
    reason = ""
    while True:
        opcode, payload = ws.receive(deadline)
        if opcode == 0x8:
            reason = payload[2:].decode("utf-8", "replace") if len(payload) >= 2 else ""
            break
    ws.stream.close()
    if reason != "session_revoked":
        raise RuntimeError("logout did not revoke the active terminal")
else:
    raise RuntimeError("unsupported terminal probe mode")

print("TERMINAL_PROBE_PASS")
"#;

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
dpkg-query -W -f='${{db:Status-Abbrev}}' openssh-client | grep -q '^ii'
test -x /usr/bin/ssh
test -x /usr/bin/setsid
test -x /usr/bin/stty
ldd /usr/lib/jw-agent/jw-authd | grep -q 'libpam\.so\.0'
ldd /usr/lib/jw-agent/jw-agentd | grep -q 'libsqlite3\.so\.0'
test -x /usr/lib/jw-agent/jw-certd
test -x /usr/lib/jw-agent/jw-edge
test -f /usr/lib/systemd/system/jw-edge.service
grep -Fq 'client_max_body_size 64k;' "$tmpdir/usr/share/jw-agent/nginx/jw-agent-management.conf.template"
grep -Fq 'location = /api/v1/files/upload {{' "$tmpdir/usr/share/jw-agent/nginx/jw-agent-management.conf.template"
grep -Fq 'client_max_body_size 8m;' "$tmpdir/usr/share/jw-agent/nginx/jw-agent-management.conf.template"
grep -Fq 'include /usr/share/jw-agent/nginx/acme-challenge.conf;' "$tmpdir/usr/share/jw-agent/nginx/jw-agent-management.conf.template"
grep -Fq 'd /var/lib/jw-agent 0751 root jw-agent -' "$tmpdir/usr/lib/tmpfiles.d/jw-agent.conf"
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
systemctl cat jw-opsd.service | grep -Fq 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK'
systemctl cat jw-opsd.service | grep -Fq 'ReadWritePaths=/run/jw-agent /var/lib/jw-agent/opsd /etc/nginx /etc/apache2 /etc/php/8.3/fpm -/etc/ufw'
systemctl cat jw-certd@.service | grep -Fq 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
! systemctl cat jw-certd@.service | grep -Fq 'IPAddressDeny=any'
systemctl cat jw-authd@.service | grep -Fq 'CollectMode=inactive-or-failed'
systemctl cat jw-certd@.service | grep -Fq 'CollectMode=inactive-or-failed'
systemctl cat jw-edge.service | grep -Fq 'User=jw-agent'
systemctl cat jw-edge.service | grep -Fq 'NoNewPrivileges=yes'
systemctl cat jw-edge.service | grep -Fq 'ProtectSystem=strict'
systemctl cat jw-edge.service | grep -Fq 'CapabilityBoundingSet='
sudo test -S /run/jw-agent/authd.sock
sudo test -S /run/jw-agent-certd/certd.sock
sudo test -S /run/jw-agent/opsd.sock
sudo test -S /run/jw-agent-proxy/agentd.sock
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent/authd.sock)" = jw-agent:jw-agent:600
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent-certd/certd.sock)" = root:root:600
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent/opsd.sock)" = root:jw-agent:660
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent)" = root:jw-agent:2750
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent/askpass)" = jw-agent:jw-agent:700
test "$(sudo stat -c '%U:%G:%a' /etc/jw-agent/ssh_known_hosts)" = root:root:644
sudo grep -Eq '^jw-agent-loopback[[:space:]]+ssh-ed25519[[:space:]]+' /etc/jw-agent/ssh_known_hosts
test "$(sudo stat -c '%U:%G:%a' /var/lib/jw-agent/opsd)" = root:root:700
test "$(sudo stat -c '%U:%G:%a' /var/lib/jw-agent/opsd/snapshots)" = root:root:700
test "$(sudo stat -c '%U:%G:%a' /var/lib/jw-agent/opsd/opsd.sqlite3)" = root:jw-agent:600
test "$(sudo stat -c '%U:%G:%a' /var/lib/jw-agent)" = root:jw-agent:751
test "$(sudo stat -c '%U:%G:%a' /var/lib/jw-agent/acme-webroot)" = root:root:755
sudo -u www-data test -x /var/lib/jw-agent
sudo -u www-data test -x /var/lib/jw-agent/acme-webroot
test "$(stat -c '%U:%G:%a' /run/jw-agent-proxy)" = jw-agent:jw-agent-proxy:2750
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent-proxy/agentd.sock)" = jw-agent:jw-agent-proxy:660
id -nG jw-agent | tr ' ' '\n' | grep -Fxq jw-agent-proxy
id -nG www-data | tr ' ' '\n' | grep -Fxq jw-agent-proxy
agent_pid=$(systemctl show -p MainPID --value jw-agentd.service)
ops_pid=$(systemctl show -p MainPID --value jw-opsd.service)
test "$agent_pid" -gt 1
test "$ops_pid" -gt 1
test "$(awk '/^CapEff:/{print $2}' "/proc/$agent_pid/status")" = 0000000000000000
test "$(awk '/^CapEff:/{print $2}' "/proc/$ops_pid/status")" = 0000000000001400
test "$(systemctl show -p PrivateNetwork --value jw-opsd.service)" = no
! sudo ss -H -ltnup | grep -F 'jw-opsd'
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
    let reset = config.ssh(RESTART_AGENTD_READY, None, timeout)?;
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
    let reset = config.ssh(RESTART_AGENTD_READY, None, timeout)?;
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
        session.enter_administrative(&config, &password, timeout)?;
        session.require_management_site_protected(&config, timeout)?;
        let enabled = session.operate(&config, P2_VALID_SITE, "enabled", timeout)?;
        require_terminal(&enabled, "SUCCEEDED", "valid site enable")?;
        let runtime = config.ssh(
        "sudo test -L /etc/nginx/sites-enabled/jw-agent-vm-operation.conf && sudo systemctl is-active --quiet nginx.service",
        None,
        timeout,
        )?;
        require_success(&runtime, "enabled Nginx fixture", false)?;

        let noop = session.operate(&config, P2_VALID_SITE, "enabled", timeout)?;
        require_terminal(&noop, "SUCCEEDED", "already-target no-op")?;
        if !noop.contains("\"resultCode\":\"verified_noop\"") {
            return Err(String::from("no-op receipt omitted verified_noop evidence"));
        }

        let disabled = session.operate(&config, P2_VALID_SITE, "disabled", timeout)?;
        require_terminal(&disabled, "SUCCEEDED", "valid site disable")?;
        require_link_absent(&config, P2_VALID_SITE, timeout)?;
        restart_edge_and_agentd_and_wait(&config, timeout)?;

        let syntax_rollback = session.operate(&config, P2_INVALID_SITE, "enabled", timeout)?;
        require_terminal(&syntax_rollback, "ROLLED_BACK", "syntax failure rollback")?;
        require_link_absent(&config, P2_INVALID_SITE, timeout)?;

        install_reload_fail_once(&config, timeout)?;
        let reload_rollback = session.operate(&config, P2_VALID_SITE, "enabled", timeout)?;
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
        let disk_guard = session.operate(&config, P2_VALID_SITE, "enabled", timeout)?;
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

pub fn gate_p2_certificate_inventory(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    let cleanup = r#"sudo sh -eu -c '
rm -rf /etc/letsencrypt/live/jw-agent-p1.test /etc/letsencrypt/archive/jw-agent-p1.test
rm -f /etc/letsencrypt/renewal/jw-agent-p1.test.conf
'"#;
    let before = config.ssh(cleanup, None, timeout)?;
    require_success(&before, "certificate inventory fixture cleanup", false)?;
    let result = (|| {
        let setup = r#"sudo sh -eu -c '
mkdir -p /etc/letsencrypt/live/jw-agent-p1.test /etc/letsencrypt/archive/jw-agent-p1.test /etc/letsencrypt/renewal
install -o root -g root -m 0644 /etc/jw-agent/tls/server.crt /etc/letsencrypt/archive/jw-agent-p1.test/cert1.pem
install -o root -g root -m 0644 /etc/jw-agent/tls/server.crt /etc/letsencrypt/archive/jw-agent-p1.test/chain1.pem
install -o root -g root -m 0644 /etc/jw-agent/tls/server.crt /etc/letsencrypt/archive/jw-agent-p1.test/fullchain1.pem
install -o root -g root -m 0600 /etc/jw-agent/tls/server.key /etc/letsencrypt/archive/jw-agent-p1.test/privkey1.pem
ln -s ../../archive/jw-agent-p1.test/cert1.pem /etc/letsencrypt/live/jw-agent-p1.test/cert.pem
ln -s ../../archive/jw-agent-p1.test/chain1.pem /etc/letsencrypt/live/jw-agent-p1.test/chain.pem
ln -s ../../archive/jw-agent-p1.test/fullchain1.pem /etc/letsencrypt/live/jw-agent-p1.test/fullchain.pem
ln -s ../../archive/jw-agent-p1.test/privkey1.pem /etc/letsencrypt/live/jw-agent-p1.test/privkey.pem
printf "%s\n" "version = 2.9.0" "archive_dir = /etc/letsencrypt/archive/jw-agent-p1.test" "cert = /etc/letsencrypt/live/jw-agent-p1.test/cert.pem" "privkey = /etc/letsencrypt/live/jw-agent-p1.test/privkey.pem" "chain = /etc/letsencrypt/live/jw-agent-p1.test/chain.pem" "fullchain = /etc/letsencrypt/live/jw-agent-p1.test/fullchain.pem" "[renewalparams]" "authenticator = webroot" "webroot_path = /var/lib/jw-agent/acme-webroot" > /etc/letsencrypt/renewal/jw-agent-p1.test.conf
chmod 0600 /etc/letsencrypt/renewal/jw-agent-p1.test.conf
'"#;
        let installed = config.ssh(setup, None, timeout)?;
        require_success(&installed, "certificate inventory fixture install", false)?;
        let restarted = config.ssh(
            "sudo systemctl restart jw-opsd.service jw-agentd.service",
            None,
            timeout,
        )?;
        require_success(&restarted, "certificate inventory service restart", false)?;
        wait_for_public_agent(&config, timeout)?;
        let session = P2ApiSession::login(&config, &password, timeout)?;
        let inventory = session.get(&config, "/api/v1/certificates", timeout)?;
        expect_http(&inventory, 200, "certificate inventory")?;
        for expected in [
            "\"primaryDomain\":\"jw-agent-p1.test\"",
            "\"privateKeyPresent\":true",
            "\"renewalConfigPresent\":true",
            "\"webrootManaged\":true",
            "\"timerEnabled\":true",
            "\"timerActive\":true",
            "\"fingerprintSha256\":\"sha256:",
            "…/live/jw-agent-p1.test/fullchain.pem",
        ] {
            if !inventory.body.contains(expected) {
                return Err(format!("certificate inventory omitted {expected}"));
            }
        }
        for forbidden in ["/etc/letsencrypt", "BEGIN PRIVATE KEY", "server.key"] {
            if inventory.body.contains(forbidden) {
                return Err(format!("certificate inventory exposed {forbidden}"));
            }
        }
        let escaped = config.ssh(
            "sudo ln -sfn /etc/passwd /etc/letsencrypt/live/jw-agent-p1.test/fullchain.pem",
            None,
            timeout,
        )?;
        require_success(&escaped, "certificate escaped target fixture", false)?;
        let rejected = session.get(&config, "/api/v1/certificates", timeout)?;
        expect_http(&rejected, 200, "certificate escaped target rejection")?;
        if !rejected
            .body
            .contains("certificate_invalid:jw-agent-p1.test")
            || rejected
                .body
                .contains("\"primaryDomain\":\"jw-agent-p1.test\"")
            || rejected.body.contains("/etc/passwd")
        {
            return Err(String::from(
                "escaped certificate target was not rejected without path disclosure",
            ));
        }
        Ok(())
    })();
    let cleaned = config.ssh(cleanup, None, timeout);
    match (result, cleaned) {
        (Ok(()), Ok(cleanup_result)) => require_success(
            &cleanup_result,
            "certificate inventory fixture cleanup",
            false,
        ),
        (Err(error), Ok(cleanup_result)) => match require_success(
            &cleanup_result,
            "certificate inventory fixture cleanup",
            false,
        ) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(format!(
                "{error}; certificate cleanup also failed: {cleanup_error}"
            )),
        },
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; certificate cleanup also failed: {cleanup_error}"
        )),
    }
}

pub fn gate_p2_certbot_renew_operation(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    let prepared = config.ssh(
        "sudo systemctl enable --now certbot.timer\nsudo systemctl restart jw-certd.socket jw-opsd.service jw-agentd.service",
        None,
        timeout,
    )?;
    require_success(&prepared, "Certbot renewal operation preparation", false)?;
    wait_for_public_agent(&config, timeout)?;
    let result = (|| {
        let mut session = P2ApiSession::login(&config, &password, timeout)?;
        session.enter_administrative(&config, &password, timeout)?;
        let success = session.operate_certbot_renew_test(&config, &password, timeout)?;
        require_terminal(&success, "SUCCEEDED", "Certbot renewal dry-run")?;
        for evidence in [
            "\"resultCode\":\"certbot_renew_dry_run_started\"",
            "\"resultCode\":\"certbot_renew_dry_run_completed\"",
            "\"resultCode\":\"renewal_test_verified\"",
        ] {
            if !success.contains(evidence) {
                return Err(format!("Certbot renewal receipt omitted {evidence}"));
            }
        }
        for forbidden in [
            "No renewals were attempted",
            "/etc/letsencrypt",
            "BEGIN PRIVATE KEY",
            "accountEmail",
        ] {
            if success.contains(forbidden) {
                return Err(format!("Certbot renewal receipt exposed {forbidden}"));
            }
        }
        let snapshot = config.ssh(
            "sudo find /var/lib/jw-agent/opsd/snapshots -type f -name certificate-inventory.json -user root -perm 0600 -print -quit | grep -q .\n! sudo strings /var/lib/jw-agent/opsd/opsd.sqlite3 | grep -Fq 'No renewals were attempted'\n! sudo journalctl -u jw-opsd.service -u jw-agentd.service -u 'jw-certd@*.service' --no-pager -o cat | grep -Fq 'No renewals were attempted'\n! pgrep -x jw-certd >/dev/null\n! find /run/jw-agent-certd -maxdepth 1 -type f -name 'request-*.ini' | grep -q .",
            None,
            timeout,
        )?;
        require_success(&snapshot, "Certbot renewal evidence boundary", false)?;

        let disabled = config.ssh("sudo systemctl disable --now certbot.timer", None, timeout)?;
        require_success(&disabled, "Certbot timer failure fixture", false)?;
        let failure = session.operate_certbot_renew_test(&config, &password, timeout)?;
        require_terminal(&failure, "REJECTED", "Certbot unhealthy timer rejection")?;
        if !failure.contains("\"resultCode\":\"renewal_timer_unhealthy\"")
            || failure.contains("\"rollbackResult\":\"verified\"")
        {
            return Err(String::from(
                "Certbot timer failure was missing or falsely reported as rolled back",
            ));
        }
        Ok(())
    })();
    let restored = config.ssh(
        "sudo systemctl enable --now certbot.timer\nsudo systemctl restart jw-certd.socket jw-opsd.service jw-agentd.service",
        None,
        timeout,
    );
    match (result, restored) {
        (Ok(()), Ok(output)) => {
            require_success(&output, "Certbot renewal operation cleanup", false)
        }
        (Err(error), Ok(output)) => {
            match require_success(&output, "Certbot renewal operation cleanup", false) {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!(
                    "{error}; Certbot renewal cleanup also failed: {cleanup_error}"
                )),
            }
        }
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; Certbot renewal cleanup also failed: {cleanup_error}"
        )),
    }
}

pub fn gate_p2_certbot_issue_failure(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    cleanup_certbot_issue_fixture(&config, timeout)?;
    let result = (|| {
        prepare_certbot_issue_fixture(&config, timeout)?;
        wait_for_public_agent(&config, timeout)?;
        let mut session = P2ApiSession::login(&config, &password, timeout)?;
        session.enter_administrative(&config, &password, timeout)?;
        let receipt = session.operate_certbot_issue_staging_failure(
            &config,
            &password,
            "jw-agent-vm-certbot@example.com",
            timeout,
        )?;
        require_terminal(&receipt, "REJECTED", "Certbot staging issuance failure")?;
        for expected in [
            "\"resultCode\":\"certbot_staging_dry_run_started\"",
            "\"resultCode\":\"certbot_issue_command_failed\"",
            "\"resultCode\":\"issuance_failed\"",
            "\"rollbackSupport\":\"not_guaranteed\"",
        ] {
            if !receipt.contains(expected) {
                return Err(format!("Certbot issue failure receipt omitted {expected}"));
            }
        }
        if receipt.contains("jw-agent-vm-certbot@example.com")
            || receipt.contains("\"rollbackResult\":\"verified\"")
        {
            return Err(String::from(
                "Certbot issue failure exposed the account email or claimed a false rollback",
            ));
        }
        let inventory = session.get(&config, "/api/v1/certificates", timeout)?;
        expect_http(&inventory, 200, "post-failure certificate inventory")?;
        if json_string_field(&inventory.body, "inventoryDigest")?
            != json_string_field(&receipt, "beforeDigest")?
            || inventory.body.contains(&format!(
                "\"primaryDomain\":{}",
                json_string(&config.public_host)
            ))
        {
            return Err(String::from(
                "failed staging issuance changed the certificate inventory",
            ));
        }
        let evidence = config.ssh(
            r#"set -eu
sudo find /var/lib/jw-agent/opsd/snapshots -type f -name certificate-inventory.json -user root -perm 0600 -print -quit | grep -q .
! sudo sh -c 'find /var/lib/jw-agent/opsd -maxdepth 1 -type f -name "opsd.sqlite3*" -print0 | xargs -0 -r strings' | grep -Fq 'jw-agent-vm-certbot@example.com'
! sudo journalctl -u jw-opsd.service -u jw-agentd.service -u 'jw-certd@*.service' --no-pager -o cat | grep -Fq 'jw-agent-vm-certbot@example.com'
! sudo find /var/lib/jw-agent/opsd/proposals -type f -print -quit | grep -q .
! pgrep -x jw-certd >/dev/null
! find /run/jw-agent-certd -maxdepth 1 -type f -name 'request-*.ini' | grep -q .
! sudo test -e /etc/letsencrypt/renewal/jw-agent-p1.test.conf"#,
            None,
            timeout,
        )?;
        require_success(&evidence, "Certbot issue failure evidence boundary", false)
    })();
    let cleanup = cleanup_certbot_issue_fixture(&config, timeout);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; Certbot issue fixture cleanup also failed: {cleanup_error}"
        )),
    }
}

pub fn gate_p2_certbot_attach_operation(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    cleanup_certbot_attach_fixture(&config, timeout)?;
    let result = (|| {
        prepare_certbot_attach_fixture(&config, timeout)?;
        wait_for_public_agent(&config, timeout)?;
        thread::sleep(Duration::from_secs(7));
        let mut session = P2ApiSession::login(&config, &password, timeout)?;
        session.enter_administrative(&config, &password, timeout)?;
        let success = session.operate_certbot_attach(&config, &password, timeout)?;
        require_terminal(&success.receipt, "SUCCEEDED", "Certbot Nginx TLS attach")?;
        for expected in [
            "\"level\":\"g2_reversible_config\"",
            "\"rollbackSupport\":\"automatic_bounded\"",
            "\"resultCode\":\"tls_directives_replaced\"",
            "\"resultCode\":\"nginx_config_valid\"",
            "\"resultCode\":\"nginx_reloaded\"",
            "\"resultCode\":\"tls_attachment_verified\"",
        ] {
            if !success.receipt.contains(expected) {
                return Err(format!("Certbot attach receipt omitted {expected}"));
            }
        }
        if json_string_field(&success.receipt, "beforeDigest")? != success.site_digest {
            return Err(String::from(
                "Certbot attach receipt did not bind its before digest to the protected config",
            ));
        }
        let runtime = config.ssh(
            &format!(
                "sudo grep -Fxq '    ssl_certificate /etc/letsencrypt/live/{}/fullchain.pem;' /etc/nginx/sites-available/jw-agent-p1\nsudo grep -Fxq '    ssl_certificate_key /etc/letsencrypt/live/{}/privkey.pem;' /etc/nginx/sites-available/jw-agent-p1\nsudo systemctl is-active --quiet nginx.service\nprintf '' | openssl s_client -connect 127.0.0.1:443 -servername {} 2>/dev/null | openssl x509 -outform DER | sha256sum",
                config.public_host, config.public_host, config.public_host,
            ),
            None,
            timeout,
        )?;
        require_success(&runtime, "Certbot attach TLS runtime", false)?;
        let runtime_fingerprint = text(&runtime.stdout)?
            .split_whitespace()
            .next()
            .ok_or_else(|| String::from("TLS runtime fingerprint missing"))?;
        if format!("sha256:{runtime_fingerprint}") != success.certificate_fingerprint {
            return Err(String::from(
                "loopback SNI certificate fingerprint did not match the planned lineage",
            ));
        }

        restore_certbot_attach_baseline(&config, timeout)?;
        install_certbot_attach_tls_fault(&config, timeout)?;
        let rolled_back = session.operate_certbot_attach(&config, &password, timeout)?;
        require_terminal(
            &rolled_back.receipt,
            "ROLLED_BACK",
            "Certbot attach TLS verifier rollback",
        )?;
        for expected in [
            "\"resultCode\":\"tls_read_back_failed\"",
            "\"resultCode\":\"rollback_verified\"",
            "\"rollbackResult\":\"verified\"",
        ] {
            if !rolled_back.receipt.contains(expected) {
                return Err(format!(
                    "Certbot attach rollback receipt omitted {expected}"
                ));
            }
        }
        let restored = config.ssh(
            "sudo cmp -s /etc/nginx/sites-available/jw-agent-p1 /var/tmp/jw-agent-vm-certbot-attach.nginx\nsudo nginx -t\nsudo systemctl is-active --quiet nginx.service\nsudo find /var/lib/jw-agent/opsd/snapshots -type f -name managed-config.json -user root -perm 0600 -print -quit | grep -q .\n! sudo sh -c 'find /var/lib/jw-agent/opsd -maxdepth 1 -type f -name \"opsd.sqlite3*\" -print0 | xargs -0 -r strings' | grep -Fq 'BEGIN CERTIFICATE'\n! sudo journalctl -u jw-opsd.service -u jw-agentd.service -u 'jw-certd@*.service' --no-pager -o cat | grep -Fq 'BEGIN CERTIFICATE'\n! pgrep -x jw-certd >/dev/null",
            None,
            timeout,
        )?;
        require_success(&restored, "Certbot attach exact rollback evidence", false)
    })();
    let cleanup = cleanup_certbot_attach_fixture(&config, timeout);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; Certbot attach fixture cleanup also failed: {cleanup_error}"
        )),
    }
}

pub fn gate_p2_openssh_terminal(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    restart_edge_and_agentd_and_wait(&config, timeout)?;
    let runtime = config.ssh(
        &format!(r#"set -eu
systemctl is-active --quiet ssh.service
test "$(sudo stat -c '%U:%G:%a' /etc/jw-agent/ssh_known_hosts)" = root:root:644
test "$(sudo stat -c '%U:%G:%a' /run/jw-agent/askpass)" = jw-agent:jw-agent:700
sudo grep -Eq '^jw-agent-loopback[[:space:]]+ssh-ed25519[[:space:]]+' /etc/jw-agent/ssh_known_hosts
test -x /usr/bin/ssh
test -x /usr/bin/setsid
test -x /usr/bin/stty
sudo /usr/sbin/sshd -T -C user={},addr=127.0.0.1,laddr=127.0.0.1,host=localhost | grep -Fxq 'passwordauthentication yes'
sudo /usr/sbin/sshd -T -C user={},addr={},laddr={},host=localhost | grep -Fxq 'passwordauthentication no'"#,
            config.admin_user,
            config.admin_user,
            config.public_address,
            config.public_address,
        ),
        None,
        timeout,
    )?;
    require_success(&runtime, "OpenSSH terminal runtime authority", false)?;

    let session = P2ApiSession::login(&config, &password, timeout)?;
    let capability = session.get(&config, "/api/v1/terminal", timeout)?;
    expect_http(&capability, 200, "terminal capability")?;
    for expected in [
        "\"available\":true",
        "\"level\":\"g1_verified_action\"",
        "\"rollbackSupport\":\"not_guaranteed\"",
        "\"ticketTtlSeconds\":30",
        "\"idleTimeoutSeconds\":0",
        "\"maxLifetimeSeconds\":0",
        "\"maxFrameBytes\":16384",
        "\"maxSessionsPerUser\":1",
    ] {
        if !capability.body.contains(expected) {
            return Err(format!("terminal capability omitted {expected}"));
        }
    }
    let cookie = session.public_cookie_header()?;

    let success_ticket = session.issue_terminal_ticket(&config, &password, timeout)?;
    run_terminal_websocket_probe(
        &config,
        &cookie,
        &session.csrf_token,
        &success_ticket,
        "success_replay",
        timeout,
    )?;
    thread::sleep(Duration::from_millis(250));

    let origin_ticket = session.issue_terminal_ticket(&config, &password, timeout)?;
    run_terminal_websocket_probe(
        &config,
        &cookie,
        &session.csrf_token,
        &origin_ticket,
        "wrong_origin",
        timeout,
    )?;
    thread::sleep(Duration::from_millis(250));

    let revoke_ticket = session.issue_terminal_ticket(&config, &password, timeout)?;
    run_terminal_websocket_probe(
        &config,
        &cookie,
        &session.csrf_token,
        &revoke_ticket,
        "logout_revoke",
        timeout,
    )?;

    let evidence = config.ssh(
        r#"set -eu
attempt=0
while test "$attempt" -lt 50; do
    if ! pgrep -u jw-agent -f '/usr/bin/(ssh|setsid)' >/dev/null 2>&1 && ! sudo find /run/jw-agent/askpass -mindepth 1 -print -quit | grep -q .; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
! pgrep -u jw-agent -f '/usr/bin/(ssh|setsid)' >/dev/null 2>&1
! sudo find /run/jw-agent/askpass -mindepth 1 -print -quit | grep -q .
sudo python3 -c 'import sqlite3; c=sqlite3.connect("/var/lib/jw-agent/agentd/agentd.sqlite3"); rows=c.execute("select state,close_reason,bytes_in,bytes_out from terminal_sessions order by started_at_unix_ms desc limit 3").fetchall(); assert len(rows)==3; assert all(r[0]=="closed" for r in rows); assert any(r[1]=="session_revoked" for r in rows); assert any(r[2]>0 and r[3]>0 for r in rows); names={r[1] for r in c.execute("pragma table_info(terminal_sessions)")}; assert not names.intersection({"command","input","output","password","ticket"})'
systemctl is-active --quiet ssh.service
sudo journalctl -u jw-agentd.service --since '10 minutes ago' --no-pager -o cat | grep -Fq 'reason=session_revoked'"#,
        None,
        timeout,
    )?;
    require_success(&evidence, "OpenSSH terminal audit and cleanup", false)
}

pub fn gate_p2_openssh_sftp_readonly(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    restart_edge_and_agentd_and_wait(&config, timeout)?;
    let fixture_command = format!(
        r#"set -eu
admin_home="$(getent passwd -- {admin} | cut -d: -f6)"
test -n "$admin_home"
case "$admin_home" in /*) ;; *) exit 1 ;; esac
fixture="$admin_home/jw-agent-sftp-fixture"
sudo rm -rf -- "$fixture"
sudo -H -u {admin} mkdir -p "$fixture/subdirectory"
printf 'JW_SFTP_READ_ONLY_VM_OK\nsecond line\n' | sudo -H -u {admin} tee "$fixture/readme.txt" >/dev/null
printf 'nested\n' | sudo -H -u {admin} tee "$fixture/subdirectory/nested.txt" >/dev/null
sudo -H -u {admin} python3 -c 'from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(b"x" * (300 * 1024))' "$fixture/large-text.txt"
sudo -H -u {admin} python3 -c 'from pathlib import Path; import sys; f=Path(sys.argv[1]).open("wb"); f.truncate(9 * 1024 * 1024); f.close()' "$fixture/large-download.bin"
sudo -H -u {admin} ln -s /etc "$fixture/outside-link"
sudo -H -u {admin} chmod 0700 "$fixture" "$fixture/subdirectory"
sudo -H -u {admin} chmod 0600 "$fixture/readme.txt" "$fixture/subdirectory/nested.txt" "$fixture/large-text.txt" "$fixture/large-download.bin""#,
        admin = config.admin_user
    );
    let prepared = config.ssh(&fixture_command, None, timeout)?;
    require_success(&prepared, "SFTP home fixture preparation", false)?;

    let result = (|| {
        let session = P2ApiSession::login(&config, &password, timeout)?;
        let capability = session.get(&config, "/api/v1/files", timeout)?;
        expect_http(&capability, 200, "SFTP read-only capability")?;
        for expected in [
            "\"available\":true",
            "\"level\":\"g0_observe_only\"",
            "\"rollbackSupport\":\"not_applicable\"",
            "\"rootLabel\":\"~\"",
            "\"idleTimeoutSeconds\":0",
            "\"maxLifetimeSeconds\":0",
            "\"maxListEntries\":500",
            "\"maxTextBytes\":262144",
            "\"maxDownloadBytes\":8388608",
            "\"maxSessionsPerUser\":1",
        ] {
            if !capability.body.contains(expected) {
                return Err(format!("SFTP capability omitted {expected}"));
            }
        }

        let token = session.create_file_session(&config, &password, timeout)?;
        let root = session.file_request(&config, "list", &token, "", timeout)?;
        expect_http(&root, 200, "SFTP home list")?;
        if !root.body.contains("\"name\":\"jw-agent-sftp-fixture\"")
            || root.body.contains("\"path\":\"/")
        {
            return Err(String::from(
                "SFTP root listing missed the fixture or exposed an absolute home path",
            ));
        }
        let listing =
            session.file_request(&config, "list", &token, "jw-agent-sftp-fixture", timeout)?;
        expect_http(&listing, 200, "SFTP fixture list")?;
        for expected in [
            "\"name\":\"subdirectory\"",
            "\"name\":\"readme.txt\"",
            "\"name\":\"outside-link\"",
            "\"kind\":\"symbolic_link\"",
        ] {
            if !listing.body.contains(expected) {
                return Err(format!("SFTP fixture listing omitted {expected}"));
            }
        }
        let stat = session.file_request(
            &config,
            "stat",
            &token,
            "jw-agent-sftp-fixture/readme.txt",
            timeout,
        )?;
        expect_http(&stat, 200, "SFTP file stat")?;
        if !stat.body.contains("\"kind\":\"regular\"")
            || !stat
                .body
                .contains("\"path\":\"jw-agent-sftp-fixture/readme.txt\"")
        {
            return Err(String::from("SFTP stat returned an unexpected identity"));
        }
        let text = session.file_request(
            &config,
            "read",
            &token,
            "jw-agent-sftp-fixture/readme.txt",
            timeout,
        )?;
        expect_http(&text, 200, "SFTP bounded text read")?;
        if !text
            .body
            .contains("JW_SFTP_READ_ONLY_VM_OK\\nsecond line\\n")
            || !text.body.contains("\"lineEnding\":\"lf\"")
            || !text.body.contains("\"digest\":\"sha256:")
        {
            return Err(String::from("SFTP text read omitted content metadata"));
        }
        let download = session.file_request(
            &config,
            "download",
            &token,
            "jw-agent-sftp-fixture/readme.txt",
            timeout,
        )?;
        expect_http(&download, 200, "SFTP bounded download")?;
        if !download.body.contains("JW_SFTP_READ_ONLY_VM_OK") {
            return Err(String::from("SFTP download body did not match the fixture"));
        }

        for (path, expected_status, label) in [
            ("../etc/passwd", 400, "traversal"),
            ("/etc/passwd", 400, "absolute path"),
            (
                "jw-agent-sftp-fixture/outside-link/passwd",
                403,
                "symlink escape",
            ),
        ] {
            let denied = session.file_request(&config, "read", &token, path, timeout)?;
            expect_http(&denied, expected_status, &format!("SFTP {label} denial"))?;
        }
        let large_text = session.file_request(
            &config,
            "read",
            &token,
            "jw-agent-sftp-fixture/large-text.txt",
            timeout,
        )?;
        expect_http(&large_text, 413, "SFTP text size denial")?;
        let large_download = session.file_request(
            &config,
            "download",
            &token,
            "jw-agent-sftp-fixture/large-download.bin",
            timeout,
        )?;
        expect_http(&large_download, 413, "SFTP download size denial")?;

        let wrong_origin = session.file_request_with_origin(
            &config,
            "list",
            &token,
            "jw-agent-sftp-fixture",
            "https://wrong-origin.invalid",
            timeout,
        )?;
        expect_http(&wrong_origin, 403, "SFTP wrong Origin denial")?;
        let after_origin =
            session.file_request(&config, "list", &token, "jw-agent-sftp-fixture", timeout)?;
        expect_http(&after_origin, 200, "SFTP session after wrong Origin")?;

        let other = P2ApiSession::login(&config, &password, timeout)?;
        let cross_session =
            other.file_request(&config, "list", &token, "jw-agent-sftp-fixture", timeout)?;
        expect_http(&cross_session, 401, "SFTP cross-session denial")?;

        session.close_file_session(&config, &token, timeout)?;
        let replay =
            session.file_request(&config, "list", &token, "jw-agent-sftp-fixture", timeout)?;
        expect_http(&replay, 401, "closed SFTP session replay denial")?;

        let revoked_token = session.create_file_session(&config, &password, timeout)?;
        let before_logout = session.file_request(
            &config,
            "list",
            &revoked_token,
            "jw-agent-sftp-fixture",
            timeout,
        )?;
        expect_http(&before_logout, 200, "SFTP session before logout")?;
        session.logout(&config, timeout)?;

        let evidence = config.ssh(
            r#"set -eu
attempt=0
while test "$attempt" -lt 50; do
    if ! pgrep -u jw-agent -f '/usr/bin/ssh' >/dev/null 2>&1 && ! sudo find /run/jw-agent/askpass -mindepth 1 -print -quit | grep -q .; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
! pgrep -u jw-agent -f '/usr/bin/ssh' >/dev/null 2>&1
! sudo find /run/jw-agent/askpass -mindepth 1 -print -quit | grep -q .
sudo python3 -c 'import sqlite3; c=sqlite3.connect("/var/lib/jw-agent/agentd/agentd.sqlite3"); rows=c.execute("select state,close_reason from file_sessions order by started_at_unix_ms desc limit 2").fetchall(); assert len(rows)==2; assert all(r[0]=="closed" for r in rows); assert {r[1] for r in rows}=={"user_closed","session_revoked"}; events=c.execute("select action,length(path_digest),byte_count,result from file_access_events where session_id in (select session_id from file_sessions order by started_at_unix_ms desc limit 2)").fetchall(); assert events; assert all(r[1]==32 for r in events); assert {r[0] for r in events}.issuperset({"list","stat","read","download"}); names={r[1] for r in c.execute("pragma table_info(file_access_events)")}; assert not names.intersection({"path","content","password","token","file_body"})'
! sudo sh -c 'find /var/lib/jw-agent/agentd -maxdepth 1 -type f -name "agentd.sqlite3*" -print0 | xargs -0 -r strings' | grep -Fq 'jw-agent-sftp-fixture'
! sudo sh -c 'find /var/lib/jw-agent/agentd -maxdepth 1 -type f -name "agentd.sqlite3*" -print0 | xargs -0 -r strings' | grep -Fq 'JW_SFTP_READ_ONLY_VM_OK'
! sudo journalctl -u jw-agentd.service --since '10 minutes ago' --no-pager -o cat | grep -Fq 'JW_SFTP_READ_ONLY_VM_OK'
systemctl is-active --quiet ssh.service
sudo /usr/sbin/sshd -T -C user="$USER",addr=127.0.0.1,laddr=127.0.0.1,host=localhost | grep -Fxq 'passwordauthentication yes'"#,
            None,
            timeout,
        )?;
        require_success(&evidence, "OpenSSH SFTP read-only audit and cleanup", false)
    })();

    let cleanup_command = format!(
        r#"set -eu
admin_home="$(getent passwd -- {admin} | cut -d: -f6)"
test -n "$admin_home"
case "$admin_home" in /*) ;; *) exit 1 ;; esac
sudo rm -rf -- "$admin_home/jw-agent-sftp-fixture""#,
        admin = config.admin_user
    );
    let cleanup = config.ssh(&cleanup_command, None, timeout);
    let cleanup =
        cleanup.and_then(|result| require_success(&result, "SFTP home fixture cleanup", false));
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; SFTP fixture cleanup also failed: {cleanup_error}"
        )),
    }
}

pub fn gate_p2_openssh_sftp_atomic_upload(_root: &Path, timeout: Duration) -> Result<(), String> {
    const CREATE: &[u8] = b"JW_SFTP_G1_CREATE_OK\n";
    const CREATE_DIGEST: &str =
        "sha256:e2f9121cfa02403f744a46631666b07a4c5517162888fc39a96db225da5fec94";
    const REPLACE: &[u8] = b"JW_SFTP_G1_REPLACE_OK\n";
    const REPLACE_DIGEST: &str =
        "sha256:883864d2696dfc6585c6feb4ceb9beb77865fda5db976f87613d289611c50dfd";
    const STALE: &[u8] = b"JW_SFTP_G1_STALE_PLAN\n";
    const STALE_DIGEST: &str =
        "sha256:b700aaae1c6e1c453f6f29d138c1e9f597ba96c20030d54094855158d3b616f9";
    const ORIGIN: &[u8] = b"JW_SFTP_G1_ORIGIN_OK\n";
    const ORIGIN_DIGEST: &str =
        "sha256:a0940e4b44b2bf792259b25f2688a27f16cba5c155e4595f0c43543340273a55";
    const DIGEST_OK: &[u8] = b"JW_SFTP_G1_DIGEST_OK\n";
    const DIGEST_OK_VALUE: &str =
        "sha256:ce1b2b30134dd725ebf6e9c2cff223d82e8965cc93942b25726eb05077368a20";
    const DIGEST_NO: &[u8] = b"JW_SFTP_G1_DIGEST_NO\n";

    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    restart_edge_and_agentd_and_wait(&config, timeout)?;
    let fixture_command = format!(
        r#"set -eu
admin_home="$(getent passwd -- {admin} | cut -d: -f6)"
test -n "$admin_home"
case "$admin_home" in /*) ;; *) exit 1 ;; esac
fixture="$admin_home/jw-agent-sftp-upload-fixture"
sudo rm -rf -- "$fixture"
sudo -H -u {admin} mkdir -p "$fixture/directory-target"
printf 'before\n' | sudo -H -u {admin} tee "$fixture/replace.txt" >/dev/null
printf 'stale-before\n' | sudo -H -u {admin} tee "$fixture/stale.txt" >/dev/null
sudo -H -u {admin} ln -s /etc/passwd "$fixture/symlink-target"
sudo -H -u {admin} chmod 0700 "$fixture" "$fixture/directory-target"
sudo -H -u {admin} chmod 0640 "$fixture/replace.txt" "$fixture/stale.txt"
sudo grep -Fq 'location = /api/v1/files/upload {{' /etc/nginx/sites-available/jw-agent-p1
sudo grep -Fq 'client_max_body_size 8m;' /etc/nginx/sites-available/jw-agent-p1
sudo nginx -t"#,
        admin = config.admin_user,
    );
    let prepared = config.ssh(&fixture_command, None, timeout)?;
    require_success(&prepared, "SFTP atomic upload fixture preparation", false)?;

    let result = (|| {
        let session = P2ApiSession::login(&config, &password, timeout)?;
        let capability = session.get(&config, "/api/v1/files", timeout)?;
        expect_http(&capability, 200, "SFTP G1 capability")?;
        for expected in [
            "\"level\":\"g1_verified_action\"",
            "\"rollbackSupport\":\"not_guaranteed\"",
            "\"maxUploadBytes\":8388608",
            "\"uploadPlanTtlSeconds\":120",
        ] {
            if !capability.body.contains(expected) {
                return Err(format!("SFTP G1 capability omitted {expected}"));
            }
        }

        let mut file_session = session.create_file_session(&config, &password, timeout)?;
        let base = "jw-agent-sftp-upload-fixture";

        let create_path = format!("{base}/created.txt");
        let create_plan = session.create_file_upload_plan(
            &config,
            FileUploadPlanInput {
                password: &password,
                file_session_token: &file_session,
                path: &create_path,
                content_bytes: CREATE.len(),
                content_digest: CREATE_DIGEST,
                overwrite_confirmed: false,
            },
            timeout,
        )?;
        let created =
            session.apply_file_upload(&config, &file_session, &create_plan, CREATE, timeout)?;
        expect_verified_upload(&created, &create_path, CREATE_DIGEST, "SFTP G1 create")?;
        let replay =
            session.apply_file_upload(&config, &file_session, &create_plan, CREATE, timeout)?;
        expect_http(&replay, 401, "SFTP G1 plan replay denial")?;

        let replace_path = format!("{base}/replace.txt");
        let missing_confirmation = session.file_upload_plan_request(
            &config,
            FileUploadPlanInput {
                password: &password,
                file_session_token: &file_session,
                path: &replace_path,
                content_bytes: REPLACE.len(),
                content_digest: REPLACE_DIGEST,
                overwrite_confirmed: false,
            },
            timeout,
        )?;
        expect_http(
            &missing_confirmation,
            409,
            "SFTP G1 overwrite confirmation denial",
        )?;
        let replace_plan = session.create_file_upload_plan(
            &config,
            FileUploadPlanInput {
                password: &password,
                file_session_token: &file_session,
                path: &replace_path,
                content_bytes: REPLACE.len(),
                content_digest: REPLACE_DIGEST,
                overwrite_confirmed: true,
            },
            timeout,
        )?;
        let replaced =
            session.apply_file_upload(&config, &file_session, &replace_plan, REPLACE, timeout)?;
        expect_verified_upload(&replaced, &replace_path, REPLACE_DIGEST, "SFTP G1 replace")?;

        let stale_path = format!("{base}/stale.txt");
        let stale_plan = session.create_file_upload_plan(
            &config,
            FileUploadPlanInput {
                password: &password,
                file_session_token: &file_session,
                path: &stale_path,
                content_bytes: STALE.len(),
                content_digest: STALE_DIGEST,
                overwrite_confirmed: true,
            },
            timeout,
        )?;
        let external = format!(
            "printf 'external-change\\n' | sudo -H -u {} tee \"$(getent passwd -- {} | cut -d: -f6)/{stale_path}\" >/dev/null",
            config.admin_user, config.admin_user,
        );
        let changed = config.ssh(&external, None, timeout)?;
        require_success(&changed, "SFTP stale target mutation fixture", false)?;
        let stale_apply =
            session.apply_file_upload(&config, &file_session, &stale_plan, STALE, timeout)?;
        expect_http(&stale_apply, 409, "SFTP stale target denial")?;
        if !stale_apply.body.contains("\"code\":\"target_changed\"") {
            return Err(String::from("SFTP stale target returned the wrong denial"));
        }

        session.close_file_session(&config, &file_session, timeout)?;
        restart_edge_and_agentd_and_wait(&config, timeout)?;
        file_session = session.create_file_session(&config, &password, timeout)?;

        for (path, expected_status, label) in [
            (format!("{base}/symlink-target"), 403, "symlink target"),
            (format!("{base}/directory-target"), 409, "directory target"),
            (String::from("../outside.txt"), 400, "traversal target"),
        ] {
            let denied = session.file_upload_plan_request(
                &config,
                FileUploadPlanInput {
                    password: &password,
                    file_session_token: &file_session,
                    path: &path,
                    content_bytes: CREATE.len(),
                    content_digest: CREATE_DIGEST,
                    overwrite_confirmed: true,
                },
                timeout,
            )?;
            expect_http(&denied, expected_status, &format!("SFTP G1 {label} denial"))?;
        }

        let digest_path = format!("{base}/digest-mismatch.txt");
        let digest_plan = session.create_file_upload_plan(
            &config,
            FileUploadPlanInput {
                password: &password,
                file_session_token: &file_session,
                path: &digest_path,
                content_bytes: DIGEST_OK.len(),
                content_digest: DIGEST_OK_VALUE,
                overwrite_confirmed: false,
            },
            timeout,
        )?;
        let digest_denied =
            session.apply_file_upload(&config, &file_session, &digest_plan, DIGEST_NO, timeout)?;
        expect_http(&digest_denied, 400, "SFTP G1 digest mismatch denial")?;

        session.close_file_session(&config, &file_session, timeout)?;
        restart_edge_and_agentd_and_wait(&config, timeout)?;
        file_session = session.create_file_session(&config, &password, timeout)?;

        let origin_path = format!("{base}/origin.txt");
        let origin_plan = session.create_file_upload_plan(
            &config,
            FileUploadPlanInput {
                password: &password,
                file_session_token: &file_session,
                path: &origin_path,
                content_bytes: ORIGIN.len(),
                content_digest: ORIGIN_DIGEST,
                overwrite_confirmed: false,
            },
            timeout,
        )?;
        let wrong_origin = session.apply_file_upload_with_origin(
            &config,
            &file_session,
            &origin_plan,
            ORIGIN,
            "https://wrong-origin.invalid",
            timeout,
        )?;
        expect_http(&wrong_origin, 403, "SFTP G1 wrong Origin denial")?;
        let origin_success =
            session.apply_file_upload(&config, &file_session, &origin_plan, ORIGIN, timeout)?;
        expect_verified_upload(
            &origin_success,
            &origin_path,
            ORIGIN_DIGEST,
            "SFTP G1 post-Origin apply",
        )?;

        session.close_file_session(&config, &file_session, timeout)?;
        let evidence_command = format!(
            r#"set -eu
admin_home="$(getent passwd -- {admin} | cut -d: -f6)"
fixture="$admin_home/jw-agent-sftp-upload-fixture"
test "$(sudo sha256sum -- "$fixture/created.txt" | awk '{{print $1}}')" = e2f9121cfa02403f744a46631666b07a4c5517162888fc39a96db225da5fec94
test "$(sudo sha256sum -- "$fixture/replace.txt" | awk '{{print $1}}')" = 883864d2696dfc6585c6feb4ceb9beb77865fda5db976f87613d289611c50dfd
test "$(sudo sha256sum -- "$fixture/stale.txt" | awk '{{print $1}}')" = 12961f0089ce2736dcc352e0e80f2a297b40c7dcee25ed2d8bb8b158d4715030
test "$(sudo sha256sum -- "$fixture/origin.txt" | awk '{{print $1}}')" = a0940e4b44b2bf792259b25f2688a27f16cba5c155e4595f0c43543340273a55
test "$(sudo stat -c %a "$fixture/created.txt")" = 600
test "$(sudo stat -c %a "$fixture/replace.txt")" = 640
test ! -e "$fixture/digest-mismatch.txt"
! sudo -H -u {admin} find "$fixture" -maxdepth 1 -name '.jw-agent-upload-*.tmp' -print -quit | grep -q .
attempt=0
while test "$attempt" -lt 50; do
    if ! pgrep -u jw-agent -f '/usr/bin/ssh' >/dev/null 2>&1 && ! sudo find /run/jw-agent/askpass -mindepth 1 -print -quit | grep -q .; then break; fi
    attempt=$((attempt + 1))
    sleep 0.1
done
! pgrep -u jw-agent -f '/usr/bin/ssh' >/dev/null 2>&1
! sudo find /run/jw-agent/askpass -mindepth 1 -print -quit | grep -q .
sudo python3 -c 'import sqlite3; c=sqlite3.connect("/var/lib/jw-agent/agentd/agentd.sqlite3"); sids=[r[0] for r in c.execute("select session_id from file_sessions order by started_at_unix_ms desc limit 3")]; rows=c.execute("select state,result,length(path_digest),target_state,byte_count from file_uploads where session_id in (?,?,?) order by planned_at_unix_ms",sids).fetchall(); assert len(rows)==5; assert sum(r[0]=="verified" for r in rows)==3; assert sum(r[0]=="failed" for r in rows)==2; assert all(r[2]==32 for r in rows); assert {{r[3] for r in rows}}=={{"create","replace"}}; assert not {{r[1] for r in rows}}.intersection({{"applying","planned","manual_check"}}); names={{r[1] for r in c.execute("pragma table_info(file_uploads)")}}; assert not names.intersection({{"path","content","password","token","temporary_path","file_body"}})'
! sudo sh -c 'find /var/lib/jw-agent/agentd -maxdepth 1 -type f -name "agentd.sqlite3*" -print0 | xargs -0 -r strings' | grep -Fq 'jw-agent-sftp-upload-fixture'
! sudo sh -c 'find /var/lib/jw-agent/agentd -maxdepth 1 -type f -name "agentd.sqlite3*" -print0 | xargs -0 -r strings' | grep -Fq 'JW_SFTP_G1_'
! sudo journalctl -u jw-agentd.service --since '10 minutes ago' --no-pager -o cat | grep -Fq 'JW_SFTP_G1_'
systemctl is-active --quiet ssh.service"#,
            admin = config.admin_user,
        );
        let evidence = config.ssh(&evidence_command, None, timeout)?;
        require_success(&evidence, "OpenSSH SFTP atomic upload evidence", false)
    })();

    let cleanup_command = format!(
        r#"set -eu
admin_home="$(getent passwd -- {admin} | cut -d: -f6)"
sudo rm -rf -- "$admin_home/jw-agent-sftp-upload-fixture""#,
        admin = config.admin_user,
    );
    let cleanup = config.ssh(&cleanup_command, None, timeout);
    let cleanup = cleanup
        .and_then(|value| require_success(&value, "SFTP atomic upload fixture cleanup", false));
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; SFTP atomic upload cleanup also failed: {cleanup_error}"
        )),
    }
}

fn expect_verified_upload(
    response: &HttpResponse,
    path: &str,
    digest: &str,
    label: &str,
) -> Result<(), String> {
    expect_http(response, 200, label)?;
    if !response
        .body
        .contains(&format!("\"path\":{}", json_string(path)))
        || !response.body.contains(digest)
        || !response.body.contains("\"level\":\"g1_verified_action\"")
        || !response
            .body
            .contains("\"rollbackSupport\":\"not_guaranteed\"")
    {
        return Err(format!("{label} omitted verified G1 read-back evidence"));
    }
    Ok(())
}

fn run_terminal_websocket_probe(
    config: &VmConfig,
    cookie: &str,
    csrf_token: &str,
    ticket: &str,
    mode: &str,
    timeout: Duration,
) -> Result<(), String> {
    if !matches!(mode, "success_replay" | "wrong_origin" | "logout_revoke") {
        return Err(String::from("unsupported terminal websocket probe mode"));
    }
    let input = format!(
        "{{\"address\":{},\"host\":{},\"ca\":{},\"cookie\":{},\"csrf\":{},\"ticket\":{},\"mode\":{}}}",
        json_string(&config.public_address.to_string()),
        json_string(&config.public_host),
        json_string(&config.ca_certificate.display().to_string()),
        json_string(cookie),
        json_string(csrf_token),
        json_string(ticket),
        json_string(mode),
    );
    let arguments = [OsString::from("-c"), OsString::from(TERMINAL_WS_PROBE)];
    let result = run_capture(
        OsStr::new("python3"),
        &arguments,
        Some(input.as_bytes()),
        timeout,
    )?;
    require_success(&result, "bounded terminal websocket probe", false)?;
    if text(&result.stdout)?.trim() != "TERMINAL_PROBE_PASS" {
        return Err(String::from(
            "bounded terminal websocket probe returned unexpected evidence",
        ));
    }
    Ok(())
}

fn prepare_certbot_attach_fixture(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let script = r#"sudo sh -eu -c '
test ! -e /var/tmp/jw-agent-vm-certbot-attach.active
cp -a /etc/nginx/sites-available/jw-agent-p1 /var/tmp/jw-agent-vm-certbot-attach.nginx
touch /var/tmp/jw-agent-vm-certbot-attach.active
mkdir -p /etc/letsencrypt/live/__HOST__ /etc/letsencrypt/archive/__HOST__ /etc/letsencrypt/renewal
install -o root -g root -m 0644 /etc/jw-agent/tls/server.crt /etc/letsencrypt/archive/__HOST__/cert1.pem
install -o root -g root -m 0644 /etc/jw-agent/tls/server.crt /etc/letsencrypt/archive/__HOST__/chain1.pem
install -o root -g root -m 0644 /etc/jw-agent/tls/server.crt /etc/letsencrypt/archive/__HOST__/fullchain1.pem
install -o root -g root -m 0600 /etc/jw-agent/tls/server.key /etc/letsencrypt/archive/__HOST__/privkey1.pem
ln -s ../../archive/__HOST__/cert1.pem /etc/letsencrypt/live/__HOST__/cert.pem
ln -s ../../archive/__HOST__/chain1.pem /etc/letsencrypt/live/__HOST__/chain.pem
ln -s ../../archive/__HOST__/fullchain1.pem /etc/letsencrypt/live/__HOST__/fullchain.pem
ln -s ../../archive/__HOST__/privkey1.pem /etc/letsencrypt/live/__HOST__/privkey.pem
printf "%s\n" "version = 2.9.0" "archive_dir = /etc/letsencrypt/archive/__HOST__" "cert = /etc/letsencrypt/live/__HOST__/cert.pem" "privkey = /etc/letsencrypt/live/__HOST__/privkey.pem" "chain = /etc/letsencrypt/live/__HOST__/chain.pem" "fullchain = /etc/letsencrypt/live/__HOST__/fullchain.pem" "[renewalparams]" "authenticator = webroot" "webroot_path = /var/lib/jw-agent/acme-webroot" > /etc/letsencrypt/renewal/__HOST__.conf
chmod 0600 /etc/letsencrypt/renewal/__HOST__.conf
systemctl enable --now certbot.timer
nginx -t
systemctl reload nginx.service
systemctl reset-failed jw-certd.socket jw-opsd.service jw-agentd.service
systemctl restart jw-certd.socket jw-opsd.service jw-agentd.service
'"#
        .replace("__HOST__", &config.public_host);
    let prepared = config.ssh(&script, None, timeout)?;
    require_success(&prepared, "Certbot attach fixture preparation", false)
}

fn restore_certbot_attach_baseline(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let restored = config.ssh(
        "sudo cp -a /var/tmp/jw-agent-vm-certbot-attach.nginx /etc/nginx/sites-available/jw-agent-p1\nsudo nginx -t\nsudo systemctl reload nginx.service",
        None,
        timeout,
    )?;
    require_success(&restored, "Certbot attach baseline restoration", false)
}

fn install_certbot_attach_tls_fault(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let installed = config.ssh(
        r#"sudo sh -eu -c '
mkdir -p /etc/systemd/system/jw-certd@.service.d
printf "%s\n" "[Service]" "InaccessiblePaths=/usr/bin/openssl" > /etc/systemd/system/jw-certd@.service.d/attach-fault.conf
systemctl daemon-reload
'"#,
        None,
        timeout,
    )?;
    require_success(&installed, "Certbot attach TLS fault installation", false)
}

fn cleanup_certbot_attach_fixture(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let script = r#"sudo sh -eu -c '
if test -e /var/tmp/jw-agent-vm-certbot-attach.active; then
    cp -a /var/tmp/jw-agent-vm-certbot-attach.nginx /etc/nginx/sites-available/jw-agent-p1
fi
rm -f /var/tmp/jw-agent-vm-certbot-attach.nginx /var/tmp/jw-agent-vm-certbot-attach.active
rm -rf /etc/letsencrypt/live/__HOST__ /etc/letsencrypt/archive/__HOST__
rm -f /etc/letsencrypt/renewal/__HOST__.conf
rm -f /etc/systemd/system/jw-certd@.service.d/attach-fault.conf
rmdir /etc/systemd/system/jw-certd@.service.d 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now certbot.timer
nginx -t
systemctl reload nginx.service
systemctl reset-failed jw-certd.socket jw-opsd.service jw-agentd.service
systemctl restart jw-certd.socket jw-opsd.service jw-agentd.service
'"#
    .replace("__HOST__", &config.public_host);
    let cleaned = config.ssh(&script, None, timeout)?;
    require_success(&cleaned, "Certbot attach fixture cleanup", false)
}

fn prepare_certbot_issue_fixture(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let script = r#"sudo sh -eu -c '
test ! -e /var/tmp/jw-agent-vm-certbot-issue.active
cp -a /etc/default/jw-agent /var/tmp/jw-agent-vm-certbot-issue.default
cp -a /etc/nginx/sites-available/jw-agent-p1 /var/tmp/jw-agent-vm-certbot-issue.nginx
cp -a /etc/hosts /var/tmp/jw-agent-vm-certbot-issue.hosts
touch /var/tmp/jw-agent-vm-certbot-issue.active
if grep -q "^JW_AGENT_PUBLIC_ADDRESSES=" /etc/default/jw-agent; then
    sed -i "s|^JW_AGENT_PUBLIC_ADDRESSES=.*|JW_AGENT_PUBLIC_ADDRESSES=__ADDRESS__|" /etc/default/jw-agent
else
    printf "%s\n" "JW_AGENT_PUBLIC_ADDRESSES=__ADDRESS__" >> /etc/default/jw-agent
fi
sed -i "/# jw-agent-vm-certbot-issue$/d" /etc/hosts
printf "%s\n" "__ADDRESS__ __HOST__ # jw-agent-vm-certbot-issue" >> /etc/hosts
if ! grep -Fq "include /usr/share/jw-agent/nginx/acme-challenge.conf;" /etc/nginx/sites-available/jw-agent-p1; then
    sed -i "0,/    server_name __HOST__;/s|    server_name __HOST__;|    server_name __HOST__;\\n\\n    include /usr/share/jw-agent/nginx/acme-challenge.conf;|" /etc/nginx/sites-available/jw-agent-p1
    sed -i "0,/    return 308 /s|    return 308 .*;|    location / { return 308 https://\$host\$request_uri; }|" /etc/nginx/sites-available/jw-agent-p1
fi
grep -Fq "include /usr/share/jw-agent/nginx/acme-challenge.conf;" /etc/nginx/sites-available/jw-agent-p1
grep -Fq "location / {" /etc/nginx/sites-available/jw-agent-p1 || { echo "HTTP redirect was not moved into a fallback location" >&2; exit 1; }
install -d -o root -g root -m 0755 /var/lib/jw-agent/acme-webroot/.well-known/acme-challenge
printf "%s\n" "jw-agent-vm-acme" > /var/lib/jw-agent/acme-webroot/.well-known/acme-challenge/preflight
chmod 0644 /var/lib/jw-agent/acme-webroot/.well-known/acme-challenge/preflight
nginx -t
systemctl reload nginx.service
systemctl reset-failed jw-agentd.service
systemctl restart jw-agentd.service
status=000
attempt=0
while test "$attempt" -lt 50; do
    status=$(curl -sS -o /var/tmp/jw-agent-vm-acme-response -w "%{http_code}" -H "Host: __HOST__" http://127.0.0.1/.well-known/acme-challenge/preflight)
    if test "$status" = 200 && grep -Fxq "jw-agent-vm-acme" /var/tmp/jw-agent-vm-acme-response; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
if test "$status" != 200; then
    echo "ACME webroot preflight returned HTTP $status" >&2
    exit 1
fi
grep -Fxq "jw-agent-vm-acme" /var/tmp/jw-agent-vm-acme-response || { echo "ACME webroot preflight body mismatch" >&2; exit 1; }
rm -f /var/tmp/jw-agent-vm-acme-response
'"#
        .replace("__HOST__", &config.public_host)
        .replace("__ADDRESS__", &config.public_address.to_string());
    let prepared = config.ssh(&script, None, timeout)?;
    require_success(&prepared, "Certbot issue fixture preparation", false)
}

fn cleanup_certbot_issue_fixture(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let script = r#"sudo sh -eu -c '
if test -e /var/tmp/jw-agent-vm-certbot-issue.active; then
    cp -a /var/tmp/jw-agent-vm-certbot-issue.default /etc/default/jw-agent
    cp -a /var/tmp/jw-agent-vm-certbot-issue.nginx /etc/nginx/sites-available/jw-agent-p1
    cp -a /var/tmp/jw-agent-vm-certbot-issue.hosts /etc/hosts
    rm -f /var/tmp/jw-agent-vm-certbot-issue.default /var/tmp/jw-agent-vm-certbot-issue.nginx /var/tmp/jw-agent-vm-certbot-issue.hosts /var/tmp/jw-agent-vm-certbot-issue.active
    rm -f /var/tmp/jw-agent-vm-acme-response
    rm -f /var/lib/jw-agent/acme-webroot/.well-known/acme-challenge/preflight
    nginx -t
    systemctl reload nginx.service
    systemctl reset-failed jw-agentd.service
    systemctl restart jw-agentd.service
fi
'"#;
    let cleaned = config.ssh(script, None, timeout)?;
    require_success(&cleaned, "Certbot issue fixture cleanup", false)
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
        session.enter_administrative(&config, &password, timeout)?;
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
        let restarted = config.ssh(
            "sudo systemctl reset-failed jw-opsd.service\nsudo systemctl restart jw-opsd.service",
            None,
            timeout,
        )?;
        require_success(&restarted, "internal temporary startup cleanup", false)?;
        session.wait_for_operation_available(&config, timeout)?;
        let removed = config.ssh(
            &format!("sudo test ! -e /etc/nginx/sites-available/{P2_INTERNAL_TEMP}"),
            None,
            timeout,
        )?;
        require_success(&removed, "internal temporary removal", false)?;

        let saved =
            session.operate_managed_config(&config, P2_MANAGED_SITE, &managed_saved, timeout)?;
        require_terminal(&saved, "SUCCEEDED", "managed config save")?;
        if !saved.contains("\"resultCode\":\"config_verified\"") {
            return Err(String::from(
                "managed config receipt omitted config_verified evidence",
            ));
        }
        require_file_equals(&config, P2_MANAGED_SITE, managed_saved.as_bytes(), timeout)?;

        let noop =
            session.operate_managed_config(&config, P2_MANAGED_SITE, &managed_saved, timeout)?;
        require_terminal(&noop, "SUCCEEDED", "managed config no-op")?;
        if !noop.contains("\"resultCode\":\"verified_noop\"") {
            return Err(String::from(
                "managed config no-op omitted verified_noop evidence",
            ));
        }

        let syntax_rollback = session.operate_managed_config(
            &config,
            P2_MANAGED_SITE,
            "server { this_is_not_valid_nginx_syntax; }\n",
            timeout,
        )?;
        require_terminal(
            &syntax_rollback,
            "ROLLED_BACK",
            "managed config syntax rollback",
        )?;
        if !contains_nginx_config_failure_result(&syntax_rollback) {
            return Err(String::from(
                "managed config syntax receipt omitted failure evidence",
            ));
        }
        require_file_equals(&config, P2_MANAGED_SITE, managed_saved.as_bytes(), timeout)?;

        install_reload_fail_once(&config, timeout)?;
        let reload_rollback = session.operate_managed_config(
            &config,
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
        let stale = session.approve_managed_config(&config, &stale_plan, timeout)?;
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
        session.require_managed_config_unloaded(&config, P2_MANAGED_SITE, timeout)?;
        let inactive = session.get(
            &config,
            &format!("/api/v1/config-resources/{resource_id}"),
            timeout,
        )?;
        expect_http(&inactive, 200, "inactive managed config resource")?;
        if !inactive
            .body
            .contains("\"adapterId\":\"nginx/ubuntu-24.04-tree-v1\"")
            || !inactive.body.contains("\"validate_only\"")
        {
            return Err(String::from(
                "inactive Nginx file omitted its bounded tree editing contract",
            ));
        }
        Ok(())
    })();
    let cleanup = cleanup_managed_config_fixture(&config, timeout);
    let nginx_result = match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; managed config cleanup also failed: {cleanup_error}"
        )),
    };
    nginx_result?;
    php_fpm::gate_p2_php_fpm(_root, timeout)?;
    apache::gate_p2_apache_managed_config(_root, timeout)
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

#[derive(Clone, Copy)]
struct FileUploadPlanInput<'a> {
    password: &'a str,
    file_session_token: &'a str,
    path: &'a str,
    content_bytes: usize,
    content_digest: &'a str,
    overwrite_confirmed: bool,
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

    fn enter_administrative(
        &mut self,
        config: &VmConfig,
        password: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let body = format!(
            "{{\"password\":{},\"additionalAuthCode\":null}}",
            json_string(password)
        );
        let response = public_api_request(
            config,
            "POST",
            "/api/v1/auth/administrative-access",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(body.as_bytes()),
            timeout,
        )?;
        expect_http(&response, 200, "P2 administrative access")?;
        if !response
            .body
            .contains("\"administrativeAccess\":\"administrative\"")
        {
            return Err(String::from(
                "P2 administrative access did not return the bounded access mode",
            ));
        }
        self.csrf_token = json_string_field(&response.body, "csrfToken")?;
        Ok(())
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

    fn issue_terminal_ticket(
        &self,
        config: &VmConfig,
        password: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let body = format!(
            "{{\"password\":{},\"rows\":24,\"cols\":80,\"riskConfirmed\":true}}",
            json_string(password),
        );
        let response = public_api_request(
            config,
            "POST",
            "/api/v1/terminal/tickets",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(body.as_bytes()),
            timeout,
        )?;
        expect_http(&response, 201, "terminal one-shot ticket")?;
        if response.body.contains(password)
            || !response.body.contains("\"level\":\"g1_verified_action\"")
            || !response
                .body
                .contains("\"rollbackSupport\":\"not_guaranteed\"")
            || !response
                .body
                .contains("\"websocketPath\":\"/api/v1/terminal/connect\"")
        {
            return Err(String::from(
                "terminal ticket response leaked a credential or omitted its G1 boundary",
            ));
        }
        let ticket = json_string_field(&response.body, "ticket")?;
        if ticket.len() != 43
            || !ticket
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(String::from("terminal ticket shape is invalid"));
        }
        Ok(ticket)
    }

    fn create_file_session(
        &self,
        config: &VmConfig,
        password: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let body = format!(
            "{{\"password\":{},\"readOnlyConfirmed\":true}}",
            json_string(password),
        );
        let response = public_api_request(
            config,
            "POST",
            "/api/v1/files/sessions",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(body.as_bytes()),
            timeout,
        )?;
        expect_http(&response, 201, "read-only SFTP session")?;
        if response.body.contains(password)
            || !response.body.contains("\"level\":\"g0_observe_only\"")
            || !response
                .body
                .contains("\"rollbackSupport\":\"not_applicable\"")
            || !response.body.contains("\"rootLabel\":\"~\"")
        {
            return Err(String::from(
                "file session response leaked a credential or omitted its G0 boundary",
            ));
        }
        let token = json_string_field(&response.body, "sessionToken")?;
        if token.len() != 43
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(String::from("file session token shape is invalid"));
        }
        Ok(token)
    }

    fn file_request(
        &self,
        config: &VmConfig,
        endpoint: &str,
        file_session_token: &str,
        path: &str,
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        self.file_request_with_origin(
            config,
            endpoint,
            file_session_token,
            path,
            &format!("https://{}", config.public_host),
            timeout,
        )
    }

    fn file_request_with_origin(
        &self,
        config: &VmConfig,
        endpoint: &str,
        file_session_token: &str,
        path: &str,
        origin: &str,
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        if !matches!(endpoint, "list" | "stat" | "read" | "download") {
            return Err(String::from("unsupported file endpoint"));
        }
        let body = format!(
            "{{\"sessionToken\":{},\"path\":{}}}",
            json_string(file_session_token),
            json_string(path),
        );
        public_api_request_with_origin(
            config,
            PublicApiTarget {
                method: "POST",
                path: &format!("/api/v1/files/{endpoint}"),
                origin,
            },
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(body.as_bytes()),
            timeout,
        )
    }

    fn file_upload_plan_request(
        &self,
        config: &VmConfig,
        input: FileUploadPlanInput<'_>,
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        let body = format!(
            "{{\"sessionToken\":{},\"path\":{},\"contentBytes\":{},\"contentDigest\":{},\"password\":{},\"nonReversibleConfirmed\":true,\"overwriteConfirmed\":{}}}",
            json_string(input.file_session_token),
            json_string(input.path),
            input.content_bytes,
            json_string(input.content_digest),
            json_string(input.password),
            input.overwrite_confirmed,
        );
        public_api_request(
            config,
            "POST",
            "/api/v1/files/upload/plans",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(body.as_bytes()),
            timeout,
        )
    }

    fn create_file_upload_plan(
        &self,
        config: &VmConfig,
        input: FileUploadPlanInput<'_>,
        timeout: Duration,
    ) -> Result<String, String> {
        let response = self.file_upload_plan_request(config, input, timeout)?;
        expect_http(&response, 201, "G1 file upload plan")?;
        if response.body.contains(input.password)
            || response.body.contains(input.file_session_token)
            || !response.body.contains("\"level\":\"g1_verified_action\"")
            || !response
                .body
                .contains("\"rollbackSupport\":\"not_guaranteed\"")
            || !response.body.contains(input.content_digest)
        {
            return Err(String::from(
                "file upload plan leaked a credential or omitted its exact G1 boundary",
            ));
        }
        let token = json_string_field(&response.body, "planToken")?;
        validate_api_secret(&token, "file upload plan token")?;
        Ok(token)
    }

    fn apply_file_upload_with_origin(
        &self,
        config: &VmConfig,
        file_session_token: &str,
        plan_token: &str,
        content: &[u8],
        origin: &str,
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        public_api_binary_upload_with_origin(
            config,
            BinaryUploadInput {
                origin,
                cookie_jar: &self.cookie_jar.path,
                csrf_token: &self.csrf_token,
                file_session_token,
                plan_token,
                body: content,
            },
            timeout,
        )
    }

    fn apply_file_upload(
        &self,
        config: &VmConfig,
        file_session_token: &str,
        plan_token: &str,
        content: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        self.apply_file_upload_with_origin(
            config,
            file_session_token,
            plan_token,
            content,
            &format!("https://{}", config.public_host),
            timeout,
        )
    }

    fn close_file_session(
        &self,
        config: &VmConfig,
        file_session_token: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let body = format!("{{\"sessionToken\":{}}}", json_string(file_session_token),);
        let response = public_api_request(
            config,
            "POST",
            "/api/v1/files/sessions/close",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(body.as_bytes()),
            timeout,
        )?;
        expect_http(&response, 204, "file session close")
    }

    fn logout(&self, config: &VmConfig, timeout: Duration) -> Result<(), String> {
        let response = public_api_request(
            config,
            "POST",
            "/api/v1/auth/logout",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(&[]),
            timeout,
        )?;
        expect_http(&response, 204, "P2 API logout")
    }

    fn public_cookie_header(&self) -> Result<String, String> {
        let content = fs::read_to_string(&self.cookie_jar.path)
            .map_err(|error| format!("cannot read terminal cookie jar: {error}"))?;
        for line in content.lines() {
            let normalized = line.strip_prefix("#HttpOnly_").map_or(line, |value| value);
            if normalized.starts_with('#') || normalized.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = normalized.split('\t').collect();
            if fields.len() == 7 && fields[5] == "__Host-jw_session" {
                let token = fields[6];
                if token.len() == 43
                    && token
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    return Ok(format!("__Host-jw_session={token}"));
                }
            }
        }
        Err(String::from(
            "public terminal session cookie is unavailable",
        ))
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
        let approval_body = format!(
            "{{\"schemaVersion\":{},\"planId\":{},\"planHash\":{},\"idempotencyKey\":{}}}",
            site.schema_version,
            json_string(&plan_id),
            json_string(&plan_hash),
            json_string(&idempotency_key),
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
        let inventory = self.get(config, "/api/v1/services/nginx/configurations", timeout)?;
        expect_http(&inventory, 200, "managed config Nginx observation")?;
        Ok(json_managed_config_tree_fields(&inventory.body, site_name)?.resource_id)
    }

    fn require_managed_config_unloaded(
        &self,
        config: &VmConfig,
        site_name: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let inventory = self.get(config, "/api/v1/services/nginx/configurations", timeout)?;
        expect_http(&inventory, 200, "inactive managed config observation")?;
        let object = json_configuration_object(&inventory.body, site_name)?;
        if object.contains("\"loaded\":false") && object.contains("\"available\":true") {
            Ok(())
        } else {
            Err(String::from(
                "inactive Nginx file was not retained as a bounded editable resource",
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
        let inventory = self.get(config, "/api/v1/services/nginx/configurations", timeout)?;
        expect_http(&inventory, 200, "managed config Nginx observation")?;
        let site = json_managed_config_tree_fields(&inventory.body, site_name)?;
        let resource = self.get(
            config,
            &format!("/api/v1/config-resources/{}", site.resource_id),
            timeout,
        )?;
        expect_http(&resource, 200, "managed config resource")?;
        let max_bytes = json_unsigned_field(&resource.body, "maxBytes")?;
        let tree_adapter = resource
            .body
            .contains("\"adapterId\":\"nginx/ubuntu-24.04-tree-v1\"");
        let reload = resource.body.contains("\"reload\"");
        let validate_only = resource.body.contains("\"validate_only\"");
        let recovery_assurance = resource.body.contains("\"level\":\"g2_reversible_config\"");
        if max_bytes != 131_072 || !tree_adapter || !reload || !validate_only || !recovery_assurance
        {
            return Err(format!(
                "managed config resource contract mismatch: max_bytes={max_bytes}, tree_adapter={tree_adapter}, reload={reload}, validate_only={validate_only}, recovery_assurance={recovery_assurance}"
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
        let reload_action = plan.body.contains("\"serviceAction\":\"reload\"");
        let recovery_assurance = plan.body.contains("\"level\":\"g2_reversible_config\"");
        let masked_path = json_string_field(&plan.body, "maskedPath")?;
        let expected_masked_path = format!("/etc/nginx/sites-available/{site_name}");
        if !reload_action || !recovery_assurance || masked_path != expected_masked_path {
            return Err(format!(
                "managed config plan mismatch: reload_action={reload_action}, recovery_assurance={recovery_assurance}, masked_path={masked_path}"
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
        plan: &ManagedConfigPlanFields,
        timeout: Duration,
    ) -> Result<String, String> {
        let approval_body = format!(
            "{{\"schemaVersion\":{},\"planId\":{},\"planHash\":{},\"idempotencyKey\":{},\"approvalIntent\":{{\"validationConfirmed\":true,\"serviceActionConfirmed\":true}}}}",
            plan.schema_version,
            json_string(&plan.plan_id),
            json_string(&plan.plan_hash),
            json_string(&plan.idempotency_key),
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
        validate_atom(&plan.plan_id, "managed config plan ID", "_-")?;
        let proposal_removed = config.ssh(
            &format!(
                "sudo test ! -e /var/lib/jw-agent/opsd/proposals/{}",
                plan.plan_id
            ),
            None,
            timeout,
        )?;
        require_success(
            &proposal_removed,
            "managed config exact proposal cleanup",
            false,
        )?;
        Ok(receipt.body)
    }

    fn operate_managed_config(
        &mut self,
        config: &VmConfig,
        site_name: &str,
        proposed_content: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let plan = self.plan_managed_config(config, site_name, proposed_content, timeout)?;
        self.approve_managed_config(config, &plan, timeout)
    }

    fn operate_certbot_issue_staging_failure(
        &mut self,
        config: &VmConfig,
        password: &str,
        account_email: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let inventory = self.get(config, "/api/v1/certificates", timeout)?;
        expect_http(&inventory, 200, "Certbot issue inventory")?;
        let operation_type = json_string_field(&inventory.body, "issueOperationType")?;
        if operation_type != "certbot.certificate.issue/v1" {
            return Err(String::from(
                "certificate inventory did not advertise typed issuance",
            ));
        }
        let schema_version = u16::try_from(json_unsigned_field(&inventory.body, "schemaVersion")?)
            .map_err(|_| String::from("certificate schema version overflow"))?;
        let inventory_digest = json_string_field(&inventory.body, "inventoryDigest")?;
        let sites = self.get(config, "/api/v1/services/nginx/sites", timeout)?;
        expect_http(&sites, 200, "Certbot issue Nginx observation")?;
        let site = json_issue_site_fields(&sites.body, "jw-agent-p1")?;
        let idempotency_key = operation_idempotency_key()?;
        let plan_body = format!(
            "{{\"schemaVersion\":{},\"operationType\":{},\"primaryDomain\":{},\"alternativeDomains\":[],\"accountEmail\":{},\"environment\":\"staging\",\"siteId\":{},\"expectedSiteDigest\":{},\"expectedInventoryDigest\":{},\"tosAgreed\":true,\"idempotencyKey\":{}}}",
            schema_version,
            json_string(&operation_type),
            json_string(&config.public_host),
            json_string(account_email),
            json_string(&site.site_id),
            json_string(&site.available_digest),
            json_string(&inventory_digest),
            json_string(&idempotency_key),
        );
        let plan = public_api_request(
            config,
            "POST",
            "/api/v1/operations/certbot/issue/plans",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(plan_body.as_bytes()),
            timeout,
        )?;
        expect_http(&plan, 200, "Certbot staging issue plan")?;
        if !plan.body.contains("\"level\":\"g1_verified_action\"")
            || !plan.body.contains("\"rollbackSupport\":\"not_guaranteed\"")
            || !plan.body.contains("\"localPort80Reachable\":true")
            || !plan.body.contains(&format!(
                "\"resolvedAddresses\":[{}]",
                json_string(&config.public_address.to_string())
            ))
            || !plan
                .body
                .contains("\"maskedAccountEmail\":\"j***@example.com\"")
            || plan.body.contains(account_email)
        {
            return Err(String::from(
                "Certbot issue plan omitted preflight/G1 evidence or exposed the account email",
            ));
        }
        let plan_id = json_string_field(&plan.body, "planId")?;
        let plan_hash = json_string_field(&plan.body, "planHash")?;
        let reauth_body = format!(
            "{{\"password\":{},\"purpose\":{{\"kind\":\"operation\",\"planHash\":{}}}}}",
            json_string(password),
            json_string(&plan_hash),
        );
        thread::sleep(Duration::from_secs(7));
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
            "Certbot issue exact-plan PAM reauthentication",
        )?;
        self.csrf_token = json_string_field(&reauth.body, "csrfToken")?;
        let reauth_token = json_string_field(&reauth.body, "reauthToken")?;
        let approval_body = format!(
            "{{\"schemaVersion\":{},\"planId\":{},\"planHash\":{},\"idempotencyKey\":{},\"reauthToken\":{},\"externalEffectConfirmed\":true,\"localAttachDeferredConfirmed\":true}}",
            schema_version,
            json_string(&plan_id),
            json_string(&plan_hash),
            json_string(&idempotency_key),
            json_string(&reauth_token),
        );
        let accepted = public_api_request(
            config,
            "POST",
            "/api/v1/operations/certbot/issue/approvals",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(approval_body.as_bytes()),
            timeout,
        )?;
        expect_http(&accepted, 202, "Certbot staging issue approval")?;
        let operation_id = json_string_field(&accepted.body, "operationId")?;
        let event_stream = json_string_field(&accepted.body, "eventStream")?;
        if event_stream != format!("/api/v1/operations/{operation_id}/events") {
            return Err(String::from(
                "Certbot issue returned a non-canonical event stream",
            ));
        }
        let operation_path = format!("/api/v1/operations/{operation_id}");
        let started = Instant::now();
        loop {
            let current = self.get(config, &operation_path, timeout)?;
            expect_http(&current, 200, "Certbot issue receipt")?;
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
                return Err(String::from(
                    "Certbot staging issue did not reach a terminal receipt before timeout",
                ));
            }
            thread::sleep(Duration::from_millis(250));
        }
    }

    fn operate_certbot_attach(
        &mut self,
        config: &VmConfig,
        password: &str,
        timeout: Duration,
    ) -> Result<CertbotAttachOutcome, String> {
        let inventory = self.get(config, "/api/v1/certificates", timeout)?;
        expect_http(&inventory, 200, "Certbot attach inventory")?;
        let operation_type = json_string_field(&inventory.body, "attachOperationType")?;
        if operation_type != "certbot.certificate.attach/v1" {
            return Err(String::from(
                "certificate inventory did not advertise typed Nginx TLS attach",
            ));
        }
        let schema_version = u16::try_from(json_unsigned_field(&inventory.body, "schemaVersion")?)
            .map_err(|_| String::from("certificate schema version overflow"))?;
        let inventory_digest = json_string_field(&inventory.body, "inventoryDigest")?;
        let certificate_fingerprint = json_string_field(&inventory.body, "fingerprintSha256")?;
        let sites = self.get(config, "/api/v1/services/nginx/sites", timeout)?;
        expect_http(&sites, 200, "Certbot attach Nginx observation")?;
        let site = json_issue_site_fields(&sites.body, "jw-agent-p1")?;
        let idempotency_key = operation_idempotency_key()?;
        let plan_body = format!(
            "{{\"schemaVersion\":{},\"operationType\":{},\"primaryDomain\":{},\"siteId\":{},\"expectedSiteDigest\":{},\"expectedInventoryDigest\":{},\"expectedCertificateFingerprint\":{},\"idempotencyKey\":{}}}",
            schema_version,
            json_string(&operation_type),
            json_string(&config.public_host),
            json_string(&site.site_id),
            json_string(&site.available_digest),
            json_string(&inventory_digest),
            json_string(&certificate_fingerprint),
            json_string(&idempotency_key),
        );
        let plan = public_api_request(
            config,
            "POST",
            "/api/v1/operations/certbot/attach/plans",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(plan_body.as_bytes()),
            timeout,
        )?;
        expect_http(&plan, 200, "Certbot attach plan")?;
        for expected in [
            "\"level\":\"g2_reversible_config\"",
            "\"rollbackSupport\":\"automatic_bounded\"",
            "\"currentCertificatePath\":\"…/jw-agent/tls/server.crt\"",
            "\"targetCertificatePath\":\"…/live/",
            "\"timerEnabled\":true",
            "\"timerActive\":true",
        ] {
            if !plan.body.contains(expected) {
                return Err(format!("Certbot attach plan omitted {expected}"));
            }
        }
        let plan_id = json_string_field(&plan.body, "planId")?;
        let plan_hash = json_string_field(&plan.body, "planHash")?;
        let reauth_body = format!(
            "{{\"password\":{},\"purpose\":{{\"kind\":\"operation\",\"planHash\":{}}}}}",
            json_string(password),
            json_string(&plan_hash),
        );
        thread::sleep(Duration::from_secs(7));
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
            "Certbot attach exact-plan PAM reauthentication",
        )?;
        self.csrf_token = json_string_field(&reauth.body, "csrfToken")?;
        let reauth_token = json_string_field(&reauth.body, "reauthToken")?;
        let approval_body = format!(
            "{{\"schemaVersion\":{},\"planId\":{},\"planHash\":{},\"idempotencyKey\":{},\"reauthToken\":{},\"configReplaceConfirmed\":true,\"serviceReloadConfirmed\":true}}",
            schema_version,
            json_string(&plan_id),
            json_string(&plan_hash),
            json_string(&idempotency_key),
            json_string(&reauth_token),
        );
        let accepted = public_api_request(
            config,
            "POST",
            "/api/v1/operations/certbot/attach/approvals",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(approval_body.as_bytes()),
            timeout,
        )?;
        expect_http(&accepted, 202, "Certbot attach approval")?;
        let operation_id = json_string_field(&accepted.body, "operationId")?;
        let event_stream = json_string_field(&accepted.body, "eventStream")?;
        if event_stream != format!("/api/v1/operations/{operation_id}/events") {
            return Err(String::from(
                "Certbot attach returned a non-canonical event stream",
            ));
        }
        let operation_path = format!("/api/v1/operations/{operation_id}");
        let started = Instant::now();
        loop {
            let current = self.get(config, &operation_path, timeout)?;
            expect_http(&current, 200, "Certbot attach receipt")?;
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
                return Ok(CertbotAttachOutcome {
                    receipt: current.body,
                    site_digest: site.available_digest,
                    certificate_fingerprint,
                });
            }
            if started.elapsed() >= timeout {
                return Err(String::from(
                    "Certbot attach did not reach a terminal receipt before timeout",
                ));
            }
            thread::sleep(Duration::from_millis(250));
        }
    }

    fn operate_certbot_renew_test(
        &mut self,
        config: &VmConfig,
        password: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let inventory = self.get(config, "/api/v1/certificates", timeout)?;
        expect_http(&inventory, 200, "Certbot renewal inventory")?;
        let operation_type = json_string_field(&inventory.body, "renewTestOperationType")?;
        if operation_type != "certbot.certificate.renew_test/v1" {
            return Err(String::from(
                "certificate inventory did not advertise the typed renewal test",
            ));
        }
        let schema_version = u16::try_from(json_unsigned_field(&inventory.body, "schemaVersion")?)
            .map_err(|_| String::from("certificate schema version overflow"))?;
        let inventory_digest = json_string_field(&inventory.body, "inventoryDigest")?;
        let idempotency_key = operation_idempotency_key()?;
        let plan_body = format!(
            "{{\"schemaVersion\":{},\"operationType\":{},\"expectedInventoryDigest\":{},\"idempotencyKey\":{}}}",
            schema_version,
            json_string(&operation_type),
            json_string(&inventory_digest),
            json_string(&idempotency_key),
        );
        let plan = public_api_request(
            config,
            "POST",
            "/api/v1/operations/certbot/renew-test/plans",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(plan_body.as_bytes()),
            timeout,
        )?;
        expect_http(&plan, 200, "Certbot renewal plan")?;
        if !plan.body.contains("\"level\":\"g1_verified_action\"")
            || !plan.body.contains("\"rollbackSupport\":\"not_guaranteed\"")
            || !plan.body.contains("ACME staging")
        {
            return Err(String::from(
                "Certbot renewal plan omitted its G1 external-effect boundary",
            ));
        }
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
        expect_http(&reauth, 200, "Certbot exact-plan PAM reauthentication")?;
        self.csrf_token = json_string_field(&reauth.body, "csrfToken")?;
        let reauth_token = json_string_field(&reauth.body, "reauthToken")?;
        let approval_body = format!(
            "{{\"schemaVersion\":{},\"planId\":{},\"planHash\":{},\"idempotencyKey\":{},\"reauthToken\":{},\"externalEffectConfirmed\":true}}",
            schema_version,
            json_string(&plan_id),
            json_string(&plan_hash),
            json_string(&idempotency_key),
            json_string(&reauth_token),
        );
        let accepted = public_api_request(
            config,
            "POST",
            "/api/v1/operations/certbot/renew-test/approvals",
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            Some(approval_body.as_bytes()),
            timeout,
        )?;
        expect_http(&accepted, 202, "Certbot renewal approval")?;
        let operation_id = json_string_field(&accepted.body, "operationId")?;
        let event_stream = json_string_field(&accepted.body, "eventStream")?;
        if event_stream != format!("/api/v1/operations/{operation_id}/events") {
            return Err(String::from(
                "Certbot renewal returned a non-canonical event stream",
            ));
        }
        let operation_path = format!("/api/v1/operations/{operation_id}");
        let started = Instant::now();
        loop {
            let current = self.get(config, &operation_path, timeout)?;
            expect_http(&current, 200, "Certbot renewal receipt")?;
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
                return Err(String::from(
                    "Certbot renewal test did not reach a terminal receipt before timeout",
                ));
            }
            thread::sleep(Duration::from_millis(250));
        }
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

struct CertbotIssueSiteFields {
    site_id: String,
    available_digest: String,
}

struct CertbotAttachOutcome {
    receipt: String,
    site_digest: String,
    certificate_fingerprint: String,
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

fn json_configuration_object<'a>(body: &'a str, site_name: &str) -> Result<&'a str, String> {
    let masked_path = format!("/etc/nginx/sites-available/{site_name}");
    let marker = format!("\"maskedPath\":{}", json_string(&masked_path));
    let marker_index = body
        .find(&marker)
        .ok_or_else(|| format!("managed Nginx config `{masked_path}` was not observed"))?;
    let start = body[..marker_index]
        .rfind('{')
        .ok_or_else(|| String::from("Nginx configuration object start is missing"))?;
    let remainder = &body[start..];
    let end = remainder
        .find("\"assurance\":")
        .map_or(remainder.len(), std::convert::identity);
    Ok(&remainder[..end])
}

fn json_managed_config_tree_fields(
    body: &str,
    site_name: &str,
) -> Result<ManagedConfigSiteFields, String> {
    let object = json_configuration_object(body, site_name)?;
    let schema = json_unsigned_field(object, "schemaVersion")?;
    Ok(ManagedConfigSiteFields {
        schema_version: u16::try_from(schema)
            .map_err(|_| String::from("managed config schema version overflow"))?,
        operation_type: json_string_field(object, "operationType")?,
        resource_id: json_string_field(object, "resourceId")?,
    })
}

fn json_issue_site_fields(body: &str, site_name: &str) -> Result<CertbotIssueSiteFields, String> {
    let object = json_site_object(body, site_name)?;
    if !object.contains("\"protected\":true") || !object.contains("\"enabled\":true") {
        return Err(String::from(
            "Certbot issue site is not the enabled protected management vhost",
        ));
    }
    Ok(CertbotIssueSiteFields {
        site_id: json_string_field(object, "siteId")?,
        available_digest: json_string_field(object, "availableDigest")?,
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
    api_request_with_origin_on_port(
        config,
        PublicApiTarget {
            method,
            path,
            origin: &format!("https://{}", config.public_host),
        },
        443,
        cookie_jar,
        csrf_token,
        body,
        timeout,
    )
}

fn independent_edge_api_request(
    config: &VmConfig,
    method: &str,
    path: &str,
    cookie_jar: &Path,
    csrf_token: Option<&str>,
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    api_request_with_origin_on_port(
        config,
        PublicApiTarget {
            method,
            path,
            origin: &format!("https://{}:9443", config.public_host),
        },
        9_443,
        cookie_jar,
        csrf_token,
        body,
        timeout,
    )
}

struct PublicApiTarget<'a> {
    method: &'a str,
    path: &'a str,
    origin: &'a str,
}

struct BinaryUploadInput<'a> {
    origin: &'a str,
    cookie_jar: &'a Path,
    csrf_token: &'a str,
    file_session_token: &'a str,
    plan_token: &'a str,
    body: &'a [u8],
}

fn public_api_request_with_origin(
    config: &VmConfig,
    target: PublicApiTarget<'_>,
    cookie_jar: &Path,
    csrf_token: Option<&str>,
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    api_request_with_origin_on_port(config, target, 443, cookie_jar, csrf_token, body, timeout)
}

fn api_request_with_origin_on_port(
    config: &VmConfig,
    target: PublicApiTarget<'_>,
    port: u16,
    cookie_jar: &Path,
    csrf_token: Option<&str>,
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    if !target.path.starts_with("/api/") || !matches!(target.method, "GET" | "POST") {
        return Err(String::from("P2 API request rejected an unsupported shape"));
    }
    if !matches!(port, 443 | 9_443) {
        return Err(String::from("P2 API request rejected an unsupported port"));
    }
    if !target.origin.starts_with("https://") || target.origin.len() > 512 {
        return Err(String::from("P2 API request rejected an invalid Origin"));
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
            "{}:{port}:{}",
            config.public_host, config.public_address,
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
        OsString::from(format!("Origin: {}", target.origin)),
    ];
    if let Some(header) = &csrf_header {
        arguments.push(OsString::from("--header"));
        arguments.push(OsString::from(format!("@{}", header.path.display())));
    }
    if target.method == "POST" {
        arguments.push(OsString::from("--header"));
        arguments.push(OsString::from("Content-Type: application/json"));
        arguments.push(OsString::from("--data-binary"));
        arguments.push(OsString::from("@-"));
    }
    let authority = if port == 443 {
        config.public_host.clone()
    } else {
        format!("{}:{port}", config.public_host)
    };
    arguments.push(OsString::from(format!(
        "https://{authority}{}",
        target.path
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

fn public_api_binary_upload_with_origin(
    config: &VmConfig,
    input: BinaryUploadInput<'_>,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    if !input.origin.starts_with("https://") || input.origin.len() > 512 {
        return Err(String::from("file upload rejected an invalid Origin"));
    }
    validate_api_secret(input.csrf_token, "CSRF token")?;
    validate_api_secret(input.file_session_token, "file session token")?;
    validate_api_secret(input.plan_token, "file upload plan token")?;
    let secret_headers = TemporarySecretFile::create_with_contents(
        "jw-agent-p2-upload-headers",
        format!(
            "X-CSRF-Token: {}\nX-JW-File-Session: {}\nX-JW-Upload-Plan: {}\n",
            input.csrf_token, input.file_session_token, input.plan_token,
        )
        .as_bytes(),
    )?;
    let arguments = vec![
        OsString::from("--silent"),
        OsString::from("--show-error"),
        OsString::from("--max-time"),
        OsString::from(timeout.as_secs().min(235).to_string()),
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
        input.cookie_jar.as_os_str().to_owned(),
        OsString::from("--cookie-jar"),
        input.cookie_jar.as_os_str().to_owned(),
        OsString::from("--header"),
        OsString::from(format!("Origin: {}", input.origin)),
        OsString::from("--header"),
        OsString::from(format!("@{}", secret_headers.path.display())),
        OsString::from("--header"),
        OsString::from("Content-Type: application/octet-stream"),
        OsString::from("--data-binary"),
        OsString::from("@-"),
        OsString::from(format!(
            "https://{}/api/v1/files/upload",
            config.public_host
        )),
    ];
    let result = run_capture(OsStr::new("curl"), &arguments, Some(input.body), timeout)?;
    if !result.status.success() || result.stdout_truncated || result.stderr_truncated {
        return Err(format!(
            "file upload transport failed with {} (response and credentials redacted)",
            result.status
        ));
    }
    parse_http_response(&result.stdout)
}

fn validate_api_secret(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(format!("{label} shape is invalid"))
    }
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
    let actual = json_string_field(body, "terminalState")?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} returned terminal state {actual}, expected {expected}"
        ))
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
        let arguments = self.public_curl_arguments(suffix);
        run_capture(OsStr::new("curl"), &arguments, input, timeout)
    }

    fn public_curl_arguments(&self, suffix: &[&str]) -> Vec<OsString> {
        self.tls_curl_arguments(443, suffix)
    }

    fn independent_edge_curl(
        &self,
        suffix: &[&str],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Captured, String> {
        let arguments = self.tls_curl_arguments(9_443, suffix);
        run_capture(OsStr::new("curl"), &arguments, input, timeout)
    }

    fn tls_curl_arguments(&self, port: u16, suffix: &[&str]) -> Vec<OsString> {
        let mut arguments = vec![
            OsString::from("--silent"),
            OsString::from("--show-error"),
            OsString::from("--max-time"),
            OsString::from("12"),
            OsString::from("--resolve"),
            OsString::from(format!(
                "{}:{port}:{}",
                self.public_host, self.public_address
            )),
            OsString::from("--cacert"),
            self.ca_certificate.as_os_str().to_owned(),
        ];
        for argument in suffix {
            if is_http_endpoint(argument) {
                let authority = if port == 443 {
                    self.public_host.clone()
                } else {
                    format!("{}:{port}", self.public_host)
                };
                arguments.push(OsString::from(format!("https://{authority}{argument}",)));
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
        || value == "/services"
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
