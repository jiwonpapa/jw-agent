#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::time::Duration;

use crate::process::run_capture;

use super::{RECOVERY_HOST, VmConfig, expect_http, parse_http_response, require_success, text};

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

    let mismatched_identity = run_capture(
        OsStr::new("curl"),
        &[
            OsString::from("--silent"),
            OsString::from("--show-error"),
            OsString::from("--fail"),
            OsString::from("--max-time"),
            OsString::from("12"),
            OsString::from("--resolve"),
            OsString::from(format!(
                "tls-identity-mismatch.invalid:443:{}",
                config.public_address
            )),
            OsString::from("--cacert"),
            config.ca_certificate.as_os_str().to_owned(),
            OsString::from("https://tls-identity-mismatch.invalid/api/v1/health"),
        ],
        None,
        Duration::from_secs(15),
    )?;
    if mismatched_identity.status.success() {
        return Err(String::from(
            "TLS certificate accepted a hostname outside its identity",
        ));
    }
    Ok(())
}
