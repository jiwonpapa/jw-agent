#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Duration;

use crate::read_text;

pub(crate) fn gate_p2_independent_edge_boundary(
    root: &Path,
    _timeout: Duration,
) -> Result<(), String> {
    let manifest = read_text(&root.join("crates/jw-edge/Cargo.toml"))?;
    let workspace = read_text(&root.join("Cargo.toml"))?;
    let config = read_text(&root.join("crates/jw-edge/src/config.rs"))?;
    let edge_main = read_text(&root.join("crates/jw-edge/src/main.rs"))?;
    let proxy = read_text(&root.join("crates/jw-edge/src/proxy.rs"))?;
    let tls = read_text(&root.join("crates/jw-edge/src/tls.rs"))?;
    let service = read_text(&root.join("packaging/systemd/jw-edge.service"))?;
    let tmpfiles = read_text(&root.join("packaging/tmpfiles/jw-agent.conf"))?;
    let runner = read_text(&root.join("crates/jw-opsd/src/runner.rs"))?;
    let operation = read_text(&root.join("crates/jw-opsd/src/engine/service_operation.rs"))?;
    let inventory = read_text(&root.join("crates/jw-agentd/src/service_inventory.rs"))?;
    let mut failures = Vec::new();

    for (content, needle, label) in [
        (&workspace, "\"crates/jw-edge\"", "workspace member"),
        (
            &workspace,
            "tokio-rustls = { version = \"=0.26.4\"",
            "exact tokio-rustls pin",
        ),
        (
            &workspace,
            "rustls-pemfile = { version = \"=2.2.0\"",
            "exact PEM parser pin",
        ),
        (&manifest, "tokio-rustls.workspace = true", "edge TLS owner"),
        (&config, "0.0.0.0:9443", "unprivileged default port"),
        (
            &config,
            "must use an unprivileged port",
            "privileged-port rejection",
        ),
        (
            &proxy,
            "request transfer encoding is rejected",
            "transfer-encoding rejection",
        ),
        (
            &proxy,
            "request content length is rejected",
            "duplicate content-length rejection",
        ),
        (
            &proxy,
            "X-JW-Client-Address: ",
            "trusted peer-address injection",
        ),
        (&tls, "rustls::crypto::ring", "single TLS provider"),
        (&service, "User=jw-agent", "unprivileged service user"),
        (&service, "NoNewPrivileges=yes", "no-new-privileges sandbox"),
        (
            &service,
            "StartLimitIntervalSec=0",
            "dependency restart resilience",
        ),
        (
            &service,
            "Wants=jw-agentd.service",
            "non-owning agentd startup relation",
        ),
        (
            &edge_main,
            "wait_for_upstream(&config.upstream_socket)",
            "in-process upstream recovery",
        ),
        (
            &edge_main,
            "UnixStream::connect(upstream_socket)",
            "live upstream readiness proof",
        ),
        (&service, "ProtectSystem=strict", "read-only system sandbox"),
        (&service, "CapabilityBoundingSet=", "empty capability bound"),
        (
            &service,
            "ReadOnlyPaths=/etc/jw-agent/edge",
            "read-only TLS material",
        ),
        (
            &service,
            "ReadWritePaths=/run/jw-agent-edge",
            "bounded readiness path",
        ),
        (&service, "UMask=0155", "readiness socket connect mask"),
        (
            &tmpfiles,
            "d /run/jw-agent-edge 0751 jw-agent jw-agent -",
            "persistent non-writable readiness directory",
        ),
        (
            &edge_main,
            "from_mode(0o622)",
            "connect-only readiness socket mode",
        ),
        (
            &edge_main,
            "from_mode(0o600)",
            "private readiness marker mode",
        ),
        (
            &config,
            "/run/jw-agent-edge/ready.sock",
            "shared readiness socket",
        ),
        (
            &edge_main,
            "UnixListener::bind(&config.ready_socket)",
            "live readiness listener",
        ),
        (&edge_main, "JW-EDGE-READY-V1", "bounded readiness response"),
        (
            &runner,
            "UnixStream::connect(path)",
            "networkless readiness client",
        ),
        (
            &operation,
            "management_ingress_dependency",
            "two-phase Nginx stop guard",
        ),
        (
            &inventory,
            "independent_edge_ready",
            "capability advertisement guard",
        ),
    ] {
        if !content.contains(needle) {
            failures.push(format!("independent edge is missing {label}"));
        }
    }
    for (content, needle, label) in [
        (&manifest, "jw-authd", "authd dependency"),
        (&manifest, "jw-opsd", "opsd dependency"),
        (&manifest, "ffi-pam", "PAM dependency"),
        (&manifest, "openssl", "OpenSSL dependency"),
        (&proxy, "/run/jw-agent/opsd.sock", "opsd socket"),
        (&proxy, "/run/jw-agent/authd.sock", "authd socket"),
        (&config, "0.0.0.0:443", "privileged default listener"),
        (
            &service,
            "RuntimeDirectory=jw-agent-edge",
            "restart-recreated readiness directory",
        ),
        (
            &service,
            "Requires=jw-agentd.service",
            "agentd stop propagation",
        ),
        (
            &service,
            "PartOf=jw-agentd.service",
            "agentd restart coupling",
        ),
    ] {
        if content.to_ascii_lowercase().contains(needle) {
            failures.push(format!("independent edge contains forbidden {label}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}
