use std::time::Duration;

use super::receipt::require_command_evidence;
use super::{P2ApiSession, VmConfig, require_file_equals, require_success, require_terminal};

pub(super) fn verify_timeout(
    config: &VmConfig,
    session: &mut P2ApiSession,
    expected_content: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    install(config, timeout)?;
    let verification = (|| {
        session.wait_for_operation_available(config, timeout)?;
        let receipt = session.operate_managed_config(
            config,
            super::P2_MANAGED_SITE,
            super::P2_MANAGED_RELOAD_CHANGE,
            timeout,
        )?;
        require_terminal(
            &receipt,
            "ROLLED_BACK",
            "managed config validator timeout rollback",
        )?;
        require_command_evidence(&receipt, "nginx_config_test", false, true, false, true)?;
        require_file_equals(config, super::P2_MANAGED_SITE, expected_content, timeout)
    })();
    let cleanup = remove(config, timeout);
    match (verification, cleanup) {
        (Ok(()), Ok(())) => session.wait_for_operation_available(config, timeout),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; timeout fixture cleanup failed: {cleanup_error}"
        )),
    }
}

fn install(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let wrapper = br#"#!/bin/sh
set -eu
if test -e /run/jw-agent/jw-agent-vm-nginx-timeout; then
    rm -f /run/jw-agent/jw-agent-vm-nginx-timeout
    index=0
    while test "$index" -lt 8192; do
        printf '0123456789abcdef' >&2
        index=$((index + 1))
    done
    sleep 30
fi
exec /var/lib/jw-agent/opsd/jw-agent-vm-nginx-real "$@"
"#;
    let install_wrapper = config.ssh(
        "sudo install -o root -g root -m 0755 /usr/sbin/nginx /var/lib/jw-agent/opsd/jw-agent-vm-nginx-real\nsudo install -o root -g root -m 0755 /dev/stdin /var/lib/jw-agent/opsd/jw-agent-vm-nginx",
        Some(wrapper),
        timeout,
    )?;
    require_success(
        &install_wrapper,
        "managed config timeout command wrapper",
        false,
    )?;

    let drop_in =
        b"[Service]\nBindReadOnlyPaths=/var/lib/jw-agent/opsd/jw-agent-vm-nginx:/usr/sbin/nginx\n";
    let install_drop_in = config.ssh(
        "sudo install -d -o root -g root -m 0755 /etc/systemd/system/jw-opsd.service.d\nsudo install -o root -g root -m 0644 /dev/stdin /etc/systemd/system/jw-opsd.service.d/90-jw-agent-vm-command-timeout.conf\nsudo touch /run/jw-agent/jw-agent-vm-nginx-timeout\nsudo systemctl daemon-reload\nsudo systemctl restart jw-opsd.service",
        Some(drop_in),
        timeout,
    )?;
    require_success(
        &install_drop_in,
        "managed config timeout namespace binding",
        false,
    )
}

fn remove(config: &VmConfig, timeout: Duration) -> Result<(), String> {
    let result = config.ssh(
        "sudo rm -f /etc/systemd/system/jw-opsd.service.d/90-jw-agent-vm-command-timeout.conf /var/lib/jw-agent/opsd/jw-agent-vm-nginx /var/lib/jw-agent/opsd/jw-agent-vm-nginx-real /run/jw-agent/jw-agent-vm-nginx-timeout\nsudo systemctl daemon-reload\nsudo systemctl restart jw-opsd.service\nsudo nginx -t\nsudo systemctl reload nginx.service",
        None,
        timeout,
    )?;
    require_success(&result, "managed config timeout fixture cleanup", false)
}
