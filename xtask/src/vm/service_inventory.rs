use std::path::Path;
use std::time::Duration;

use super::{P2ApiSession, VmConfig, expect_http, read_secret, require_success};

pub(crate) fn gate_p2_service_inventory(_root: &Path, timeout: Duration) -> Result<(), String> {
    let config = VmConfig::load()?;
    let password = read_secret(&config.password_file)?;
    let setup = config.ssh(
        r#"set -eu
printf '%s\n' \
  '[Unit]' \
  'Description=JW Agent disposable service inventory fixture' \
  '[Service]' \
  'Type=oneshot' \
  'ExecStart=/usr/bin/false' \
  | sudo tee /etc/systemd/system/operator-inventory-fixture.service >/dev/null
sudo chmod 0644 /etc/systemd/system/operator-inventory-fixture.service
sudo systemctl daemon-reload
sudo systemctl reset-failed operator-inventory-fixture.service || true
if sudo systemctl start operator-inventory-fixture.service; then
  exit 1
fi
test "$(systemctl is-failed operator-inventory-fixture.service)" = failed
"#,
        None,
        timeout,
    )?;
    require_success(&setup, "service inventory failed-unit fixture", false)?;

    let result = verify_service_inventory(&config, &password, timeout);
    let cleanup = config.ssh(
        r#"set -eu
sudo systemctl reset-failed operator-inventory-fixture.service || true
sudo rm -f /etc/systemd/system/operator-inventory-fixture.service
sudo systemctl daemon-reload
"#,
        None,
        timeout,
    )?;
    require_success(&cleanup, "service inventory fixture cleanup", false)?;
    result
}

fn verify_service_inventory(
    config: &VmConfig,
    password: &str,
    timeout: Duration,
) -> Result<(), String> {
    let session = P2ApiSession::login(config, password, timeout)?;
    let response = session.get(config, "/api/v1/services", timeout)?;
    expect_http(&response, 200, "service inventory API")?;
    for required in [
        "\"status\":\"observed\"",
        "\"templateProfile\":\"ubuntu-24.04-v1\"",
        "\"unitName\":\"nginx.service\"",
        "\"displayName\":\"Nginx\"",
        "\"support\":\"supported_observe\"",
        "\"unitName\":\"jw-agentd.service\"",
        "\"visibility\":\"system\"",
        "\"unitName\":\"operator-inventory-fixture.service\"",
        "\"runtimeState\":\"failed\"",
        "\"visibility\":\"discovered\"",
        "\"support\":\"discovered_read_only\"",
        "\"readOnly\":true",
        "\"hiddenByDefault\":false",
    ] {
        if !response.body.contains(required) {
            return Err(format!(
                "service inventory response is missing required evidence `{required}`"
            ));
        }
    }
    for forbidden in ["ExecStart=", "/etc/systemd/system/", "systemctl show"] {
        if response.body.contains(forbidden) {
            return Err(format!(
                "service inventory response leaked forbidden command detail `{forbidden}`"
            ));
        }
    }
    session.logout(config, timeout)
}
