use std::path::Path;
use std::time::Duration;

use super::run_command;

pub(crate) fn gate_web_lint(root: &Path, timeout: Duration) -> Result<(), String> {
    run_command(&root.join("apps/web"), "bun", ["run", "lint"], timeout)
}

pub(crate) fn gate_web_unit(root: &Path, timeout: Duration) -> Result<(), String> {
    run_command(&root.join("apps/web"), "bun", ["run", "test"], timeout)
}

pub(crate) fn gate_web_build(root: &Path, timeout: Duration) -> Result<(), String> {
    run_command(&root.join("apps/web"), "bun", ["run", "build"], timeout)
}

pub(crate) fn gate_web_browser(root: &Path, timeout: Duration) -> Result<(), String> {
    run_command(&root.join("apps/web"), "bun", ["run", "test:e2e"], timeout)
}
