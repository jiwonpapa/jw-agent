#![forbid(unsafe_code)]

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::process::run_capture_in;
use crate::{compare_files, run_command_os};

const NODE_MIN_MAJOR: u32 = 22;
const NODE_MAX_MAJOR: u32 = 24;

pub fn gate_openapi_drift(root: &Path, timeout: Duration) -> Result<(), String> {
    let temporary = root
        .join("target")
        .join(format!("xtask-openapi-{}", std::process::id()));
    fs::create_dir_all(root.join("target")).map_err(|error| error.to_string())?;
    fs::create_dir(&temporary).map_err(|error| {
        format!(
            "cannot create contract evidence directory {}: {error}",
            temporary.display()
        )
    })?;
    let result = generate_and_compare_contracts(root, &temporary, timeout);
    let cleanup = fs::remove_dir_all(&temporary).map_err(|error| {
        format!(
            "cannot remove contract evidence directory {}: {error}",
            temporary.display()
        )
    });
    match (result, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn generate_and_compare_contracts(
    root: &Path,
    temporary: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let generated_openapi = temporary.join("openapi.json");
    let generated_schema = temporary.join("schema.d.ts");
    run_command_os(
        root,
        OsStr::new("cargo"),
        &[
            OsString::from("run"),
            OsString::from("--locked"),
            OsString::from("--quiet"),
            OsString::from("-p"),
            OsString::from("jw-agentd"),
            OsString::from("--"),
            OsString::from("openapi"),
            generated_openapi.as_os_str().to_owned(),
        ],
        timeout,
    )?;

    let generator = root.join("apps/web/node_modules/openapi-typescript/bin/cli.js");
    if !generator.is_file() {
        return Err(String::from(
            "OpenAPI generator missing; run bun install in apps/web",
        ));
    }
    let node = select_node_runtime(root)?;
    run_command_os(
        root,
        node.as_os_str(),
        &[
            generator.as_os_str().to_owned(),
            generated_openapi.as_os_str().to_owned(),
            OsString::from("-o"),
            generated_schema.as_os_str().to_owned(),
        ],
        timeout,
    )?;
    compare_files(root, &generated_openapi, &root.join("api/openapi.json"))?;
    compare_files(
        root,
        &generated_schema,
        &root.join("apps/web/src/shared/api/generated/schema.d.ts"),
    )
}

fn select_node_runtime(root: &Path) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if let Some(configured) = env::var_os("JW_OPENAPI_NODE") {
        candidates.push(PathBuf::from(configured));
    }
    if let Some(home) = env::var_os("HOME") {
        candidates
            .push(PathBuf::from(home).join(".local/share/jw-agent/toolchains/node-v24/bin/node"));
    }
    candidates.extend([
        PathBuf::from("/opt/homebrew/opt/node@24/bin/node"),
        PathBuf::from("/usr/local/opt/node@24/bin/node"),
        PathBuf::from("/usr/bin/node"),
        PathBuf::from("node"),
    ]);

    let mut observations = Vec::new();
    for candidate in candidates {
        if candidate.components().count() > 1 && !candidate.is_file() {
            continue;
        }
        let captured = match run_capture_in(
            Some(root),
            candidate.as_os_str(),
            &[OsString::from("--version")],
            None,
            Duration::from_secs(5),
        ) {
            Ok(value) => value,
            Err(error) => {
                observations.push(format!("{}: {error}", candidate.display()));
                continue;
            }
        };
        let version = String::from_utf8_lossy(&captured.stdout);
        match node_major(&version) {
            Some(major)
                if captured.status.success()
                    && (NODE_MIN_MAJOR..=NODE_MAX_MAJOR).contains(&major) =>
            {
                match runtime_io_probe(root, &candidate) {
                    Ok(()) => return Ok(candidate),
                    Err(error) => observations.push(format!(
                        "{}: responsive I/O probe failed: {error}",
                        candidate.display()
                    )),
                }
            }
            Some(major) => observations.push(format!("{}: Node {major}", candidate.display())),
            None => observations.push(format!("{}: invalid version", candidate.display())),
        }
    }
    Err(format!(
        "OpenAPI generation requires a responsive official Node {NODE_MIN_MAJOR}-{NODE_MAX_MAJOR}; set JW_OPENAPI_NODE or install the local node-v24 toolchain ({})",
        observations.join(", ")
    ))
}

fn runtime_io_probe(root: &Path, candidate: &Path) -> Result<(), String> {
    let probe_file = root.join("apps/web/node_modules/openapi-typescript/package.json");
    let script = "const fs=require('node:fs');fs.readFile(process.argv[1],e=>{if(e){console.error(e.code);process.exitCode=1}})";
    let captured = run_capture_in(
        Some(root),
        candidate.as_os_str(),
        &[
            OsString::from("-e"),
            OsString::from(script),
            probe_file.into_os_string(),
        ],
        None,
        Duration::from_secs(2),
    )?;
    if captured.status.success() {
        Ok(())
    } else {
        Err(format!("probe exited with {}", captured.status))
    }
}

fn node_major(value: &str) -> Option<u32> {
    value
        .trim()
        .strip_prefix('v')
        .and_then(|version| version.split('.').next())
        .and_then(|major| major.parse::<u32>().ok())
}

#[cfg(test)]
mod tests {
    use super::node_major;

    #[test]
    fn node_major_is_exact_and_non_panicking() {
        assert_eq!(node_major("v24.19.0\n"), Some(24));
        assert_eq!(node_major("25.5.0"), None);
        assert_eq!(node_major("latest"), None);
    }
}
