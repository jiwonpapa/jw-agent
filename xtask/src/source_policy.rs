#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_MAX_LINES: usize = 1_250;
const SOURCE_ROOTS: &[&str] = &["crates", "xtask/src", "apps/web/src", "apps/web/tests"];

// Existing hotspots may shrink but must not grow. Split them inside the owning crate or feature
// before adding behavior; do not create a new crate only to satisfy this budget.
const LEGACY_BUDGETS: &[(&str, usize)] = &[
    ("crates/jw-opsd/src/engine.rs", 4_396),
    ("xtask/src/vm.rs", 4_081),
    ("crates/jw-agentd/src/api.rs", 3_284),
    ("xtask/src/main.rs", 1_650),
    ("crates/jw-opsd/src/ledger.rs", 1_503),
    (
        "apps/web/src/features/certificates/certificates-screen.tsx",
        1_495,
    ),
    ("apps/web/tests/e2e/app.spec.ts", 1_485),
];

pub fn gate_source_size_ratchet(root: &Path, _timeout: std::time::Duration) -> Result<(), String> {
    let mut failures = Vec::new();
    for (relative, budget) in LEGACY_BUDGETS {
        let path = root.join(relative);
        let lines = source_lines(&path)?;
        if lines > *budget {
            failures.push(format!(
                "{relative} grew to {lines} lines; budget is {budget}"
            ));
        }
    }

    for path in source_files(root)? {
        let relative = display_relative(root, &path);
        if LEGACY_BUDGETS.iter().any(|(legacy, _)| *legacy == relative) || is_generated(root, &path)
        {
            continue;
        }
        let lines = source_lines(&path)?;
        if lines > DEFAULT_MAX_LINES {
            failures.push(format!(
                "{relative} has {lines} lines; split within its owner before exceeding {DEFAULT_MAX_LINES}"
            ));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn source_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    let mut pending: Vec<PathBuf> = SOURCE_ROOTS.iter().map(|path| root.join(path)).collect();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("cannot read directory entry: {error}"))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file()
                && matches!(
                    path.extension().and_then(OsStr::to_str),
                    Some("rs" | "ts" | "tsx")
                )
            {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn source_lines(path: &Path) -> Result<usize, String> {
    fs::read_to_string(path)
        .map(|source| source.lines().count())
        .map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn is_generated(root: &Path, path: &Path) -> bool {
    path.starts_with(root.join("apps/web/src/shared/api/generated"))
        || path == root.join("apps/web/src/routeTree.gen.ts")
}

fn display_relative<'a>(root: &Path, path: &'a Path) -> &'a str {
    match path.strip_prefix(root).ok().and_then(Path::to_str) {
        Some(relative) => relative,
        None => "non_utf8_source_path",
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_MAX_LINES, LEGACY_BUDGETS};

    #[test]
    fn budgets_are_unique_and_only_relax_the_default_for_known_hotspots() {
        let mut paths: Vec<&str> = LEGACY_BUDGETS.iter().map(|(path, _)| *path).collect();
        let original_len = paths.len();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), original_len);
        assert!(
            LEGACY_BUDGETS
                .iter()
                .all(|(_, budget)| *budget > DEFAULT_MAX_LINES)
        );
    }
}
