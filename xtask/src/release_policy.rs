#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

const PRODUCT_MANIFESTS: &[(&str, &str)] = &[
    ("ffi-pam", "crates/ffi-pam/Cargo.toml"),
    ("jw-agentd", "crates/jw-agentd/Cargo.toml"),
    ("jw-authd", "crates/jw-authd/Cargo.toml"),
    ("jw-certd", "crates/jw-certd/Cargo.toml"),
    ("jw-contracts", "crates/jw-contracts/Cargo.toml"),
    ("jw-edge", "crates/jw-edge/Cargo.toml"),
    ("jw-opsd", "crates/jw-opsd/Cargo.toml"),
];
const CHANGELOG_CATEGORIES: &[&str] = &[
    "Added",
    "Changed",
    "Deprecated",
    "Removed",
    "Fixed",
    "Security",
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct SemVer {
    original: String,
    core: [String; 3],
    prerelease: Option<Vec<String>>,
}

impl SemVer {
    fn parse(value: &str) -> Result<Self, String> {
        if value.is_empty() || value.trim() != value {
            return Err(String::from(
                "version is empty or has surrounding whitespace",
            ));
        }

        let (without_build, build) = match value.split_once('+') {
            Some((left, right)) if !right.contains('+') => (left, Some(right)),
            Some(_) => return Err(String::from("version has more than one build separator")),
            None => (value, None),
        };
        if let Some(identifiers) = build {
            validate_identifiers(identifiers, false, "build metadata")?;
        }

        let (core, prerelease) = match without_build.split_once('-') {
            Some((left, right)) => (left, Some(right)),
            None => (without_build, None),
        };
        let parts: Vec<&str> = core.split('.').collect();
        if parts.len() != 3 {
            return Err(String::from("version core must contain major.minor.patch"));
        }
        for part in &parts {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(String::from("major, minor, and patch must be numeric"));
            }
            if part.len() > 1 && part.starts_with('0') {
                return Err(String::from(
                    "numeric core identifiers cannot have leading zeroes",
                ));
            }
        }

        let prerelease = match prerelease {
            Some(identifiers) => {
                validate_identifiers(identifiers, true, "prerelease")?;
                Some(identifiers.split('.').map(String::from).collect())
            }
            None => None,
        };

        Ok(Self {
            original: value.to_string(),
            core: [
                parts[0].to_string(),
                parts[1].to_string(),
                parts[2].to_string(),
            ],
            prerelease,
        })
    }

    fn core_string(&self) -> String {
        self.core.join(".")
    }

    fn precedence_cmp(&self, other: &Self) -> Ordering {
        for index in 0..self.core.len() {
            let ordering = numeric_cmp(&self.core[index], &other.core[index]);
            if ordering != Ordering::Equal {
                return ordering;
            }
        }
        match (&self.prerelease, &other.prerelease) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(left), Some(right)) => prerelease_cmp(left, right),
        }
    }
}

pub fn gate_release_policy(root: &Path, _timeout: Duration) -> Result<(), String> {
    let workspace_manifest = read(&root.join("Cargo.toml"))?;
    let product_version = workspace_version(&workspace_manifest)?;
    let parsed_product = SemVer::parse(&product_version)
        .map_err(|error| format!("workspace product version `{product_version}`: {error}"))?;

    validate_product_manifests(root, &product_version)?;
    validate_web_version(root, &product_version)?;
    validate_lockfile(root, &product_version)?;
    validate_debian_version(root, &parsed_product)?;
    validate_changelog(&read(&root.join("CHANGELOG.md"))?)
}

fn validate_identifiers(
    value: &str,
    reject_numeric_leading_zero: bool,
    label: &str,
) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    for identifier in value.split('.') {
        if identifier.is_empty()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!("{label} contains an invalid identifier"));
        }
        if reject_numeric_leading_zero
            && identifier.bytes().all(|byte| byte.is_ascii_digit())
            && identifier.len() > 1
            && identifier.starts_with('0')
        {
            return Err(format!(
                "numeric {label} identifiers cannot have leading zeroes"
            ));
        }
    }
    Ok(())
}

fn numeric_cmp(left: &str, right: &str) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn prerelease_cmp(left: &[String], right: &[String]) -> Ordering {
    for (left_identifier, right_identifier) in left.iter().zip(right) {
        let left_numeric = left_identifier.bytes().all(|byte| byte.is_ascii_digit());
        let right_numeric = right_identifier.bytes().all(|byte| byte.is_ascii_digit());
        let ordering = match (left_numeric, right_numeric) {
            (true, true) => numeric_cmp(left_identifier, right_identifier),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => left_identifier.cmp(right_identifier),
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn workspace_version(manifest: &str) -> Result<String, String> {
    let mut in_workspace_package = false;
    for line in manifest.lines() {
        let trimmed = without_comment(line).trim();
        if trimmed.starts_with('[') {
            in_workspace_package = trimmed == "[workspace.package]";
            continue;
        }
        if in_workspace_package && let Some(version) = quoted_assignment(trimmed, "version") {
            return Ok(version.to_string());
        }
    }
    Err(String::from(
        "Cargo.toml is missing [workspace.package].version",
    ))
}

fn validate_product_manifests(root: &Path, product_version: &str) -> Result<(), String> {
    let mut failures = Vec::new();
    for (_, relative) in PRODUCT_MANIFESTS {
        let manifest = read(&root.join(relative))?;
        if !manifest
            .lines()
            .any(|line| without_comment(line).trim() == "version.workspace = true")
        {
            failures.push(format!(
                "{relative} must inherit workspace product version {product_version}"
            ));
        }
    }
    finish(failures)
}

fn validate_web_version(root: &Path, product_version: &str) -> Result<(), String> {
    let package = read(&root.join("apps/web/package.json"))?;
    let version = json_string_field(&package, "version")
        .ok_or_else(|| String::from("apps/web/package.json is missing string version"))?;
    if version == product_version {
        Ok(())
    } else {
        Err(format!(
            "web version `{version}` differs from product version `{product_version}`"
        ))
    }
}

fn validate_lockfile(root: &Path, product_version: &str) -> Result<(), String> {
    let lockfile = read(&root.join("Cargo.lock"))?;
    let mut failures = Vec::new();
    for (name, _) in PRODUCT_MANIFESTS {
        let found = lockfile.split("[[package]]").skip(1).find_map(|block| {
            let package_name = block
                .lines()
                .find_map(|line| quoted_assignment(line.trim(), "name"))?;
            if package_name != *name {
                return None;
            }
            block
                .lines()
                .find_map(|line| quoted_assignment(line.trim(), "version"))
                .map(String::from)
        });
        match found {
            Some(version) if version == product_version => {}
            Some(version) => failures.push(format!(
                "Cargo.lock {name} version `{version}` differs from `{product_version}`"
            )),
            None => failures.push(format!("Cargo.lock is missing product package {name}")),
        }
    }
    finish(failures)
}

fn validate_debian_version(root: &Path, product: &SemVer) -> Result<(), String> {
    let changelog = read(&root.join("packaging/debian/changelog"))?;
    let first_line = changelog
        .lines()
        .next()
        .ok_or_else(|| String::from("Debian changelog is empty"))?;
    let after_name = first_line
        .strip_prefix("jw-agent (")
        .ok_or_else(|| String::from("Debian changelog has an invalid first line"))?;
    let close = after_name
        .find(')')
        .ok_or_else(|| String::from("Debian changelog version is not closed"))?;
    let debian_version = &after_name[..close];
    if debian_version_matches(product, debian_version) {
        Ok(())
    } else {
        Err(format!(
            "Debian version `{debian_version}` does not map to product version `{}`",
            product.original
        ))
    }
}

fn debian_version_matches(product: &SemVer, debian_version: &str) -> bool {
    let core = product.core_string();
    match &product.prerelease {
        Some(identifiers) => {
            let expected = format!("{core}~{}", identifiers.join("."));
            debian_version == expected || debian_version.starts_with(&format!("{expected}-"))
        }
        None => {
            debian_version == core
                || debian_version.starts_with(&format!("{core}-"))
                || debian_version.starts_with(&format!("{core}~p"))
        }
    }
}

fn validate_changelog(content: &str) -> Result<(), String> {
    let required_fragments = [
        "# Changelog",
        "[Keep a Changelog 1.1.0]",
        "[Semantic Versioning 2.0.0]",
        "[Unreleased]: ",
    ];
    let mut failures: Vec<String> = required_fragments
        .iter()
        .filter(|fragment| !content.contains(*fragment))
        .map(|fragment| format!("CHANGELOG.md is missing `{fragment}`"))
        .collect();
    let mut saw_unreleased = false;
    let mut saw_release_heading = false;
    let mut release_versions = Vec::new();
    let mut release_names = BTreeSet::new();

    for line in content.lines() {
        if line.starts_with("### ") {
            let category = line.trim_start_matches("### ");
            if !CHANGELOG_CATEGORIES.contains(&category) {
                failures.push(format!("unsupported changelog category `{category}`"));
            }
        }
        if !line.starts_with("## ") {
            continue;
        }
        if line == "## [Unreleased]" {
            if saw_unreleased || saw_release_heading {
                failures.push(String::from(
                    "Unreleased must be the first and only such section",
                ));
            }
            saw_unreleased = true;
            continue;
        }
        saw_release_heading = true;
        if !saw_unreleased {
            failures.push(String::from(
                "Unreleased must precede every release section",
            ));
        }
        match parse_release_heading(line) {
            Ok((version, _date)) => {
                if !release_names.insert(version.original.clone()) {
                    failures.push(format!("duplicate release {}", version.original));
                }
                let link = format!("[{}]: ", version.original);
                if !content
                    .lines()
                    .any(|candidate| candidate.starts_with(&link))
                {
                    failures.push(format!(
                        "release {} has no comparison link",
                        version.original
                    ));
                }
                release_versions.push(version);
            }
            Err(error) => failures.push(error),
        }
    }

    if !saw_unreleased {
        failures.push(String::from("CHANGELOG.md has no Unreleased section"));
    }
    for pair in release_versions.windows(2) {
        if pair[0].precedence_cmp(&pair[1]) != Ordering::Greater {
            failures.push(format!(
                "release sections are not newest-first: {} before {}",
                pair[0].original, pair[1].original
            ));
        }
    }
    finish(failures)
}

fn parse_release_heading(line: &str) -> Result<(SemVer, &str), String> {
    let rest = line
        .strip_prefix("## [")
        .ok_or_else(|| format!("invalid release heading `{line}`"))?;
    let close = rest
        .find(']')
        .ok_or_else(|| format!("invalid release heading `{line}`"))?;
    let version_text = &rest[..close];
    let suffix = rest[close + 1..]
        .strip_prefix(" - ")
        .ok_or_else(|| format!("release heading lacks ISO date `{line}`"))?;
    if suffix.len() < 10 {
        return Err(format!("release heading lacks ISO date `{line}`"));
    }
    let date = &suffix[..10];
    let trailing = suffix[10..].trim();
    if !trailing.is_empty() && trailing != "[YANKED]" {
        return Err(format!("invalid release heading suffix `{line}`"));
    }
    validate_iso_date(date).map_err(|error| format!("release `{version_text}`: {error}"))?;
    let version = SemVer::parse(version_text)
        .map_err(|error| format!("release version `{version_text}`: {error}"))?;
    Ok((version, date))
}

fn validate_iso_date(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
    {
        return Err(format!("date `{value}` is not YYYY-MM-DD"));
    }
    let year = parse_date_part(&value[..4])?;
    let month = parse_date_part(&value[5..7])?;
    let day = parse_date_part(&value[8..10])?;
    let leap = year % 400 == 0 || (year % 4 == 0 && year % 100 != 0);
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(format!("date `{value}` has an invalid month")),
    };
    if day == 0 || day > maximum {
        return Err(format!("date `{value}` has an invalid day"));
    }
    Ok(())
}

fn parse_date_part(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|error| format!("invalid date component: {error}"))
}

fn quoted_assignment<'a>(line: &'a str, expected_key: &str) -> Option<&'a str> {
    let (key, value) = line.split_once('=')?;
    if key.trim() != expected_key {
        return None;
    }
    let value = value.trim().strip_prefix('"')?;
    let close = value.find('"')?;
    if !value[close + 1..].trim().is_empty() {
        return None;
    }
    Some(&value[..close])
}

fn json_string_field<'a>(content: &'a str, field: &str) -> Option<&'a str> {
    let prefix = format!("\"{field}\"");
    for line in content.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix(&prefix) else {
            continue;
        };
        let rest = rest.trim_start();
        let rest = rest.strip_prefix(':')?.trim_start().strip_prefix('"')?;
        let close = rest.find('"')?;
        return Some(&rest[..close]);
    }
    None
}

fn without_comment(line: &str) -> &str {
    match line.split_once('#') {
        Some((content, _)) => content,
        None => line,
    }
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn finish(failures: Vec<String>) -> Result<(), String> {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SemVer, debian_version_matches, json_string_field, parse_release_heading,
        validate_changelog, validate_iso_date, workspace_version,
    };
    use std::cmp::Ordering;

    #[test]
    fn accepts_semver_and_orders_prereleases() {
        let alpha = SemVer::parse("1.0.0-alpha.1");
        let release = SemVer::parse("1.0.0+build.7");
        assert!(
            matches!((alpha, release), (Ok(left), Ok(right)) if left.precedence_cmp(&right) == Ordering::Less)
        );
    }

    #[test]
    fn rejects_invalid_semver() {
        for value in ["1", "1.2", "01.2.3", "1.2.3-01", "v1.2.3", "1.2.3+"] {
            assert!(SemVer::parse(value).is_err(), "accepted invalid {value}");
        }
    }

    #[test]
    fn validates_release_heading_and_calendar_date() {
        assert!(parse_release_heading("## [1.2.3-rc.1] - 2024-02-29").is_ok());
        assert!(validate_iso_date("2023-02-29").is_err());
        assert!(parse_release_heading("## [1.2] - 2024-01-01").is_err());
    }

    #[test]
    fn rejects_unknown_category_and_reverse_order() {
        let changelog = "# Changelog\n[Keep a Changelog 1.1.0]\n[Semantic Versioning 2.0.0]\n## [Unreleased]\n### Added\n- x\n## [1.0.0] - 2024-01-01\n### Breaking\n- x\n## [1.1.0] - 2024-02-01\n- y\n[Unreleased]: main\n[1.0.0]: one\n[1.1.0]: two\n";
        let error = validate_changelog(changelog);
        assert!(error.is_err());
    }

    #[test]
    fn detects_product_version_drift_inputs() {
        assert_eq!(
            workspace_version("[workspace.package]\nversion = \"0.2.0\"\n"),
            Ok(String::from("0.2.0"))
        );
        assert_eq!(
            json_string_field("{\n  \"version\": \"0.2.1\"\n}\n", "version"),
            Some("0.2.1")
        );
        let stable = SemVer::parse("0.2.0");
        assert!(
            matches!(stable, Ok(ref version) if debian_version_matches(version, "0.2.0~p2.24"))
        );
        let candidate = SemVer::parse("0.3.0-rc.1");
        assert!(
            matches!(candidate, Ok(ref version) if debian_version_matches(version, "0.3.0~rc.1-1"))
        );
        let drift = SemVer::parse("0.3.0");
        assert!(matches!(drift, Ok(ref version) if !debian_version_matches(version, "0.2.0-1")));
    }
}
