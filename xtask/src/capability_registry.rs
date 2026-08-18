#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

const REGISTRY_PATH: &str = "docs/00-governance/capabilities-v1.json";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    P1,
    P2,
    P3,
    P4,
    P5,
    Future,
}

impl Phase {
    const ALL: [Self; 6] = [
        Self::P1,
        Self::P2,
        Self::P3,
        Self::P4,
        Self::P5,
        Self::Future,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::P1 => "P1 기반",
            Self::P2 => "P2 로컬 유지보수",
            Self::P3 => "P3 Community RC",
            Self::P4 => "P4 중앙 읽기 전용",
            Self::P5 => "P5 중앙 typed 작업",
            Self::Future => "후속 검토",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ReleaseScope {
    Mvp,
    Deferred,
    Excluded,
    Forbidden,
}

impl ReleaseScope {
    const fn label(self) -> &'static str {
        match self {
            Self::Mvp => "MVP",
            Self::Deferred => "후순위",
            Self::Excluded => "제외",
            Self::Forbidden => "금지",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ImplementationStatus {
    Implemented,
    Partial,
    Planned,
    Excluded,
    Forbidden,
}

impl ImplementationStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Implemented => "구현",
            Self::Partial => "부분 구현",
            Self::Planned => "미구현",
            Self::Excluded => "제외",
            Self::Forbidden => "금지",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SupportStatus {
    Supported,
    Limited,
    Unverified,
    Unsupported,
}

impl SupportStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Supported => "지원",
            Self::Limited => "제한 지원",
            Self::Unverified => "미검증",
            Self::Unsupported => "미지원",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum EvidenceLevel {
    Policy,
    Doc,
    LocalPass,
    BrowserPass,
    VmPass,
    ReleasePass,
    Unverified,
}

impl EvidenceLevel {
    const fn label(self) -> &'static str {
        match self {
            Self::Policy => "정책",
            Self::Doc => "문서",
            Self::LocalPass => "LOCAL_PASS",
            Self::BrowserPass => "BROWSER_PASS",
            Self::VmPass => "VM_PASS",
            Self::ReleasePass => "RELEASE_PASS",
            Self::Unverified => "UNVERIFIED",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Assurance {
    G0,
    G1,
    G2,
    Mixed,
    None,
}

impl Assurance {
    const fn label(self) -> &'static str {
        match self {
            Self::G0 => "G0",
            Self::G1 => "G1",
            Self::G2 => "G2",
            Self::Mixed => "혼합",
            Self::None => "해당 없음",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema_version: u32,
    reviewed: String,
    generated_document: String,
    capabilities: Vec<Capability>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capability {
    id: String,
    name: String,
    owner: String,
    phase: Phase,
    release_scope: ReleaseScope,
    implementation: ImplementationStatus,
    support: SupportStatus,
    evidence: EvidenceLevel,
    assurance: Assurance,
    reference: String,
    #[serde(default)]
    spec: Option<String>,
    #[serde(default)]
    api_paths: Vec<String>,
    #[serde(default)]
    operation_types: Vec<String>,
    #[serde(default)]
    gates: Vec<String>,
    #[serde(default)]
    blocker: Option<String>,
}

pub fn gate_capability_registry(root: &Path, _timeout: Duration) -> Result<(), String> {
    let registry = load_registry(root)?;
    validate_registry(root, &registry)?;
    let expected = render_document(&registry);
    let generated_path = checked_workspace_path(root, &registry.generated_document)?;
    let actual = fs::read_to_string(&generated_path)
        .map_err(|error| format!("cannot read {}: {error}", generated_path.display()))?;
    if actual == expected {
        Ok(())
    } else {
        Err(String::from(
            "capability status snapshot drift; run `cargo xtask render-capabilities`",
        ))
    }
}

pub fn write_generated_document(root: &Path) -> Result<(), String> {
    let registry = load_registry(root)?;
    validate_registry(root, &registry)?;
    let generated_path = checked_workspace_path(root, &registry.generated_document)?;
    let Some(parent) = generated_path.parent() else {
        return Err(String::from("generated capability document has no parent"));
    };
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    fs::write(&generated_path, render_document(&registry))
        .map_err(|error| format!("cannot write {}: {error}", generated_path.display()))?;
    println!("rendered {}", display_relative(root, &generated_path));
    Ok(())
}

fn load_registry(root: &Path) -> Result<Registry, String> {
    let path = root.join(REGISTRY_PATH);
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    serde_json::from_str(&source).map_err(|error| format!("invalid {REGISTRY_PATH}: {error}"))
}

fn validate_registry(root: &Path, registry: &Registry) -> Result<(), String> {
    let mut failures = Vec::new();
    if registry.schema_version != 1 {
        failures.push(format!(
            "unsupported schema_version {}",
            registry.schema_version
        ));
    }
    if !is_calendar_date(&registry.reviewed) {
        failures.push(String::from("reviewed must use YYYY-MM-DD"));
    }
    if registry.capabilities.is_empty() {
        failures.push(String::from("capability registry is empty"));
    }

    let openapi_paths = openapi_paths(root)?;
    let operation_source = operation_source(root)?;
    let gate_ids = gate_ids(root)?;
    let spec_index = fs::read_to_string(root.join("docs/90-specs/README.md"))
        .map_err(|error| format!("cannot read spec index: {error}"))?;
    let mut capability_ids = BTreeSet::new();

    for capability in &registry.capabilities {
        validate_capability(
            root,
            capability,
            &openapi_paths,
            &operation_source,
            &gate_ids,
            &spec_index,
            &mut capability_ids,
            &mut failures,
        );
    }

    let generated = checked_workspace_path(root, &registry.generated_document)?;
    if generated.extension().and_then(|value| value.to_str()) != Some("md") {
        failures.push(String::from("generated_document must be Markdown"));
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_capability(
    root: &Path,
    capability: &Capability,
    openapi_paths: &BTreeSet<String>,
    operation_source: &str,
    gate_ids: &BTreeSet<String>,
    spec_index: &str,
    capability_ids: &mut BTreeSet<String>,
    failures: &mut Vec<String>,
) {
    let id = capability.id.as_str();
    if !valid_id(id) {
        failures.push(format!("{id}: invalid id"));
    }
    if !capability_ids.insert(capability.id.clone()) {
        failures.push(format!("{id}: duplicate id"));
    }
    for (label, value) in [("name", &capability.name), ("owner", &capability.owner)] {
        if value.trim().is_empty() || value.contains(['|', '\n', '\r']) {
            failures.push(format!("{id}: invalid {label}"));
        }
    }
    validate_reference(root, id, "reference", &capability.reference, failures);
    if let Some(spec) = &capability.spec {
        validate_reference(root, id, "spec", spec, failures);
        match spec.strip_prefix("docs/90-specs/") {
            Some(relative) if spec_index.contains(relative) => {}
            Some(_) => failures.push(format!("{id}: spec is missing from specification index")),
            None => failures.push(format!("{id}: spec must be under docs/90-specs")),
        }
    }
    for path in &capability.api_paths {
        if !openapi_paths.contains(path) {
            failures.push(format!("{id}: OpenAPI path {path} is absent"));
        }
    }
    for operation in &capability.operation_types {
        if !operation_source.contains(&format!("\"{operation}\"")) {
            failures.push(format!("{id}: operation type {operation} is absent"));
        }
    }
    for gate in &capability.gates {
        if !gate_ids.contains(gate) {
            failures.push(format!("{id}: unknown GateId {gate}"));
        }
    }
    validate_state_combination(capability, failures);
}

fn validate_state_combination(capability: &Capability, failures: &mut Vec<String>) {
    let id = capability.id.as_str();
    match capability.implementation {
        ImplementationStatus::Implemented => {
            if capability.gates.is_empty()
                || matches!(
                    capability.evidence,
                    EvidenceLevel::Policy | EvidenceLevel::Doc | EvidenceLevel::Unverified
                )
            {
                failures.push(format!(
                    "{id}: implemented capability needs executable evidence"
                ));
            }
        }
        ImplementationStatus::Partial => {
            if capability.gates.is_empty() || capability.blocker.is_none() {
                failures.push(format!("{id}: partial capability needs gates and blocker"));
            }
        }
        ImplementationStatus::Planned => {
            if capability.evidence != EvidenceLevel::Unverified
                || !capability.api_paths.is_empty()
                || !capability.operation_types.is_empty()
            {
                failures.push(format!(
                    "{id}: planned capability cannot claim runtime surface"
                ));
            }
        }
        ImplementationStatus::Excluded | ImplementationStatus::Forbidden => {
            if capability.evidence != EvidenceLevel::Policy
                || !capability.api_paths.is_empty()
                || !capability.operation_types.is_empty()
                || !capability.gates.is_empty()
                || capability.assurance != Assurance::None
            {
                failures.push(format!("{id}: excluded capability has runtime evidence"));
            }
        }
    }
    if capability.release_scope == ReleaseScope::Forbidden
        && capability.implementation != ImplementationStatus::Forbidden
    {
        failures.push(format!(
            "{id}: forbidden scope must use forbidden implementation"
        ));
    }
    if capability.implementation == ImplementationStatus::Forbidden
        && capability.support != SupportStatus::Unsupported
    {
        failures.push(format!("{id}: forbidden capability must be unsupported"));
    }
}

fn validate_reference(
    root: &Path,
    id: &str,
    label: &str,
    relative: &str,
    failures: &mut Vec<String>,
) {
    match checked_workspace_path(root, relative) {
        Ok(path) if path.is_file() => {}
        Ok(_) => failures.push(format!("{id}: {label} is not a file: {relative}")),
        Err(error) => failures.push(format!("{id}: {error}")),
    }
}

fn checked_workspace_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!("unsafe workspace path {relative}"));
    }
    Ok(root.join(path))
}

fn openapi_paths(root: &Path) -> Result<BTreeSet<String>, String> {
    let path = root.join("api/openapi.json");
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&source)
        .map_err(|error| format!("invalid committed OpenAPI: {error}"))?;
    let Some(paths) = value.get("paths").and_then(serde_json::Value::as_object) else {
        return Err(String::from("committed OpenAPI has no paths object"));
    };
    Ok(paths.keys().cloned().collect())
}

fn operation_source(root: &Path) -> Result<String, String> {
    let mut combined = String::new();
    for relative in [
        "crates/jw-contracts/src/operation.rs",
        "crates/jw-contracts/src/certificate.rs",
        "crates/jw-contracts/src/firewall.rs",
    ] {
        let path = root.join(relative);
        combined.push_str(
            &fs::read_to_string(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?,
        );
    }
    Ok(combined)
}

fn gate_ids(root: &Path) -> Result<BTreeSet<String>, String> {
    let source = fs::read_to_string(root.join("xtask/src/main.rs"))
        .map_err(|error| format!("cannot read xtask gate registry: {error}"))?;
    let mut ids = BTreeSet::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed
            .strip_prefix("id: \"")
            .and_then(|value| value.strip_suffix("\","))
        {
            ids.insert(String::from(value));
        }
    }
    if ids.is_empty() {
        Err(String::from("xtask GateId registry is empty"))
    } else {
        Ok(ids)
    }
}

fn render_document(registry: &Registry) -> String {
    let implemented = registry
        .capabilities
        .iter()
        .filter(|item| item.implementation == ImplementationStatus::Implemented)
        .count();
    let partial = registry
        .capabilities
        .iter()
        .filter(|item| item.implementation == ImplementationStatus::Partial)
        .count();
    let planned = registry
        .capabilities
        .iter()
        .filter(|item| item.implementation == ImplementationStatus::Planned)
        .count();
    let outside = registry.capabilities.len() - implemented - partial - planned;
    let mut output = format!(
        "# Capability Status\n\nStatus: Accepted  \nAuthority: Generated Capability Snapshot  \nOwner: Maintainers  \nLast reviewed: {}\n\n",
        registry.reviewed
    );
    output.push_str(
        "이 문서는 [capabilities-v1.json](../00-governance/capabilities-v1.json)에서 생성됩니다. 직접 수정하지 않습니다. 상태를 바꾼 뒤 `cargo xtask render-capabilities`를 실행하고 `GOV-009`로 검증합니다.\n\n",
    );
    output.push_str(&format!(
        "현재 등록: 전체 {}개 · 구현 {}개 · 부분 구현 {}개 · 미구현 {}개 · 제외/금지 {}개\n\n",
        registry.capabilities.len(),
        implemented,
        partial,
        planned,
        outside
    ));

    for phase in Phase::ALL {
        let mut rows: Vec<&Capability> = registry
            .capabilities
            .iter()
            .filter(|item| item.phase == phase)
            .collect();
        if rows.is_empty() {
            continue;
        }
        rows.sort_by(|left, right| left.id.cmp(&right.id));
        output.push_str(&format!("## {}\n\n", phase.label()));
        output.push_str("| 기능 | 범위 | 구현 | 지원 | 증거 | 보장 | 기준·남은 조건 |\n");
        output.push_str("|---|---|---|---|---|---|---|\n");
        for capability in rows {
            let reference = markdown_reference(&capability.reference, &capability.name);
            let blocker = capability
                .blocker
                .as_deref()
                .map_or("—", std::convert::identity);
            output.push_str(&format!(
                "| `{}` {} | {} | {} | {} | {} | {} | {} · {} |\n",
                capability.id,
                reference,
                capability.release_scope.label(),
                capability.implementation.label(),
                capability.support.label(),
                capability.evidence.label(),
                capability.assurance.label(),
                escape_cell(&capability.owner),
                escape_cell(blocker),
            ));
        }
        output.push('\n');
    }
    output
}

fn markdown_reference(path: &str, label: &str) -> String {
    let target = match path.strip_prefix("docs/") {
        Some(relative) => format!("../{relative}"),
        None => String::from(path),
    };
    format!("[{}]({target})", escape_cell(label))
}

fn escape_cell(value: &str) -> String {
    value
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
        .trim()
        .to_string()
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '-')
        })
}

fn is_calendar_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value
            .chars()
            .enumerate()
            .all(|(index, character)| matches!(index, 4 | 7) || character.is_ascii_digit())
}

fn display_relative(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root).ok().and_then(Path::to_str) {
        Some(relative) => String::from(relative),
        None => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{is_calendar_date, valid_id};

    #[test]
    fn capability_id_is_bounded_and_machine_stable() {
        assert!(valid_id("service.managed-config"));
        assert!(!valid_id("Service Managed Config"));
        assert!(!valid_id("../service"));
    }

    #[test]
    fn reviewed_date_has_exact_shape() {
        assert!(is_calendar_date("2026-08-18"));
        assert!(!is_calendar_date("2026-8-18"));
        assert!(!is_calendar_date("2026/08/18"));
    }
}
