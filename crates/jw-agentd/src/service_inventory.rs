use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use jw_contracts::{
    ManagedServiceAction, OPERATION_SCHEMA_VERSION, ObservationStatus, SERVICE_CONTROL_OPERATION,
    ServiceCategory, ServiceRuntimeState, ServiceSummary, ServiceSupport, ServiceVisibility,
    ServicesView, service_id, service_state_digest,
};
use serde::Deserialize;

const CATALOG_JSON: &str = include_str!("../service-catalog/ubuntu-24.04-v1.json");
const CATALOG_SCHEMA_VERSION: u16 = 1;
const MAX_SERVICES: usize = 512;
const MAX_STDOUT_BYTES: usize = 512 * 1_024;
const MAX_STDERR_BYTES: usize = 32 * 1_024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const SYSTEMCTL_ARGUMENTS: &[&str] = &[
    "show",
    "--type=service",
    "--type=timer",
    "--all",
    "--no-pager",
    "--property=Id",
    "--property=Description",
    "--property=LoadState",
    "--property=ActiveState",
    "--property=SubState",
    "--property=UnitFileState",
    "--property=FragmentPath",
];

#[derive(Clone, Debug)]
pub struct ServiceObservationProfile {
    pub systemctl: PathBuf,
    pub edge_ready_path: PathBuf,
}

impl Default for ServiceObservationProfile {
    fn default() -> Self {
        Self {
            systemctl: PathBuf::from("/usr/bin/systemctl"),
            edge_ready_path: PathBuf::from("/run/jw-agent-edge/ready"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceCatalog {
    schema_version: u16,
    profile: String,
    templates: Vec<ServiceTemplate>,
    product_unit_patterns: Vec<String>,
    system_unit_patterns: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceTemplate {
    id: String,
    display_name: String,
    purpose: String,
    category: ServiceCategory,
    support: ServiceSupport,
    unit_patterns: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SystemdUnit {
    unit_name: String,
    description: String,
    active_state: String,
    sub_state: String,
    unit_file_state: Option<String>,
    fragment_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParseResult {
    units: Vec<SystemdUnit>,
    rejected_records: usize,
}

pub fn observe_services(profile: &ServiceObservationProfile, observed_at: String) -> ServicesView {
    if !cfg!(target_os = "linux") {
        return unavailable_view(
            observed_at,
            ObservationStatus::UnsupportedPlatform,
            String::from("ubuntu-24.04-v1"),
        );
    }
    let catalog = match load_catalog() {
        Ok(value) => value,
        Err(_) => {
            return unavailable_view(
                observed_at,
                ObservationStatus::Partial,
                String::from("catalog_invalid"),
            );
        }
    };
    let output = match run_systemctl(&profile.systemctl) {
        Ok(value) => value,
        Err(_) => {
            return unavailable_view(observed_at, ObservationStatus::Partial, catalog.profile);
        }
    };
    let text = match String::from_utf8(output) {
        Ok(value) => value,
        Err(_) => {
            return unavailable_view(observed_at, ObservationStatus::Partial, catalog.profile);
        }
    };
    let parsed = parse_systemctl_show(&text);
    let independent_edge_ready = profile.edge_ready_path.is_file()
        && parsed.units.iter().any(|unit| {
            unit.unit_name == "jw-edge.service"
                && unit.active_state == "active"
                && unit.sub_state == "running"
        });
    let mut services = parsed
        .units
        .into_iter()
        .map(|unit| classify_unit(&catalog, unit, independent_edge_ready))
        .collect::<Vec<ServiceSummary>>();
    services.sort_by(service_order);
    let truncated = services.len() > MAX_SERVICES;
    services.truncate(MAX_SERVICES);
    let status = if truncated || parsed.rejected_records > 0 {
        ObservationStatus::Partial
    } else {
        ObservationStatus::Observed
    };
    ServicesView {
        observed_at,
        status,
        template_profile: catalog.profile,
        services,
        truncated,
    }
}

fn unavailable_view(
    observed_at: String,
    status: ObservationStatus,
    template_profile: String,
) -> ServicesView {
    ServicesView {
        observed_at,
        status,
        template_profile,
        services: Vec::new(),
        truncated: false,
    }
}

fn load_catalog() -> Result<ServiceCatalog, String> {
    let catalog = serde_json::from_str::<ServiceCatalog>(CATALOG_JSON)
        .map_err(|_| String::from("service catalog decode failed"))?;
    validate_catalog(&catalog)?;
    Ok(catalog)
}

fn validate_catalog(catalog: &ServiceCatalog) -> Result<(), String> {
    if catalog.schema_version != CATALOG_SCHEMA_VERSION
        || catalog.profile != "ubuntu-24.04-v1"
        || catalog.templates.is_empty()
    {
        return Err(String::from("service catalog header rejected"));
    }
    let mut ids = BTreeSet::new();
    for template in &catalog.templates {
        if !valid_id(&template.id)
            || !ids.insert(template.id.as_str())
            || template.display_name.trim().is_empty()
            || template.purpose.trim().is_empty()
            || template.unit_patterns.is_empty()
        {
            return Err(String::from("service catalog template rejected"));
        }
        for pattern in &template.unit_patterns {
            validate_pattern(pattern)?;
        }
    }
    for pattern in catalog
        .product_unit_patterns
        .iter()
        .chain(catalog.system_unit_patterns.iter())
    {
        validate_pattern(pattern)?;
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn validate_pattern(pattern: &str) -> Result<(), String> {
    let wildcard_count = pattern.bytes().filter(|byte| *byte == b'*').count();
    if pattern.is_empty()
        || pattern.len() > 255
        || wildcard_count > 1
        || !(pattern.ends_with(".service") || pattern.ends_with(".timer"))
        || pattern
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b'/')
    {
        return Err(String::from("service catalog unit pattern rejected"));
    }
    Ok(())
}

fn parse_systemctl_show(value: &str) -> ParseResult {
    let mut records = BTreeMap::<String, String>::new();
    let mut units = Vec::new();
    let mut rejected_records = 0_usize;
    for line in value.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            if !records.is_empty() {
                if records.get("LoadState").map(String::as_str) == Some("loaded") {
                    match parse_record(&records) {
                        Some(unit) => units.push(unit),
                        None => rejected_records = rejected_records.saturating_add(1),
                    }
                } else if !records.contains_key("LoadState") {
                    rejected_records = rejected_records.saturating_add(1);
                }
                records.clear();
            }
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            rejected_records = rejected_records.saturating_add(1);
            continue;
        };
        if matches!(
            key,
            "Id" | "Description"
                | "LoadState"
                | "ActiveState"
                | "SubState"
                | "UnitFileState"
                | "FragmentPath"
        ) {
            records.insert(key.to_owned(), raw.to_owned());
        }
    }
    let mut unique = BTreeMap::new();
    for unit in units {
        unique.entry(unit.unit_name.clone()).or_insert(unit);
    }
    ParseResult {
        units: unique.into_values().collect(),
        rejected_records,
    }
}

fn parse_record(record: &BTreeMap<String, String>) -> Option<SystemdUnit> {
    if record.get("LoadState").map(String::as_str) != Some("loaded") {
        return None;
    }
    let unit_name = record.get("Id")?.trim();
    if !valid_unit_name(unit_name)
        || !(unit_name.ends_with(".service") || unit_name.ends_with(".timer"))
    {
        return None;
    }
    let active_state = bounded_atom(record.get("ActiveState")?, 32)?;
    let sub_state = bounded_atom(record.get("SubState")?, 32)?;
    let description = record
        .get("Description")
        .map_or_else(|| unit_name.to_owned(), |value| bounded_text(value, 256));
    let unit_file_state = record
        .get("UnitFileState")
        .and_then(|value| (!value.is_empty()).then(|| bounded_atom(value, 32)))
        .flatten();
    let fragment_path = record
        .get("FragmentPath")
        .and_then(|value| valid_fragment_path(value).then(|| value.to_owned()));
    Some(SystemdUnit {
        unit_name: unit_name.to_owned(),
        description,
        active_state,
        sub_state,
        unit_file_state,
        fragment_path,
    })
}

fn valid_unit_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'/')
}

fn bounded_atom(value: &str, max_bytes: usize) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-' || byte == b'_'))
    .then(|| value.to_owned())
}

fn bounded_text(value: &str, max_chars: usize) -> String {
    value
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(max_chars)
        .collect()
}

fn valid_fragment_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 1_024
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace())
}

fn classify_unit(
    catalog: &ServiceCatalog,
    unit: SystemdUnit,
    independent_edge_ready: bool,
) -> ServiceSummary {
    let template = catalog.templates.iter().find(|template| {
        template
            .unit_patterns
            .iter()
            .any(|pattern| unit_matches(pattern, &unit.unit_name))
    });
    let product_or_system = catalog
        .product_unit_patterns
        .iter()
        .chain(catalog.system_unit_patterns.iter())
        .any(|pattern| unit_matches(pattern, &unit.unit_name));
    let local_custom = unit
        .fragment_path
        .as_deref()
        .is_some_and(|path| path.starts_with("/etc/systemd/system/"));
    let (template_id, display_name, purpose, category, visibility, support, hidden_by_default) =
        if let Some(template) = template {
            (
                Some(template.id.clone()),
                template.display_name.clone(),
                template.purpose.clone(),
                template.category,
                ServiceVisibility::Primary,
                template.support,
                false,
            )
        } else if local_custom && !product_or_system {
            (
                None,
                unit.unit_name.trim_end_matches(".service").to_owned(),
                fallback_purpose(&unit),
                ServiceCategory::Custom,
                ServiceVisibility::Discovered,
                ServiceSupport::DiscoveredReadOnly,
                false,
            )
        } else {
            (
                None,
                unit.unit_name.clone(),
                fallback_purpose(&unit),
                ServiceCategory::System,
                ServiceVisibility::System,
                ServiceSupport::SystemInternal,
                true,
            )
        };
    let runtime_state = runtime_state(&unit.active_state, &unit.sub_state);
    let active = matches!(
        runtime_state,
        ServiceRuntimeState::Running | ServiceRuntimeState::Active
    );
    let controlled = matches!(
        unit.unit_name.as_str(),
        "nginx.service" | "php8.3-fpm.service"
    );
    let allowed_actions = if controlled {
        if active {
            let mut actions = vec![ManagedServiceAction::Restart, ManagedServiceAction::Reload];
            if unit.unit_name != "nginx.service" || independent_edge_ready {
                actions.push(ManagedServiceAction::Stop);
            }
            actions
        } else {
            vec![ManagedServiceAction::Start]
        }
    } else {
        Vec::new()
    };
    let state_digest = service_state_digest(&unit.unit_name, active);
    ServiceSummary {
        service_id: service_id(&unit.unit_name),
        template_id,
        unit_name: unit.unit_name,
        display_name,
        purpose,
        category,
        runtime_state,
        active_state: unit.active_state,
        sub_state: unit.sub_state,
        unit_file_state: unit.unit_file_state,
        visibility,
        support,
        read_only: !controlled,
        hidden_by_default,
        state_digest,
        allowed_actions,
        operation_type: controlled.then(|| String::from(SERVICE_CONTROL_OPERATION)),
        operation_schema_version: controlled.then_some(OPERATION_SCHEMA_VERSION),
    }
}

fn fallback_purpose(unit: &SystemdUnit) -> String {
    if unit.description.is_empty() || unit.description == unit.unit_name {
        String::from("설치된 systemd unit입니다. JW Agent가 역할을 추측하지 않습니다.")
    } else {
        unit.description.clone()
    }
}

fn unit_matches(pattern: &str, unit_name: &str) -> bool {
    match pattern.split_once('*') {
        Some((prefix, suffix)) => unit_name.starts_with(prefix) && unit_name.ends_with(suffix),
        None => pattern == unit_name,
    }
}

fn runtime_state(active_state: &str, sub_state: &str) -> ServiceRuntimeState {
    match (active_state, sub_state) {
        ("failed", _) => ServiceRuntimeState::Failed,
        ("active", "running") | ("active", "listening") => ServiceRuntimeState::Running,
        ("active", _) => ServiceRuntimeState::Active,
        ("inactive", _) => ServiceRuntimeState::Stopped,
        ("activating" | "deactivating" | "reloading", _) => ServiceRuntimeState::Transitioning,
        _ => ServiceRuntimeState::Unknown,
    }
}

fn service_order(left: &ServiceSummary, right: &ServiceSummary) -> std::cmp::Ordering {
    service_priority(left)
        .cmp(&service_priority(right))
        .then_with(|| left.display_name.cmp(&right.display_name))
        .then_with(|| left.unit_name.cmp(&right.unit_name))
}

fn service_priority(service: &ServiceSummary) -> (u8, u8, u8) {
    let failed = u8::from(service.runtime_state != ServiceRuntimeState::Failed);
    let visibility = match service.visibility {
        ServiceVisibility::Primary => 0,
        ServiceVisibility::Discovered => 1,
        ServiceVisibility::System => 2,
    };
    let stopped = u8::from(service.runtime_state == ServiceRuntimeState::Stopped);
    (failed, visibility, stopped)
}

fn run_systemctl(executable: &Path) -> Result<Vec<u8>, String> {
    if executable != Path::new("/usr/bin/systemctl") || !executable.is_file() {
        return Err(String::from("systemctl unavailable"));
    }
    let mut command = Command::new(executable);
    command
        .args(SYSTEMCTL_ARGUMENTS)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|_| String::from("systemctl spawn failed"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| String::from("systemctl stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| String::from("systemctl stderr unavailable"))?;
    let stdout_reader = spawn_reader(stdout, MAX_STDOUT_BYTES);
    let stderr_reader = spawn_reader(stderr, MAX_STDERR_BYTES);
    let (status, timed_out) = wait_bounded(&mut child, COMMAND_TIMEOUT)?;
    let stdout = join_reader(stdout_reader)?;
    let stderr = join_reader(stderr_reader)?;
    if timed_out || !status.success() || stdout.truncated || stderr.truncated {
        return Err(String::from("systemctl observation rejected"));
    }
    Ok(stdout.bytes)
}

#[derive(Debug)]
struct BoundedStream {
    bytes: Vec<u8>,
    truncated: bool,
}

fn spawn_reader<R>(reader: R, cap: usize) -> JoinHandle<Result<BoundedStream, String>>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || read_bounded(reader, cap))
}

fn read_bounded<R: Read>(mut reader: R, cap: usize) -> Result<BoundedStream, String> {
    let mut captured = Vec::with_capacity(cap.min(8 * 1_024));
    let mut buffer = [0_u8; 8 * 1_024];
    let mut total = 0_usize;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| String::from("systemctl output read failed"))?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count);
        if captured.len() < cap {
            let remaining = cap.saturating_sub(captured.len());
            captured.extend_from_slice(&buffer[..remaining.min(count)]);
        }
    }
    Ok(BoundedStream {
        bytes: captured,
        truncated: total > cap,
    })
}

fn join_reader(handle: JoinHandle<Result<BoundedStream, String>>) -> Result<BoundedStream, String> {
    handle
        .join()
        .map_err(|_| String::from("systemctl output reader failed"))?
}

fn wait_bounded(child: &mut Child, timeout: Duration) -> Result<(ExitStatus, bool), String> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| String::from("systemctl wait failed"))?
        {
            return Ok((status, false));
        }
        if started.elapsed() >= timeout {
            terminate_process_group(child)?;
            let status = child
                .wait()
                .map_err(|_| String::from("systemctl reap failed"))?;
            return Ok((status, true));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn terminate_process_group(child: &mut Child) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;

        let pid = i32::try_from(child.id()).map_err(|_| String::from("systemctl pid overflow"))?;
        let _term_result = killpg(Pid::from_raw(pid), Signal::SIGTERM);
        let grace = Instant::now();
        while grace.elapsed() < Duration::from_secs(1) {
            if child
                .try_wait()
                .map_err(|_| String::from("systemctl termination wait failed"))?
                .is_some()
            {
                let _kill_result = killpg(Pid::from_raw(pid), Signal::SIGKILL);
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _kill_result = killpg(Pid::from_raw(pid), Signal::SIGKILL);
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        child
            .kill()
            .map_err(|_| String::from("systemctl termination failed"))
    }
}

#[cfg(test)]
mod tests {
    use jw_contracts::{ServiceRuntimeState, ServiceSupport, ServiceVisibility};

    use super::{classify_unit, load_catalog, parse_systemctl_show, unit_matches};

    const FIXTURE: &str = r#"Id=nginx.service
Description=A high performance web server and a reverse proxy server
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
FragmentPath=/usr/lib/systemd/system/nginx.service

Id=php8.3-fpm.service
Description=The PHP 8.3 FastCGI Process Manager
LoadState=loaded
ActiveState=failed
SubState=failed
UnitFileState=enabled
FragmentPath=/usr/lib/systemd/system/php8.3-fpm.service

Id=acme-worker.service
Description=Customer application worker
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
FragmentPath=/etc/systemd/system/acme-worker.service

Id=systemd-resolved.service
Description=Network Name Resolution
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
FragmentPath=/usr/lib/systemd/system/systemd-resolved.service

Id=missing.service
Description=missing.service
LoadState=not-found
ActiveState=inactive
SubState=dead
UnitFileState=
FragmentPath=
"#;

    #[test]
    fn catalog_is_valid_and_php_pattern_is_version_tolerant() -> Result<(), String> {
        let catalog = load_catalog()?;
        assert_eq!(catalog.profile, "ubuntu-24.04-v1");
        assert!(unit_matches("php*-fpm.service", "php8.3-fpm.service"));
        assert!(!unit_matches("php*-fpm.service", "php8.3-cli.service"));
        Ok(())
    }

    #[test]
    fn fixture_classifies_primary_custom_and_system_without_hiding_failures() -> Result<(), String>
    {
        let catalog = load_catalog()?;
        let parsed = parse_systemctl_show(FIXTURE);
        assert_eq!(parsed.units.len(), 4);
        let services = parsed
            .units
            .into_iter()
            .map(|unit| classify_unit(&catalog, unit, true))
            .collect::<Vec<_>>();
        let nginx = services
            .iter()
            .find(|service| service.unit_name == "nginx.service")
            .ok_or_else(|| String::from("nginx fixture missing"))?;
        assert_eq!(nginx.visibility, ServiceVisibility::Primary);
        assert_eq!(nginx.support, ServiceSupport::SupportedObserve);
        assert_eq!(nginx.runtime_state, ServiceRuntimeState::Running);
        let php = services
            .iter()
            .find(|service| service.unit_name == "php8.3-fpm.service")
            .ok_or_else(|| String::from("php fixture missing"))?;
        assert_eq!(php.runtime_state, ServiceRuntimeState::Failed);
        assert!(!php.hidden_by_default);
        let custom = services
            .iter()
            .find(|service| service.unit_name == "acme-worker.service")
            .ok_or_else(|| String::from("custom fixture missing"))?;
        assert_eq!(custom.visibility, ServiceVisibility::Discovered);
        assert_eq!(custom.support, ServiceSupport::DiscoveredReadOnly);
        let system = services
            .iter()
            .find(|service| service.unit_name == "systemd-resolved.service")
            .ok_or_else(|| String::from("system fixture missing"))?;
        assert_eq!(system.visibility, ServiceVisibility::System);
        assert!(system.hidden_by_default);
        Ok(())
    }

    #[test]
    fn malformed_and_unloaded_records_are_not_reported_as_services() {
        let parsed = parse_systemctl_show(
            "Id=missing.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n\nnot-a-property\n\n",
        );
        assert!(parsed.units.is_empty());
        assert!(parsed.rejected_records >= 1);
    }

    #[test]
    fn nginx_stop_is_hidden_until_independent_edge_is_ready() -> Result<(), String> {
        let catalog = load_catalog()?;
        let parsed = parse_systemctl_show(FIXTURE);
        let nginx_unit = parsed
            .units
            .into_iter()
            .find(|unit| unit.unit_name == "nginx.service")
            .ok_or_else(|| String::from("nginx fixture missing"))?;
        let without_edge = classify_unit(&catalog, nginx_unit.clone(), false);
        assert!(
            !without_edge
                .allowed_actions
                .contains(&jw_contracts::ManagedServiceAction::Stop)
        );
        let with_edge = classify_unit(&catalog, nginx_unit, true);
        assert!(
            with_edge
                .allowed_actions
                .contains(&jw_contracts::ManagedServiceAction::Stop)
        );
        Ok(())
    }
}
