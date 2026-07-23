use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use jw_contracts::{
    AssuranceLevel, AssuranceView, DiskObservation, HostObservation, MANAGED_CONFIG_OPERATION,
    MemoryObservation, NGINX_CONFIG_ADAPTER_ID, NGINX_LAYOUT_ID, NGINX_MANAGED_CONFIG_MAX_BYTES,
    NGINX_SITE_STATE_OPERATION, NginxSiteObservation, NginxSitesView, OPERATION_SCHEMA_VERSION,
    ObservationStatus, RollbackSupport, managed_config_bytes_supported, nginx_config_resource_id,
    nginx_enabled_state_digest, nginx_internal_temporary_name, nginx_management_config,
    nginx_site_id, sha256_digest,
};

const MAX_TEXT_BYTES: u64 = 64 * 1_024;
const MAX_NGINX_SITES: usize = 512;
const MAX_NGINX_CONFIG_BYTES: u64 = 1024 * 1024;
const MANAGEMENT_SITE: &str = "jw-agent-management.conf";

#[derive(Clone, Debug)]
pub struct ObservationProfile {
    pub os_release: PathBuf,
    pub hostname: PathBuf,
    pub kernel_release: PathBuf,
    pub uptime: PathBuf,
    pub cpu_stat: PathBuf,
    pub load_average: PathBuf,
    pub meminfo: PathBuf,
    pub nginx_available: PathBuf,
    pub nginx_enabled: PathBuf,
}

impl Default for ObservationProfile {
    fn default() -> Self {
        Self {
            os_release: PathBuf::from("/etc/os-release"),
            hostname: PathBuf::from("/etc/hostname"),
            kernel_release: PathBuf::from("/proc/sys/kernel/osrelease"),
            uptime: PathBuf::from("/proc/uptime"),
            cpu_stat: PathBuf::from("/proc/stat"),
            load_average: PathBuf::from("/proc/loadavg"),
            meminfo: PathBuf::from("/proc/meminfo"),
            nginx_available: PathBuf::from("/etc/nginx/sites-available"),
            nginx_enabled: PathBuf::from("/etc/nginx/sites-enabled"),
        }
    }
}

pub async fn observe_host(profile: &ObservationProfile, observed_at: String) -> HostObservation {
    let first_cpu = read_bounded(&profile.cpu_stat).and_then(|value| parse_cpu_sample(&value));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let second_cpu = read_bounded(&profile.cpu_stat).and_then(|value| parse_cpu_sample(&value));
    let cpu_usage_percent = first_cpu
        .zip(second_cpu)
        .and_then(|(first, second)| cpu_usage_percent(first, second));
    let logical_cpu_count = std::thread::available_parallelism()
        .ok()
        .and_then(|value| u32::try_from(value.get()).ok());
    let os = match read_bounded(&profile.os_release) {
        Some(value) => parse_key_values(&value),
        None => BTreeMap::new(),
    };
    let hostname = read_bounded(&profile.hostname).map(|value| value.trim().to_owned());
    let kernel_release = read_bounded(&profile.kernel_release).map(|value| value.trim().to_owned());
    let uptime_seconds = read_bounded(&profile.uptime)
        .and_then(|value| value.split_whitespace().next().map(str::to_owned))
        .and_then(|value| value.parse::<f64>().ok())
        .map(|value| value.max(0.0) as u64);
    let mut load_averages = (None, None, None);
    if let Some(values) =
        read_bounded(&profile.load_average).and_then(|value| parse_load_averages(&value))
    {
        load_averages = values;
    }
    let (load_average_one, load_average_five, load_average_fifteen) = load_averages;
    let memory = read_bounded(&profile.meminfo).and_then(|value| parse_memory(&value));
    let root_disk = observe_root_disk();
    let status = if cfg!(target_os = "linux") {
        if os.is_empty() || hostname.is_none() {
            ObservationStatus::Partial
        } else {
            ObservationStatus::Observed
        }
    } else {
        ObservationStatus::UnsupportedPlatform
    };

    HostObservation {
        observed_at,
        status,
        hostname,
        os_id: os.get("ID").cloned(),
        os_version_id: os.get("VERSION_ID").cloned(),
        os_pretty_name: os.get("PRETTY_NAME").cloned(),
        architecture: std::env::consts::ARCH.to_owned(),
        kernel_release,
        uptime_seconds,
        logical_cpu_count,
        cpu_usage_percent,
        load_average_one,
        load_average_five,
        load_average_fifteen,
        memory,
        root_disk,
    }
}

fn parse_load_averages(value: &str) -> Option<(Option<f64>, Option<f64>, Option<f64>)> {
    let mut fields = value.split_whitespace();
    Some((
        fields.next()?.parse::<f64>().ok(),
        fields.next()?.parse::<f64>().ok(),
        fields.next()?.parse::<f64>().ok(),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CpuSample {
    total: u64,
    idle: u64,
}

fn parse_cpu_sample(value: &str) -> Option<CpuSample> {
    let mut values = value.lines().next()?.split_whitespace();
    if values.next()? != "cpu" {
        return None;
    }
    let user = values.next()?.parse::<u64>().ok()?;
    let nice = values.next()?.parse::<u64>().ok()?;
    let system = values.next()?.parse::<u64>().ok()?;
    let idle = values.next()?.parse::<u64>().ok()?;
    let io_wait = values.next()?.parse::<u64>().ok()?;
    let irq = values.next()?.parse::<u64>().ok()?;
    let soft_irq = values.next()?.parse::<u64>().ok()?;
    let steal = values
        .next()
        .and_then(|item| item.parse::<u64>().ok())
        .map_or(0, |value| value);
    let total = user
        .checked_add(nice)?
        .checked_add(system)?
        .checked_add(idle)?
        .checked_add(io_wait)?
        .checked_add(irq)?
        .checked_add(soft_irq)?
        .checked_add(steal)?;
    Some(CpuSample {
        total,
        idle: idle.checked_add(io_wait)?,
    })
}

fn cpu_usage_percent(first: CpuSample, second: CpuSample) -> Option<f64> {
    let total = second.total.checked_sub(first.total)?;
    let idle = second.idle.checked_sub(first.idle)?;
    if total == 0 || idle > total {
        return None;
    }
    Some(((total - idle) as f64 / total as f64) * 100.0)
}

pub fn observe_nginx_with_mutation_gate(
    profile: &ObservationProfile,
    observed_at: String,
    mutation_gate_reason: Option<&str>,
) -> NginxSitesView {
    if !cfg!(target_os = "linux") {
        return NginxSitesView {
            observed_at,
            status: ObservationStatus::UnsupportedPlatform,
            sites: Vec::new(),
            truncated: false,
        };
    }
    if !profile.nginx_available.is_dir() && !profile.nginx_enabled.is_dir() {
        return NginxSitesView {
            observed_at,
            status: ObservationStatus::NotInstalled,
            sites: Vec::new(),
            truncated: false,
        };
    }

    let mut sites = BTreeMap::<String, (bool, bool)>::new();
    let mut truncated = false;
    collect_sites(&profile.nginx_available, true, &mut sites, &mut truncated);
    collect_sites(&profile.nginx_enabled, false, &mut sites, &mut truncated);
    let status = if truncated {
        ObservationStatus::Partial
    } else {
        ObservationStatus::Observed
    };
    let sites = sites
        .into_iter()
        .take(MAX_NGINX_SITES)
        .map(|(name, (available, enabled))| {
            observe_nginx_site(profile, name, available, enabled, mutation_gate_reason)
        })
        .collect();
    NginxSitesView {
        observed_at,
        status,
        sites,
        truncated,
    }
}

fn observe_nginx_site(
    profile: &ObservationProfile,
    name: String,
    available: bool,
    enabled: bool,
    mutation_gate_reason: Option<&str>,
) -> NginxSiteObservation {
    let preconditions = inspect_nginx_preconditions(profile, &name, available, enabled);
    let (
        site_id,
        available_digest,
        enabled_state_digest,
        content_protected,
        managed_config_supported,
        path_reason,
    ) = match preconditions {
        Ok((
            site_id,
            available_digest,
            enabled_state_digest,
            content_protected,
            managed_config_supported,
        )) => (
            Some(site_id),
            Some(available_digest),
            Some(enabled_state_digest),
            content_protected,
            managed_config_supported,
            None,
        ),
        Err(reason) => (None, None, None, false, false, Some(reason)),
    };
    let protected = name == MANAGEMENT_SITE || content_protected;
    let reason = if protected {
        Some("JW Agent 공개 관리 리소스는 일반 Nginx 작업에서 변경할 수 없습니다.")
    } else {
        path_reason.or(mutation_gate_reason)
    };
    let assurance = nginx_assurance(reason);
    let operation_type = assurance
        .operation_available
        .then(|| String::from(NGINX_SITE_STATE_OPERATION));
    let operation_schema_version = assurance
        .operation_available
        .then_some(OPERATION_SCHEMA_VERSION);
    let managed_config_available = assurance.operation_available && managed_config_supported;
    let managed_config_resource_id =
        managed_config_available.then(|| nginx_config_resource_id(NGINX_CONFIG_ADAPTER_ID, &name));
    NginxSiteObservation {
        name,
        site_id,
        available,
        enabled,
        protected,
        available_digest,
        enabled_state_digest,
        operation_type,
        operation_schema_version,
        managed_config_resource_id,
        managed_config_operation_type: managed_config_available
            .then(|| String::from(MANAGED_CONFIG_OPERATION)),
        managed_config_schema_version: managed_config_available.then_some(OPERATION_SCHEMA_VERSION),
        assurance,
    }
}

fn inspect_nginx_preconditions(
    profile: &ObservationProfile,
    name: &str,
    available: bool,
    enabled: bool,
) -> Result<(String, String, String, bool, bool), &'static str> {
    if !available {
        return Err("원본 설정 파일이 없어 변경 계획을 만들 수 없습니다.");
    }
    let available_path = profile.nginx_available.join(name);
    let metadata = fs::symlink_metadata(&available_path)
        .map_err(|_| "원본 설정 파일을 다시 읽을 수 없습니다.")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("원본 설정이 일반 파일이 아니어서 변경할 수 없습니다.");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.nlink() != 1 || (cfg!(target_os = "linux") && metadata.uid() != 0) {
            return Err("원본 설정의 소유권 또는 hard link 정책이 맞지 않습니다.");
        }
    }
    if metadata.len() > MAX_NGINX_CONFIG_BYTES {
        return Err("원본 설정 파일이 허용 크기를 초과했습니다.");
    }
    let bytes = read_bytes_bounded(&available_path, MAX_NGINX_CONFIG_BYTES)
        .ok_or("원본 설정 파일을 안전하게 읽을 수 없습니다.")?;
    if enabled {
        let enabled_path = profile.nginx_enabled.join(name);
        let enabled_metadata = fs::symlink_metadata(&enabled_path)
            .map_err(|_| "활성 링크를 다시 읽을 수 없습니다.")?;
        if !enabled_metadata.file_type().is_symlink() {
            return Err("활성 항목이 허용된 symbolic link가 아닙니다.");
        }
        let resolved_enabled =
            fs::canonicalize(enabled_path).map_err(|_| "활성 링크의 대상을 확인할 수 없습니다.")?;
        let resolved_available = fs::canonicalize(&available_path)
            .map_err(|_| "원본 설정의 실제 경로를 확인할 수 없습니다.")?;
        if resolved_enabled != resolved_available {
            return Err("활성 링크가 발견된 원본 설정을 가리키지 않습니다.");
        }
    }
    let managed_config_supported = enabled
        && bytes.len() <= NGINX_MANAGED_CONFIG_MAX_BYTES
        && managed_config_bytes_supported(&bytes)
        && managed_mode_supported(&metadata);
    Ok((
        nginx_site_id(NGINX_LAYOUT_ID, name),
        sha256_digest(&bytes),
        nginx_enabled_state_digest(enabled),
        nginx_management_config(&bytes),
        managed_config_supported,
    ))
}

fn managed_mode_supported(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        metadata.mode() & 0o133 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

fn nginx_assurance(reason: Option<&str>) -> AssuranceView {
    if let Some(reason) = reason {
        return AssuranceView {
            level: AssuranceLevel::G0ObserveOnly,
            rollback_support: RollbackSupport::NotApplicable,
            operation_available: false,
            scope: vec![String::from("Nginx 사이트 상태 관찰")],
            excluded_effects: vec![String::from("site enable·disable와 Nginx reload")],
            apply_verifier: Vec::new(),
            rollback_verifier: Vec::new(),
            reason: Some(reason.to_owned()),
        };
    }
    AssuranceView {
        level: AssuranceLevel::G2ReversibleConfig,
        rollback_support: RollbackSupport::AutomaticBounded,
        operation_available: true,
        scope: vec![String::from("발견된 site의 sites-enabled link 상태")],
        excluded_effects: vec![
            String::from("sites-available 설정 내용"),
            String::from("기존 연결과 Nginx process의 과거 상태"),
        ],
        apply_verifier: vec![
            String::from("enabled link read-back"),
            String::from("nginx -t"),
            String::from("reload 후 active 확인"),
        ],
        rollback_verifier: vec![
            String::from("이전 link 상태 복원"),
            String::from("nginx -t와 reload 후 active 확인"),
        ],
        reason: None,
    }
}

fn collect_sites(
    directory: &Path,
    available: bool,
    sites: &mut BTreeMap<String, (bool, bool)>,
    truncated: &mut bool,
) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry_result in entries.take(MAX_NGINX_SITES + 1) {
        let Ok(entry) = entry_result else {
            continue;
        };
        if sites.len() >= MAX_NGINX_SITES {
            *truncated = true;
            break;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.is_empty()
            || name.len() > 255
            || name == "."
            || name == ".."
            || nginx_internal_temporary_name(&name)
        {
            continue;
        }
        let flags = sites.entry(name).or_insert((false, false));
        if available {
            flags.0 = true;
        } else {
            flags.1 = true;
        }
    }
}

fn read_bounded(path: &Path) -> Option<String> {
    let bytes = read_bytes_bounded(path, MAX_TEXT_BYTES)?;
    String::from_utf8(bytes).ok()
}

fn read_bytes_bounded(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    let file = fs::File::open(path).ok()?;
    let mut bounded = file.take(max_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    bounded.read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > max_bytes {
        return None;
    }
    Some(bytes)
}

fn parse_key_values(value: &str) -> BTreeMap<String, String> {
    value
        .lines()
        .filter_map(|line| {
            let (key, raw) = line.split_once('=')?;
            if !key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
            {
                return None;
            }
            let unquoted = match raw
                .strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
            {
                Some(inner) => inner,
                None => raw,
            };
            let parsed = unquoted.replace("\\\"", "\"").replace("\\\\", "\\");
            Some((key.to_owned(), parsed))
        })
        .collect()
}

fn parse_memory(value: &str) -> Option<MemoryObservation> {
    let values: BTreeMap<&str, u64> = value
        .lines()
        .filter_map(|line| {
            let (key, remainder) = line.split_once(':')?;
            let kibibytes = remainder.split_whitespace().next()?.parse::<u64>().ok()?;
            Some((key, kibibytes.saturating_mul(1_024)))
        })
        .collect();
    Some(MemoryObservation {
        total_bytes: *values.get("MemTotal")?,
        available_bytes: *values.get("MemAvailable")?,
    })
}

fn observe_root_disk() -> Option<DiskObservation> {
    let stats = nix::sys::statvfs::statvfs("/").ok()?;
    let block_size = stats.fragment_size();
    Some(DiskObservation {
        total_bytes: u64::from(stats.blocks()).saturating_mul(block_size),
        available_bytes: u64::from(stats.blocks_available()).saturating_mul(block_size),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use jw_contracts::{
        NGINX_LAYOUT_ID, NGINX_MANAGEMENT_PROXY_INCLUDE, nginx_enabled_state_digest, nginx_site_id,
        sha256_digest,
    };

    use super::{
        CpuSample, ObservationProfile, collect_sites, cpu_usage_percent,
        inspect_nginx_preconditions, parse_cpu_sample,
    };

    #[test]
    fn cpu_usage_uses_bounded_proc_stat_deltas() {
        let first = parse_cpu_sample("cpu  100 2 30 800 10 3 5 0\n");
        let second = parse_cpu_sample("cpu  130 2 40 850 10 3 5 0\n");
        assert_eq!(
            first,
            Some(CpuSample {
                total: 950,
                idle: 810,
            })
        );
        let percent = first
            .zip(second)
            .and_then(|(start, end)| cpu_usage_percent(start, end));
        assert!(percent.is_some_and(|value| (value - 44.444_444).abs() < 0.001));
        assert!(parse_cpu_sample("intr 1 2 3\n").is_none());
        assert!(
            cpu_usage_percent(
                CpuSample { total: 1, idle: 1 },
                CpuSample { total: 1, idle: 1 }
            )
            .is_none()
        );
    }

    #[test]
    fn nginx_inventory_excludes_exact_internal_temporary_files() -> Result<(), String> {
        let root = test_root("internal-temporary")?;
        fs::create_dir_all(&root).map_err(|error| error.to_string())?;
        fs::write(root.join(".jw-agent-0123456789abcdef.tmp"), b"pending")
            .map_err(|error| error.to_string())?;
        fs::write(root.join("example.com"), b"server {}\n").map_err(|error| error.to_string())?;
        let mut sites = BTreeMap::new();
        let mut truncated = false;
        collect_sites(&root, true, &mut sites, &mut truncated);
        assert_eq!(sites.len(), 1);
        assert!(sites.contains_key("example.com"));
        assert!(!truncated);
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn nginx_precondition_identity_is_stable_for_a_safe_disabled_site() -> Result<(), String> {
        let root = test_root("safe-disabled")?;
        let profile = profile(&root);
        fs::create_dir_all(&profile.nginx_available).map_err(|error| error.to_string())?;
        fs::create_dir_all(&profile.nginx_enabled).map_err(|error| error.to_string())?;
        let content = b"server {}\n";
        fs::write(profile.nginx_available.join("example.com"), content)
            .map_err(|error| error.to_string())?;
        let (site_id, available_digest, state_digest, protected, managed) =
            inspect_nginx_preconditions(&profile, "example.com", true, false)
                .map_err(str::to_owned)?;
        assert_eq!(site_id, nginx_site_id(NGINX_LAYOUT_ID, "example.com"));
        assert_eq!(available_digest, sha256_digest(content));
        assert_eq!(state_digest, nginx_enabled_state_digest(false));
        assert!(!protected);
        assert!(!managed);
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn nginx_precondition_allows_managed_config_only_for_exact_enabled_link() -> Result<(), String>
    {
        let root = test_root("safe-enabled")?;
        let profile = profile(&root);
        fs::create_dir_all(&profile.nginx_available).map_err(|error| error.to_string())?;
        fs::create_dir_all(&profile.nginx_enabled).map_err(|error| error.to_string())?;
        fs::write(profile.nginx_available.join("example.com"), b"server {}\n")
            .map_err(|error| error.to_string())?;
        std::os::unix::fs::symlink(
            "../sites-available/example.com",
            profile.nginx_enabled.join("example.com"),
        )
        .map_err(|error| error.to_string())?;
        let (_, _, _, protected, managed) =
            inspect_nginx_preconditions(&profile, "example.com", true, true)
                .map_err(str::to_owned)?;
        assert!(!protected);
        assert!(managed);
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn nginx_precondition_protects_proxy_include_under_custom_basename() -> Result<(), String> {
        let root = test_root("protected-custom-name")?;
        let profile = profile(&root);
        fs::create_dir_all(&profile.nginx_available).map_err(|error| error.to_string())?;
        fs::create_dir_all(&profile.nginx_enabled).map_err(|error| error.to_string())?;
        let mut content = Vec::from(b"server { " as &[u8]);
        content.extend_from_slice(NGINX_MANAGEMENT_PROXY_INCLUDE);
        content.extend_from_slice(b" }\n");
        fs::write(
            profile.nginx_available.join("operator-selected-name"),
            content,
        )
        .map_err(|error| error.to_string())?;
        let (_, _, _, protected, managed) =
            inspect_nginx_preconditions(&profile, "operator-selected-name", true, false)
                .map_err(str::to_owned)?;
        assert!(protected);
        assert!(!managed);
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn nginx_precondition_rejects_an_enabled_link_to_another_source() -> Result<(), String> {
        let root = test_root("outside-link")?;
        let profile = profile(&root);
        fs::create_dir_all(&profile.nginx_available).map_err(|error| error.to_string())?;
        fs::create_dir_all(&profile.nginx_enabled).map_err(|error| error.to_string())?;
        fs::write(profile.nginx_available.join("example.com"), b"server {}\n")
            .map_err(|error| error.to_string())?;
        fs::write(root.join("outside.conf"), b"server {}\n").map_err(|error| error.to_string())?;
        std::os::unix::fs::symlink(
            root.join("outside.conf"),
            profile.nginx_enabled.join("example.com"),
        )
        .map_err(|error| error.to_string())?;
        let result = inspect_nginx_preconditions(&profile, "example.com", true, true);
        assert_eq!(
            result,
            Err("활성 링크가 발견된 원본 설정을 가리키지 않습니다.")
        );
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    fn profile(root: &std::path::Path) -> ObservationProfile {
        ObservationProfile {
            nginx_available: root.join("sites-available"),
            nginx_enabled: root.join("sites-enabled"),
            ..ObservationProfile::default()
        }
    }

    fn test_root(label: &str) -> Result<std::path::PathBuf, String> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|error| error.to_string())?;
        Ok(std::env::temp_dir().join(format!(
            "jw-agentd-observation-{label}-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(random)
        )))
    }
}
