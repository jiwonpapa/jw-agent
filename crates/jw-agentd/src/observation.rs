use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use jw_contracts::{
    AssuranceLevel, AssuranceView, DiskObservation, HostObservation, MemoryObservation,
    NginxSiteObservation, NginxSitesView, ObservationStatus, RollbackSupport,
};

const MAX_TEXT_BYTES: u64 = 64 * 1_024;
const MAX_NGINX_SITES: usize = 512;
const MANAGEMENT_SITE: &str = "jw-agent-management.conf";

#[derive(Clone, Debug)]
pub struct ObservationProfile {
    pub os_release: PathBuf,
    pub hostname: PathBuf,
    pub kernel_release: PathBuf,
    pub uptime: PathBuf,
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
            load_average: PathBuf::from("/proc/loadavg"),
            meminfo: PathBuf::from("/proc/meminfo"),
            nginx_available: PathBuf::from("/etc/nginx/sites-available"),
            nginx_enabled: PathBuf::from("/etc/nginx/sites-enabled"),
        }
    }
}

pub fn observe_host(profile: &ObservationProfile, observed_at: String) -> HostObservation {
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
    let load_average_one = read_bounded(&profile.load_average)
        .and_then(|value| value.split_whitespace().next().map(str::to_owned))
        .and_then(|value| value.parse::<f64>().ok());
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
        load_average_one,
        memory,
        root_disk,
    }
}

pub fn observe_nginx(profile: &ObservationProfile, observed_at: String) -> NginxSitesView {
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
        .map(|(name, (available, enabled))| NginxSiteObservation {
            assurance: nginx_assurance(name == MANAGEMENT_SITE),
            protected: name == MANAGEMENT_SITE,
            name,
            available,
            enabled,
        })
        .collect();
    NginxSitesView {
        observed_at,
        status,
        sites,
        truncated,
    }
}

fn nginx_assurance(protected: bool) -> AssuranceView {
    let reason = if protected {
        "JW Agent 공개 관리 리소스는 일반 Nginx 작업에서 변경할 수 없습니다."
    } else {
        "현재 P1은 읽기 전용이며 G2 변경 작업은 Ubuntu VM 검증 전입니다."
    };
    AssuranceView {
        level: AssuranceLevel::G0ObserveOnly,
        rollback_support: RollbackSupport::NotApplicable,
        operation_available: false,
        scope: vec![String::from("Nginx 사이트 상태 관찰")],
        excluded_effects: vec![String::from("site enable·disable와 Nginx reload")],
        apply_verifier: Vec::new(),
        rollback_verifier: Vec::new(),
        reason: Some(reason.to_owned()),
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
        if name.is_empty() || name.len() > 255 || name == "." || name == ".." {
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
    let file = fs::File::open(path).ok()?;
    let mut bounded = file.take(MAX_TEXT_BYTES.saturating_add(1));
    let mut bytes = Vec::new();
    bounded.read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_TEXT_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
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
