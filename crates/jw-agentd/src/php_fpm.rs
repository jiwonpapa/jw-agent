use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use jw_contracts::{
    AssuranceLevel, AssuranceView, MANAGED_CONFIG_OPERATION, OPERATION_SCHEMA_VERSION,
    ObservationStatus, PHP_FPM_CONFIG_ADAPTER_ID, PHP_FPM_CONFIG_MAX_BYTES,
    PHP_FPM_EXTENSION_MAX_ENTRIES, PHP_FPM_GLOBAL_CONFIG_ADAPTER_ID,
    PHP_FPM_POOL_CONFIG_ADAPTER_ID, PHP_FPM_SUPPORTED_VERSION, PHP_FPM_UNIT,
    PhpFpmManagedConfigView, PhpFpmRuntimeView, PhpFpmView, RollbackSupport, ServiceRuntimeState,
    ServicesView, managed_config_bytes_supported, php_fpm_config_resource_id,
};

#[derive(Clone, Debug)]
pub struct PhpFpmObservationProfile {
    pub php_root: PathBuf,
}

impl Default for PhpFpmObservationProfile {
    fn default() -> Self {
        Self {
            php_root: PathBuf::from("/etc/php"),
        }
    }
}

pub fn observe_php_fpm(
    profile: &PhpFpmObservationProfile,
    services: &ServicesView,
    observed_at: String,
) -> PhpFpmView {
    if !cfg!(target_os = "linux") {
        return PhpFpmView {
            observed_at,
            status: ObservationStatus::UnsupportedPlatform,
            runtimes: Vec::new(),
        };
    }
    let Some(service) = services
        .services
        .iter()
        .find(|service| service.unit_name == PHP_FPM_UNIT)
    else {
        return PhpFpmView {
            observed_at,
            status: ObservationStatus::NotInstalled,
            runtimes: Vec::new(),
        };
    };

    let fpm_root = profile.php_root.join(PHP_FPM_SUPPORTED_VERSION).join("fpm");
    let php_ini = fpm_root.join("php.ini");
    let php_fpm_global = fpm_root.join("php-fpm.conf");
    let php_fpm_pool_www = fpm_root.join("pool.d/www.conf");
    let extension_root = fpm_root.join("conf.d");
    let (extensions, extension_count, extensions_truncated, extension_partial) =
        observe_extensions(&extension_root);
    let blocked_reason = managed_config_blocked_reason(&php_ini, service.runtime_state);
    let operation_available = blocked_reason.is_none();
    let managed_configs = vec![
        managed_config_view(
            PHP_FPM_CONFIG_ADAPTER_ID,
            "PHP 8.3 FPM · php.ini",
            "/etc/php/8.3/fpm/php.ini",
            &php_ini,
            service.runtime_state,
        ),
        managed_config_view(
            PHP_FPM_GLOBAL_CONFIG_ADAPTER_ID,
            "PHP 8.3 FPM · 전역 설정",
            "/etc/php/8.3/fpm/php-fpm.conf",
            &php_fpm_global,
            service.runtime_state,
        ),
        managed_config_view(
            PHP_FPM_POOL_CONFIG_ADAPTER_ID,
            "PHP 8.3 FPM · www pool",
            "/etc/php/8.3/fpm/pool.d/www.conf",
            &php_fpm_pool_www,
            service.runtime_state,
        ),
    ];
    let runtime = PhpFpmRuntimeView {
        version: String::from(PHP_FPM_SUPPORTED_VERSION),
        unit_name: service.unit_name.clone(),
        runtime_state: service.runtime_state,
        active_state: service.active_state.clone(),
        sub_state: service.sub_state.clone(),
        php_ini_masked_path: String::from("/etc/php/8.3/fpm/php.ini"),
        pool_directory_masked_path: String::from("/etc/php/8.3/fpm/pool.d"),
        extension_directory_masked_path: String::from("/etc/php/8.3/fpm/conf.d"),
        extensions,
        extension_count,
        extensions_truncated,
        managed_configs,
        managed_config_resource_id: operation_available
            .then(|| php_fpm_config_resource_id(PHP_FPM_CONFIG_ADAPTER_ID)),
        managed_config_operation_type: operation_available
            .then(|| String::from(MANAGED_CONFIG_OPERATION)),
        managed_config_schema_version: operation_available.then_some(OPERATION_SCHEMA_VERSION),
        assurance: php_fpm_assurance(
            operation_available,
            blocked_reason.clone(),
            "표준 php.ini 한 파일",
        ),
        blocked_reason,
    };
    PhpFpmView {
        observed_at,
        status: if extension_partial {
            ObservationStatus::Partial
        } else {
            ObservationStatus::Observed
        },
        runtimes: vec![runtime],
    }
}

fn managed_config_view(
    adapter_id: &str,
    display_name: &str,
    masked_path: &str,
    path: &Path,
    runtime_state: ServiceRuntimeState,
) -> PhpFpmManagedConfigView {
    let blocked_reason = managed_config_blocked_reason(path, runtime_state);
    let available = blocked_reason.is_none();
    PhpFpmManagedConfigView {
        resource_id: php_fpm_config_resource_id(adapter_id),
        operation_type: String::from(MANAGED_CONFIG_OPERATION),
        schema_version: OPERATION_SCHEMA_VERSION,
        display_name: String::from(display_name),
        masked_path: String::from(masked_path),
        available,
        assurance: php_fpm_assurance(available, blocked_reason.clone(), display_name),
        blocked_reason,
    }
}

fn managed_config_blocked_reason(
    path: &Path,
    runtime_state: ServiceRuntimeState,
) -> Option<String> {
    if !matches!(
        runtime_state,
        ServiceRuntimeState::Running | ServiceRuntimeState::Active
    ) {
        return Some(String::from("service_inactive"));
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(_) => return Some(String::from("resource_missing")),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Some(String::from("resource_not_regular"));
    }
    #[cfg(unix)]
    if metadata.nlink() != 1
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o133 != 0
    {
        return Some(String::from("resource_metadata_rejected"));
    }
    if metadata.len()
        > u64::try_from(PHP_FPM_CONFIG_MAX_BYTES).map_or(u64::MAX, std::convert::identity)
    {
        return Some(String::from("size_limit"));
    }
    let Ok(capacity) = usize::try_from(metadata.len()) else {
        return Some(String::from("size_limit"));
    };
    let mut bytes = Vec::with_capacity(capacity);
    if File::open(path)
        .and_then(|mut source| source.read_to_end(&mut bytes))
        .is_err()
        || !managed_config_bytes_supported(&bytes)
    {
        return Some(String::from("invalid_encoding"));
    }
    None
}

fn observe_extensions(root: &Path) -> (Vec<String>, u16, bool, bool) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return (Vec::new(), 0, false, true);
    };
    let mut names = BTreeSet::new();
    let mut partial = false;
    for entry in entries {
        let Ok(entry) = entry else {
            partial = true;
            continue;
        };
        let Some(name) = entry.file_name().to_str().and_then(extension_name) else {
            continue;
        };
        names.insert(name);
    }
    let extension_count = u16::try_from(names.len()).map_or(u16::MAX, std::convert::identity);
    let extensions_truncated = names.len() > PHP_FPM_EXTENSION_MAX_ENTRIES;
    let extensions = names
        .into_iter()
        .take(PHP_FPM_EXTENSION_MAX_ENTRIES)
        .collect();
    (extensions, extension_count, extensions_truncated, partial)
}

fn extension_name(filename: &str) -> Option<String> {
    let stem = filename.strip_suffix(".ini")?;
    let candidate = stem
        .split_once('-')
        .filter(|(prefix, _)| prefix.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(stem, |(_, value)| value);
    (!candidate.is_empty()
        && candidate.len() <= 64
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    .then(|| candidate.to_owned())
}

fn php_fpm_assurance(
    operation_available: bool,
    reason: Option<String>,
    resource_label: &str,
) -> AssuranceView {
    AssuranceView {
        level: AssuranceLevel::G2ReversibleConfig,
        rollback_support: RollbackSupport::AutomaticBounded,
        operation_available,
        scope: vec![format!(
            "Ubuntu PHP 8.3 FPM {resource_label}과 검증된 reload"
        )],
        excluded_effects: vec![
            String::from("선택하지 않은 다른 FPM·CLI·Apache SAPI 설정과 extension package"),
            String::from("진행 중 request와 외부 root 변경"),
        ],
        apply_verifier: vec![
            String::from("php-fpm8.3 -t"),
            String::from("php8.3-fpm.service active"),
            String::from("content·owner·mode read-back"),
        ],
        rollback_verifier: vec![
            String::from("이전 bytes·owner·mode 복원"),
            String::from("문법 검사·reload·active 재확인"),
        ],
        reason,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use jw_contracts::{
        ObservationStatus, ServiceCategory, ServiceRuntimeState, ServiceSummary, ServiceSupport,
        ServiceVisibility, ServicesView,
    };

    use super::{PhpFpmObservationProfile, observe_php_fpm};

    #[test]
    fn observes_php_fpm_extensions_and_managed_resource() -> Result<(), String> {
        let root = test_root()?;
        let fpm = root.join("8.3/fpm");
        fs::create_dir_all(fpm.join("conf.d")).map_err(|error| error.to_string())?;
        fs::write(fpm.join("php.ini"), "memory_limit = 128M\n")
            .map_err(|error| error.to_string())?;
        #[cfg(unix)]
        fs::set_permissions(fpm.join("php.ini"), fs::Permissions::from_mode(0o644))
            .map_err(|error| error.to_string())?;
        fs::write(fpm.join("conf.d/20-curl.ini"), "extension=curl\n")
            .map_err(|error| error.to_string())?;
        let view = observe_php_fpm(
            &PhpFpmObservationProfile {
                php_root: root.clone(),
            },
            &services(),
            String::from("2026-07-22T00:00:00Z"),
        );
        let runtime = view.runtimes.first().ok_or("runtime missing")?;
        assert_eq!(runtime.extensions, vec![String::from("curl")]);
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    fn services() -> ServicesView {
        ServicesView {
            observed_at: String::from("2026-07-22T00:00:00Z"),
            status: ObservationStatus::Observed,
            template_profile: String::from("ubuntu-24.04-v1"),
            services: vec![ServiceSummary {
                service_id: String::from("svc_php"),
                template_id: Some(String::from("php-fpm")),
                unit_name: String::from("php8.3-fpm.service"),
                display_name: String::from("PHP-FPM"),
                purpose: String::from("PHP runtime"),
                category: ServiceCategory::Runtime,
                runtime_state: ServiceRuntimeState::Running,
                active_state: String::from("active"),
                sub_state: String::from("running"),
                unit_file_state: Some(String::from("enabled")),
                visibility: ServiceVisibility::Primary,
                support: ServiceSupport::SupportedObserve,
                read_only: true,
                hidden_by_default: false,
            }],
            truncated: false,
        }
    }

    fn test_root() -> Result<PathBuf, String> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|error| error.to_string())?;
        Ok(std::env::temp_dir().join(format!(
            "jw-agentd-php-fpm-{}-{}",
            std::process::id(),
            u64::from_le_bytes(random)
        )))
    }
}
