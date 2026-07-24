use std::fs::File;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use jw_contracts::{
    APACHE_CONF_CONFIG_ADAPTER_ID, APACHE_CONF_RESOURCE_PREFIX, APACHE_MAIN_CONFIG_ADAPTER_ID,
    APACHE_MAIN_RESOURCE_PREFIX, APACHE_PORTS_CONFIG_ADAPTER_ID, APACHE_PORTS_RESOURCE_PREFIX,
    APACHE_SITE_CONFIG_ADAPTER_ID, APACHE_SITE_RESOURCE_PREFIX, AssuranceLevel, AssuranceView,
    MANAGED_CONFIG_MAX_BYTES, MANAGED_CONFIG_OPERATION, MANAGED_SERVICE_CONFIG_MAX_ENTRIES,
    ManagedServiceConfigInventoryView, ManagedServiceConfigView, NGINX_CONF_D_CONFIG_ADAPTER_ID,
    NGINX_CONF_D_RESOURCE_PREFIX, NGINX_MAIN_CONFIG_ADAPTER_ID, NGINX_MAIN_RESOURCE_PREFIX,
    OPERATION_SCHEMA_VERSION, ObservationStatus, RollbackSupport, ServiceRuntimeState,
    ServicesView, managed_config_bytes_supported, managed_service_config_resource_id,
};

#[derive(Clone, Debug)]
pub struct ServiceConfigObservationProfile {
    pub nginx_root: PathBuf,
    pub apache_root: PathBuf,
}

impl Default for ServiceConfigObservationProfile {
    fn default() -> Self {
        Self {
            nginx_root: PathBuf::from("/etc/nginx"),
            apache_root: PathBuf::from("/etc/apache2"),
        }
    }
}

pub fn observe_service_configs(
    profile: &ServiceConfigObservationProfile,
    services: &ServicesView,
    service_key: &str,
    observed_at: String,
) -> ManagedServiceConfigInventoryView {
    if !cfg!(target_os = "linux") {
        return empty_inventory(
            observed_at,
            service_key,
            "",
            "",
            ObservationStatus::UnsupportedPlatform,
        );
    }
    match service_key {
        "nginx" => observe_nginx(profile, services, observed_at),
        "apache" => observe_apache(profile, services, observed_at),
        _ => empty_inventory(
            observed_at,
            service_key,
            "",
            "",
            ObservationStatus::UnsupportedPlatform,
        ),
    }
}

fn observe_nginx(
    profile: &ServiceConfigObservationProfile,
    services: &ServicesView,
    observed_at: String,
) -> ManagedServiceConfigInventoryView {
    let unit = "nginx.service";
    let Some(service) = services
        .services
        .iter()
        .find(|service| service.unit_name == unit)
    else {
        return empty_inventory(
            observed_at,
            "nginx",
            unit,
            "Nginx",
            ObservationStatus::NotInstalled,
        );
    };
    let active = service_active(service.runtime_state);
    let main = profile.nginx_root.join("nginx.conf");
    let mut configs = vec![config_view(
        NGINX_MAIN_RESOURCE_PREFIX,
        NGINX_MAIN_CONFIG_ADAPTER_ID,
        "nginx.conf",
        "Nginx · nginx.conf",
        "/etc/nginx/nginx.conf",
        &main,
        active,
        "Nginx",
    )];
    let conf_d_active = std::fs::read_to_string(&main)
        .is_ok_and(|content| content.contains("include /etc/nginx/conf.d/*.conf;"));
    append_directory(
        &mut configs,
        &profile.nginx_root.join("conf.d"),
        None,
        NGINX_CONF_D_RESOURCE_PREFIX,
        NGINX_CONF_D_CONFIG_ADAPTER_ID,
        "Nginx · conf.d",
        "/etc/nginx/conf.d",
        active && conf_d_active,
        if conf_d_active {
            None
        } else {
            Some("include_not_active")
        },
        "Nginx",
    );
    finish_inventory(observed_at, "nginx", unit, "Nginx", configs)
}

fn observe_apache(
    profile: &ServiceConfigObservationProfile,
    services: &ServicesView,
    observed_at: String,
) -> ManagedServiceConfigInventoryView {
    let unit = "apache2.service";
    let Some(service) = services
        .services
        .iter()
        .find(|service| service.unit_name == unit)
    else {
        return empty_inventory(
            observed_at,
            "apache",
            unit,
            "Apache HTTP Server",
            ObservationStatus::NotInstalled,
        );
    };
    let active = service_active(service.runtime_state);
    let mut configs = vec![
        config_view(
            APACHE_MAIN_RESOURCE_PREFIX,
            APACHE_MAIN_CONFIG_ADAPTER_ID,
            "apache2.conf",
            "Apache · apache2.conf",
            "/etc/apache2/apache2.conf",
            &profile.apache_root.join("apache2.conf"),
            active,
            "Apache",
        ),
        config_view(
            APACHE_PORTS_RESOURCE_PREFIX,
            APACHE_PORTS_CONFIG_ADAPTER_ID,
            "ports.conf",
            "Apache · ports.conf",
            "/etc/apache2/ports.conf",
            &profile.apache_root.join("ports.conf"),
            active,
            "Apache",
        ),
    ];
    append_directory(
        &mut configs,
        &profile.apache_root.join("conf-available"),
        Some(&profile.apache_root.join("conf-enabled")),
        APACHE_CONF_RESOURCE_PREFIX,
        APACHE_CONF_CONFIG_ADAPTER_ID,
        "Apache · conf",
        "/etc/apache2/conf-available",
        active,
        None,
        "Apache",
    );
    append_directory(
        &mut configs,
        &profile.apache_root.join("sites-available"),
        Some(&profile.apache_root.join("sites-enabled")),
        APACHE_SITE_RESOURCE_PREFIX,
        APACHE_SITE_CONFIG_ADAPTER_ID,
        "Apache · site",
        "/etc/apache2/sites-available",
        active,
        None,
        "Apache",
    );
    finish_inventory(observed_at, "apache", unit, "Apache HTTP Server", configs)
}

#[allow(clippy::too_many_arguments)]
fn append_directory(
    configs: &mut Vec<ManagedServiceConfigView>,
    available_root: &Path,
    enabled_root: Option<&Path>,
    prefix: &str,
    adapter_id: &str,
    display_prefix: &str,
    masked_root: &str,
    service_active: bool,
    forced_reason: Option<&str>,
    service_name: &str,
) {
    let Ok(entries) = std::fs::read_dir(available_root) else {
        return;
    };
    let mut names = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|name| safe_config_basename(name))
        .collect::<Vec<_>>();
    names.sort();
    for basename in names {
        if configs.len() > MANAGED_SERVICE_CONFIG_MAX_ENTRIES {
            break;
        }
        let enabled =
            enabled_root.is_none_or(|root| enabled_link_matches(available_root, root, &basename));
        let reason = forced_reason.or((!enabled).then_some("resource_not_active"));
        configs.push(config_view_with_reason(
            prefix,
            adapter_id,
            &basename,
            &format!("{display_prefix} · {basename}"),
            &format!("{masked_root}/{basename}"),
            &available_root.join(&basename),
            service_active && enabled && reason.is_none(),
            reason,
            service_name,
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn config_view(
    prefix: &str,
    adapter_id: &str,
    logical_name: &str,
    display_name: &str,
    masked_path: &str,
    path: &Path,
    service_active: bool,
    service_name: &str,
) -> ManagedServiceConfigView {
    config_view_with_reason(
        prefix,
        adapter_id,
        logical_name,
        display_name,
        masked_path,
        path,
        service_active,
        None,
        service_name,
    )
}

#[allow(clippy::too_many_arguments)]
fn config_view_with_reason(
    prefix: &str,
    adapter_id: &str,
    logical_name: &str,
    display_name: &str,
    masked_path: &str,
    path: &Path,
    service_active: bool,
    forced_reason: Option<&str>,
    service_name: &str,
) -> ManagedServiceConfigView {
    let reason = forced_reason
        .map(str::to_owned)
        .or_else(|| (!service_active).then(|| String::from("service_inactive")))
        .or_else(|| regular_file_blocked_reason(path));
    let available = reason.is_none();
    ManagedServiceConfigView {
        resource_id: managed_service_config_resource_id(prefix, adapter_id, logical_name),
        operation_type: String::from(MANAGED_CONFIG_OPERATION),
        schema_version: OPERATION_SCHEMA_VERSION,
        display_name: String::from(display_name),
        masked_path: String::from(masked_path),
        available,
        blocked_reason: reason.clone(),
        assurance: service_config_assurance(service_name, display_name, available, reason),
    }
}

fn regular_file_blocked_reason(path: &Path) -> Option<String> {
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
        > u64::try_from(MANAGED_CONFIG_MAX_BYTES).map_or(u64::MAX, std::convert::identity)
    {
        return Some(String::from("size_limit"));
    }
    let Ok(capacity) = usize::try_from(metadata.len()) else {
        return Some(String::from("size_limit"));
    };
    let mut bytes = Vec::with_capacity(capacity);
    if File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .is_err()
        || !managed_config_bytes_supported(&bytes)
    {
        return Some(String::from("invalid_encoding"));
    }
    None
}

fn enabled_link_matches(available_root: &Path, enabled_root: &Path, basename: &str) -> bool {
    let link = enabled_root.join(basename);
    let Ok(metadata) = std::fs::symlink_metadata(&link) else {
        return false;
    };
    if !metadata.file_type().is_symlink() {
        return false;
    }
    let Ok(target) = std::fs::read_link(link) else {
        return false;
    };
    let Some(directory) = available_root.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let relative_target = format!("../{directory}/{basename}");
    target == available_root.join(basename) || target == Path::new(&relative_target)
}

fn safe_config_basename(value: &str) -> bool {
    value.ends_with(".conf")
        && value.len() <= 128
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn service_active(state: ServiceRuntimeState) -> bool {
    matches!(
        state,
        ServiceRuntimeState::Running | ServiceRuntimeState::Active
    )
}

fn service_config_assurance(
    service_name: &str,
    resource_name: &str,
    operation_available: bool,
    reason: Option<String>,
) -> AssuranceView {
    AssuranceView {
        level: AssuranceLevel::G2ReversibleConfig,
        rollback_support: RollbackSupport::AutomaticBounded,
        operation_available,
        scope: vec![format!(
            "{resource_name} 한 파일과 검증된 {service_name} reload"
        )],
        excluded_effects: vec![
            String::from("선택하지 않은 설정 파일과 진행 중 request"),
            String::from("제품 밖 root 사용자의 동시 변경"),
        ],
        apply_verifier: vec![
            String::from("원자 교체와 content·metadata read-back"),
            format!("{service_name} 공식 문법 검사"),
            format!("{service_name} reload 후 active 확인"),
        ],
        rollback_verifier: vec![
            String::from("이전 bytes·owner·mode 복원"),
            String::from("문법 검사와 reload 후 active 재확인"),
        ],
        reason,
    }
}

fn finish_inventory(
    observed_at: String,
    service_key: &str,
    unit_name: &str,
    display_name: &str,
    mut configs: Vec<ManagedServiceConfigView>,
) -> ManagedServiceConfigInventoryView {
    let truncated = configs.len() > MANAGED_SERVICE_CONFIG_MAX_ENTRIES;
    configs.truncate(MANAGED_SERVICE_CONFIG_MAX_ENTRIES);
    ManagedServiceConfigInventoryView {
        observed_at,
        status: ObservationStatus::Observed,
        service_key: String::from(service_key),
        unit_name: String::from(unit_name),
        display_name: String::from(display_name),
        configs,
        truncated,
    }
}

fn empty_inventory(
    observed_at: String,
    service_key: &str,
    unit_name: &str,
    display_name: &str,
    status: ObservationStatus,
) -> ManagedServiceConfigInventoryView {
    ManagedServiceConfigInventoryView {
        observed_at,
        status,
        service_key: String::from(service_key),
        unit_name: String::from(unit_name),
        display_name: String::from(display_name),
        configs: Vec::new(),
        truncated: false,
    }
}
