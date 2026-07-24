use std::fs::File;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use jw_contracts::{
    APACHE_TREE_CONFIG_ADAPTER_ID, APACHE_TREE_RESOURCE_PREFIX, MANAGED_CONFIG_MAX_BYTES,
    MANAGED_CONFIG_OPERATION, MANAGED_SERVICE_CONFIG_MAX_DEPTH, MANAGED_SERVICE_CONFIG_MAX_ENTRIES,
    ManagedServiceConfigInventoryView, ManagedServiceConfigView, NGINX_TREE_CONFIG_ADAPTER_ID,
    NGINX_TREE_RESOURCE_PREFIX, OPERATION_SCHEMA_VERSION, ObservationStatus, ServiceRuntimeState,
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
        "nginx" => observe_tree(
            services,
            TreeProfile {
                service_key: "nginx",
                unit_name: "nginx.service",
                display_name: "Nginx",
                masked_root: "/etc/nginx",
                root: &profile.nginx_root,
                adapter_id: NGINX_TREE_CONFIG_ADAPTER_ID,
                resource_prefix: NGINX_TREE_RESOURCE_PREFIX,
            },
            observed_at,
        ),
        "apache" => observe_tree(
            services,
            TreeProfile {
                service_key: "apache",
                unit_name: "apache2.service",
                display_name: "Apache HTTP Server",
                masked_root: "/etc/apache2",
                root: &profile.apache_root,
                adapter_id: APACHE_TREE_CONFIG_ADAPTER_ID,
                resource_prefix: APACHE_TREE_RESOURCE_PREFIX,
            },
            observed_at,
        ),
        _ => empty_inventory(
            observed_at,
            service_key,
            "",
            "",
            ObservationStatus::UnsupportedPlatform,
        ),
    }
}

struct TreeProfile<'a> {
    service_key: &'a str,
    unit_name: &'a str,
    display_name: &'a str,
    masked_root: &'a str,
    root: &'a Path,
    adapter_id: &'a str,
    resource_prefix: &'a str,
}

fn observe_tree(
    services: &ServicesView,
    profile: TreeProfile<'_>,
    observed_at: String,
) -> ManagedServiceConfigInventoryView {
    let Some(service) = services
        .services
        .iter()
        .find(|service| service.unit_name == profile.unit_name)
    else {
        return empty_inventory(
            observed_at,
            profile.service_key,
            profile.unit_name,
            profile.display_name,
            ObservationStatus::NotInstalled,
        );
    };
    let service_active = matches!(
        service.runtime_state,
        ServiceRuntimeState::Running | ServiceRuntimeState::Active
    );
    let mut files = Vec::new();
    collect_tree_files(profile.root, profile.root, 0, &mut files);
    files.sort();
    let truncated = files.len() > MANAGED_SERVICE_CONFIG_MAX_ENTRIES;
    files.truncate(MANAGED_SERVICE_CONFIG_MAX_ENTRIES);
    let configs = files
        .into_iter()
        .filter_map(|path| {
            let relative = path.strip_prefix(profile.root).ok()?;
            let relative_path = safe_relative_path(relative)?;
            let blocked_reason = regular_file_blocked_reason(&path, &relative_path);
            let available = blocked_reason.is_none();
            let loaded = resource_loaded(profile.service_key, profile.root, &relative_path);
            Some(ManagedServiceConfigView {
                resource_id: managed_service_config_resource_id(
                    profile.resource_prefix,
                    profile.adapter_id,
                    &relative_path,
                ),
                operation_type: String::from(MANAGED_CONFIG_OPERATION),
                schema_version: OPERATION_SCHEMA_VERSION,
                display_name: relative
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map_or_else(|| relative_path.clone(), str::to_owned),
                masked_path: format!("{}/{}", profile.masked_root, relative_path),
                relative_path: relative_path.clone(),
                loaded,
                service_active,
                available,
                blocked_reason: blocked_reason.clone(),
            })
        })
        .collect();
    ManagedServiceConfigInventoryView {
        observed_at,
        status: ObservationStatus::Observed,
        service_key: String::from(profile.service_key),
        unit_name: String::from(profile.unit_name),
        display_name: String::from(profile.display_name),
        configs,
        truncated,
    }
}

fn collect_tree_files(root: &Path, directory: &Path, depth: usize, files: &mut Vec<PathBuf>) {
    if depth > MANAGED_SERVICE_CONFIG_MAX_DEPTH || files.len() > MANAGED_SERVICE_CONFIG_MAX_ENTRIES
    {
        return;
    }
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();
    for path in paths {
        if files.len() > MANAGED_SERVICE_CONFIG_MAX_ENTRIES {
            return;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_tree_files(root, &path, depth.saturating_add(1), files);
        } else if metadata.is_file() && path.starts_with(root) {
            files.push(path);
        }
    }
}

fn safe_relative_path(path: &Path) -> Option<String> {
    if path.components().count() > MANAGED_SERVICE_CONFIG_MAX_DEPTH.saturating_add(1)
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    let value = path.to_str()?;
    if value.is_empty()
        || value.len() > 512
        || value.split('/').any(|part| {
            part.is_empty()
                || part.starts_with('.')
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return None;
    }
    Some(String::from(value))
}

fn regular_file_blocked_reason(path: &Path, relative_path: &str) -> Option<String> {
    if secret_candidate(relative_path) {
        return Some(String::from("protected_resource"));
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
    if contains_private_key_marker(&bytes) {
        return Some(String::from("protected_resource"));
    }
    None
}

fn secret_candidate(relative_path: &str) -> bool {
    let lowered = relative_path.to_ascii_lowercase();
    [
        "private",
        "privkey",
        "credential",
        "password",
        "passwd",
        "secret",
        "token",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
        || [".key", ".pem", ".p12", ".pfx"]
            .iter()
            .any(|suffix| lowered.ends_with(suffix))
}

fn contains_private_key_marker(bytes: &[u8]) -> bool {
    [
        b"-----BEGIN PRIVATE KEY-----".as_slice(),
        b"-----BEGIN RSA PRIVATE KEY-----".as_slice(),
        b"-----BEGIN EC PRIVATE KEY-----".as_slice(),
        b"-----BEGIN OPENSSH PRIVATE KEY-----".as_slice(),
    ]
    .iter()
    .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
}

fn resource_loaded(service_key: &str, root: &Path, relative_path: &str) -> bool {
    match service_key {
        "nginx" => {
            relative_path == "nginx.conf"
                || relative_path.starts_with("conf.d/")
                || symlink_exists_for(root, "sites-enabled", relative_path, "sites-available")
        }
        "apache" => {
            matches!(relative_path, "apache2.conf" | "ports.conf" | "envvars")
                || symlink_exists_for(root, "conf-enabled", relative_path, "conf-available")
                || symlink_exists_for(root, "mods-enabled", relative_path, "mods-available")
                || symlink_exists_for(root, "sites-enabled", relative_path, "sites-available")
        }
        _ => false,
    }
}

fn symlink_exists_for(root: &Path, enabled: &str, relative_path: &str, available: &str) -> bool {
    let Some(basename) = relative_path.strip_prefix(&format!("{available}/")) else {
        return false;
    };
    std::fs::symlink_metadata(root.join(enabled).join(basename))
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
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
