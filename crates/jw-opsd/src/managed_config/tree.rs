use std::path::{Component, Path};

use jw_contracts::{
    MANAGED_SERVICE_CONFIG_MAX_DEPTH, MANAGED_SERVICE_CONFIG_MAX_ENTRIES,
    managed_service_config_resource_id,
};

use crate::config::OpsPaths;
use crate::error::OpsError;
use crate::nginx::validate_root;

use super::{ManagedConfigAdapter, ManagedConfigResource, read_regular_managed_config};

pub(super) fn discover_tree_managed_config(
    paths: &OpsPaths,
    adapter: ManagedConfigAdapter,
    root: &Path,
    requested_resource_id: &str,
    resource_prefix: &str,
) -> Result<ManagedConfigResource, OpsError> {
    validate_root(root, paths.enforce_root_ownership)?;
    let mut directories = vec![(root.to_path_buf(), 0_usize)];
    let mut observed_entries = 0_usize;
    while let Some((directory, depth)) = directories.pop() {
        if depth > MANAGED_SERVICE_CONFIG_MAX_DEPTH {
            continue;
        }
        validate_root(&directory, paths.enforce_root_ownership)?;
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| OpsError::Filesystem(error.to_string()))?;
        for entry_result in entries {
            observed_entries = observed_entries.saturating_add(1);
            if observed_entries > MANAGED_SERVICE_CONFIG_MAX_ENTRIES {
                return Err(OpsError::Rejected("inventory_truncated"));
            }
            let entry = entry_result.map_err(|error| OpsError::Filesystem(error.to_string()))?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| OpsError::Filesystem(error.to_string()))?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                directories.push((path, depth.saturating_add(1)));
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| OpsError::Rejected("path_policy"))?;
            let relative_path = safe_tree_relative_path(relative)?;
            let resource_id = managed_service_config_resource_id(
                resource_prefix,
                adapter.adapter_id(),
                &relative_path,
            );
            if resource_id != requested_resource_id {
                continue;
            }
            if secret_tree_resource(&relative_path) {
                return Err(OpsError::Rejected("protected_resource"));
            }
            let basename = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(OpsError::Rejected("path_policy"))?;
            let parent = path.parent().ok_or(OpsError::Rejected("path_policy"))?;
            let resource = read_regular_managed_config(
                paths,
                adapter,
                parent,
                basename,
                &relative_path,
                resource_id,
            )?;
            if contains_private_key_marker(resource.content.as_bytes()) {
                return Err(OpsError::Rejected("protected_resource"));
            }
            return Ok(resource);
        }
    }
    Err(OpsError::Rejected("resource_missing"))
}

fn safe_tree_relative_path(path: &Path) -> Result<String, OpsError> {
    if path.components().count() > MANAGED_SERVICE_CONFIG_MAX_DEPTH.saturating_add(1)
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(OpsError::Rejected("path_policy"));
    }
    let value = path.to_str().ok_or(OpsError::Rejected("path_policy"))?;
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
        return Err(OpsError::Rejected("path_policy"));
    }
    Ok(String::from(value))
}

fn secret_tree_resource(relative_path: &str) -> bool {
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
