use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use jw_contracts::sha256_digest;
use serde::{Deserialize, Serialize};

use crate::config::{OpsPaths, OpsPolicy};
use crate::error::OpsError;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NginxLinkSnapshot {
    pub schema_version: u16,
    pub site_id: String,
    pub basename: String,
    pub enabled: bool,
    pub available_digest: String,
    pub enabled_state_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedConfigSnapshot {
    pub schema_version: u16,
    pub resource_id: String,
    pub basename: String,
    pub content: String,
    pub content_digest: String,
    pub metadata_digest: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificateInventorySnapshot {
    pub schema_version: u16,
    pub inventory_digest: String,
    pub timer_enabled: bool,
    pub timer_active: bool,
    pub certificate_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotRecord {
    pub relative_path: String,
    pub digest: String,
}

pub fn write_nginx_snapshot(
    paths: &OpsPaths,
    policy: &OpsPolicy,
    operation_id: &str,
    snapshot: &NginxLinkSnapshot,
) -> Result<SnapshotRecord, OpsError> {
    let bytes =
        serde_json::to_vec(snapshot).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    write_snapshot_bytes(paths, policy, operation_id, "nginx-link.json", &bytes)
}

pub fn write_managed_config_snapshot(
    paths: &OpsPaths,
    policy: &OpsPolicy,
    operation_id: &str,
    snapshot: &ManagedConfigSnapshot,
) -> Result<SnapshotRecord, OpsError> {
    let bytes =
        serde_json::to_vec(snapshot).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    write_snapshot_bytes(paths, policy, operation_id, "managed-config.json", &bytes)
}

pub fn write_certificate_inventory_snapshot(
    paths: &OpsPaths,
    policy: &OpsPolicy,
    operation_id: &str,
    snapshot: &CertificateInventorySnapshot,
) -> Result<SnapshotRecord, OpsError> {
    let bytes =
        serde_json::to_vec(snapshot).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    write_snapshot_bytes(
        paths,
        policy,
        operation_id,
        "certificate-inventory.json",
        &bytes,
    )
}

fn write_snapshot_bytes(
    paths: &OpsPaths,
    policy: &OpsPolicy,
    operation_id: &str,
    filename: &str,
    bytes: &[u8],
) -> Result<SnapshotRecord, OpsError> {
    prepare_private_root(&paths.snapshots, paths.enforce_root_ownership)?;
    require_capacity(&paths.snapshots, policy.snapshot_min_free_bytes)?;
    let operation_directory = paths.snapshots.join(operation_id);
    std::fs::create_dir(&operation_directory)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    set_mode(&operation_directory, 0o700)?;
    validate_private_directory(&operation_directory, paths.enforce_root_ownership)?;
    let relative_path = format!("{operation_id}/{filename}");
    let snapshot_path = paths.snapshots.join(&relative_path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&snapshot_path)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    set_file_mode(&file, 0o600)?;
    file.write_all(bytes)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    file.sync_all()
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    let digest = sha256_digest(bytes);
    let mut read_back = Vec::with_capacity(bytes.len());
    File::open(&snapshot_path)
        .and_then(|mut source| source.read_to_end(&mut read_back))
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if sha256_digest(&read_back) != digest {
        return Err(OpsError::Rejected("snapshot_read_back_mismatch"));
    }
    File::open(&operation_directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    File::open(&paths.snapshots)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    Ok(SnapshotRecord {
        relative_path,
        digest,
    })
}

pub fn read_nginx_snapshot(
    paths: &OpsPaths,
    record: &SnapshotRecord,
) -> Result<NginxLinkSnapshot, OpsError> {
    let bytes = read_snapshot_bytes(paths, record, 64 * 1_024)?;
    serde_json::from_slice(&bytes).map_err(|error| OpsError::Filesystem(error.to_string()))
}

pub fn read_managed_config_snapshot(
    paths: &OpsPaths,
    record: &SnapshotRecord,
) -> Result<ManagedConfigSnapshot, OpsError> {
    let bytes = read_snapshot_bytes(paths, record, 2 * 1_024 * 1_024)?;
    serde_json::from_slice(&bytes).map_err(|error| OpsError::Filesystem(error.to_string()))
}

pub fn read_certificate_inventory_snapshot(
    paths: &OpsPaths,
    record: &SnapshotRecord,
) -> Result<CertificateInventorySnapshot, OpsError> {
    let bytes = read_snapshot_bytes(paths, record, 64 * 1_024)?;
    serde_json::from_slice(&bytes).map_err(|error| OpsError::Filesystem(error.to_string()))
}

fn read_snapshot_bytes(
    paths: &OpsPaths,
    record: &SnapshotRecord,
    max_bytes: u64,
) -> Result<Vec<u8>, OpsError> {
    if record.relative_path.starts_with('/')
        || record
            .relative_path
            .split('/')
            .any(|component| matches!(component, "" | "." | ".."))
    {
        return Err(OpsError::Rejected("snapshot_path_rejected"));
    }
    let path = paths.snapshots.join(&record.relative_path);
    validate_private_directory(&paths.snapshots, paths.enforce_root_ownership)?;
    let Some(operation_directory) = path.parent() else {
        return Err(OpsError::Rejected("snapshot_path_rejected"));
    };
    validate_private_directory(operation_directory, paths.enforce_root_ownership)?;
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
        return Err(OpsError::Rejected("snapshot_file_rejected"));
    }
    #[cfg(unix)]
    if metadata.nlink() != 1
        || (paths.enforce_root_ownership && metadata.uid() != 0)
        || metadata.mode() & 0o077 != 0
    {
        return Err(OpsError::ForensicLockdown);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .map_err(|_| OpsError::Rejected("snapshot_file_rejected"))?,
    );
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if sha256_digest(&bytes) != record.digest {
        return Err(OpsError::ForensicLockdown);
    }
    Ok(bytes)
}

pub(crate) fn prepare_private_root(
    path: &Path,
    enforce_root_ownership: bool,
) -> Result<(), OpsError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(OpsError::Rejected("snapshot_root_rejected")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path)
                .map_err(|create_error| OpsError::Filesystem(create_error.to_string()))?;
        }
        Err(error) => return Err(OpsError::Filesystem(error.to_string())),
    }
    set_mode(path, 0o700)?;
    validate_private_directory(path, enforce_root_ownership)
}

pub(crate) fn validate_private_directory(
    path: &Path,
    enforce_root_ownership: bool,
) -> Result<(), OpsError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| OpsError::ForensicLockdown)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(OpsError::ForensicLockdown);
    }
    #[cfg(unix)]
    if (enforce_root_ownership && metadata.uid() != 0) || metadata.mode() & 0o077 != 0 {
        return Err(OpsError::ForensicLockdown);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn require_capacity(path: &Path, minimum_free_bytes: u64) -> Result<(), OpsError> {
    use nix::sys::statvfs::statvfs;

    let stats = statvfs(path).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    let free = stats
        .blocks_available()
        .saturating_mul(stats.fragment_size());
    if free < minimum_free_bytes {
        Err(OpsError::Rejected("snapshot_space_insufficient"))
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn require_capacity(_path: &Path, _minimum_free_bytes: u64) -> Result<(), OpsError> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_mode(path: &Path, mode: u32) -> Result<(), OpsError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| OpsError::Filesystem(error.to_string()))
}

#[cfg(not(unix))]
pub(crate) fn set_mode(_path: &Path, _mode: u32) -> Result<(), OpsError> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_file_mode(file: &File, mode: u32) -> Result<(), OpsError> {
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|error| OpsError::Filesystem(error.to_string()))
}

#[cfg(not(unix))]
pub(crate) fn set_file_mode(_file: &File, _mode: u32) -> Result<(), OpsError> {
    Ok(())
}
