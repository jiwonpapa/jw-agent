use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use jw_contracts::nginx_internal_temporary_name;

use crate::config::OpsPaths;
use crate::error::OpsError;
use crate::nginx::validate_root;

pub fn cleanup_internal_temporaries(paths: &OpsPaths) -> Result<(), OpsError> {
    cleanup_temporaries_in_root(&paths.nginx_available, paths.enforce_root_ownership)?;
    cleanup_temporaries_in_root(&paths.nginx_conf_d, paths.enforce_root_ownership)?;
    cleanup_parent_temporaries(&paths.nginx_main, paths.enforce_root_ownership)?;
    cleanup_parent_temporaries(&paths.apache_main, paths.enforce_root_ownership)?;
    cleanup_parent_temporaries(&paths.apache_ports, paths.enforce_root_ownership)?;
    cleanup_temporaries_in_root(&paths.apache_conf_available, paths.enforce_root_ownership)?;
    cleanup_temporaries_in_root(&paths.apache_sites_available, paths.enforce_root_ownership)?;
    if let Some(root) = paths.php_fpm_ini.parent() {
        cleanup_temporaries_in_root(root, paths.enforce_root_ownership)?;
    }
    cleanup_temporaries_in_root(&paths.php_fpm_pool_dir, paths.enforce_root_ownership)?;
    Ok(())
}

fn cleanup_parent_temporaries(path: &Path, enforce_root_ownership: bool) -> Result<(), OpsError> {
    let root = path
        .parent()
        .ok_or(OpsError::Rejected("unsupported_layout"))?;
    cleanup_temporaries_in_root(root, enforce_root_ownership)
}

fn cleanup_temporaries_in_root(root: &Path, enforce_root_ownership: bool) -> Result<(), OpsError> {
    if !root.exists() {
        return Ok(());
    }
    validate_root(root, enforce_root_ownership)?;
    let entries =
        std::fs::read_dir(root).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    let mut removed = false;
    for entry_result in entries {
        let entry = entry_result.map_err(|error| OpsError::Filesystem(error.to_string()))?;
        let Some(basename) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !nginx_internal_temporary_name(&basename) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(entry.path())
            .map_err(|error| OpsError::Filesystem(error.to_string()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(OpsError::ForensicLockdown);
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 || (enforce_root_ownership && metadata.uid() != 0) {
            return Err(OpsError::ForensicLockdown);
        }
        std::fs::remove_file(entry.path())
            .map_err(|error| OpsError::Filesystem(error.to_string()))?;
        removed = true;
    }
    if removed {
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    }
    Ok(())
}
