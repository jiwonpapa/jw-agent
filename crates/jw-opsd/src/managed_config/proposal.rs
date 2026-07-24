use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use jw_contracts::{MANAGED_CONFIG_MAX_BYTES, managed_config_bytes_supported, sha256_digest};

use crate::config::{OpsPaths, OpsPolicy};
use crate::error::OpsError;
use crate::snapshot::{
    prepare_private_root, require_capacity, set_file_mode, set_mode, validate_private_directory,
};

use super::ProposalRecord;
use super::text::validate_relative_path;

pub fn write_proposal(
    paths: &OpsPaths,
    policy: &OpsPolicy,
    plan_id: &str,
    content: &str,
) -> Result<ProposalRecord, OpsError> {
    if content.len() > MANAGED_CONFIG_MAX_BYTES {
        return Err(OpsError::Rejected("size_limit"));
    }
    if !managed_config_bytes_supported(content.as_bytes()) {
        return Err(OpsError::Rejected("invalid_encoding"));
    }
    prepare_private_root(&paths.proposals, paths.enforce_root_ownership)?;
    require_capacity(&paths.proposals, policy.snapshot_min_free_bytes)?;
    let plan_directory = paths.proposals.join(plan_id);
    std::fs::create_dir(&plan_directory)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    set_mode(&plan_directory, 0o700)?;
    validate_private_directory(&plan_directory, paths.enforce_root_ownership)?;
    let relative_path = format!("{plan_id}/content");
    let path = paths.proposals.join(&relative_path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    set_file_mode(&file, 0o600)?;
    file.write_all(content.as_bytes())
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    file.sync_all()
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    File::open(&plan_directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    File::open(&paths.proposals)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    Ok(ProposalRecord {
        relative_path,
        digest: sha256_digest(content.as_bytes()),
    })
}

pub fn read_proposal(paths: &OpsPaths, record: &ProposalRecord) -> Result<String, OpsError> {
    validate_relative_path(&record.relative_path)?;
    prepare_private_root(&paths.proposals, paths.enforce_root_ownership)?;
    let path = paths.proposals.join(&record.relative_path);
    let parent = path
        .parent()
        .ok_or(OpsError::Rejected("proposal_path_rejected"))?;
    validate_private_directory(parent, paths.enforce_root_ownership)?;
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len()
            > u64::try_from(MANAGED_CONFIG_MAX_BYTES).map_or(u64::MAX, std::convert::identity)
    {
        return Err(OpsError::Rejected("proposal_file_rejected"));
    }
    #[cfg(unix)]
    if metadata.nlink() != 1
        || (paths.enforce_root_ownership && metadata.uid() != 0)
        || metadata.mode() & 0o077 != 0
    {
        return Err(OpsError::ForensicLockdown);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| OpsError::Rejected("size_limit"))?,
    );
    File::open(path)
        .and_then(|mut source| source.read_to_end(&mut bytes))
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if sha256_digest(&bytes) != record.digest || !managed_config_bytes_supported(&bytes) {
        return Err(OpsError::ForensicLockdown);
    }
    String::from_utf8(bytes).map_err(|_| OpsError::ForensicLockdown)
}

pub fn remove_proposal(paths: &OpsPaths, record: &ProposalRecord) -> Result<(), OpsError> {
    validate_relative_path(&record.relative_path)?;
    let path = paths.proposals.join(&record.relative_path);
    let parent = path
        .parent()
        .ok_or(OpsError::Rejected("proposal_path_rejected"))?;
    std::fs::remove_file(&path).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    std::fs::remove_dir(parent).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    File::open(&paths.proposals)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| OpsError::Filesystem(error.to_string()))
}
