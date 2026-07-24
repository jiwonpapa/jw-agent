#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use jw_contracts::sha256_digest;

use crate::error::OpsError;

pub(super) fn digest(mode: u32, uid: u32, gid: u32) -> String {
    sha256_digest(format!("jw-agent/managed-metadata/v1\0{mode:o}\0{uid}\0{gid}").as_bytes())
}

pub(super) fn validate(
    metadata: &std::fs::Metadata,
    enforce_root_ownership: bool,
) -> Result<(), OpsError> {
    #[cfg(unix)]
    {
        if enforce_root_ownership && (metadata.uid() != 0 || metadata.gid() != 0) {
            return Err(OpsError::Rejected("path_owner_violation"));
        }
        let mode = metadata.mode() & 0o7777;
        if mode & 0o133 != 0 {
            return Err(OpsError::Rejected("path_mode_violation"));
        }
    }
    Ok(())
}
