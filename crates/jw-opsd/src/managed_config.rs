use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use jw_contracts::{
    MANAGED_CONFIG_MAX_BYTES, ManagedConfigResourceView, NGINX_CONFIG_ADAPTER_ID, NGINX_LAYOUT_ID,
    NginxSiteState, OPERATION_SCHEMA_VERSION, ServiceAction, managed_config_bytes_supported,
    nginx_config_resource_id, nginx_internal_temporary_name, nginx_site_id, sha256_digest,
};
use serde::{Deserialize, Serialize};

use crate::config::{OpsPaths, OpsPolicy};
use crate::error::OpsError;
use crate::nginx::{
    discover_site, read_available_content, safe_basename, validate_available_metadata,
    validate_root,
};
use crate::snapshot::{
    prepare_private_root, require_capacity, set_file_mode, set_mode, validate_private_directory,
};

pub(crate) const MANAGED_CONFIG_IMPACT: [&str; 3] = [
    "등록된 Nginx 설정 파일 하나의 bytes·owner·mode를 교체합니다.",
    "nginx -t가 성공한 경우에만 nginx.service reload를 실행합니다.",
    "문법·reload·active·read-back 실패 시 직전 파일을 자동 복원합니다.",
];
pub(crate) const MANAGED_CONFIG_RECOVERY_PATH: [&str; 4] = [
    "SSH로 서버에 접속합니다.",
    "JW Agent receipt의 operation ID와 snapshot 상태를 확인합니다.",
    "대상 Nginx 설정 파일을 검토하고 nginx -t를 실행합니다.",
    "검증 성공 후 nginx.service를 reload합니다.",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedConfigResource {
    pub resource_id: String,
    pub basename: String,
    pub content: String,
    pub content_digest: String,
    pub metadata_digest: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl ManagedConfigResource {
    pub fn view(
        &self,
        assurance: jw_contracts::AssuranceView,
    ) -> Result<ManagedConfigResourceView, OpsError> {
        Ok(ManagedConfigResourceView {
            schema_version: OPERATION_SCHEMA_VERSION,
            adapter_id: String::from(NGINX_CONFIG_ADAPTER_ID),
            resource_id: self.resource_id.clone(),
            display_name: self.basename.clone(),
            masked_path: format!("…/sites-available/{}", self.basename),
            content: self.content.clone(),
            content_digest: self.content_digest.clone(),
            metadata_digest: self.metadata_digest.clone(),
            max_bytes: u32::try_from(MANAGED_CONFIG_MAX_BYTES)
                .map_err(|_| OpsError::Storage(String::from("config size overflow")))?,
            allowed_service_actions: vec![ServiceAction::Reload],
            assurance,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedConfigPlanPayload {
    pub proposal_relative_path: String,
    pub proposal_digest: String,
    pub proposed_content_digest: String,
    pub current_bytes: u32,
    pub proposed_bytes: u32,
    pub added_lines: u32,
    pub removed_lines: u32,
    pub diff_summary: Vec<String>,
    pub service_action: ServiceAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalRecord {
    pub relative_path: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffStats {
    pub added_lines: u32,
    pub removed_lines: u32,
    pub summary: Vec<String>,
}

pub fn cleanup_internal_temporaries(paths: &OpsPaths) -> Result<(), OpsError> {
    if !paths.nginx_available.exists() {
        return Ok(());
    }
    validate_root(&paths.nginx_available, paths.enforce_root_ownership)?;
    let entries = std::fs::read_dir(&paths.nginx_available)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
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
        if metadata.nlink() != 1 || (paths.enforce_root_ownership && metadata.uid() != 0) {
            return Err(OpsError::ForensicLockdown);
        }
        std::fs::remove_file(entry.path())
            .map_err(|error| OpsError::Filesystem(error.to_string()))?;
        removed = true;
    }
    if removed {
        File::open(&paths.nginx_available)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    }
    Ok(())
}

pub fn discover_managed_config(
    paths: &OpsPaths,
    requested_resource_id: &str,
) -> Result<ManagedConfigResource, OpsError> {
    validate_root(&paths.nginx_available, paths.enforce_root_ownership)?;
    let entries = std::fs::read_dir(&paths.nginx_available)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    for entry_result in entries {
        let entry = entry_result.map_err(|error| OpsError::Filesystem(error.to_string()))?;
        let basename = safe_basename(&entry.file_name())?;
        if nginx_internal_temporary_name(&basename) {
            continue;
        }
        let resource_id = nginx_config_resource_id(NGINX_CONFIG_ADAPTER_ID, &basename);
        if resource_id != requested_resource_id {
            continue;
        }
        let (bytes, metadata, protected) = read_available_content(paths, &basename)?;
        validate_available_metadata(&metadata, paths.enforce_root_ownership)?;
        validate_managed_metadata(&metadata, paths.enforce_root_ownership)?;
        if protected {
            return Err(OpsError::Rejected("protected_resource"));
        }
        let site = discover_site(paths, &nginx_site_id(NGINX_LAYOUT_ID, &basename))?;
        if site.state != NginxSiteState::Enabled {
            return Err(OpsError::Rejected("resource_not_active"));
        }
        if bytes.len() > MANAGED_CONFIG_MAX_BYTES {
            return Err(OpsError::Rejected("size_limit"));
        }
        if !managed_config_bytes_supported(&bytes) {
            return Err(OpsError::Rejected("invalid_encoding"));
        }
        let content =
            String::from_utf8(bytes).map_err(|_| OpsError::Rejected("invalid_encoding"))?;
        let mode = metadata_mode(&metadata);
        let uid = metadata_uid(&metadata);
        let gid = metadata_gid(&metadata);
        let content_digest = sha256_digest(content.as_bytes());
        let metadata_digest = managed_metadata_digest(mode, uid, gid);
        return Ok(ManagedConfigResource {
            resource_id,
            basename,
            content,
            content_digest,
            metadata_digest,
            mode,
            uid,
            gid,
        });
    }
    Err(OpsError::Rejected("resource_missing"))
}

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

pub fn replace_managed_config(
    paths: &OpsPaths,
    expected: &ManagedConfigResource,
    content: &str,
) -> Result<ManagedConfigResource, OpsError> {
    let current = discover_managed_config(paths, &expected.resource_id)?;
    if current.content_digest != expected.content_digest
        || current.metadata_digest != expected.metadata_digest
    {
        return Err(OpsError::Rejected("stale_resource"));
    }
    if content.len() > MANAGED_CONFIG_MAX_BYTES {
        return Err(OpsError::Rejected("size_limit"));
    }
    if !managed_config_bytes_supported(content.as_bytes()) {
        return Err(OpsError::Rejected("invalid_encoding"));
    }
    atomic_replace(
        paths,
        &expected.basename,
        content,
        expected.mode,
        expected.uid,
        expected.gid,
    )?;
    discover_managed_config(paths, &expected.resource_id)
}

pub fn restore_managed_config(
    paths: &OpsPaths,
    resource_id: &str,
    basename: &str,
    content: &str,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<ManagedConfigResource, OpsError> {
    if nginx_config_resource_id(NGINX_CONFIG_ADAPTER_ID, basename) != resource_id {
        return Err(OpsError::Rejected("resource_identity_mismatch"));
    }
    validate_root(&paths.nginx_available, paths.enforce_root_ownership)?;
    let (_bytes, metadata, _protected) = read_available_content(paths, basename)?;
    validate_available_metadata(&metadata, paths.enforce_root_ownership)?;
    validate_managed_metadata(&metadata, paths.enforce_root_ownership)?;
    atomic_replace(paths, basename, content, mode, uid, gid)?;
    discover_managed_config(paths, resource_id)
}

fn atomic_replace(
    paths: &OpsPaths,
    basename: &str,
    content: &str,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<(), OpsError> {
    let suffix = random_suffix()?;
    let temporary = paths
        .nginx_available
        .join(format!(".jw-agent-{suffix}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if let Err(error) = set_file_mode(&file, mode & 0o7777) {
        let _cleanup = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = set_file_owner(&file, uid, gid) {
        let _cleanup = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = file
        .write_all(content.as_bytes())
        .and_then(|()| file.sync_all())
    {
        let _cleanup = std::fs::remove_file(&temporary);
        return Err(OpsError::Filesystem(error.to_string()));
    }
    let destination = paths.nginx_available.join(basename);
    if let Err(error) = std::fs::rename(&temporary, &destination) {
        let _cleanup = std::fs::remove_file(&temporary);
        return Err(OpsError::Filesystem(error.to_string()));
    }
    File::open(&paths.nginx_available)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    Ok(())
}

#[must_use]
pub fn diff_stats(current: &str, proposed: &str) -> DiffStats {
    let before: Vec<&str> = current.lines().collect();
    let after: Vec<&str> = proposed.lines().collect();
    let prefix = before
        .iter()
        .zip(after.iter())
        .take_while(|(left, right)| left == right)
        .count();
    let max_suffix = before
        .len()
        .saturating_sub(prefix)
        .min(after.len().saturating_sub(prefix));
    let suffix = (0..max_suffix)
        .take_while(|offset| {
            before[before.len().saturating_sub(1 + offset)]
                == after[after.len().saturating_sub(1 + offset)]
        })
        .count();
    let removed = &before[prefix..before.len().saturating_sub(suffix)];
    let added = &after[prefix..after.len().saturating_sub(suffix)];
    let mut summary = Vec::new();
    for line in removed.iter().take(20) {
        summary.push(format!("-{}", bounded_line(line)));
    }
    for line in added.iter().take(20) {
        summary.push(format!("+{}", bounded_line(line)));
    }
    if removed.len().saturating_add(added.len()) > summary.len() {
        summary.push(String::from("… diff preview truncated"));
    }
    DiffStats {
        added_lines: u32::try_from(added.len()).map_or(u32::MAX, std::convert::identity),
        removed_lines: u32::try_from(removed.len()).map_or(u32::MAX, std::convert::identity),
        summary,
    }
}

fn managed_metadata_digest(mode: u32, uid: u32, gid: u32) -> String {
    sha256_digest(format!("jw-agent/managed-metadata/v1\0{mode:o}\0{uid}\0{gid}").as_bytes())
}

fn validate_managed_metadata(
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

fn validate_relative_path(value: &str) -> Result<(), OpsError> {
    if value.starts_with('/')
        || value
            .split('/')
            .any(|component| matches!(component, "" | "." | ".."))
    {
        Err(OpsError::Rejected("proposal_path_rejected"))
    } else {
        Ok(())
    }
}

fn bounded_line(value: &str) -> String {
    let mut output = value.chars().take(160).collect::<String>();
    if value.chars().count() > 160 {
        output.push('…');
    }
    output
}

fn random_suffix() -> Result<String, OpsError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|error| OpsError::Storage(error.to_string()))?;
    Ok(format!("{:016x}", u64::from_le_bytes(bytes)))
}

#[cfg(unix)]
fn metadata_mode(metadata: &std::fs::Metadata) -> u32 {
    metadata.mode() & 0o7777
}

#[cfg(not(unix))]
fn metadata_mode(_metadata: &std::fs::Metadata) -> u32 {
    0o600
}

#[cfg(unix)]
fn metadata_uid(metadata: &std::fs::Metadata) -> u32 {
    metadata.uid()
}

#[cfg(not(unix))]
fn metadata_uid(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn metadata_gid(metadata: &std::fs::Metadata) -> u32 {
    metadata.gid()
}

#[cfg(not(unix))]
fn metadata_gid(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(target_os = "linux")]
fn set_file_owner(file: &File, uid: u32, gid: u32) -> Result<(), OpsError> {
    use nix::unistd::{Gid, Uid, fchown};

    let metadata = file
        .metadata()
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if metadata.uid() == uid && metadata.gid() == gid {
        return Ok(());
    }
    fchown(file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
        .map_err(|error| OpsError::Filesystem(error.to_string()))
}

#[cfg(not(target_os = "linux"))]
fn set_file_owner(_file: &File, _uid: u32, _gid: u32) -> Result<(), OpsError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use jw_contracts::{NGINX_CONFIG_ADAPTER_ID, nginx_config_resource_id};

    use crate::config::OpsPaths;

    use super::{
        cleanup_internal_temporaries, diff_stats, discover_managed_config, replace_managed_config,
    };

    #[test]
    fn discovers_and_atomically_replaces_allowlisted_resource() -> Result<(), String> {
        let root = test_root("replace")?;
        let paths = OpsPaths::for_test(&root);
        fs::create_dir_all(&paths.nginx_available).map_err(|error| error.to_string())?;
        fs::create_dir_all(&paths.nginx_enabled).map_err(|error| error.to_string())?;
        fs::write(paths.nginx_available.join("example.com"), "server {}\n")
            .map_err(|error| error.to_string())?;
        fs::write(
            paths.nginx_available.join(".jw-agent-0123456789abcdef.tmp"),
            "not a resource\n",
        )
        .map_err(|error| error.to_string())?;
        std::os::unix::fs::symlink(
            "../sites-available/example.com",
            paths.nginx_enabled.join("example.com"),
        )
        .map_err(|error| error.to_string())?;
        let id = nginx_config_resource_id(NGINX_CONFIG_ADAPTER_ID, "example.com");
        let before = discover_managed_config(&paths, &id).map_err(|error| error.to_string())?;
        let after = replace_managed_config(&paths, &before, "server { listen 8080; }\n")
            .map_err(|error| error.to_string())?;
        assert_eq!(after.content, "server { listen 8080; }\n");
        assert_ne!(before.content_digest, after.content_digest);
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn diff_summary_is_bounded_and_directional() {
        let stats = diff_stats("a\nb\nc\n", "a\nx\nc\n");
        assert_eq!(stats.removed_lines, 1);
        assert_eq!(stats.added_lines, 1);
        assert_eq!(stats.summary, vec![String::from("-b"), String::from("+x")]);
    }

    #[test]
    fn removes_only_exact_internal_temporary_files() -> Result<(), String> {
        let root = test_root("cleanup-temp")?;
        let paths = OpsPaths::for_test(&root);
        fs::create_dir_all(&paths.nginx_available).map_err(|error| error.to_string())?;
        let temporary = paths.nginx_available.join(".jw-agent-0123456789abcdef.tmp");
        let ordinary = paths.nginx_available.join(".jw-agent-example.com.tmp");
        fs::write(&temporary, "pending").map_err(|error| error.to_string())?;
        fs::write(&ordinary, "owned elsewhere").map_err(|error| error.to_string())?;
        cleanup_internal_temporaries(&paths).map_err(|error| error.to_string())?;
        assert!(!temporary.exists());
        assert!(ordinary.exists());
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    fn test_root(label: &str) -> Result<std::path::PathBuf, String> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|error| error.to_string())?;
        Ok(std::env::temp_dir().join(format!(
            "jw-opsd-managed-{label}-{}-{}",
            std::process::id(),
            u64::from_le_bytes(random)
        )))
    }
}
