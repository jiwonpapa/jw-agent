use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use jw_contracts::{
    NGINX_LAYOUT_ID, NginxSiteState, nginx_enabled_state_digest as enabled_state_digest,
    nginx_management_config, nginx_site_id as site_id, sha256_digest,
};

use crate::config::OpsPaths;
use crate::error::OpsError;

const AVAILABLE_FILE_MAX_BYTES: u64 = 1024 * 1024;
const MANAGEMENT_SITE: &str = "jw-agent-management.conf";
pub(crate) const NGINX_IMPACT: [&str; 2] = [
    "Nginx enabled symlink 상태가 변경됩니다.",
    "nginx -t 후 nginx.service reload를 실행합니다.",
];
pub(crate) const NGINX_RECOVERY_PATH: [&str; 3] = [
    "SSH로 서버에 접속합니다.",
    "JW Agent receipt와 Nginx 설정을 확인합니다.",
    "nginx -t 성공 후 Nginx를 reload합니다.",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NginxSite {
    pub site_id: String,
    pub basename: String,
    pub available_digest: String,
    pub enabled_state_digest: String,
    pub state: NginxSiteState,
    pub protected: bool,
}

pub fn discover_site(paths: &OpsPaths, requested_site_id: &str) -> Result<NginxSite, OpsError> {
    validate_root(&paths.nginx_available, paths.enforce_root_ownership)?;
    validate_root(&paths.nginx_enabled, paths.enforce_root_ownership)?;
    let entries = std::fs::read_dir(&paths.nginx_available)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    for entry_result in entries {
        let entry = entry_result.map_err(|error| OpsError::Filesystem(error.to_string()))?;
        let basename = safe_basename(&entry.file_name())?;
        let candidate_id = site_id(NGINX_LAYOUT_ID, &basename);
        if candidate_id != requested_site_id {
            continue;
        }
        let (available_digest, metadata, management_config) = read_available(paths, &basename)?;
        validate_available_metadata(&metadata, paths.enforce_root_ownership)?;
        let enabled = read_enabled(paths, &basename, &entry.path())?;
        return Ok(NginxSite {
            site_id: candidate_id,
            basename: basename.clone(),
            available_digest,
            enabled_state_digest: enabled_state_digest(enabled),
            state: if enabled {
                NginxSiteState::Enabled
            } else {
                NginxSiteState::Disabled
            },
            protected: basename == MANAGEMENT_SITE || management_config,
        });
    }
    Err(OpsError::Rejected("site_missing"))
}

pub fn set_enabled(paths: &OpsPaths, site: &NginxSite, enabled: bool) -> Result<(), OpsError> {
    let available_path = paths.nginx_available.join(&site.basename);
    let currently_enabled = read_enabled(paths, &site.basename, &available_path)?;
    if currently_enabled == enabled {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    set_enabled_linux(paths, &site.basename, enabled)?;

    #[cfg(not(target_os = "linux"))]
    set_enabled_portable(paths, &site.basename, enabled)?;

    File::open(&paths.nginx_enabled)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    let after = read_enabled(paths, &site.basename, &available_path)?;
    if after == enabled {
        Ok(())
    } else {
        Err(OpsError::Rejected("read_back_failed"))
    }
}

fn read_available(paths: &OpsPaths, basename: &str) -> Result<(String, Metadata, bool), OpsError> {
    #[cfg(target_os = "linux")]
    let mut file = open_available_linux(&paths.nginx_available, basename)?;

    #[cfg(not(target_os = "linux"))]
    let mut file = File::open(paths.nginx_available.join(basename))
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;

    let metadata = file
        .metadata()
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if metadata.len() > AVAILABLE_FILE_MAX_BYTES {
        return Err(OpsError::Rejected("available_file_too_large"));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| OpsError::Rejected("available_file_too_large"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    let protected = nginx_management_config(&bytes);
    Ok((sha256_digest(&bytes), metadata, protected))
}

#[cfg(target_os = "linux")]
fn open_available_linux(root: &Path, basename: &str) -> Result<File, OpsError> {
    use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};

    let directory = File::open(root).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC)
        .resolve(
            ResolveFlag::RESOLVE_BENEATH
                | ResolveFlag::RESOLVE_NO_SYMLINKS
                | ResolveFlag::RESOLVE_NO_MAGICLINKS
                | ResolveFlag::RESOLVE_NO_XDEV,
        );
    openat2(&directory, basename, how)
        .map(File::from)
        .map_err(|_| OpsError::Rejected("path_policy_violation"))
}

fn read_enabled(paths: &OpsPaths, basename: &str, available: &Path) -> Result<bool, OpsError> {
    let link = paths.nginx_enabled.join(basename);
    let metadata = match std::fs::symlink_metadata(&link) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(OpsError::Filesystem(error.to_string())),
    };
    if !metadata.file_type().is_symlink() {
        return Err(OpsError::Rejected("enabled_entry_not_symlink"));
    }
    let resolved_link = std::fs::canonicalize(&link)
        .map_err(|_| OpsError::Rejected("enabled_link_unresolvable"))?;
    let resolved_available = std::fs::canonicalize(available)
        .map_err(|_| OpsError::Rejected("available_unresolvable"))?;
    if resolved_link == resolved_available {
        Ok(true)
    } else {
        Err(OpsError::Rejected("enabled_link_outside_source"))
    }
}

fn validate_root(root: &Path, enforce_root_ownership: bool) -> Result<(), OpsError> {
    let metadata = std::fs::symlink_metadata(root)
        .map_err(|_| OpsError::Rejected("unsupported_nginx_layout"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(OpsError::Rejected("path_policy_violation"));
    }
    #[cfg(unix)]
    if enforce_root_ownership && metadata.uid() != 0 {
        return Err(OpsError::Rejected("path_owner_violation"));
    }
    Ok(())
}

fn validate_available_metadata(
    metadata: &Metadata,
    enforce_root_ownership: bool,
) -> Result<(), OpsError> {
    if !metadata.is_file() {
        return Err(OpsError::Rejected("available_not_regular"));
    }
    #[cfg(unix)]
    {
        if metadata.nlink() != 1 {
            return Err(OpsError::Rejected("available_hardlink_rejected"));
        }
        if enforce_root_ownership && metadata.uid() != 0 {
            return Err(OpsError::Rejected("path_owner_violation"));
        }
    }
    Ok(())
}

fn safe_basename(value: &OsStr) -> Result<String, OpsError> {
    let basename = value
        .to_str()
        .ok_or(OpsError::Rejected("site_name_not_utf8"))?;
    if basename.is_empty()
        || basename.len() > 255
        || matches!(basename, "." | "..")
        || basename.contains('/')
        || basename.contains('\0')
    {
        return Err(OpsError::Rejected("site_name_rejected"));
    }
    Ok(basename.to_owned())
}

#[cfg(target_os = "linux")]
fn set_enabled_linux(paths: &OpsPaths, basename: &str, enabled: bool) -> Result<(), OpsError> {
    use nix::unistd::{UnlinkatFlags, symlinkat, unlinkat};

    let directory = File::open(&paths.nginx_enabled)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if enabled {
        let target = PathBuf::from("../sites-available").join(basename);
        symlinkat(&target, &directory, basename)
            .map_err(|_| OpsError::Rejected("link_create_failed"))
    } else {
        unlinkat(&directory, basename, UnlinkatFlags::NoRemoveDir)
            .map_err(|_| OpsError::Rejected("link_remove_failed"))
    }
}

#[cfg(not(target_os = "linux"))]
fn set_enabled_portable(paths: &OpsPaths, basename: &str, enabled: bool) -> Result<(), OpsError> {
    use std::os::unix::fs::symlink;

    let link = paths.nginx_enabled.join(basename);
    if enabled {
        symlink(PathBuf::from("../sites-available").join(basename), link)
            .map_err(|error| OpsError::Filesystem(error.to_string()))
    } else {
        std::fs::remove_file(link).map_err(|error| OpsError::Filesystem(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use jw_contracts::{
        NGINX_LAYOUT_ID, NGINX_MANAGEMENT_MARKER, NginxSiteState,
        nginx_enabled_state_digest as enabled_state_digest, nginx_site_id as site_id,
    };

    use crate::config::OpsPaths;

    use super::{discover_site, set_enabled};

    #[test]
    fn discovers_and_toggles_only_the_hashed_site() -> Result<(), String> {
        let root = test_root("toggle")?;
        let paths = OpsPaths::for_test(&root);
        prepare(&paths, "example.com", b"server {}\n")?;
        let id = site_id(NGINX_LAYOUT_ID, "example.com");
        let before = discover_site(&paths, &id).map_err(|error| error.to_string())?;
        assert_eq!(before.state, NginxSiteState::Disabled);
        assert_eq!(before.enabled_state_digest, enabled_state_digest(false));
        set_enabled(&paths, &before, true).map_err(|error| error.to_string())?;
        let after = discover_site(&paths, &id).map_err(|error| error.to_string())?;
        assert_eq!(after.state, NginxSiteState::Enabled);
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn rejects_enabled_link_to_another_source() -> Result<(), String> {
        let root = test_root("outside")?;
        let paths = OpsPaths::for_test(&root);
        prepare(&paths, "example.com", b"server {}\n")?;
        fs::write(root.join("outside.conf"), b"server {}\n").map_err(|error| error.to_string())?;
        std::os::unix::fs::symlink(
            root.join("outside.conf"),
            paths.nginx_enabled.join("example.com"),
        )
        .map_err(|error| error.to_string())?;
        let id = site_id(NGINX_LAYOUT_ID, "example.com");
        let error = discover_site(&paths, &id).err();
        assert!(matches!(
            error,
            Some(crate::error::OpsError::Rejected(
                "enabled_link_outside_source"
            ))
        ));
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn protects_management_config_independent_of_basename() -> Result<(), String> {
        let root = test_root("protected-marker")?;
        let paths = OpsPaths::for_test(&root);
        let mut content = Vec::from(b"# " as &[u8]);
        content.extend_from_slice(NGINX_MANAGEMENT_MARKER);
        content.extend_from_slice(b"\nserver {}\n");
        prepare(&paths, "customer-selected-name", &content)?;
        let id = site_id(NGINX_LAYOUT_ID, "customer-selected-name");
        let site = discover_site(&paths, &id).map_err(|error| error.to_string())?;
        assert!(site.protected);
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    fn prepare(paths: &OpsPaths, basename: &str, content: &[u8]) -> Result<(), String> {
        fs::create_dir_all(&paths.nginx_available).map_err(|error| error.to_string())?;
        fs::create_dir_all(&paths.nginx_enabled).map_err(|error| error.to_string())?;
        fs::write(paths.nginx_available.join(basename), content).map_err(|error| error.to_string())
    }

    fn test_root(label: &str) -> Result<std::path::PathBuf, String> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|error| error.to_string())?;
        let root = std::env::temp_dir().join(format!(
            "jw-opsd-nginx-{label}-{}-{}",
            std::process::id(),
            u64::from_le_bytes(random)
        ));
        if Path::new(&root).exists() {
            return Err(String::from("test root collision"));
        }
        Ok(root)
    }
}
