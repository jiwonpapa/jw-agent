use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use jw_contracts::PASSWORD_MAX_BYTES;
use zeroize::Zeroizing;

use crate::config::DEFAULT_ASKPASS_DIRECTORY;

const ASKPASS_MODE: &str = "JW_AGENT_ASKPASS_MODE";
const ASKPASS_FIFO: &str = "JW_AGENT_ASKPASS_FIFO";

#[must_use]
pub fn requested() -> bool {
    std::env::var(ASKPASS_MODE).as_deref() == Ok("1")
}

pub fn run() -> Result<(), String> {
    if !requested() {
        return Err(String::from("askpass mode was not requested"));
    }
    let path = std::env::var(ASKPASS_FIFO)
        .map(PathBuf::from)
        .map_err(|_| String::from("askpass channel is unavailable"))?;
    validate_path(&path)?;
    let parent = path
        .parent()
        .ok_or_else(|| String::from("askpass channel is invalid"))?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| String::from("askpass channel is unavailable"))?;
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| String::from("askpass channel is unavailable"))?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.permissions().mode() & 0o077 != 0
        || !metadata.file_type().is_fifo()
        || metadata.uid() != parent_metadata.uid()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(String::from("askpass channel is invalid"));
    }
    let channel = OpenOptions::new()
        .read(true)
        .open(&path)
        .map_err(|_| String::from("askpass channel open failed"))?;
    fs::remove_file(&path).map_err(|_| String::from("askpass channel consume failed"))?;

    let limit = u64::try_from(PASSWORD_MAX_BYTES.saturating_add(2))
        .map_err(|_| String::from("askpass size limit is invalid"))?;
    let mut secret = Zeroizing::new(Vec::with_capacity(PASSWORD_MAX_BYTES.saturating_add(1)));
    channel
        .take(limit)
        .read_to_end(secret.as_mut())
        .map_err(|_| String::from("askpass channel read failed"))?;
    if secret.len() < 2
        || secret.len() > PASSWORD_MAX_BYTES.saturating_add(1)
        || secret.last() != Some(&b'\n')
    {
        return Err(String::from("askpass secret is invalid"));
    }
    secret.pop();
    if secret.contains(&b'\n') || secret.contains(&b'\r') || secret.contains(&0) {
        return Err(String::from("askpass secret is invalid"));
    }
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(secret.as_ref())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_| String::from("askpass response failed"))
}

fn validate_path(path: &Path) -> Result<(), String> {
    if path.parent() != Some(Path::new(DEFAULT_ASKPASS_DIRECTORY)) {
        return Err(String::from("askpass channel is invalid"));
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| String::from("askpass channel is invalid"))?;
    let Some(identifier) = name
        .strip_prefix("askpass-")
        .and_then(|value| value.strip_suffix(".fifo"))
    else {
        return Err(String::from("askpass channel is invalid"));
    };
    if identifier.len() != 32
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(String::from("askpass channel is invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::validate_path;

    #[test]
    fn askpass_path_is_exact_and_server_generated() {
        assert!(
            validate_path(Path::new(
                "/run/jw-agent/askpass/askpass-0123456789abcdef0123456789abcdef.fifo"
            ))
            .is_ok()
        );
        assert!(validate_path(Path::new("/tmp/askpass-deadbeef.fifo")).is_err());
        assert!(
            validate_path(Path::new(
                "/run/jw-agent/askpass/askpass-../../etc/shadow.fifo"
            ))
            .is_err()
        );
    }
}
