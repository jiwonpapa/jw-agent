use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{AssuranceView, SecretString};

pub const FILE_IDLE_TIMEOUT_SECONDS: u64 = 2 * 60;
pub const FILE_MAX_LIFETIME_SECONDS: u64 = 10 * 60;
pub const FILE_MAX_PATH_BYTES: usize = 1_024;
pub const FILE_MAX_COMPONENT_BYTES: usize = 255;
pub const FILE_MAX_LIST_ENTRIES: usize = 500;
pub const FILE_MAX_TEXT_BYTES: u64 = 256 * 1_024;
pub const FILE_MAX_DOWNLOAD_BYTES: u64 = 8 * 1_024 * 1_024;
pub const FILE_SESSION_TOKEN_BYTES: usize = 43;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileLimitsView {
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
    pub max_path_bytes: usize,
    pub max_component_bytes: usize,
    pub max_list_entries: usize,
    pub max_text_bytes: u64,
    pub max_download_bytes: u64,
    pub max_sessions_per_user: u16,
}

impl Default for FileLimitsView {
    fn default() -> Self {
        Self {
            idle_timeout_seconds: FILE_IDLE_TIMEOUT_SECONDS,
            max_lifetime_seconds: FILE_MAX_LIFETIME_SECONDS,
            max_path_bytes: FILE_MAX_PATH_BYTES,
            max_component_bytes: FILE_MAX_COMPONENT_BYTES,
            max_list_entries: FILE_MAX_LIST_ENTRIES,
            max_text_bytes: FILE_MAX_TEXT_BYTES,
            max_download_bytes: FILE_MAX_DOWNLOAD_BYTES,
            max_sessions_per_user: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileCapabilityView {
    pub available: bool,
    pub reason: Option<String>,
    pub username: String,
    pub root_label: String,
    pub assurance: AssuranceView,
    pub limits: FileLimitsView,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileSessionRequest {
    #[schema(value_type = String, format = Password, max_length = 1024)]
    pub password: SecretString,
    pub read_only_confirmed: bool,
}

impl FileSessionRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.password.byte_len() == 0
            || self.password.byte_len() > crate::auth::PASSWORD_MAX_BYTES
        {
            return Err("password_length");
        }
        if self
            .password
            .expose()
            .bytes()
            .any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
        {
            return Err("password_characters");
        }
        if !self.read_only_confirmed {
            return Err("file_read_only_confirmation_required");
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileSessionView {
    #[schema(value_type = String, format = Password)]
    pub session_token: SecretString,
    pub expires_at: String,
    pub root_label: String,
    pub assurance: AssuranceView,
    pub limits: FileLimitsView,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilePathRequest {
    #[schema(value_type = String, format = Password)]
    pub session_token: SecretString,
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileSessionCloseRequest {
    #[schema(value_type = String, format = Password)]
    pub session_token: SecretString,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Directory,
    Regular,
    SymbolicLink,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileEntryView {
    pub name: String,
    pub path: String,
    pub kind: FileKind,
    pub size_bytes: Option<u64>,
    pub modified_at_unix_seconds: Option<u32>,
    pub permissions: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileListView {
    pub path: String,
    pub entries: Vec<FileEntryView>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileStatView {
    pub path: String,
    pub kind: FileKind,
    pub size_bytes: Option<u64>,
    pub modified_at_unix_seconds: Option<u32>,
    pub permissions: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileTextView {
    pub path: String,
    pub content: String,
    pub size_bytes: u64,
    pub digest: String,
    pub line_ending: String,
}

pub fn validate_file_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        return Ok(());
    }
    if path.starts_with('/') || path.len() > FILE_MAX_PATH_BYTES {
        return Err("path_invalid");
    }
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > FILE_MAX_COMPONENT_BYTES
            || component
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control())
        {
            return Err("path_invalid");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_file_path;

    #[test]
    fn path_is_relative_and_component_bounded() {
        assert!(validate_file_path("").is_ok());
        assert!(validate_file_path("Documents/report.txt").is_ok());
        assert!(validate_file_path("/etc/passwd").is_err());
        assert!(validate_file_path("../outside").is_err());
        assert!(validate_file_path("safe//file").is_err());
        assert!(validate_file_path("safe\nfile").is_err());
    }
}
