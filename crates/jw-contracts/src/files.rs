use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{AssuranceView, SecretString, validate_digest};

pub const FILE_IDLE_TIMEOUT_SECONDS: u64 = 2 * 60;
pub const FILE_MAX_LIFETIME_SECONDS: u64 = 10 * 60;
pub const FILE_MAX_PATH_BYTES: usize = 1_024;
pub const FILE_MAX_COMPONENT_BYTES: usize = 255;
pub const FILE_MAX_LIST_ENTRIES: usize = 500;
pub const FILE_MAX_TEXT_BYTES: u64 = 256 * 1_024;
pub const FILE_MAX_DOWNLOAD_BYTES: u64 = 8 * 1_024 * 1_024;
pub const FILE_MAX_UPLOAD_BYTES: u64 = 8 * 1_024 * 1_024;
pub const FILE_SESSION_TOKEN_BYTES: usize = 43;
pub const FILE_UPLOAD_PLAN_TOKEN_BYTES: usize = 43;
pub const FILE_UPLOAD_PLAN_TTL_SECONDS: u64 = 2 * 60;

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
    pub max_upload_bytes: u64,
    pub upload_plan_ttl_seconds: u64,
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
            max_upload_bytes: FILE_MAX_UPLOAD_BYTES,
            upload_plan_ttl_seconds: FILE_UPLOAD_PLAN_TTL_SECONDS,
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
    pub upload_assurance: AssuranceView,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileUploadTargetState {
    Create,
    Replace,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileUploadPlanRequest {
    #[schema(value_type = String, format = Password)]
    pub session_token: SecretString,
    pub path: String,
    pub content_bytes: u64,
    pub content_digest: String,
    #[schema(value_type = String, format = Password, max_length = 1024)]
    pub password: SecretString,
    pub non_reversible_confirmed: bool,
    pub overwrite_confirmed: bool,
}

impl FileUploadPlanRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_file_path(&self.path)?;
        if self.path.is_empty()
            || self
                .path
                .rsplit('/')
                .next()
                .is_some_and(is_reserved_upload_name)
        {
            return Err("upload_path_invalid");
        }
        if self.content_bytes > FILE_MAX_UPLOAD_BYTES {
            return Err("upload_too_large");
        }
        validate_digest(&self.content_digest).map_err(|_| "upload_digest_invalid")?;
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
        if !self.non_reversible_confirmed {
            return Err("upload_non_reversible_confirmation_required");
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileUploadPlanView {
    #[schema(value_type = String, format = Password)]
    pub plan_token: SecretString,
    pub expires_at: String,
    pub path: String,
    pub target_state: FileUploadTargetState,
    pub before_digest: Option<String>,
    pub after_digest: String,
    pub content_bytes: u64,
    pub assurance: AssuranceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileUploadResultView {
    pub path: String,
    pub target_state: FileUploadTargetState,
    pub digest: String,
    pub content_bytes: u64,
    pub verification: String,
    pub assurance: AssuranceView,
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

#[must_use]
pub fn is_reserved_upload_name(name: &str) -> bool {
    name.starts_with(".jw-agent-upload-")
}

#[cfg(test)]
mod tests {
    use crate::SecretString;

    use super::{FileUploadPlanRequest, validate_file_path};

    #[test]
    fn path_is_relative_and_component_bounded() {
        assert!(validate_file_path("").is_ok());
        assert!(validate_file_path("Documents/report.txt").is_ok());
        assert!(validate_file_path("/etc/passwd").is_err());
        assert!(validate_file_path("../outside").is_err());
        assert!(validate_file_path("safe//file").is_err());
        assert!(validate_file_path("safe\nfile").is_err());
    }

    #[test]
    fn upload_plan_requires_bounded_digest_and_g1_confirmation() {
        let valid = FileUploadPlanRequest {
            session_token: SecretString::new("F".repeat(43)),
            path: String::from("Documents/report.txt"),
            content_bytes: 4,
            content_digest: String::from(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            password: SecretString::new(String::from("secret")),
            non_reversible_confirmed: true,
            overwrite_confirmed: false,
        };
        assert!(valid.validate().is_ok());

        let reserved = FileUploadPlanRequest {
            path: String::from("Documents/.jw-agent-upload-user.tmp"),
            ..valid
        };
        assert_eq!(reserved.validate(), Err("upload_path_invalid"));
    }
}
