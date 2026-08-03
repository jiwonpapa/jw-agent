use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::validate_digest;

pub const OPERATION_COMMAND_CLASS_MAX_BYTES: usize = 64;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationCommandEvidenceView {
    pub class: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout_digest: String,
    pub stdout_truncated: bool,
    pub stderr_digest: String,
    pub stderr_truncated: bool,
}

impl OperationCommandEvidenceView {
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.class.is_empty()
            || self.class.len() > OPERATION_COMMAND_CLASS_MAX_BYTES
            || !self
                .class
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err("command_class");
        }
        if self.success && (self.timed_out || self.exit_code != Some(0)) {
            return Err("command_success");
        }
        validate_digest(&self.stdout_digest)?;
        validate_digest(&self.stderr_digest)
    }
}
