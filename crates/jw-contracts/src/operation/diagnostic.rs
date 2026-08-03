use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{validate_ascii_range, validate_managed_config_resource_id};

pub const MANAGED_CONFIG_DIAGNOSTIC_MAX_ENTRIES: usize = 32;
pub const MANAGED_CONFIG_DIAGNOSTIC_MAX_MESSAGE_BYTES: usize = 240;
pub const MANAGED_CONFIG_DIAGNOSTIC_MAX_RELATED_LINES: usize = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManagedConfigDiagnosticSeverity {
    Error,
    Warning,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedConfigDiagnosticView {
    pub service: String,
    pub validator: String,
    pub resource_id: Option<String>,
    pub masked_path: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub severity: ManagedConfigDiagnosticSeverity,
    pub code: String,
    pub message: String,
    pub related_changed_lines: Vec<u32>,
    #[serde(default)]
    pub cause_candidate_lines: Vec<u32>,
}

impl ManagedConfigDiagnosticView {
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        validate_ascii_range(&self.service, 1, 32, "diagnostic_service")?;
        validate_ascii_range(&self.validator, 1, 64, "diagnostic_validator")?;
        if let Some(resource_id) = &self.resource_id {
            validate_managed_config_resource_id(resource_id)?;
        }
        if let Some(masked_path) = &self.masked_path
            && (masked_path.is_empty()
                || masked_path.len() > 512
                || masked_path.bytes().any(|byte| byte.is_ascii_control()))
        {
            return Err("diagnostic_masked_path");
        }
        if self.line == Some(0) {
            return Err("diagnostic_line");
        }
        if self.column == Some(0) {
            return Err("diagnostic_column");
        }
        validate_ascii_range(&self.code, 1, 96, "diagnostic_code")?;
        if self.message.is_empty()
            || self.message.len() > MANAGED_CONFIG_DIAGNOSTIC_MAX_MESSAGE_BYTES
            || self.message.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err("diagnostic_message");
        }
        if self.related_changed_lines.len() > MANAGED_CONFIG_DIAGNOSTIC_MAX_RELATED_LINES
            || self.related_changed_lines.contains(&0)
        {
            return Err("diagnostic_related_lines");
        }
        if self.cause_candidate_lines.len() > MANAGED_CONFIG_DIAGNOSTIC_MAX_RELATED_LINES
            || self.cause_candidate_lines.contains(&0)
        {
            return Err("diagnostic_cause_candidate_lines");
        }
        Ok(())
    }
}
