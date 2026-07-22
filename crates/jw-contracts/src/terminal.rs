use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{AssuranceView, SecretString};

pub const TERMINAL_TICKET_TTL_SECONDS: u64 = 30;
pub const TERMINAL_IDLE_TIMEOUT_SECONDS: u64 = 5 * 60;
pub const TERMINAL_MAX_LIFETIME_SECONDS: u64 = 30 * 60;
pub const TERMINAL_MAX_FRAME_BYTES: usize = 16 * 1_024;
pub const TERMINAL_MAX_OUTPUT_BUFFER_BYTES: usize = 256 * 1_024;
pub const TERMINAL_MIN_ROWS: u16 = 12;
pub const TERMINAL_MAX_ROWS: u16 = 120;
pub const TERMINAL_MIN_COLS: u16 = 40;
pub const TERMINAL_MAX_COLS: u16 = 300;

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalTicketRequest {
    #[schema(value_type = String, format = Password, max_length = 1024)]
    pub password: SecretString,
    #[schema(value_type = Option<String>, format = Password, min_length = 6, max_length = 6)]
    pub additional_auth_code: Option<SecretString>,
    pub rows: u16,
    pub cols: u16,
    pub risk_confirmed: bool,
}

impl TerminalTicketRequest {
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
        validate_terminal_size(self.rows, self.cols)?;
        if !self.risk_confirmed {
            return Err("terminal_risk_confirmation_required");
        }
        if let Some(code) = &self.additional_auth_code {
            crate::validate_totp_code(code.expose())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TerminalLimitsView {
    pub ticket_ttl_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
    pub max_frame_bytes: usize,
    pub max_output_buffer_bytes: usize,
    pub max_sessions_per_user: u16,
}

impl Default for TerminalLimitsView {
    fn default() -> Self {
        Self {
            ticket_ttl_seconds: TERMINAL_TICKET_TTL_SECONDS,
            idle_timeout_seconds: TERMINAL_IDLE_TIMEOUT_SECONDS,
            max_lifetime_seconds: TERMINAL_MAX_LIFETIME_SECONDS,
            max_frame_bytes: TERMINAL_MAX_FRAME_BYTES,
            max_output_buffer_bytes: TERMINAL_MAX_OUTPUT_BUFFER_BYTES,
            max_sessions_per_user: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TerminalCapabilityView {
    pub available: bool,
    pub reason: Option<String>,
    pub username: String,
    pub assurance: AssuranceView,
    pub limits: TerminalLimitsView,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TerminalTicketView {
    #[schema(value_type = String, format = Password)]
    pub ticket: SecretString,
    pub expires_at: String,
    pub websocket_path: String,
    pub assurance: AssuranceView,
    pub limits: TerminalLimitsView,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminalClientMessage {
    Input { data: String },
    Resize { rows: u16, cols: u16 },
}

pub fn validate_terminal_size(rows: u16, cols: u16) -> Result<(), &'static str> {
    if !(TERMINAL_MIN_ROWS..=TERMINAL_MAX_ROWS).contains(&rows) {
        return Err("terminal_rows");
    }
    if !(TERMINAL_MIN_COLS..=TERMINAL_MAX_COLS).contains(&cols) {
        return Err("terminal_cols");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::SecretString;

    use super::TerminalTicketRequest;

    #[test]
    fn ticket_request_requires_explicit_risk_and_bounded_terminal() {
        let valid = TerminalTicketRequest {
            password: SecretString::new(String::from("secret")),
            additional_auth_code: None,
            rows: 24,
            cols: 80,
            risk_confirmed: true,
        };
        assert!(valid.validate().is_ok());

        let rejected = TerminalTicketRequest {
            password: SecretString::new(String::from("secret")),
            additional_auth_code: None,
            rows: 2,
            cols: 4,
            risk_confirmed: false,
        };
        assert!(rejected.validate().is_err());
    }
}
