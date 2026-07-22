use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::SecretString;

pub const TOTP_PROVIDER_ID: &str = "totp/v1";
pub const TOTP_CODE_BYTES: usize = 6;
pub const TOTP_RECOVERY_CODE_BYTES: usize = 31;

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TotpEnrollmentStartRequest {
    #[schema(value_type = String, format = Password, max_length = 256)]
    pub reauth_token: SecretString,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpEnrollmentStartView {
    pub enrollment_id: String,
    pub provider_id: String,
    #[schema(value_type = String, format = Password)]
    pub manual_key: SecretString,
    #[schema(value_type = String, format = Password)]
    pub otpauth_uri: SecretString,
    #[schema(value_type = Vec<String>, format = Password)]
    pub recovery_codes: Vec<SecretString>,
    pub expires_at: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TotpEnrollmentConfirmRequest {
    pub enrollment_id: String,
    #[schema(value_type = String, format = Password, min_length = 6, max_length = 6)]
    pub code: SecretString,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TotpEnrollmentState {
    AwaitingNextCode,
    Ready,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpEnrollmentConfirmView {
    pub state: TotpEnrollmentState,
    pub provider_id: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TotpVerificationRequest {
    #[schema(value_type = String, format = Password, max_length = 256)]
    pub reauth_token: SecretString,
    pub plan_hash: String,
    #[schema(value_type = String, format = Password, min_length = 6, max_length = 6)]
    pub code: SecretString,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpVerificationView {
    #[schema(value_type = String, format = Password)]
    pub additional_auth_claim: SecretString,
    pub expires_at: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TotpRecoveryResetRequest {
    #[schema(value_type = String, format = Password, max_length = 256)]
    pub reauth_token: SecretString,
    #[schema(value_type = String, format = Password, max_length = 31)]
    pub recovery_code: SecretString,
}

pub fn validate_totp_code(code: &str) -> Result<(), &'static str> {
    if code.len() == TOTP_CODE_BYTES && code.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(())
    } else {
        Err("additional_authentication_rejected")
    }
}

pub fn validate_enrollment_id(value: &str) -> Result<(), &'static str> {
    if value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("totp_enrollment_rejected")
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_enrollment_id, validate_totp_code};

    #[test]
    fn totp_inputs_are_exactly_bounded() {
        assert!(validate_totp_code("123456").is_ok());
        assert!(validate_totp_code("12345").is_err());
        assert!(validate_totp_code("12345a").is_err());
        assert!(validate_enrollment_id("0123456789abcdef0123456789abcdef").is_ok());
        assert!(validate_enrollment_id("../enrollment").is_err());
    }
}
