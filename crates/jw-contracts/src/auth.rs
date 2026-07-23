use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::ToSchema;
use zeroize::{Zeroize, Zeroizing};

pub const USERNAME_MAX_BYTES: usize = 64;
pub const PASSWORD_MAX_BYTES: usize = 1_024;
pub const REQUEST_ID_MAX_BYTES: usize = 64;
pub const REMOTE_ADDRESS_MAX_BYTES: usize = 128;
pub const PLAN_HASH_MAX_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Operator,
    Viewer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IngressChannel {
    Public,
    Recovery,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdministrativeAccessState {
    Standard,
    Administrative,
}

impl IngressChannel {
    #[must_use]
    pub const fn cookie_name(self) -> &'static str {
        match self {
            Self::Public => "__Host-jw_session",
            Self::Recovery => "jw_recovery_session",
        }
    }

    #[must_use]
    pub const fn forbidden_cookie_name(self) -> &'static str {
        match self {
            Self::Public => "jw_recovery_session",
            Self::Recovery => "__Host-jw_session",
        }
    }
}

pub struct SecretString(Zeroizing<String>);

impl SecretString {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.expose())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginRequest {
    #[schema(max_length = 64)]
    pub username: String,
    #[schema(value_type = String, format = Password, max_length = 1024)]
    pub password: SecretString,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ReauthPurpose {
    Operation {
        #[serde(rename = "planHash")]
        plan_hash: String,
    },
    SecurityPolicyChange {
        #[serde(rename = "targetPolicy")]
        target_policy: crate::AdditionalAuthPolicy,
    },
    TotpEnrollment,
    TotpRecoveryReset,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReauthRequest {
    #[schema(value_type = String, format = Password, max_length = 1024)]
    pub password: SecretString,
    pub purpose: ReauthPurpose,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdministrativeAccessRequest {
    #[schema(value_type = String, format = Password, max_length = 1024)]
    pub password: SecretString,
    #[schema(value_type = Option<String>, format = Password)]
    pub additional_auth_code: Option<SecretString>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Subject {
    pub uid: u32,
    pub username: String,
    pub role: Role,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    pub subject: Subject,
    pub ingress: IngressChannel,
    pub authenticated_at: String,
    pub idle_expires_at: String,
    pub absolute_expires_at: String,
    #[schema(format = Password)]
    pub csrf_token: String,
    pub additional_auth_policy: crate::AdditionalAuthPolicy,
    pub administrative_access: AdministrativeAccessState,
    pub administrative_expires_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReauthView {
    pub session: SessionView,
    #[schema(format = Password)]
    pub reauth_token: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthPurpose {
    Login,
    StepUp { context_digest: String },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub deadline_unix_ms: i64,
    pub username: String,
    pub password: SecretString,
    pub remote_address: Option<String>,
    pub purpose: AuthPurpose,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthFailureClass {
    Denied,
    Unsupported,
    Unavailable,
    InvalidRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuthResult {
    Authenticated {
        subject: Subject,
        account_validated_at: String,
    },
    Failed {
        class: AuthFailureClass,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthResponse {
    pub protocol_version: u16,
    pub request_id: String,
    pub result: AuthResult,
}

impl AuthRequest {
    pub fn validate(&self, now_unix_ms: i64) -> Result<(), &'static str> {
        validate_text(&self.request_id, 1, REQUEST_ID_MAX_BYTES, "request_id")?;
        validate_username(&self.username)?;
        if self.password.byte_len() == 0 || self.password.byte_len() > PASSWORD_MAX_BYTES {
            return Err("password_length");
        }
        if self.deadline_unix_ms <= now_unix_ms {
            return Err("deadline_expired");
        }
        if let Some(remote_address) = &self.remote_address {
            validate_text(
                remote_address,
                1,
                REMOTE_ADDRESS_MAX_BYTES,
                "remote_address",
            )?;
        }
        if let AuthPurpose::StepUp { context_digest } = &self.purpose {
            validate_text(context_digest, 1, PLAN_HASH_MAX_BYTES, "context_digest")?;
        }
        Ok(())
    }
}

pub fn validate_username(username: &str) -> Result<(), &'static str> {
    validate_text(username, 1, USERNAME_MAX_BYTES, "username")?;
    if username
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err("username_characters");
    }
    Ok(())
}

fn validate_text(
    value: &str,
    minimum: usize,
    maximum: usize,
    error: &'static str,
) -> Result<(), &'static str> {
    let length = value.len();
    if length < minimum || length > maximum {
        Err(error)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthPurpose, AuthRequest, SecretString};
    use crate::IPC_PROTOCOL_VERSION;

    #[test]
    fn secret_debug_is_redacted() {
        let secret = SecretString::new(String::from("do-not-print"));
        assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");
    }

    #[test]
    fn auth_request_rejects_expired_deadline() {
        let request = AuthRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("req-1"),
            deadline_unix_ms: 10,
            username: String::from("operator"),
            password: SecretString::new(String::from("secret")),
            remote_address: None,
            purpose: AuthPurpose::Login,
        };
        assert_eq!(request.validate(10), Err("deadline_expired"));
    }
}
