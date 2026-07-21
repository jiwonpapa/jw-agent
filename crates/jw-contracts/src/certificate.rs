use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    AssuranceView, IDEMPOTENCY_KEY_MAX_BYTES, IDEMPOTENCY_KEY_MIN_BYTES, IPC_PROTOCOL_VERSION,
    OPERATION_SCHEMA_VERSION, OperationApprovalRequest, Subject, validate_digest,
};

pub const CERT_FRAME_MAX_BYTES: usize = 16 * 1_024;
pub const CERTBOT_ISSUE_OPERATION: &str = "certbot.certificate.issue/v1";
pub const CERTBOT_RENEW_TEST_OPERATION: &str = "certbot.certificate.renew_test/v1";
pub const CERTBOT_MAX_DOMAINS: usize = 5;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertbotRenewTestPlanRequest {
    pub schema_version: u16,
    pub operation_type: String,
    pub expected_inventory_digest: String,
    pub idempotency_key: String,
}

impl CertbotRenewTestPlanRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != OPERATION_SCHEMA_VERSION {
            return Err("schema_version");
        }
        if self.operation_type != CERTBOT_RENEW_TEST_OPERATION {
            return Err("operation_type");
        }
        validate_digest(&self.expected_inventory_digest)?;
        validate_token(
            &self.idempotency_key,
            IDEMPOTENCY_KEY_MIN_BYTES,
            IDEMPOTENCY_KEY_MAX_BYTES,
            "idempotency_key",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertbotRenewTestPlanView {
    pub schema_version: u16,
    pub operation_type: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub created_at: String,
    pub expires_at: String,
    pub actor: Subject,
    pub inventory_digest: String,
    pub timer_enabled: bool,
    pub timer_active: bool,
    pub certificate_count: u32,
    pub impact: Vec<String>,
    pub recovery_path: Vec<String>,
    pub assurance: AssuranceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertbotRenewTestApprovalRequest {
    pub schema_version: u16,
    pub plan_id: String,
    pub plan_hash: String,
    pub idempotency_key: String,
    #[schema(format = Password)]
    pub reauth_token: String,
    #[schema(format = Password)]
    pub additional_auth_claim: Option<String>,
    pub external_effect_confirmed: bool,
}

impl CertbotRenewTestApprovalRequest {
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        OperationApprovalRequest {
            schema_version: self.schema_version,
            plan_id: self.plan_id.clone(),
            plan_hash: self.plan_hash.clone(),
            idempotency_key: self.idempotency_key.clone(),
            reauth_token: self.reauth_token.clone(),
            additional_auth_claim: self.additional_auth_claim.clone(),
        }
        .validate_shape()?;
        if self.external_effect_confirmed {
            Ok(())
        } else {
            Err("external_effect_confirmation")
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CertificateEnvironment {
    Staging,
    Production,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertbotCommandRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub deadline_unix_ms: i64,
    pub command: CertbotCommand,
}

impl CertbotCommandRequest {
    pub fn validate(&self, now_unix_ms: i64) -> Result<(), &'static str> {
        if self.protocol_version != IPC_PROTOCOL_VERSION {
            return Err("protocol_version");
        }
        validate_token(&self.request_id, 1, 64, "request_id")?;
        if self.deadline_unix_ms <= now_unix_ms {
            return Err("deadline_expired");
        }
        self.command.validate()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CertbotCommand {
    Issue {
        primary_domain: String,
        domains: Vec<String>,
        account_email: String,
        environment: CertificateEnvironment,
        tos_agreed: bool,
    },
    RenewDryRun,
}

impl CertbotCommand {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Issue {
                primary_domain,
                domains,
                account_email,
                tos_agreed,
                ..
            } => {
                if !*tos_agreed {
                    return Err("tos_not_agreed");
                }
                validate_domain(primary_domain)?;
                if domains.is_empty()
                    || domains.len() > CERTBOT_MAX_DOMAINS
                    || domains.first() != Some(primary_domain)
                {
                    return Err("domains");
                }
                let mut previous: Option<&str> = None;
                for domain in domains {
                    validate_domain(domain)?;
                    if previous.is_some_and(|value| value >= domain.as_str()) {
                        return Err("domains");
                    }
                    previous = Some(domain);
                }
                validate_email(account_email)
            }
            Self::RenewDryRun => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertbotCommandClass {
    IssueStaging,
    IssueProduction,
    RenewDryRun,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertbotCommandEvidence {
    pub command_class: CertbotCommandClass,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout_digest: String,
    pub stdout_truncated: bool,
    pub stderr_digest: String,
    pub stderr_truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertbotCommandResponse {
    pub protocol_version: u16,
    pub request_id: String,
    pub result: CertbotCommandResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CertbotCommandResult {
    Completed(CertbotCommandEvidence),
    Rejected { code: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSummaryView {
    pub primary_domain: String,
    pub sans: Vec<String>,
    pub not_after: String,
    pub fingerprint_sha256: String,
    pub certificate_path: String,
    pub private_key_present: bool,
    pub renewal_config_present: bool,
    pub webroot_managed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInventoryView {
    pub schema_version: u16,
    pub observed_at: String,
    pub certbot_installed: bool,
    pub timer_enabled: bool,
    pub timer_active: bool,
    pub inventory_digest: String,
    pub certificates: Vec<CertificateSummaryView>,
    pub problems: Vec<String>,
    pub issue_operation_type: Option<String>,
    pub renew_test_operation_type: Option<String>,
    pub assurance: AssuranceView,
}

#[must_use]
pub fn canonical_domains(primary: &str, alternatives: &[String]) -> Vec<String> {
    let mut domains = alternatives.to_vec();
    domains.retain(|domain| domain != primary);
    domains.sort();
    domains.dedup();
    domains.insert(0, primary.to_owned());
    domains
}

pub fn validate_domain(domain: &str) -> Result<(), &'static str> {
    if domain.len() < 4
        || domain.len() > 253
        || !domain.is_ascii()
        || domain.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err("invalid_domain");
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2
        || labels
            .last()
            .is_none_or(|label| !label.bytes().any(|byte| byte.is_ascii_alphabetic()))
    {
        return Err("invalid_domain");
    }
    for label in labels {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
        {
            return Err("invalid_domain");
        }
    }
    Ok(())
}

fn validate_email(email: &str) -> Result<(), &'static str> {
    if email.len() < 6 || email.len() > 254 || !email.is_ascii() {
        return Err("invalid_email");
    }
    let Some((local, domain)) = email.split_once('@') else {
        return Err("invalid_email");
    };
    if local.is_empty()
        || local.len() > 64
        || domain.contains('@')
        || !local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'.' | b'!'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                )
        })
    {
        return Err("invalid_email");
    }
    validate_domain(domain).map_err(|_| "invalid_email")
}

fn validate_token(
    value: &str,
    minimum: usize,
    maximum: usize,
    code: &'static str,
) -> Result<(), &'static str> {
    if value.len() < minimum
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Err(code)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CertbotCommand, CertbotCommandRequest, CertbotRenewTestApprovalRequest,
        CertificateEnvironment, canonical_domains, validate_domain,
    };

    #[test]
    fn domains_are_canonical_bounded_and_not_shell_input() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("xn--9t4b11yi5a.example").is_ok());
        assert_eq!(validate_domain("Example.com"), Err("invalid_domain"));
        assert_eq!(validate_domain("example.com;id"), Err("invalid_domain"));
        assert_eq!(validate_domain("127.0.0.1"), Err("invalid_domain"));
        assert_eq!(
            canonical_domains(
                "example.com",
                &[String::from("www.example.com"), String::from("example.com")]
            ),
            vec![String::from("example.com"), String::from("www.example.com")]
        );
    }

    #[test]
    fn issue_request_requires_tos_sorted_domains_and_valid_email() {
        let mut request = CertbotCommandRequest {
            protocol_version: crate::IPC_PROTOCOL_VERSION,
            request_id: String::from("cert-request-01"),
            deadline_unix_ms: 2_000,
            command: CertbotCommand::Issue {
                primary_domain: String::from("example.com"),
                domains: vec![String::from("example.com"), String::from("www.example.com")],
                account_email: String::from("admin@example.com"),
                environment: CertificateEnvironment::Staging,
                tos_agreed: true,
            },
        };
        assert!(request.validate(1_000).is_ok());
        let CertbotCommand::Issue { tos_agreed, .. } = &mut request.command else {
            return;
        };
        *tos_agreed = false;
        assert_eq!(request.validate(1_000), Err("tos_not_agreed"));
    }

    #[test]
    fn renewal_approval_requires_external_effect_confirmation() {
        let mut request = CertbotRenewTestApprovalRequest {
            schema_version: 1,
            plan_id: String::from("plan_0123456789abcdef"),
            plan_hash: crate::sha256_digest(b"plan"),
            idempotency_key: String::from("renew-key-0123456"),
            reauth_token: String::from("reauth-token-0123456789"),
            additional_auth_claim: None,
            external_effect_confirmed: false,
        };
        assert_eq!(
            request.validate_shape(),
            Err("external_effect_confirmation")
        );
        request.external_effect_confirmed = true;
        assert!(request.validate_shape().is_ok());
    }
}
