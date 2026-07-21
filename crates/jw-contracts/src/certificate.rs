use std::fmt;
use std::net::IpAddr;

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

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertbotIssuePlanRequest {
    pub schema_version: u16,
    pub operation_type: String,
    pub primary_domain: String,
    pub alternative_domains: Vec<String>,
    pub account_email: String,
    pub environment: CertificateEnvironment,
    pub site_id: String,
    pub expected_site_digest: String,
    pub expected_inventory_digest: String,
    pub tos_agreed: bool,
    pub idempotency_key: String,
}

impl fmt::Debug for CertbotIssuePlanRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertbotIssuePlanRequest")
            .field("schema_version", &self.schema_version)
            .field("operation_type", &self.operation_type)
            .field("primary_domain", &self.primary_domain)
            .field("alternative_domains", &self.alternative_domains)
            .field("account_email", &"[REDACTED]")
            .field("environment", &self.environment)
            .field("site_id", &self.site_id)
            .field("expected_site_digest", &self.expected_site_digest)
            .field("expected_inventory_digest", &self.expected_inventory_digest)
            .field("tos_agreed", &self.tos_agreed)
            .field("idempotency_key", &self.idempotency_key)
            .finish()
    }
}

impl CertbotIssuePlanRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != OPERATION_SCHEMA_VERSION {
            return Err("schema_version");
        }
        if self.operation_type != CERTBOT_ISSUE_OPERATION {
            return Err("operation_type");
        }
        if !self.tos_agreed {
            return Err("tos_not_agreed");
        }
        validate_domain(&self.primary_domain)?;
        if self.alternative_domains.len() >= CERTBOT_MAX_DOMAINS {
            return Err("domains");
        }
        let domains = canonical_domains(&self.primary_domain, &self.alternative_domains);
        if domains.len() != self.alternative_domains.len().saturating_add(1)
            || domains.get(1..) != Some(self.alternative_domains.as_slice())
        {
            return Err("domains");
        }
        for domain in &self.alternative_domains {
            validate_domain(domain)?;
        }
        validate_email(&self.account_email)?;
        validate_token(&self.site_id, 12, 64, "site_id")?;
        if !self.site_id.starts_with("ngs_") {
            return Err("site_id");
        }
        validate_digest(&self.expected_site_digest)?;
        validate_digest(&self.expected_inventory_digest)?;
        validate_token(
            &self.idempotency_key,
            IDEMPOTENCY_KEY_MIN_BYTES,
            IDEMPOTENCY_KEY_MAX_BYTES,
            "idempotency_key",
        )
    }

    #[must_use]
    pub fn domains(&self) -> Vec<String> {
        canonical_domains(&self.primary_domain, &self.alternative_domains)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertbotIssuePreflightEvidence {
    pub observed_at_unix_ms: i64,
    pub resolved_addresses: Vec<String>,
    pub expected_addresses: Vec<String>,
    pub local_port_80_reachable: bool,
    pub local_port_443_reachable: bool,
}

impl CertbotIssuePreflightEvidence {
    pub fn validate(&self, now_unix_ms: i64) -> Result<(), &'static str> {
        if self.observed_at_unix_ms > now_unix_ms
            || now_unix_ms.saturating_sub(self.observed_at_unix_ms) > 60_000
        {
            return Err("preflight_stale");
        }
        validate_ip_set(&self.resolved_addresses)?;
        validate_ip_set(&self.expected_addresses)?;
        if self.resolved_addresses != self.expected_addresses {
            return Err("dns_mismatch");
        }
        if !self.local_port_80_reachable {
            return Err("challenge_unreachable");
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertbotIssuePlanInput {
    pub request: CertbotIssuePlanRequest,
    pub preflight: CertbotIssuePreflightEvidence,
}

impl fmt::Debug for CertbotIssuePlanInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertbotIssuePlanInput")
            .field("request", &self.request)
            .field("preflight", &self.preflight)
            .finish()
    }
}

impl CertbotIssuePlanInput {
    pub fn validate(&self, now_unix_ms: i64) -> Result<(), &'static str> {
        self.request.validate()?;
        self.preflight.validate(now_unix_ms)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertbotIssuePlanView {
    pub schema_version: u16,
    pub operation_type: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub created_at: String,
    pub expires_at: String,
    pub actor: Subject,
    pub primary_domain: String,
    pub domains: Vec<String>,
    pub masked_account_email: String,
    pub environment: CertificateEnvironment,
    pub site_id: String,
    pub inventory_digest: String,
    pub site_digest: String,
    pub resolved_addresses: Vec<String>,
    pub local_port_80_reachable: bool,
    pub local_port_443_reachable: bool,
    pub staging_evidence_valid: bool,
    pub impact: Vec<String>,
    pub recovery_path: Vec<String>,
    pub assurance: AssuranceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertbotIssueApprovalRequest {
    pub schema_version: u16,
    pub plan_id: String,
    pub plan_hash: String,
    pub idempotency_key: String,
    #[schema(format = Password)]
    pub reauth_token: String,
    #[schema(format = Password)]
    pub additional_auth_claim: Option<String>,
    pub external_effect_confirmed: bool,
    pub local_attach_deferred_confirmed: bool,
}

impl CertbotIssueApprovalRequest {
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
        if !self.external_effect_confirmed {
            return Err("external_effect_confirmation");
        }
        if !self.local_attach_deferred_confirmed {
            return Err("local_attach_deferred_confirmation");
        }
        Ok(())
    }
}

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

fn validate_ip_set(addresses: &[String]) -> Result<(), &'static str> {
    if addresses.is_empty() || addresses.len() > 8 {
        return Err("dns_addresses");
    }
    let mut previous: Option<IpAddr> = None;
    for address in addresses {
        let parsed = address.parse::<IpAddr>().map_err(|_| "dns_addresses")?;
        if previous.is_some_and(|value| value >= parsed) {
            return Err("dns_addresses");
        }
        previous = Some(parsed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CertbotCommand, CertbotCommandRequest, CertbotIssueApprovalRequest, CertbotIssuePlanInput,
        CertbotIssuePlanRequest, CertbotIssuePreflightEvidence, CertbotRenewTestApprovalRequest,
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

    #[test]
    fn issue_plan_is_canonical_and_keeps_email_out_of_debug() {
        let request = CertbotIssuePlanRequest {
            schema_version: 1,
            operation_type: String::from(super::CERTBOT_ISSUE_OPERATION),
            primary_domain: String::from("example.com"),
            alternative_domains: vec![String::from("www.example.com")],
            account_email: String::from("private-owner@example.com"),
            environment: CertificateEnvironment::Staging,
            site_id: String::from("ngs_0123456789abcdef"),
            expected_site_digest: crate::sha256_digest(b"site"),
            expected_inventory_digest: crate::sha256_digest(b"inventory"),
            tos_agreed: true,
            idempotency_key: String::from("issue-key-0123456"),
        };
        let input = CertbotIssuePlanInput {
            request: request.clone(),
            preflight: CertbotIssuePreflightEvidence {
                observed_at_unix_ms: 1_000,
                resolved_addresses: vec![String::from("192.0.2.10")],
                expected_addresses: vec![String::from("192.0.2.10")],
                local_port_80_reachable: true,
                local_port_443_reachable: true,
            },
        };
        assert!(input.validate(1_001).is_ok());
        assert_eq!(
            request.domains(),
            vec![String::from("example.com"), String::from("www.example.com")]
        );
        assert!(!format!("{request:?}").contains("private-owner@example.com"));

        let mut non_canonical = request;
        non_canonical.alternative_domains = vec![
            String::from("www.example.com"),
            String::from("api.example.com"),
        ];
        assert_eq!(non_canonical.validate(), Err("domains"));
    }

    #[test]
    fn issue_approval_requires_both_irreversible_boundaries() {
        let mut request = CertbotIssueApprovalRequest {
            schema_version: 1,
            plan_id: String::from("plan_0123456789abcdef"),
            plan_hash: crate::sha256_digest(b"plan"),
            idempotency_key: String::from("issue-key-0123456"),
            reauth_token: String::from("reauth-token-0123456789"),
            additional_auth_claim: None,
            external_effect_confirmed: false,
            local_attach_deferred_confirmed: false,
        };
        assert_eq!(
            request.validate_shape(),
            Err("external_effect_confirmation")
        );
        request.external_effect_confirmed = true;
        assert_eq!(
            request.validate_shape(),
            Err("local_attach_deferred_confirmation")
        );
        request.local_attach_deferred_confirmed = true;
        assert!(request.validate_shape().is_ok());
    }
}
