use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::{
    AssuranceView, IDEMPOTENCY_KEY_MAX_BYTES, IDEMPOTENCY_KEY_MIN_BYTES, OPERATION_SCHEMA_VERSION,
    Subject, sha256_digest, validate_digest,
};

pub const UFW_RULE_OPERATION: &str = "ufw.rule.set/v1";
pub const UFW_RULE_ID_PREFIX: &str = "ufr_";
pub const UFW_RULE_MAX_ENTRIES: usize = 256;
pub const UFW_COMMENT_PREFIX: &str = "jw-agent:";
const UFW_PROTECTED_TCP_PORTS: [u16; 3] = [22, 443, 9443];
const PLAN_ID_MAX_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UfwStatus {
    Active,
    Inactive,
    NotInstalled,
    UnsupportedPlatform,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UfwRuleMutation {
    Allow,
    Deny,
    Delete,
}

impl UfwRuleMutation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Delete => "delete",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UfwProtocol {
    Tcp,
    Udp,
}

impl UfwProtocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UfwRuleView {
    pub sequence: u16,
    pub rule_id: Option<String>,
    pub action: String,
    pub protocol: Option<UfwProtocol>,
    pub port: Option<u16>,
    pub source: String,
    pub destination: String,
    pub ipv6: bool,
    pub owned: bool,
    pub protected: bool,
    pub summary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UfwView {
    pub observed_at: String,
    pub status: UfwStatus,
    pub default_incoming: Option<String>,
    pub default_outgoing: Option<String>,
    pub rules: Vec<UfwRuleView>,
    pub state_digest: String,
    pub truncated: bool,
    pub mutation_available: bool,
    pub blocked_reason: Option<String>,
    pub assurance: AssuranceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UfwRulePlanRequest {
    pub schema_version: u16,
    pub operation_type: String,
    pub mutation: UfwRuleMutation,
    pub protocol: Option<UfwProtocol>,
    pub port: Option<u16>,
    pub source: Option<String>,
    pub rule_id: Option<String>,
    pub expected_state_digest: String,
    pub idempotency_key: String,
}

impl UfwRulePlanRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != OPERATION_SCHEMA_VERSION {
            return Err("schema_version");
        }
        if self.operation_type != UFW_RULE_OPERATION {
            return Err("operation_type");
        }
        validate_digest(&self.expected_state_digest)?;
        validate_ascii_range(
            &self.idempotency_key,
            IDEMPOTENCY_KEY_MIN_BYTES,
            IDEMPOTENCY_KEY_MAX_BYTES,
            "idempotency_key",
        )?;
        match self.mutation {
            UfwRuleMutation::Delete => {
                if self.protocol.is_some()
                    || self.port.is_some()
                    || self.source.is_some()
                    || !self.rule_id.as_deref().is_some_and(valid_rule_id)
                {
                    return Err("delete_shape");
                }
            }
            UfwRuleMutation::Allow | UfwRuleMutation::Deny => {
                let protocol = self.protocol.ok_or("protocol")?;
                let port = self.port.filter(|value| *value > 0).ok_or("port")?;
                if self.rule_id.is_some() {
                    return Err("rule_id");
                }
                if let Some(source) = self.source.as_deref() {
                    validate_source(source)?;
                }
                if self.mutation == UfwRuleMutation::Deny
                    && protocol == UfwProtocol::Tcp
                    && UFW_PROTECTED_TCP_PORTS.contains(&port)
                {
                    return Err("protected_management_rule");
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn generated_rule_id(&self) -> Option<String> {
        if self.mutation == UfwRuleMutation::Delete {
            return self.rule_id.clone();
        }
        let mut hasher = Sha256::new();
        hasher.update(b"jw-agent/ufw-rule/v1");
        hasher.update([0]);
        hasher.update(self.mutation.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(self.protocol?.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(self.port?.to_be_bytes());
        hasher.update([0]);
        let source = self.source.as_deref().map_or("any", std::convert::identity);
        hasher.update(source.as_bytes());
        let digest = sha256_digest(&hasher.finalize());
        let suffix = digest.trim_start_matches("sha256:").get(..24)?;
        Some(format!("{UFW_RULE_ID_PREFIX}{suffix}"))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UfwRuleApprovalRequest {
    pub schema_version: u16,
    pub plan_id: String,
    pub plan_hash: String,
    pub idempotency_key: String,
    pub impact_confirmed: bool,
}

impl UfwRuleApprovalRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != OPERATION_SCHEMA_VERSION || !self.impact_confirmed {
            return Err("approval");
        }
        validate_ascii_range(&self.plan_id, 1, PLAN_ID_MAX_BYTES, "plan_id")?;
        validate_digest(&self.plan_hash)?;
        validate_ascii_range(
            &self.idempotency_key,
            IDEMPOTENCY_KEY_MIN_BYTES,
            IDEMPOTENCY_KEY_MAX_BYTES,
            "idempotency_key",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UfwRulePlanView {
    pub schema_version: u16,
    pub operation_type: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub created_at: String,
    pub expires_at: String,
    pub actor: Subject,
    pub mutation: UfwRuleMutation,
    pub rule_id: String,
    pub protocol: UfwProtocol,
    pub port: u16,
    pub source: String,
    pub expected_state_digest: String,
    pub impact: Vec<String>,
    pub recovery_path: Vec<String>,
    pub assurance: AssuranceView,
}

#[must_use]
pub const fn ufw_protected_tcp_port(port: u16) -> bool {
    matches!(port, 22 | 443 | 9443)
}

fn validate_source(value: &str) -> Result<(), &'static str> {
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
    let parsed = IpAddr::from_str(address).map_err(|_| "invalid_source")?;
    if parsed.to_string() != address {
        return Err("invalid_source");
    }
    if let Some(prefix) = prefix {
        if prefix.is_empty()
            || (prefix.len() > 1 && prefix.starts_with('0'))
            || !prefix.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err("invalid_source");
        }
        let value = prefix.parse::<u8>().map_err(|_| "invalid_source")?;
        let maximum = if parsed.is_ipv4() { 32 } else { 128 };
        if value > maximum {
            return Err("invalid_source");
        }
    }
    Ok(())
}

fn valid_rule_id(value: &str) -> bool {
    value.len() == UFW_RULE_ID_PREFIX.len() + 24
        && value.starts_with(UFW_RULE_ID_PREFIX)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_ascii_range(
    value: &str,
    minimum: usize,
    maximum: usize,
    error: &'static str,
) -> Result<(), &'static str> {
    if value.len() < minimum
        || value.len() > maximum
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        Err(error)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(mutation: UfwRuleMutation, port: u16) -> UfwRulePlanRequest {
        UfwRulePlanRequest {
            schema_version: 1,
            operation_type: String::from(UFW_RULE_OPERATION),
            mutation,
            protocol: Some(UfwProtocol::Tcp),
            port: Some(port),
            source: Some(String::from("203.0.113.0/24")),
            rule_id: None,
            expected_state_digest: sha256_digest(b"state"),
            idempotency_key: String::from("0123456789abcdef"),
        }
    }

    #[test]
    fn protected_management_ports_cannot_be_denied() {
        assert_eq!(
            request(UfwRuleMutation::Deny, 22).validate(),
            Err("protected_management_rule")
        );
        assert_eq!(
            request(UfwRuleMutation::Deny, 9443).validate(),
            Err("protected_management_rule")
        );
    }

    #[test]
    fn typed_rule_id_is_stable_and_does_not_expose_source() -> Result<(), String> {
        let request = request(UfwRuleMutation::Deny, 8080);
        request.validate().map_err(str::to_owned)?;
        let first = request.generated_rule_id().ok_or("rule id missing")?;
        let second = request.generated_rule_id().ok_or("rule id missing")?;
        assert_eq!(first, second);
        assert!(!first.contains("203"));
        Ok(())
    }

    #[test]
    fn noncanonical_source_is_rejected() {
        let mut request = request(UfwRuleMutation::Allow, 8080);
        request.source = Some(String::from("203.000.113.1"));
        assert_eq!(request.validate(), Err("invalid_source"));
    }
}
