use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use utoipa::ToSchema;

use crate::{AssuranceView, Subject};

pub const NGINX_SITE_STATE_OPERATION: &str = "nginx.site_state.set/v1";
pub const NGINX_LAYOUT_ID: &str = "ubuntu-nginx-sites-v1";
pub const MANAGED_CONFIG_OPERATION: &str = "service.config_file.set/v1";
pub const NGINX_CONFIG_ADAPTER_ID: &str = "nginx/ubuntu-standard-v1";
pub const MANAGED_CONFIG_MAX_BYTES: usize = 24 * 1_024;
pub const NGINX_MANAGEMENT_MARKER: &[u8] = b"jw-agent:protected-management-v1";
pub const NGINX_MANAGEMENT_PROXY_INCLUDE: &[u8] =
    b"include /usr/share/jw-agent/nginx/proxy-common.conf;";
pub const OPERATION_SCHEMA_VERSION: u16 = 1;
pub const IDEMPOTENCY_KEY_MIN_BYTES: usize = 16;
pub const IDEMPOTENCY_KEY_MAX_BYTES: usize = 64;
pub const DIGEST_BYTES: usize = 71;
pub const PLAN_ID_MAX_BYTES: usize = 64;
pub const OPERATION_ID_MAX_BYTES: usize = 64;
const SITE_ID_BYTES: usize = 18;
const CONFIG_RESOURCE_ID_BYTES: usize = 18;

#[must_use]
pub fn nginx_internal_temporary_name(value: &str) -> bool {
    value
        .strip_prefix(".jw-agent-")
        .and_then(|name| name.strip_suffix(".tmp"))
        .is_some_and(|suffix| {
            suffix.len() == 16 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

#[must_use]
pub fn managed_config_bytes_supported(value: &[u8]) -> bool {
    std::str::from_utf8(value).is_ok()
        && value
            .iter()
            .all(|byte| !byte.is_ascii_control() || matches!(*byte, b'\n' | b'\r' | b'\t'))
}

#[must_use]
pub fn nginx_management_config(bytes: &[u8]) -> bool {
    contains_bytes(bytes, NGINX_MANAGEMENT_MARKER)
        || contains_bytes(bytes, NGINX_MANAGEMENT_PROXY_INCLUDE)
}

fn contains_bytes(value: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && value.windows(needle.len()).any(|window| window == needle)
}

#[must_use]
pub fn nginx_site_id(layout_id: &str, basename: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(layout_id.as_bytes());
    hasher.update([0]);
    hasher.update(basename.as_bytes());
    let digest = hasher.finalize();
    format!("ngs_{}", URL_SAFE_NO_PAD.encode(&digest[..SITE_ID_BYTES]))
}

#[must_use]
pub fn nginx_config_resource_id(adapter_id: &str, basename: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(adapter_id.as_bytes());
    hasher.update([0]);
    hasher.update(basename.as_bytes());
    let digest = hasher.finalize();
    format!(
        "ngc_{}",
        URL_SAFE_NO_PAD.encode(&digest[..CONFIG_RESOURCE_ID_BYTES])
    )
}

#[must_use]
pub fn nginx_enabled_state_digest(enabled: bool) -> String {
    let state: &[u8] = if enabled { b"enabled" } else { b"disabled" };
    let mut hasher = Sha256::new();
    hasher.update(b"jw-agent/nginx/enabled-state/v1");
    hasher.update([0]);
    hasher.update(state);
    sha256_from_raw(&hasher.finalize())
}

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> String {
    sha256_from_raw(&Sha256::digest(bytes))
}

fn sha256_from_raw(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(7 + bytes.len().saturating_mul(2));
    output.push_str("sha256:");
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NginxSiteState {
    Enabled,
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationStage {
    Planned,
    Approved,
    Snapshotted,
    Applying,
    Validating,
    Reloading,
    Verifying,
    RollingBack,
    Succeeded,
    RolledBack,
    RecoveryRequired,
    Rejected,
    Expired,
    CancelledBeforeApply,
}

impl OperationStage {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::RolledBack
                | Self::RecoveryRequired
                | Self::Rejected
                | Self::Expired
                | Self::CancelledBeforeApply
        )
    }

    #[must_use]
    pub const fn as_storage_value(self) -> &'static str {
        match self {
            Self::Planned => "PLANNED",
            Self::Approved => "APPROVED",
            Self::Snapshotted => "SNAPSHOTTED",
            Self::Applying => "APPLYING",
            Self::Validating => "VALIDATING",
            Self::Reloading => "RELOADING",
            Self::Verifying => "VERIFYING",
            Self::RollingBack => "ROLLING_BACK",
            Self::Succeeded => "SUCCEEDED",
            Self::RolledBack => "ROLLED_BACK",
            Self::RecoveryRequired => "RECOVERY_REQUIRED",
            Self::Rejected => "REJECTED",
            Self::Expired => "EXPIRED",
            Self::CancelledBeforeApply => "CANCELLED_BEFORE_APPLY",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NginxSiteStatePlanRequest {
    pub schema_version: u16,
    pub operation_type: String,
    pub site_id: String,
    pub target_state: NginxSiteState,
    pub expected_available_digest: String,
    pub expected_enabled_state_digest: String,
    pub idempotency_key: String,
}

impl NginxSiteStatePlanRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != OPERATION_SCHEMA_VERSION {
            return Err("schema_version");
        }
        if self.operation_type != NGINX_SITE_STATE_OPERATION {
            return Err("operation_type");
        }
        validate_identifier(&self.site_id, "ngs_", "site_id")?;
        validate_digest(&self.expected_available_digest)?;
        validate_digest(&self.expected_enabled_state_digest)?;
        validate_ascii_range(
            &self.idempotency_key,
            IDEMPOTENCY_KEY_MIN_BYTES,
            IDEMPOTENCY_KEY_MAX_BYTES,
            "idempotency_key",
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Reload,
    Restart,
}

impl ServiceAction {
    #[must_use]
    pub const fn as_storage_value(self) -> &'static str {
        match self {
            Self::Reload => "reload",
            Self::Restart => "restart",
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedConfigPlanRequest {
    pub schema_version: u16,
    pub operation_type: String,
    pub resource_id: String,
    pub expected_content_digest: String,
    pub expected_metadata_digest: String,
    #[schema(max_length = 24576)]
    pub proposed_content: String,
    pub service_action: ServiceAction,
    pub idempotency_key: String,
}

impl fmt::Debug for ManagedConfigPlanRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedConfigPlanRequest")
            .field("schema_version", &self.schema_version)
            .field("operation_type", &self.operation_type)
            .field("resource_id", &self.resource_id)
            .field("expected_content_digest", &self.expected_content_digest)
            .field("expected_metadata_digest", &self.expected_metadata_digest)
            .field("proposed_content", &"[REDACTED]")
            .field("service_action", &self.service_action)
            .field("idempotency_key", &self.idempotency_key)
            .finish()
    }
}

impl ManagedConfigPlanRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != OPERATION_SCHEMA_VERSION {
            return Err("schema_version");
        }
        if self.operation_type != MANAGED_CONFIG_OPERATION {
            return Err("operation_type");
        }
        validate_identifier(&self.resource_id, "ngc_", "resource_id")?;
        validate_digest(&self.expected_content_digest)?;
        validate_digest(&self.expected_metadata_digest)?;
        if self.proposed_content.len() > MANAGED_CONFIG_MAX_BYTES {
            return Err("size_limit");
        }
        if !managed_config_bytes_supported(self.proposed_content.as_bytes()) {
            return Err("invalid_encoding");
        }
        if nginx_management_config(self.proposed_content.as_bytes()) {
            return Err("protected_content");
        }
        if self.service_action != ServiceAction::Reload {
            return Err("unsupported_service_action");
        }
        validate_ascii_range(
            &self.idempotency_key,
            IDEMPOTENCY_KEY_MIN_BYTES,
            IDEMPOTENCY_KEY_MAX_BYTES,
            "idempotency_key",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedConfigApprovalIntent {
    pub validation_confirmed: bool,
    pub service_action_confirmed: bool,
}

impl ManagedConfigApprovalIntent {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.validation_confirmed && self.service_action_confirmed {
            Ok(())
        } else {
            Err("approval_intent")
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedConfigApprovalRequest {
    pub schema_version: u16,
    pub plan_id: String,
    pub plan_hash: String,
    pub idempotency_key: String,
    #[schema(format = Password)]
    pub reauth_token: String,
    #[schema(format = Password)]
    pub additional_auth_claim: Option<String>,
    pub approval_intent: ManagedConfigApprovalIntent,
}

impl ManagedConfigApprovalRequest {
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
        self.approval_intent.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedConfigResourceView {
    pub schema_version: u16,
    pub adapter_id: String,
    pub resource_id: String,
    pub display_name: String,
    pub masked_path: String,
    pub content: String,
    pub content_digest: String,
    pub metadata_digest: String,
    pub max_bytes: u32,
    pub allowed_service_actions: Vec<ServiceAction>,
    pub assurance: AssuranceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedConfigPlanView {
    pub schema_version: u16,
    pub operation_type: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub created_at: String,
    pub expires_at: String,
    pub actor: Subject,
    pub adapter_id: String,
    pub resource_id: String,
    pub display_name: String,
    pub masked_path: String,
    pub current_content_digest: String,
    pub proposed_content_digest: String,
    pub metadata_digest: String,
    pub current_bytes: u32,
    pub proposed_bytes: u32,
    pub added_lines: u32,
    pub removed_lines: u32,
    pub diff_summary: Vec<String>,
    pub service_action: ServiceAction,
    pub impact: Vec<String>,
    pub recovery_path: Vec<String>,
    pub assurance: AssuranceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationApprovalRequest {
    pub schema_version: u16,
    pub plan_id: String,
    pub plan_hash: String,
    pub idempotency_key: String,
    #[schema(format = Password)]
    pub reauth_token: String,
    #[schema(format = Password)]
    pub additional_auth_claim: Option<String>,
}

impl OperationApprovalRequest {
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.schema_version != OPERATION_SCHEMA_VERSION {
            return Err("schema_version");
        }
        validate_ascii_range(&self.plan_id, 1, PLAN_ID_MAX_BYTES, "plan_id")?;
        validate_digest(&self.plan_hash)?;
        validate_ascii_range(
            &self.idempotency_key,
            IDEMPOTENCY_KEY_MIN_BYTES,
            IDEMPOTENCY_KEY_MAX_BYTES,
            "idempotency_key",
        )?;
        validate_ascii_range(&self.reauth_token, 16, 256, "reauth_token")?;
        if let Some(claim) = &self.additional_auth_claim {
            validate_ascii_range(claim, 16, 256, "additional_auth_claim")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NginxSiteStatePlanView {
    pub schema_version: u16,
    pub operation_type: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub created_at: String,
    pub expires_at: String,
    pub actor: Subject,
    pub site_id: String,
    pub display_name: String,
    pub current_state: NginxSiteState,
    pub target_state: NginxSiteState,
    pub available_digest: String,
    pub enabled_state_digest: String,
    pub impact: Vec<String>,
    pub recovery_path: Vec<String>,
    pub assurance: AssuranceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperationStageEvidenceView {
    pub sequence: u64,
    pub stage: OperationStage,
    pub recorded_at: String,
    pub result_code: String,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperationReceiptView {
    pub schema_version: u16,
    pub operation_type: String,
    pub operation_id: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub actor: Subject,
    pub terminal_state: OperationStage,
    pub before_digest: String,
    pub after_digest: String,
    pub stages: Vec<OperationStageEvidenceView>,
    pub assurance: AssuranceView,
    pub rollback_result: Option<String>,
    pub recovery_path: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperationAcceptedView {
    pub schema_version: u16,
    pub operation_type: String,
    pub operation_id: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub actor: Subject,
    pub current_stage: OperationStage,
    pub event_stream: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub deadline_unix_ms: i64,
    pub body: OpsRequestBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum OpsRequestBody {
    Capabilities,
    CertificateInventory {
        actor: Subject,
    },
    PlanCertbotRenewTest {
        actor: Subject,
        plan: crate::CertbotRenewTestPlanRequest,
    },
    ApproveCertbotRenewTest {
        actor: Subject,
        plan_id: String,
        plan_hash: String,
        idempotency_key: String,
        external_effect_confirmed: bool,
    },
    ReadManagedConfig {
        actor: Subject,
        resource_id: String,
    },
    PlanNginxSiteState {
        actor: Subject,
        plan: NginxSiteStatePlanRequest,
    },
    ApproveNginxSiteState {
        actor: Subject,
        plan_id: String,
        plan_hash: String,
        idempotency_key: String,
    },
    PlanManagedConfig {
        actor: Subject,
        plan: ManagedConfigPlanRequest,
    },
    ApproveManagedConfig {
        actor: Subject,
        plan_id: String,
        plan_hash: String,
        idempotency_key: String,
        approval_intent: ManagedConfigApprovalIntent,
    },
    ExecuteOperation {
        actor: Subject,
        operation_id: String,
    },
    OperationReceipt {
        actor: Subject,
        operation_id: String,
    },
}

impl OpsRequest {
    pub fn validate(&self, now_unix_ms: i64) -> Result<(), &'static str> {
        if self.protocol_version != crate::IPC_PROTOCOL_VERSION {
            return Err("protocol_version");
        }
        validate_ascii_range(&self.request_id, 1, 64, "request_id")?;
        if self.deadline_unix_ms <= now_unix_ms {
            return Err("deadline_expired");
        }
        if matches!(
            &self.body,
            OpsRequestBody::ApproveCertbotRenewTest {
                external_effect_confirmed: false,
                ..
            }
        ) {
            return Err("external_effect_confirmation");
        }
        match &self.body {
            OpsRequestBody::Capabilities => Ok(()),
            OpsRequestBody::CertificateInventory { .. } => Ok(()),
            OpsRequestBody::PlanCertbotRenewTest { plan, .. } => plan.validate(),
            OpsRequestBody::ReadManagedConfig { resource_id, .. } => {
                validate_identifier(resource_id, "ngc_", "resource_id")
            }
            OpsRequestBody::PlanNginxSiteState { plan, .. } => plan.validate(),
            OpsRequestBody::PlanManagedConfig { plan, .. } => plan.validate(),
            OpsRequestBody::ApproveNginxSiteState {
                plan_id,
                plan_hash,
                idempotency_key,
                ..
            }
            | OpsRequestBody::ApproveManagedConfig {
                plan_id,
                plan_hash,
                idempotency_key,
                ..
            }
            | OpsRequestBody::ApproveCertbotRenewTest {
                plan_id,
                plan_hash,
                idempotency_key,
                ..
            } => {
                validate_ascii_range(plan_id, 1, PLAN_ID_MAX_BYTES, "plan_id")?;
                validate_digest(plan_hash)?;
                validate_ascii_range(
                    idempotency_key,
                    IDEMPOTENCY_KEY_MIN_BYTES,
                    IDEMPOTENCY_KEY_MAX_BYTES,
                    "idempotency_key",
                )
            }
            OpsRequestBody::ExecuteOperation { operation_id, .. }
            | OpsRequestBody::OperationReceipt { operation_id, .. } => {
                validate_ascii_range(operation_id, 1, OPERATION_ID_MAX_BYTES, "operation_id")
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsResponse {
    pub protocol_version: u16,
    pub request_id: String,
    pub body: OpsResponseBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OpsResponseBody {
    Capabilities(OpsCapabilityResponse),
    CertificateInventory(crate::CertificateInventoryView),
    CertbotRenewTestPlan(crate::CertbotRenewTestPlanView),
    ManagedConfigResource(ManagedConfigResourceView),
    NginxSiteStatePlan(NginxSiteStatePlanView),
    ManagedConfigPlan(ManagedConfigPlanView),
    OperationReceipt(OperationReceiptView),
    Rejected(OpsRejectedResponse),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsCapabilityResponse {
    pub read_only: bool,
    pub supported_operations: Vec<String>,
    pub forensic_lockdown: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsRejectedResponse {
    pub code: String,
}

fn validate_identifier(value: &str, prefix: &str, error: &'static str) -> Result<(), &'static str> {
    if value.len() < prefix.len().saturating_add(8)
        || value.len() > 64
        || !value.starts_with(prefix)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Err(error)
    } else {
        Ok(())
    }
}

pub fn validate_digest(value: &str) -> Result<(), &'static str> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err("digest");
    };
    if value.len() != DIGEST_BYTES
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Err("digest")
    } else {
        Ok(())
    }
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
    use super::{
        MANAGED_CONFIG_OPERATION, ManagedConfigApprovalIntent, ManagedConfigPlanRequest,
        NGINX_CONFIG_ADAPTER_ID, NGINX_LAYOUT_ID, NGINX_SITE_STATE_OPERATION, NginxSiteState,
        NginxSiteStatePlanRequest, OPERATION_SCHEMA_VERSION, OperationStage, ServiceAction,
        nginx_config_resource_id, nginx_enabled_state_digest, nginx_management_config,
        nginx_site_id, validate_digest,
    };

    #[test]
    fn terminal_stage_contract_is_explicit() {
        assert!(OperationStage::Succeeded.is_terminal());
        assert!(OperationStage::RolledBack.is_terminal());
        assert!(!OperationStage::Applying.is_terminal());
    }

    #[test]
    fn management_config_detection_accepts_marker_or_proxy_include() {
        assert!(nginx_management_config(
            b"# jw-agent:protected-management-v1\nserver {}\n"
        ));
        assert!(nginx_management_config(
            b"server { include /usr/share/jw-agent/nginx/proxy-common.conf; }\n"
        ));
        assert!(!nginx_management_config(b"server {}\n"));
    }

    #[test]
    fn internal_temporary_name_is_exact_and_not_a_site() {
        assert!(super::nginx_internal_temporary_name(
            ".jw-agent-0123456789abcdef.tmp"
        ));
        assert!(!super::nginx_internal_temporary_name(
            ".jw-agent-example.com.tmp"
        ));
        assert!(!super::nginx_internal_temporary_name("example.com"));
    }

    #[test]
    fn managed_config_text_allows_layout_whitespace_but_rejects_controls() {
        assert!(super::managed_config_bytes_supported(
            b"server {\n\tlisten 80;\r\n}\n"
        ));
        assert!(!super::managed_config_bytes_supported(b"server {}\x07\n"));
        assert!(!super::managed_config_bytes_supported(&[0xff]))
    }

    #[test]
    fn plan_rejects_path_like_site_identity() {
        let request = NginxSiteStatePlanRequest {
            schema_version: OPERATION_SCHEMA_VERSION,
            operation_type: String::from(NGINX_SITE_STATE_OPERATION),
            site_id: String::from("../../etc/passwd"),
            target_state: NginxSiteState::Enabled,
            expected_available_digest: valid_digest(),
            expected_enabled_state_digest: valid_digest(),
            idempotency_key: String::from("0123456789abcdef"),
        };
        assert_eq!(request.validate(), Err("site_id"));
    }

    #[test]
    fn digest_is_lowercase_domain_tagged_sha256() {
        assert!(validate_digest(&valid_digest()).is_ok());
        assert_eq!(
            validate_digest(
                "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            Err("digest")
        );
    }

    #[test]
    fn nginx_identity_vectors_are_stable() {
        assert_eq!(
            nginx_site_id(NGINX_LAYOUT_ID, "example.com"),
            "ngs_tQ9Xog5xTe1fh8OsTIdiw6xr"
        );
        assert_eq!(
            nginx_enabled_state_digest(false),
            "sha256:601cad563455d69a3920b52c6936bb25fc48876bb62255b09b549b823bf0550c"
        );
    }

    #[test]
    fn managed_config_request_is_typed_bounded_and_debug_redacted() {
        let mut request = ManagedConfigPlanRequest {
            schema_version: OPERATION_SCHEMA_VERSION,
            operation_type: String::from(MANAGED_CONFIG_OPERATION),
            resource_id: nginx_config_resource_id(NGINX_CONFIG_ADAPTER_ID, "example.com"),
            expected_content_digest: valid_digest(),
            expected_metadata_digest: valid_digest(),
            proposed_content: String::from("server { listen 8080; }\n"),
            service_action: ServiceAction::Reload,
            idempotency_key: String::from("managed-key-0001"),
        };
        assert!(request.validate().is_ok());
        let rendered = format!("{request:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("listen 8080"));

        request.service_action = ServiceAction::Restart;
        assert_eq!(request.validate(), Err("unsupported_service_action"));
        request.service_action = ServiceAction::Reload;
        request.proposed_content = String::from("# jw-agent:protected-management-v1\n");
        assert_eq!(request.validate(), Err("protected_content"));
    }

    #[test]
    fn managed_config_approval_requires_both_explicit_intents() {
        assert_eq!(
            ManagedConfigApprovalIntent {
                validation_confirmed: true,
                service_action_confirmed: false,
            }
            .validate(),
            Err("approval_intent")
        );
        assert!(
            ManagedConfigApprovalIntent {
                validation_confirmed: true,
                service_action_confirmed: true,
            }
            .validate()
            .is_ok()
        );
    }

    fn valid_digest() -> String {
        format!("sha256:{}", "0".repeat(64))
    }
}
