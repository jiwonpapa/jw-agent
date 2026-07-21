#![forbid(unsafe_code)]

mod assurance;
mod auth;
mod certificate;
mod framing;
mod integration;
mod observation;
mod operation;
mod problem;
mod settings;

pub use assurance::{AssuranceLevel, AssuranceView, RollbackSupport};
pub use auth::{
    AuthFailureClass, AuthPurpose, AuthRequest, AuthResponse, AuthResult, IngressChannel,
    LoginRequest, ReauthPurpose, ReauthRequest, ReauthView, Role, SecretString, SessionView,
    Subject,
};
pub use certificate::{
    CERT_FRAME_MAX_BYTES, CERTBOT_ISSUE_OPERATION, CERTBOT_MAX_DOMAINS,
    CERTBOT_RENEW_TEST_OPERATION, CertbotCommand, CertbotCommandClass, CertbotCommandEvidence,
    CertbotCommandRequest, CertbotCommandResponse, CertbotCommandResult,
    CertbotIssueApprovalRequest, CertbotIssuePlanInput, CertbotIssuePlanRequest,
    CertbotIssuePlanView, CertbotIssuePreflightEvidence, CertbotRenewTestApprovalRequest,
    CertbotRenewTestPlanRequest, CertbotRenewTestPlanView, CertificateEnvironment,
    CertificateInventoryView, CertificateSummaryView, canonical_domains, validate_domain,
};
pub use framing::{
    AUTH_FRAME_MAX_BYTES, FrameError, IPC_PROTOCOL_VERSION, OPS_FRAME_MAX_BYTES, decode_frame,
    encode_frame, read_frame, write_frame,
};
pub use integration::{
    IntegrationCatalogView, IntegrationCategory, IntegrationId, IntegrationInstallStatus,
    IntegrationLifecycleStatus, IntegrationView,
};
pub use observation::{
    CapabilityStatus, CapabilityView, DiskObservation, HealthStatus, HealthView, HostObservation,
    MemoryObservation, NginxSiteObservation, NginxSitesView, ObservationStatus, ServiceSummary,
    ServicesView,
};
pub use operation::{
    IDEMPOTENCY_KEY_MAX_BYTES, IDEMPOTENCY_KEY_MIN_BYTES, MANAGED_CONFIG_MAX_BYTES,
    MANAGED_CONFIG_OPERATION, ManagedConfigApprovalIntent, ManagedConfigApprovalRequest,
    ManagedConfigPlanRequest, ManagedConfigPlanView, ManagedConfigResourceView,
    NGINX_CONFIG_ADAPTER_ID, NGINX_LAYOUT_ID, NGINX_MANAGEMENT_MARKER,
    NGINX_MANAGEMENT_PROXY_INCLUDE, NGINX_SITE_STATE_OPERATION, NginxSiteState,
    NginxSiteStatePlanRequest, NginxSiteStatePlanView, OPERATION_SCHEMA_VERSION,
    OperationAcceptedView, OperationApprovalRequest, OperationReceiptView, OperationStage,
    OperationStageEvidenceView, OpsCapabilityResponse, OpsRejectedResponse, OpsRequest,
    OpsRequestBody, OpsResponse, OpsResponseBody, ServiceAction, managed_config_bytes_supported,
    nginx_config_resource_id, nginx_enabled_state_digest, nginx_internal_temporary_name,
    nginx_management_config, nginx_site_id, sha256_digest, validate_digest,
};
pub use problem::ProblemDetails;
pub use settings::{
    AccessSettingsView, AdditionalAuthPolicy, AdditionalAuthProviderStatus,
    UpdateAdditionalAuthRequest,
};

pub const API_VERSION: &str = "v1";
