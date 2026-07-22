#![forbid(unsafe_code)]

mod assurance;
mod auth;
mod certificate;
mod files;
mod framing;
mod integration;
mod observation;
mod operation;
mod php_fpm;
mod problem;
mod settings;
mod terminal;
mod totp;

pub use assurance::{AssuranceLevel, AssuranceView, RollbackSupport};
pub use auth::{
    AuthFailureClass, AuthPurpose, AuthRequest, AuthResponse, AuthResult, IngressChannel,
    LoginRequest, PASSWORD_MAX_BYTES, ReauthPurpose, ReauthRequest, ReauthView, Role, SecretString,
    SessionView, Subject,
};
pub use certificate::{
    CERT_FRAME_MAX_BYTES, CERTBOT_ATTACH_OPERATION, CERTBOT_ISSUE_OPERATION, CERTBOT_MAX_DOMAINS,
    CERTBOT_RENEW_TEST_OPERATION, CertbotAttachApprovalRequest, CertbotAttachPlanRequest,
    CertbotAttachPlanView, CertbotCommand, CertbotCommandClass, CertbotCommandEvidence,
    CertbotCommandRequest, CertbotCommandResponse, CertbotCommandResult,
    CertbotIssueApprovalRequest, CertbotIssuePlanInput, CertbotIssuePlanRequest,
    CertbotIssuePlanView, CertbotIssuePreflightEvidence, CertbotRenewTestApprovalRequest,
    CertbotRenewTestPlanRequest, CertbotRenewTestPlanView, CertificateEnvironment,
    CertificateInventoryView, CertificateSummaryView, canonical_domains, validate_domain,
};
pub use files::{
    FILE_IDLE_TIMEOUT_SECONDS, FILE_MAX_COMPONENT_BYTES, FILE_MAX_DOWNLOAD_BYTES,
    FILE_MAX_LIFETIME_SECONDS, FILE_MAX_LIST_ENTRIES, FILE_MAX_PATH_BYTES, FILE_MAX_TEXT_BYTES,
    FILE_MAX_UPLOAD_BYTES, FILE_SESSION_TOKEN_BYTES, FILE_UPLOAD_PLAN_TOKEN_BYTES,
    FILE_UPLOAD_PLAN_TTL_SECONDS, FileCapabilityView, FileEntryView, FileKind, FileLimitsView,
    FileListView, FilePathRequest, FileSessionCloseRequest, FileSessionRequest, FileSessionView,
    FileStatView, FileTextView, FileUploadPlanRequest, FileUploadPlanView, FileUploadResultView,
    FileUploadTargetState, is_reserved_upload_name, validate_file_path,
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
    MemoryObservation, NginxSiteObservation, NginxSitesView, ObservationStatus, ServiceCategory,
    ServiceRuntimeState, ServiceSummary, ServiceSupport, ServiceVisibility, ServicesView,
};
pub use operation::{
    IDEMPOTENCY_KEY_MAX_BYTES, IDEMPOTENCY_KEY_MIN_BYTES, MANAGED_CONFIG_MAX_BYTES,
    MANAGED_CONFIG_OPERATION, ManagedConfigApprovalIntent, ManagedConfigApprovalRequest,
    ManagedConfigPlanRequest, ManagedConfigPlanView, ManagedConfigResourceView,
    NGINX_CONFIG_ADAPTER_ID, NGINX_LAYOUT_ID, NGINX_MANAGED_CONFIG_MAX_BYTES,
    NGINX_MANAGEMENT_MARKER, NGINX_MANAGEMENT_PROXY_INCLUDE, NGINX_SITE_STATE_OPERATION,
    NginxSiteState, NginxSiteStatePlanRequest, NginxSiteStatePlanView, OPERATION_SCHEMA_VERSION,
    OperationAcceptedView, OperationApprovalRequest, OperationListView, OperationReceiptView,
    OperationStage, OperationStageEvidenceView, OpsCapabilityResponse, OpsRejectedResponse,
    OpsRequest, OpsRequestBody, OpsResponse, OpsResponseBody, ServiceAction,
    managed_config_bytes_supported, nginx_config_resource_id, nginx_enabled_state_digest,
    nginx_internal_temporary_name, nginx_management_config, nginx_site_id, sha256_digest,
    validate_digest,
};
pub use php_fpm::{
    PHP_FPM_CONFIG_ADAPTER_ID, PHP_FPM_CONFIG_MAX_BYTES, PHP_FPM_EXTENSION_MAX_ENTRIES,
    PHP_FPM_SUPPORTED_VERSION, PHP_FPM_UNIT, PhpFpmRuntimeView, PhpFpmView,
    php_fpm_config_resource_id,
};
pub use problem::ProblemDetails;
pub use settings::{
    AccessSettingsView, AdditionalAuthPolicy, AdditionalAuthProviderStatus,
    UpdateAdditionalAuthRequest,
};
pub use terminal::{
    TERMINAL_IDLE_TIMEOUT_SECONDS, TERMINAL_MAX_COLS, TERMINAL_MAX_FRAME_BYTES,
    TERMINAL_MAX_LIFETIME_SECONDS, TERMINAL_MAX_OUTPUT_BUFFER_BYTES, TERMINAL_MAX_ROWS,
    TERMINAL_MIN_COLS, TERMINAL_MIN_ROWS, TERMINAL_TICKET_TTL_SECONDS, TerminalCapabilityView,
    TerminalClientMessage, TerminalLimitsView, TerminalTicketRequest, TerminalTicketView,
    validate_terminal_size,
};
pub use totp::{
    TOTP_CODE_BYTES, TOTP_PROVIDER_ID, TOTP_RECOVERY_CODE_BYTES, TotpEnrollmentConfirmRequest,
    TotpEnrollmentConfirmView, TotpEnrollmentStartRequest, TotpEnrollmentStartView,
    TotpEnrollmentState, TotpRecoveryResetRequest, TotpVerificationRequest, TotpVerificationView,
    validate_enrollment_id, validate_totp_code,
};

pub const API_VERSION: &str = "v1";
