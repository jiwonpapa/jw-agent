#![forbid(unsafe_code)]

mod assurance;
mod auth;
mod framing;
mod integration;
mod observation;
mod problem;
mod settings;

pub use assurance::{AssuranceLevel, AssuranceView, RollbackSupport};
pub use auth::{
    AuthFailureClass, AuthPurpose, AuthRequest, AuthResponse, AuthResult, IngressChannel,
    LoginRequest, ReauthPurpose, ReauthRequest, ReauthView, Role, SecretString, SessionView,
    Subject,
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
    MemoryObservation, NginxSiteObservation, NginxSitesView, ObservationStatus,
    OpsCapabilityRequest, OpsCapabilityResponse, ServiceSummary, ServicesView,
};
pub use problem::ProblemDetails;
pub use settings::{
    AccessSettingsView, AdditionalAuthPolicy, AdditionalAuthProviderStatus,
    UpdateAdditionalAuthRequest,
};

pub const API_VERSION: &str = "v1";
