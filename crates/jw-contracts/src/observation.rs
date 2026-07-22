use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{AssuranceView, IngressChannel};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Ok,
    Degraded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Available,
    Unavailable,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Observed,
    Partial,
    NotInstalled,
    UnsupportedPlatform,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthView {
    pub status: HealthStatus,
    pub version: String,
    pub ingress: IngressChannel,
    pub pam: CapabilityStatus,
    pub opsd: CapabilityStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MemoryObservation {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiskObservation {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostObservation {
    pub observed_at: String,
    pub status: ObservationStatus,
    pub hostname: Option<String>,
    pub os_id: Option<String>,
    pub os_version_id: Option<String>,
    pub os_pretty_name: Option<String>,
    pub architecture: String,
    pub kernel_release: Option<String>,
    pub uptime_seconds: Option<u64>,
    pub load_average_one: Option<f64>,
    pub memory: Option<MemoryObservation>,
    pub root_disk: Option<DiskObservation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NginxSiteObservation {
    pub name: String,
    pub site_id: Option<String>,
    pub available: bool,
    pub enabled: bool,
    pub protected: bool,
    pub available_digest: Option<String>,
    pub enabled_state_digest: Option<String>,
    pub operation_type: Option<String>,
    pub operation_schema_version: Option<u16>,
    pub managed_config_resource_id: Option<String>,
    pub managed_config_operation_type: Option<String>,
    pub managed_config_schema_version: Option<u16>,
    pub assurance: AssuranceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NginxSitesView {
    pub observed_at: String,
    pub status: ObservationStatus,
    pub sites: Vec<NginxSiteObservation>,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceCategory {
    Web,
    Runtime,
    Database,
    Cache,
    Access,
    Security,
    Certificate,
    Container,
    Monitoring,
    Custom,
    System,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRuntimeState {
    Running,
    Active,
    Failed,
    Stopped,
    Transitioning,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceVisibility {
    Primary,
    Discovered,
    System,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceSupport {
    SupportedObserve,
    KnownReadOnly,
    DiscoveredReadOnly,
    SystemInternal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSummary {
    pub service_id: String,
    pub unit_name: String,
    pub display_name: String,
    pub purpose: String,
    pub category: ServiceCategory,
    pub runtime_state: ServiceRuntimeState,
    pub active_state: String,
    pub sub_state: String,
    pub unit_file_state: Option<String>,
    pub visibility: ServiceVisibility,
    pub support: ServiceSupport,
    pub read_only: bool,
    pub hidden_by_default: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServicesView {
    pub observed_at: String,
    pub status: ObservationStatus,
    pub template_profile: String,
    pub services: Vec<ServiceSummary>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityView {
    pub opsd: CapabilityStatus,
    pub read_only: bool,
    pub supported_operations: Vec<String>,
    pub forensic_lockdown: bool,
}
