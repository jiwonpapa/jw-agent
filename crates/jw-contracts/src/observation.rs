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
    pub available: bool,
    pub enabled: bool,
    pub protected: bool,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSummary {
    pub service: String,
    pub status: ObservationStatus,
    pub read_only: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServicesView {
    pub observed_at: String,
    pub services: Vec<ServiceSummary>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityView {
    pub opsd: CapabilityStatus,
    pub read_only: bool,
    pub supported_operations: Vec<String>,
    pub forensic_lockdown: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsCapabilityRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub deadline_unix_ms: i64,
}

impl OpsCapabilityRequest {
    pub fn validate(&self, now_unix_ms: i64) -> Result<(), &'static str> {
        if self.protocol_version != crate::IPC_PROTOCOL_VERSION {
            return Err("protocol_version");
        }
        if self.request_id.is_empty() || self.request_id.len() > 64 {
            return Err("request_id");
        }
        if self.deadline_unix_ms <= now_unix_ms {
            return Err("deadline_expired");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpsCapabilityResponse {
    pub protocol_version: u16,
    pub request_id: String,
    pub read_only: bool,
    pub supported_operations: Vec<String>,
    pub forensic_lockdown: bool,
}
