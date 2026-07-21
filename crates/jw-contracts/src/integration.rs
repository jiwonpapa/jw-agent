use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{AssuranceView, ObservationStatus};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationId {
    VpsGuard,
    G7Installer,
    G7MediaBooster,
    G7TelegramDevops,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationCategory {
    Security,
    Provisioning,
    Media,
    Notification,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationLifecycleStatus {
    Unknown,
    NotInstalled,
    NeedsSetup,
    Installed,
    Partial,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationInstallStatus {
    Blocked,
    Available,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IntegrationView {
    pub id: IntegrationId,
    pub name: String,
    pub summary: String,
    pub category: IntegrationCategory,
    pub lifecycle_status: IntegrationLifecycleStatus,
    pub install_status: IntegrationInstallStatus,
    pub detected_components: Vec<String>,
    pub install_blockers: Vec<String>,
    pub resource_claims: Vec<String>,
    pub setup_steps: Vec<String>,
    pub source_url: String,
    pub assurance: AssuranceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IntegrationCatalogView {
    pub observed_at: String,
    pub status: ObservationStatus,
    pub entries: Vec<IntegrationView>,
}
