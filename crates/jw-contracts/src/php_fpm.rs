use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::{AssuranceView, ObservationStatus, ServiceRuntimeState};

pub const PHP_FPM_CONFIG_ADAPTER_ID: &str = "php-fpm/ubuntu-24.04-8.3-v1";
pub const PHP_FPM_GLOBAL_CONFIG_ADAPTER_ID: &str = "php-fpm/ubuntu-24.04-8.3-global-v1";
pub const PHP_FPM_POOL_CONFIG_ADAPTER_ID: &str = "php-fpm/ubuntu-24.04-8.3-pool-www-v1";
pub const PHP_FPM_CONFIG_MAX_BYTES: usize = 128 * 1_024;
pub const PHP_FPM_SUPPORTED_VERSION: &str = "8.3";
pub const PHP_FPM_UNIT: &str = "php8.3-fpm.service";
pub const PHP_FPM_EXTENSION_MAX_ENTRIES: usize = 128;
const RESOURCE_ID_BYTES: usize = 18;

#[must_use]
pub fn php_fpm_config_resource_id(adapter_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(adapter_id.as_bytes());
    hasher.update([0]);
    hasher.update(b"php.ini");
    let digest = hasher.finalize();
    format!(
        "php_{}",
        URL_SAFE_NO_PAD.encode(&digest[..RESOURCE_ID_BYTES])
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PhpFpmRuntimeView {
    pub version: String,
    pub unit_name: String,
    pub runtime_state: ServiceRuntimeState,
    pub active_state: String,
    pub sub_state: String,
    pub php_ini_masked_path: String,
    pub pool_directory_masked_path: String,
    pub extension_directory_masked_path: String,
    pub extensions: Vec<String>,
    pub extension_count: u16,
    pub extensions_truncated: bool,
    pub managed_configs: Vec<PhpFpmManagedConfigView>,
    pub managed_config_resource_id: Option<String>,
    pub managed_config_operation_type: Option<String>,
    pub managed_config_schema_version: Option<u16>,
    pub blocked_reason: Option<String>,
    pub assurance: AssuranceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PhpFpmManagedConfigView {
    pub resource_id: String,
    pub operation_type: String,
    pub schema_version: u16,
    pub display_name: String,
    pub masked_path: String,
    pub available: bool,
    pub blocked_reason: Option<String>,
    pub assurance: AssuranceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PhpFpmView {
    pub observed_at: String,
    pub status: ObservationStatus,
    pub runtimes: Vec<PhpFpmRuntimeView>,
}
