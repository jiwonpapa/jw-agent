use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::ObservationStatus;

pub const MANAGED_SERVICE_CONFIG_MAX_ENTRIES: usize = 256;
pub const MANAGED_SERVICE_CONFIG_MAX_DEPTH: usize = 5;

pub const NGINX_TREE_CONFIG_ADAPTER_ID: &str = "nginx/ubuntu-24.04-tree-v1";
pub const NGINX_TREE_RESOURCE_PREFIX: &str = "ngf_";
pub const NGINX_MAIN_CONFIG_ADAPTER_ID: &str = "nginx/ubuntu-24.04-main-v1";
pub const NGINX_CONF_D_CONFIG_ADAPTER_ID: &str = "nginx/ubuntu-24.04-conf-d-v1";
pub const NGINX_MAIN_RESOURCE_PREFIX: &str = "ngm_";
pub const NGINX_CONF_D_RESOURCE_PREFIX: &str = "ngd_";

pub const APACHE_TREE_CONFIG_ADAPTER_ID: &str = "apache/ubuntu-24.04-tree-v1";
pub const APACHE_TREE_RESOURCE_PREFIX: &str = "apf_";
pub const APACHE_MAIN_CONFIG_ADAPTER_ID: &str = "apache/ubuntu-24.04-main-v1";
pub const APACHE_PORTS_CONFIG_ADAPTER_ID: &str = "apache/ubuntu-24.04-ports-v1";
pub const APACHE_CONF_CONFIG_ADAPTER_ID: &str = "apache/ubuntu-24.04-conf-enabled-v1";
pub const APACHE_SITE_CONFIG_ADAPTER_ID: &str = "apache/ubuntu-24.04-site-enabled-v1";
pub const APACHE_MAIN_RESOURCE_PREFIX: &str = "apm_";
pub const APACHE_PORTS_RESOURCE_PREFIX: &str = "app_";
pub const APACHE_CONF_RESOURCE_PREFIX: &str = "apc_";
pub const APACHE_SITE_RESOURCE_PREFIX: &str = "aps_";

const RESOURCE_ID_BYTES: usize = 18;

#[must_use]
pub fn managed_service_config_resource_id(
    prefix: &str,
    adapter_id: &str,
    logical_name: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(adapter_id.as_bytes());
    hasher.update([0]);
    hasher.update(logical_name.as_bytes());
    let digest = hasher.finalize();
    format!(
        "{prefix}{}",
        URL_SAFE_NO_PAD.encode(&digest[..RESOURCE_ID_BYTES])
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedServiceConfigView {
    pub resource_id: String,
    pub operation_type: String,
    pub schema_version: u16,
    pub display_name: String,
    pub masked_path: String,
    pub relative_path: String,
    pub loaded: bool,
    pub service_active: bool,
    pub available: bool,
    pub blocked_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedServiceConfigInventoryView {
    pub observed_at: String,
    pub status: ObservationStatus,
    pub service_key: String,
    pub unit_name: String,
    pub display_name: String,
    pub configs: Vec<ManagedServiceConfigView>,
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::{
        NGINX_CONF_D_CONFIG_ADAPTER_ID, NGINX_CONF_D_RESOURCE_PREFIX,
        managed_service_config_resource_id,
    };

    #[test]
    fn stable_resource_ids_do_not_expose_paths_and_distinguish_files() {
        let first = managed_service_config_resource_id(
            NGINX_CONF_D_RESOURCE_PREFIX,
            NGINX_CONF_D_CONFIG_ADAPTER_ID,
            "cache.conf",
        );
        let second = managed_service_config_resource_id(
            NGINX_CONF_D_RESOURCE_PREFIX,
            NGINX_CONF_D_CONFIG_ADAPTER_ID,
            "proxy.conf",
        );

        assert!(first.starts_with(NGINX_CONF_D_RESOURCE_PREFIX));
        assert!(!first.contains("cache"));
        assert_ne!(first, second);
    }
}
