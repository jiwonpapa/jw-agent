use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use jw_contracts::{
    APACHE_CONF_CONFIG_ADAPTER_ID, APACHE_CONF_RESOURCE_PREFIX, APACHE_MAIN_CONFIG_ADAPTER_ID,
    APACHE_MAIN_RESOURCE_PREFIX, APACHE_PORTS_CONFIG_ADAPTER_ID, APACHE_PORTS_RESOURCE_PREFIX,
    APACHE_SITE_CONFIG_ADAPTER_ID, APACHE_SITE_RESOURCE_PREFIX, APACHE_TREE_CONFIG_ADAPTER_ID,
    APACHE_TREE_RESOURCE_PREFIX, AssuranceLevel, AssuranceView, MANAGED_CONFIG_MAX_BYTES,
    ManagedConfigResourceView, NGINX_CONF_D_CONFIG_ADAPTER_ID, NGINX_CONF_D_RESOURCE_PREFIX,
    NGINX_CONFIG_ADAPTER_ID, NGINX_LAYOUT_ID, NGINX_MAIN_CONFIG_ADAPTER_ID,
    NGINX_MAIN_RESOURCE_PREFIX, NGINX_MANAGED_CONFIG_MAX_BYTES, NGINX_TREE_CONFIG_ADAPTER_ID,
    NGINX_TREE_RESOURCE_PREFIX, NginxSiteState, OPERATION_SCHEMA_VERSION,
    PHP_FPM_CONFIG_ADAPTER_ID, PHP_FPM_CONFIG_MAX_BYTES, PHP_FPM_DYNAMIC_POOL_CONFIG_ADAPTER_ID,
    PHP_FPM_GLOBAL_CONFIG_ADAPTER_ID, PHP_FPM_POOL_CONFIG_ADAPTER_ID, RollbackSupport,
    ServiceAction, managed_config_bytes_supported, managed_service_config_resource_id,
    nginx_config_resource_id, nginx_internal_temporary_name, nginx_site_id,
    php_fpm_config_resource_id, php_fpm_pool_config_resource_id, sha256_digest,
};
use serde::{Deserialize, Serialize};

use crate::config::OpsPaths;
use crate::error::OpsError;
use crate::nginx::{
    discover_site, read_available_content, safe_basename, validate_available_metadata,
    validate_root,
};
use crate::nginx_diagnostic::nginx_config_failure_code;
use crate::php_fpm_diagnostic::{
    php_fpm_config_failure_code, php_fpm_config_test_succeeded, validate_php_fpm_candidate,
    validate_php_ini_candidate,
};
use crate::runner::{CommandClass, CommandEvidence};
use crate::snapshot::set_file_mode;

mod cleanup;
mod metadata;
mod proposal;
mod text;
mod tree;
pub use cleanup::cleanup_internal_temporaries;
pub use proposal::{read_proposal, remove_proposal, write_proposal};
pub use text::diff_stats;
use tree::discover_tree_managed_config;
use {
    metadata::digest as managed_metadata_digest, metadata::validate as validate_managed_metadata,
};

const NGINX_MANAGED_CONFIG_IMPACT: [&str; 3] = [
    "등록된 Nginx 설정 파일 하나의 bytes·owner·mode를 교체합니다.",
    "nginx -t가 성공한 경우에만 nginx.service reload를 실행합니다.",
    "문법·reload·active·read-back 실패 시 직전 파일을 자동 복원합니다.",
];
const NGINX_MANAGED_CONFIG_RECOVERY_PATH: [&str; 4] = [
    "SSH로 서버에 접속합니다.",
    "JW Agent receipt의 operation ID와 snapshot 상태를 확인합니다.",
    "대상 Nginx 설정 파일을 검토하고 nginx -t를 실행합니다.",
    "검증 성공 후 nginx.service를 reload합니다.",
];

const PHP_FPM_MANAGED_CONFIG_IMPACT: [&str; 3] = [
    "Ubuntu PHP 8.3 FPM의 표준 php.ini bytes·owner·mode를 교체합니다.",
    "php-fpm8.3 -t가 성공한 경우에만 php8.3-fpm.service reload를 실행합니다.",
    "문법·reload·active·read-back 실패 시 직전 php.ini를 자동 복원합니다.",
];
const PHP_FPM_MANAGED_CONFIG_RECOVERY_PATH: [&str; 4] = [
    "SSH로 서버에 접속합니다.",
    "JW Agent receipt의 operation ID와 snapshot 상태를 확인합니다.",
    "/etc/php/8.3/fpm/php.ini를 검토하고 php-fpm8.3 -t를 실행합니다.",
    "검증 성공 후 php8.3-fpm.service를 reload합니다.",
];
const APACHE_MANAGED_CONFIG_IMPACT: [&str; 3] = [
    "등록된 Apache 설정 파일 하나의 bytes·owner·mode를 교체합니다.",
    "apache2ctl configtest가 성공한 경우에만 apache2.service reload를 실행합니다.",
    "문법·reload·active·read-back 실패 시 직전 파일을 자동 복원합니다.",
];
const APACHE_MANAGED_CONFIG_RECOVERY_PATH: [&str; 4] = [
    "SSH로 서버에 접속합니다.",
    "JW Agent receipt의 operation ID와 snapshot 상태를 확인합니다.",
    "대상 Apache 설정 파일을 검토하고 apache2ctl configtest를 실행합니다.",
    "검증 성공 후 apache2.service를 reload합니다.",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedConfigAdapter {
    Nginx,
    NginxTree,
    NginxMain,
    NginxConfD,
    ApacheTree,
    ApacheMain,
    ApachePorts,
    ApacheConf,
    ApacheSite,
    PhpFpm83Ini,
    PhpFpm83Global,
    PhpFpm83PoolWww,
    PhpFpm83Pool,
}

impl ManagedConfigAdapter {
    #[must_use]
    pub const fn adapter_id(self) -> &'static str {
        match self {
            Self::Nginx => NGINX_CONFIG_ADAPTER_ID,
            Self::NginxTree => NGINX_TREE_CONFIG_ADAPTER_ID,
            Self::NginxMain => NGINX_MAIN_CONFIG_ADAPTER_ID,
            Self::NginxConfD => NGINX_CONF_D_CONFIG_ADAPTER_ID,
            Self::ApacheTree => APACHE_TREE_CONFIG_ADAPTER_ID,
            Self::ApacheMain => APACHE_MAIN_CONFIG_ADAPTER_ID,
            Self::ApachePorts => APACHE_PORTS_CONFIG_ADAPTER_ID,
            Self::ApacheConf => APACHE_CONF_CONFIG_ADAPTER_ID,
            Self::ApacheSite => APACHE_SITE_CONFIG_ADAPTER_ID,
            Self::PhpFpm83Ini => PHP_FPM_CONFIG_ADAPTER_ID,
            Self::PhpFpm83Global => PHP_FPM_GLOBAL_CONFIG_ADAPTER_ID,
            Self::PhpFpm83PoolWww => PHP_FPM_POOL_CONFIG_ADAPTER_ID,
            Self::PhpFpm83Pool => PHP_FPM_DYNAMIC_POOL_CONFIG_ADAPTER_ID,
        }
    }

    #[must_use]
    pub const fn maximum_bytes(self) -> usize {
        match self {
            Self::Nginx => NGINX_MANAGED_CONFIG_MAX_BYTES,
            Self::NginxTree
            | Self::NginxMain
            | Self::NginxConfD
            | Self::ApacheTree
            | Self::ApacheMain
            | Self::ApachePorts
            | Self::ApacheConf
            | Self::ApacheSite => MANAGED_CONFIG_MAX_BYTES,
            Self::PhpFpm83Ini
            | Self::PhpFpm83Global
            | Self::PhpFpm83PoolWww
            | Self::PhpFpm83Pool => PHP_FPM_CONFIG_MAX_BYTES,
        }
    }

    #[must_use]
    pub const fn impact(self) -> &'static [&'static str] {
        match self {
            Self::Nginx => &NGINX_MANAGED_CONFIG_IMPACT,
            Self::NginxTree | Self::NginxMain | Self::NginxConfD => &NGINX_MANAGED_CONFIG_IMPACT,
            Self::ApacheTree
            | Self::ApacheMain
            | Self::ApachePorts
            | Self::ApacheConf
            | Self::ApacheSite => &APACHE_MANAGED_CONFIG_IMPACT,
            Self::PhpFpm83Ini
            | Self::PhpFpm83Global
            | Self::PhpFpm83PoolWww
            | Self::PhpFpm83Pool => &PHP_FPM_MANAGED_CONFIG_IMPACT,
        }
    }

    #[must_use]
    pub const fn recovery_path(self) -> &'static [&'static str] {
        match self {
            Self::Nginx => &NGINX_MANAGED_CONFIG_RECOVERY_PATH,
            Self::NginxTree | Self::NginxMain | Self::NginxConfD => {
                &NGINX_MANAGED_CONFIG_RECOVERY_PATH
            }
            Self::ApacheTree
            | Self::ApacheMain
            | Self::ApachePorts
            | Self::ApacheConf
            | Self::ApacheSite => &APACHE_MANAGED_CONFIG_RECOVERY_PATH,
            Self::PhpFpm83Ini
            | Self::PhpFpm83Global
            | Self::PhpFpm83PoolWww
            | Self::PhpFpm83Pool => &PHP_FPM_MANAGED_CONFIG_RECOVERY_PATH,
        }
    }

    #[must_use]
    pub const fn config_test(self) -> CommandClass {
        match self {
            Self::Nginx | Self::NginxTree | Self::NginxMain | Self::NginxConfD => {
                CommandClass::NginxConfigTest
            }
            Self::ApacheTree
            | Self::ApacheMain
            | Self::ApachePorts
            | Self::ApacheConf
            | Self::ApacheSite => CommandClass::ApacheConfigTest,
            Self::PhpFpm83Ini
            | Self::PhpFpm83Global
            | Self::PhpFpm83PoolWww
            | Self::PhpFpm83Pool => CommandClass::PhpFpm83ConfigTest,
        }
    }

    #[must_use]
    pub const fn reload(self) -> CommandClass {
        match self {
            Self::Nginx | Self::NginxTree | Self::NginxMain | Self::NginxConfD => {
                CommandClass::NginxReload
            }
            Self::ApacheTree
            | Self::ApacheMain
            | Self::ApachePorts
            | Self::ApacheConf
            | Self::ApacheSite => CommandClass::ApacheReload,
            Self::PhpFpm83Ini
            | Self::PhpFpm83Global
            | Self::PhpFpm83PoolWww
            | Self::PhpFpm83Pool => CommandClass::PhpFpm83Reload,
        }
    }

    #[must_use]
    pub const fn active(self) -> CommandClass {
        match self {
            Self::Nginx | Self::NginxTree | Self::NginxMain | Self::NginxConfD => {
                CommandClass::NginxActive
            }
            Self::ApacheTree
            | Self::ApacheMain
            | Self::ApachePorts
            | Self::ApacheConf
            | Self::ApacheSite => CommandClass::ApacheActive,
            Self::PhpFpm83Ini
            | Self::PhpFpm83Global
            | Self::PhpFpm83PoolWww
            | Self::PhpFpm83Pool => CommandClass::PhpFpm83Active,
        }
    }

    #[must_use]
    pub const fn config_valid_code(self) -> &'static str {
        match self {
            Self::Nginx | Self::NginxTree | Self::NginxMain | Self::NginxConfD => {
                "nginx_config_valid"
            }
            Self::ApacheTree
            | Self::ApacheMain
            | Self::ApachePorts
            | Self::ApacheConf
            | Self::ApacheSite => "apache_config_valid",
            Self::PhpFpm83Ini
            | Self::PhpFpm83Global
            | Self::PhpFpm83PoolWww
            | Self::PhpFpm83Pool => "php_fpm_config_valid",
        }
    }

    #[must_use]
    pub const fn reloaded_code(self) -> &'static str {
        match self {
            Self::Nginx | Self::NginxTree | Self::NginxMain | Self::NginxConfD => "nginx_reloaded",
            Self::ApacheTree
            | Self::ApacheMain
            | Self::ApachePorts
            | Self::ApacheConf
            | Self::ApacheSite => "apache_reloaded",
            Self::PhpFpm83Ini
            | Self::PhpFpm83Global
            | Self::PhpFpm83PoolWww
            | Self::PhpFpm83Pool => "php_fpm_reloaded",
        }
    }
}

pub fn managed_config_adapter(resource_id: &str) -> Result<ManagedConfigAdapter, OpsError> {
    if resource_id.starts_with("ngc_") {
        Ok(ManagedConfigAdapter::Nginx)
    } else if resource_id.starts_with(NGINX_TREE_RESOURCE_PREFIX) {
        Ok(ManagedConfigAdapter::NginxTree)
    } else if resource_id.starts_with(NGINX_MAIN_RESOURCE_PREFIX) {
        Ok(ManagedConfigAdapter::NginxMain)
    } else if resource_id.starts_with(NGINX_CONF_D_RESOURCE_PREFIX) {
        Ok(ManagedConfigAdapter::NginxConfD)
    } else if resource_id.starts_with(APACHE_TREE_RESOURCE_PREFIX) {
        Ok(ManagedConfigAdapter::ApacheTree)
    } else if resource_id.starts_with(APACHE_MAIN_RESOURCE_PREFIX) {
        Ok(ManagedConfigAdapter::ApacheMain)
    } else if resource_id.starts_with(APACHE_PORTS_RESOURCE_PREFIX) {
        Ok(ManagedConfigAdapter::ApachePorts)
    } else if resource_id.starts_with(APACHE_CONF_RESOURCE_PREFIX) {
        Ok(ManagedConfigAdapter::ApacheConf)
    } else if resource_id.starts_with(APACHE_SITE_RESOURCE_PREFIX) {
        Ok(ManagedConfigAdapter::ApacheSite)
    } else if resource_id == php_fpm_config_resource_id(PHP_FPM_CONFIG_ADAPTER_ID) {
        Ok(ManagedConfigAdapter::PhpFpm83Ini)
    } else if resource_id == php_fpm_config_resource_id(PHP_FPM_GLOBAL_CONFIG_ADAPTER_ID) {
        Ok(ManagedConfigAdapter::PhpFpm83Global)
    } else if resource_id == php_fpm_config_resource_id(PHP_FPM_POOL_CONFIG_ADAPTER_ID) {
        Ok(ManagedConfigAdapter::PhpFpm83PoolWww)
    } else if resource_id.starts_with("php_") {
        Ok(ManagedConfigAdapter::PhpFpm83Pool)
    } else {
        Err(OpsError::Rejected("resource_missing"))
    }
}

#[must_use]
pub fn managed_config_test_succeeded(
    adapter: ManagedConfigAdapter,
    evidence: &CommandEvidence,
) -> bool {
    match adapter {
        ManagedConfigAdapter::Nginx
        | ManagedConfigAdapter::NginxTree
        | ManagedConfigAdapter::NginxMain
        | ManagedConfigAdapter::NginxConfD
        | ManagedConfigAdapter::ApacheTree
        | ManagedConfigAdapter::ApacheMain
        | ManagedConfigAdapter::ApachePorts
        | ManagedConfigAdapter::ApacheConf
        | ManagedConfigAdapter::ApacheSite => evidence.success,
        ManagedConfigAdapter::PhpFpm83Ini
        | ManagedConfigAdapter::PhpFpm83Global
        | ManagedConfigAdapter::PhpFpm83PoolWww
        | ManagedConfigAdapter::PhpFpm83Pool => php_fpm_config_test_succeeded(evidence),
    }
}

#[must_use]
pub fn managed_config_failure_code(
    adapter: ManagedConfigAdapter,
    evidence: &CommandEvidence,
    basename: &str,
) -> String {
    match adapter {
        ManagedConfigAdapter::Nginx
        | ManagedConfigAdapter::NginxTree
        | ManagedConfigAdapter::NginxMain
        | ManagedConfigAdapter::NginxConfD => nginx_config_failure_code(evidence, basename),
        ManagedConfigAdapter::ApacheTree
        | ManagedConfigAdapter::ApacheMain
        | ManagedConfigAdapter::ApachePorts
        | ManagedConfigAdapter::ApacheConf
        | ManagedConfigAdapter::ApacheSite => {
            if evidence.timed_out {
                String::from("apache_config_test_timeout")
            } else {
                String::from("apache_config_invalid")
            }
        }
        ManagedConfigAdapter::PhpFpm83Ini
        | ManagedConfigAdapter::PhpFpm83Global
        | ManagedConfigAdapter::PhpFpm83PoolWww
        | ManagedConfigAdapter::PhpFpm83Pool => php_fpm_config_failure_code(evidence),
    }
}

pub fn validate_managed_config_candidate(
    adapter: ManagedConfigAdapter,
    current: &str,
    proposed: &str,
) -> Result<(), OpsError> {
    match adapter {
        ManagedConfigAdapter::Nginx
        | ManagedConfigAdapter::NginxTree
        | ManagedConfigAdapter::NginxMain
        | ManagedConfigAdapter::NginxConfD
        | ManagedConfigAdapter::ApacheTree
        | ManagedConfigAdapter::ApacheMain
        | ManagedConfigAdapter::ApachePorts
        | ManagedConfigAdapter::ApacheConf
        | ManagedConfigAdapter::ApacheSite => Ok(()),
        ManagedConfigAdapter::PhpFpm83Ini => {
            validate_php_ini_candidate(current, proposed).map_err(OpsError::RejectedOwned)
        }
        ManagedConfigAdapter::PhpFpm83Global
        | ManagedConfigAdapter::PhpFpm83PoolWww
        | ManagedConfigAdapter::PhpFpm83Pool => {
            validate_php_fpm_candidate(current, proposed).map_err(OpsError::RejectedOwned)
        }
    }
}

#[must_use]
pub fn managed_config_masked_path(adapter: ManagedConfigAdapter, display_name: &str) -> String {
    match adapter {
        ManagedConfigAdapter::Nginx => format!("…/nginx/sites-available/{display_name}"),
        ManagedConfigAdapter::NginxTree => format!("/etc/nginx/{display_name}"),
        ManagedConfigAdapter::NginxMain => String::from("…/nginx/nginx.conf"),
        ManagedConfigAdapter::NginxConfD => format!("…/nginx/conf.d/{display_name}"),
        ManagedConfigAdapter::ApacheTree => format!("/etc/apache2/{display_name}"),
        ManagedConfigAdapter::ApacheMain => String::from("…/apache2/apache2.conf"),
        ManagedConfigAdapter::ApachePorts => String::from("…/apache2/ports.conf"),
        ManagedConfigAdapter::ApacheConf => {
            format!("…/apache2/conf-available/{display_name}")
        }
        ManagedConfigAdapter::ApacheSite => {
            format!("…/apache2/sites-available/{display_name}")
        }
        ManagedConfigAdapter::PhpFpm83Ini => String::from("…/php/8.3/fpm/php.ini"),
        ManagedConfigAdapter::PhpFpm83Global => String::from("…/php/8.3/fpm/php-fpm.conf"),
        ManagedConfigAdapter::PhpFpm83PoolWww => String::from("…/php/8.3/fpm/pool.d/www.conf"),
        ManagedConfigAdapter::PhpFpm83Pool => {
            format!("…/php/8.3/fpm/pool.d/{display_name}")
        }
    }
}

#[must_use]
pub fn managed_config_assurance(adapter: ManagedConfigAdapter) -> AssuranceView {
    let (scope, excluded_effects, apply_verifier, rollback_verifier) = match adapter {
        ManagedConfigAdapter::Nginx
        | ManagedConfigAdapter::NginxTree
        | ManagedConfigAdapter::NginxMain
        | ManagedConfigAdapter::NginxConfD => (
            "등록된 Nginx 설정 파일 하나의 bytes·owner·mode와 검증된 reload",
            vec![
                String::from("include된 다른 파일과 active connection"),
                String::from("Nginx process의 과거 in-memory 상태"),
                String::from("제품 밖 root 사용자의 동시 변경"),
            ],
            vec![
                String::from("atomic replace와 content·metadata read-back"),
                String::from("nginx -t"),
                String::from("reload 후 nginx.service active"),
            ],
            vec![
                String::from("이전 bytes·owner·mode 복원"),
                String::from("nginx -t와 reload 후 active 확인"),
            ],
        ),
        ManagedConfigAdapter::ApacheTree
        | ManagedConfigAdapter::ApacheMain
        | ManagedConfigAdapter::ApachePorts
        | ManagedConfigAdapter::ApacheConf
        | ManagedConfigAdapter::ApacheSite => (
            "Ubuntu Apache의 선택한 표준 설정 파일 bytes·owner·mode와 검증된 reload",
            vec![
                String::from("선택하지 않은 다른 설정 파일과 active connection"),
                String::from("Apache process의 과거 in-memory 상태"),
                String::from("제품 밖 root 사용자의 동시 변경"),
            ],
            vec![
                String::from("atomic replace와 content·metadata read-back"),
                String::from("apache2ctl configtest"),
                String::from("reload 후 apache2.service active"),
            ],
            vec![
                String::from("이전 bytes·owner·mode 복원"),
                String::from("apache2ctl configtest와 reload 후 active 확인"),
            ],
        ),
        ManagedConfigAdapter::PhpFpm83Ini
        | ManagedConfigAdapter::PhpFpm83Global
        | ManagedConfigAdapter::PhpFpm83PoolWww
        | ManagedConfigAdapter::PhpFpm83Pool => (
            "Ubuntu PHP 8.3 FPM의 선택한 표준 설정 파일 bytes·owner·mode와 검증된 reload",
            vec![
                String::from("선택하지 않은 다른 FPM·CLI·Apache SAPI 설정과 extension package"),
                String::from("기존 request와 PHP process의 과거 in-memory 상태"),
                String::from("제품 밖 root 사용자의 동시 변경"),
            ],
            vec![
                String::from("atomic replace와 content·metadata read-back"),
                String::from("php-fpm8.3 -t와 php.ini syntax warning 부재"),
                String::from("reload 후 php8.3-fpm.service active"),
            ],
            vec![
                String::from("이전 php.ini bytes·owner·mode 복원"),
                String::from("php-fpm8.3 -t와 reload 후 active 확인"),
            ],
        ),
    };
    AssuranceView {
        level: AssuranceLevel::G2ReversibleConfig,
        rollback_support: RollbackSupport::AutomaticBounded,
        operation_available: true,
        scope: vec![String::from(scope)],
        excluded_effects,
        apply_verifier,
        rollback_verifier,
        reason: None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedConfigResource {
    pub adapter: ManagedConfigAdapter,
    pub resource_id: String,
    pub basename: String,
    pub display_name: String,
    pub root: PathBuf,
    pub content: String,
    pub content_digest: String,
    pub metadata_digest: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl ManagedConfigResource {
    pub fn view(
        &self,
        assurance: jw_contracts::AssuranceView,
    ) -> Result<ManagedConfigResourceView, OpsError> {
        Ok(ManagedConfigResourceView {
            schema_version: OPERATION_SCHEMA_VERSION,
            adapter_id: String::from(self.adapter.adapter_id()),
            resource_id: self.resource_id.clone(),
            display_name: self.display_name.clone(),
            masked_path: managed_config_masked_path(
                self.adapter,
                if matches!(
                    self.adapter,
                    ManagedConfigAdapter::NginxTree | ManagedConfigAdapter::ApacheTree
                ) {
                    &self.display_name
                } else {
                    &self.basename
                },
            ),
            content: self.content.clone(),
            content_digest: self.content_digest.clone(),
            metadata_digest: self.metadata_digest.clone(),
            max_bytes: u32::try_from(self.adapter.maximum_bytes())
                .map_err(|_| OpsError::Storage(String::from("config size overflow")))?,
            allowed_service_actions: vec![ServiceAction::Reload, ServiceAction::ValidateOnly],
            assurance,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedConfigPlanPayload {
    pub proposal_relative_path: String,
    pub proposal_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basename: Option<String>,
    pub proposed_content_digest: String,
    pub current_bytes: u32,
    pub proposed_bytes: u32,
    pub added_lines: u32,
    pub removed_lines: u32,
    pub diff_summary: Vec<String>,
    pub service_action: ServiceAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalRecord {
    pub relative_path: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffStats {
    pub added_lines: u32,
    pub removed_lines: u32,
    pub summary: Vec<String>,
}

pub fn discover_managed_config(
    paths: &OpsPaths,
    requested_resource_id: &str,
) -> Result<ManagedConfigResource, OpsError> {
    match managed_config_adapter(requested_resource_id)? {
        ManagedConfigAdapter::Nginx => discover_nginx_managed_config(paths, requested_resource_id),
        ManagedConfigAdapter::NginxTree => discover_tree_managed_config(
            paths,
            ManagedConfigAdapter::NginxTree,
            paths
                .nginx_main
                .parent()
                .ok_or(OpsError::Rejected("unsupported_layout"))?,
            requested_resource_id,
            NGINX_TREE_RESOURCE_PREFIX,
        ),
        ManagedConfigAdapter::NginxMain => discover_exact_managed_config(
            paths,
            ManagedConfigAdapter::NginxMain,
            &paths.nginx_main,
            "nginx.conf",
            "Nginx · nginx.conf",
            requested_resource_id,
            NGINX_MAIN_RESOURCE_PREFIX,
        ),
        ManagedConfigAdapter::NginxConfD => discover_directory_managed_config(
            paths,
            ManagedConfigAdapter::NginxConfD,
            &paths.nginx_conf_d,
            None,
            "Nginx · conf.d",
            requested_resource_id,
            NGINX_CONF_D_RESOURCE_PREFIX,
        ),
        ManagedConfigAdapter::ApacheTree => discover_tree_managed_config(
            paths,
            ManagedConfigAdapter::ApacheTree,
            paths
                .apache_main
                .parent()
                .ok_or(OpsError::Rejected("unsupported_layout"))?,
            requested_resource_id,
            APACHE_TREE_RESOURCE_PREFIX,
        ),
        ManagedConfigAdapter::ApacheMain => discover_exact_managed_config(
            paths,
            ManagedConfigAdapter::ApacheMain,
            &paths.apache_main,
            "apache2.conf",
            "Apache · apache2.conf",
            requested_resource_id,
            APACHE_MAIN_RESOURCE_PREFIX,
        ),
        ManagedConfigAdapter::ApachePorts => discover_exact_managed_config(
            paths,
            ManagedConfigAdapter::ApachePorts,
            &paths.apache_ports,
            "ports.conf",
            "Apache · ports.conf",
            requested_resource_id,
            APACHE_PORTS_RESOURCE_PREFIX,
        ),
        ManagedConfigAdapter::ApacheConf => discover_directory_managed_config(
            paths,
            ManagedConfigAdapter::ApacheConf,
            &paths.apache_conf_available,
            Some(&paths.apache_conf_enabled),
            "Apache · conf",
            requested_resource_id,
            APACHE_CONF_RESOURCE_PREFIX,
        ),
        ManagedConfigAdapter::ApacheSite => discover_directory_managed_config(
            paths,
            ManagedConfigAdapter::ApacheSite,
            &paths.apache_sites_available,
            Some(&paths.apache_sites_enabled),
            "Apache · site",
            requested_resource_id,
            APACHE_SITE_RESOURCE_PREFIX,
        ),
        ManagedConfigAdapter::PhpFpm83Ini => discover_php_fpm_managed_config(
            paths,
            ManagedConfigAdapter::PhpFpm83Ini,
            &paths.php_fpm_ini,
            "php.ini",
            "PHP 8.3 FPM · php.ini",
        ),
        ManagedConfigAdapter::PhpFpm83Global => discover_php_fpm_managed_config(
            paths,
            ManagedConfigAdapter::PhpFpm83Global,
            &paths.php_fpm_global,
            "php-fpm.conf",
            "PHP 8.3 FPM · 전역 설정",
        ),
        ManagedConfigAdapter::PhpFpm83PoolWww => discover_php_fpm_managed_config(
            paths,
            ManagedConfigAdapter::PhpFpm83PoolWww,
            &paths.php_fpm_pool_www,
            "www.conf",
            "PHP 8.3 FPM · www pool",
        ),
        ManagedConfigAdapter::PhpFpm83Pool => {
            discover_php_fpm_pool_config(paths, requested_resource_id)
        }
    }
}

fn discover_nginx_managed_config(
    paths: &OpsPaths,
    requested_resource_id: &str,
) -> Result<ManagedConfigResource, OpsError> {
    validate_root(&paths.nginx_available, paths.enforce_root_ownership)?;
    let entries = std::fs::read_dir(&paths.nginx_available)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    for entry_result in entries {
        let entry = entry_result.map_err(|error| OpsError::Filesystem(error.to_string()))?;
        let basename = safe_basename(&entry.file_name())?;
        if nginx_internal_temporary_name(&basename) {
            continue;
        }
        let resource_id = nginx_config_resource_id(NGINX_CONFIG_ADAPTER_ID, &basename);
        if resource_id != requested_resource_id {
            continue;
        }
        let (bytes, metadata, protected) = read_available_content(paths, &basename)?;
        validate_available_metadata(&metadata, paths.enforce_root_ownership)?;
        validate_managed_metadata(&metadata, paths.enforce_root_ownership)?;
        if protected {
            return Err(OpsError::Rejected("protected_resource"));
        }
        let site = discover_site(paths, &nginx_site_id(NGINX_LAYOUT_ID, &basename))?;
        if site.state != NginxSiteState::Enabled {
            return Err(OpsError::Rejected("resource_not_active"));
        }
        if bytes.len() > NGINX_MANAGED_CONFIG_MAX_BYTES {
            return Err(OpsError::Rejected("size_limit"));
        }
        if !managed_config_bytes_supported(&bytes) {
            return Err(OpsError::Rejected("invalid_encoding"));
        }
        let content =
            String::from_utf8(bytes).map_err(|_| OpsError::Rejected("invalid_encoding"))?;
        let mode = metadata_mode(&metadata);
        let uid = metadata_uid(&metadata);
        let gid = metadata_gid(&metadata);
        let content_digest = sha256_digest(content.as_bytes());
        let metadata_digest = managed_metadata_digest(mode, uid, gid);
        return Ok(ManagedConfigResource {
            adapter: ManagedConfigAdapter::Nginx,
            resource_id,
            display_name: basename.clone(),
            root: paths.nginx_available.clone(),
            basename,
            content,
            content_digest,
            metadata_digest,
            mode,
            uid,
            gid,
        });
    }
    Err(OpsError::Rejected("resource_missing"))
}

#[allow(clippy::too_many_arguments)]
fn discover_exact_managed_config(
    paths: &OpsPaths,
    adapter: ManagedConfigAdapter,
    path: &Path,
    basename: &str,
    display_name: &str,
    requested_resource_id: &str,
    resource_prefix: &str,
) -> Result<ManagedConfigResource, OpsError> {
    let expected_resource_id =
        managed_service_config_resource_id(resource_prefix, adapter.adapter_id(), basename);
    if requested_resource_id != expected_resource_id {
        return Err(OpsError::Rejected("resource_missing"));
    }
    let root = path
        .parent()
        .ok_or(OpsError::Rejected("unsupported_layout"))?;
    read_regular_managed_config(
        paths,
        adapter,
        root,
        basename,
        display_name,
        expected_resource_id,
    )
}

#[allow(clippy::too_many_arguments)]
fn discover_directory_managed_config(
    paths: &OpsPaths,
    adapter: ManagedConfigAdapter,
    available_root: &Path,
    enabled_root: Option<&Path>,
    display_prefix: &str,
    requested_resource_id: &str,
    resource_prefix: &str,
) -> Result<ManagedConfigResource, OpsError> {
    validate_root(available_root, paths.enforce_root_ownership)?;
    let entries = std::fs::read_dir(available_root)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    for entry_result in entries {
        let entry = entry_result.map_err(|error| OpsError::Filesystem(error.to_string()))?;
        let basename = safe_basename(&entry.file_name())?;
        if nginx_internal_temporary_name(&basename) || !basename.ends_with(".conf") {
            continue;
        }
        let resource_id =
            managed_service_config_resource_id(resource_prefix, adapter.adapter_id(), &basename);
        if resource_id != requested_resource_id {
            continue;
        }
        if let Some(enabled) = enabled_root {
            require_enabled_link(
                available_root,
                enabled,
                &basename,
                paths.enforce_root_ownership,
            )?;
        }
        return read_regular_managed_config(
            paths,
            adapter,
            available_root,
            &basename,
            &format!("{display_prefix} · {basename}"),
            resource_id,
        );
    }
    Err(OpsError::Rejected("resource_missing"))
}

fn require_enabled_link(
    available_root: &Path,
    enabled_root: &Path,
    basename: &str,
    enforce_root_ownership: bool,
) -> Result<(), OpsError> {
    validate_root(enabled_root, enforce_root_ownership)?;
    let link = enabled_root.join(basename);
    let metadata =
        std::fs::symlink_metadata(&link).map_err(|_| OpsError::Rejected("resource_not_active"))?;
    if !metadata.file_type().is_symlink() {
        return Err(OpsError::Rejected("enabled_entry_not_symlink"));
    }
    let target =
        std::fs::read_link(&link).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    let absolute = available_root.join(basename);
    let relative = available_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(|directory| PathBuf::from(format!("../{directory}/{basename}")))
        .ok_or(OpsError::Rejected("unsupported_layout"))?;
    if target != absolute && target != relative {
        return Err(OpsError::Rejected("enabled_target_mismatch"));
    }
    Ok(())
}

fn read_regular_managed_config(
    paths: &OpsPaths,
    adapter: ManagedConfigAdapter,
    root: &Path,
    basename: &str,
    display_name: &str,
    resource_id: String,
) -> Result<ManagedConfigResource, OpsError> {
    validate_root(root, paths.enforce_root_ownership)?;
    let path = root.join(basename);
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|_| OpsError::Rejected("resource_missing"))?;
    validate_available_metadata(&metadata, paths.enforce_root_ownership)?;
    validate_managed_metadata(&metadata, paths.enforce_root_ownership)?;
    if metadata.len()
        > u64::try_from(adapter.maximum_bytes()).map_or(u64::MAX, std::convert::identity)
    {
        return Err(OpsError::Rejected("size_limit"));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| OpsError::Rejected("size_limit"))?,
    );
    File::open(&path)
        .and_then(|mut source| source.read_to_end(&mut bytes))
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if !managed_config_bytes_supported(&bytes) {
        return Err(OpsError::Rejected("invalid_encoding"));
    }
    let content = String::from_utf8(bytes).map_err(|_| OpsError::Rejected("invalid_encoding"))?;
    let mode = metadata_mode(&metadata);
    let uid = metadata_uid(&metadata);
    let gid = metadata_gid(&metadata);
    Ok(ManagedConfigResource {
        adapter,
        resource_id,
        basename: String::from(basename),
        display_name: String::from(display_name),
        root: root.to_path_buf(),
        content_digest: sha256_digest(content.as_bytes()),
        metadata_digest: managed_metadata_digest(mode, uid, gid),
        content,
        mode,
        uid,
        gid,
    })
}

fn discover_php_fpm_pool_config(
    paths: &OpsPaths,
    requested_resource_id: &str,
) -> Result<ManagedConfigResource, OpsError> {
    validate_root(&paths.php_fpm_pool_dir, paths.enforce_root_ownership)?;
    let entries = std::fs::read_dir(&paths.php_fpm_pool_dir)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    for entry_result in entries {
        let entry = entry_result.map_err(|error| OpsError::Filesystem(error.to_string()))?;
        let basename = safe_basename(&entry.file_name())?;
        if nginx_internal_temporary_name(&basename) || !basename.ends_with(".conf") {
            continue;
        }
        let resource_id = php_fpm_pool_config_resource_id(&basename);
        if resource_id != requested_resource_id {
            continue;
        }
        return read_regular_managed_config(
            paths,
            ManagedConfigAdapter::PhpFpm83Pool,
            &paths.php_fpm_pool_dir,
            &basename,
            &format!("PHP 8.3 FPM · {basename} pool"),
            resource_id,
        );
    }
    Err(OpsError::Rejected("resource_missing"))
}

fn discover_php_fpm_managed_config(
    paths: &OpsPaths,
    adapter: ManagedConfigAdapter,
    path: &Path,
    basename: &str,
    display_name: &str,
) -> Result<ManagedConfigResource, OpsError> {
    let root = path
        .parent()
        .ok_or(OpsError::Rejected("unsupported_layout"))?;
    validate_root(root, paths.enforce_root_ownership)
        .map_err(|_| OpsError::Rejected("unsupported_layout"))?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| OpsError::Rejected("resource_missing"))?;
    validate_available_metadata(&metadata, paths.enforce_root_ownership)?;
    validate_managed_metadata(&metadata, paths.enforce_root_ownership)?;
    if metadata.len()
        > u64::try_from(PHP_FPM_CONFIG_MAX_BYTES).map_or(u64::MAX, std::convert::identity)
    {
        return Err(OpsError::Rejected("size_limit"));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| OpsError::Rejected("size_limit"))?,
    );
    File::open(path)
        .and_then(|mut source| source.read_to_end(&mut bytes))
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if !managed_config_bytes_supported(&bytes) {
        return Err(OpsError::Rejected("invalid_encoding"));
    }
    let content = String::from_utf8(bytes).map_err(|_| OpsError::Rejected("invalid_encoding"))?;
    let mode = metadata_mode(&metadata);
    let uid = metadata_uid(&metadata);
    let gid = metadata_gid(&metadata);
    Ok(ManagedConfigResource {
        adapter,
        resource_id: php_fpm_config_resource_id(adapter.adapter_id()),
        basename: String::from(basename),
        display_name: String::from(display_name),
        root: root.to_path_buf(),
        content_digest: sha256_digest(content.as_bytes()),
        metadata_digest: managed_metadata_digest(mode, uid, gid),
        content,
        mode,
        uid,
        gid,
    })
}

pub fn discover_protected_config(
    paths: &OpsPaths,
    requested_site_id: &str,
) -> Result<ManagedConfigResource, OpsError> {
    let site = discover_site(paths, requested_site_id)?;
    if !site.protected || site.state != NginxSiteState::Enabled {
        return Err(OpsError::Rejected("protected_resource_required"));
    }
    let (bytes, metadata, protected) = read_available_content(paths, &site.basename)?;
    validate_available_metadata(&metadata, paths.enforce_root_ownership)?;
    validate_managed_metadata(&metadata, paths.enforce_root_ownership)?;
    if !protected || bytes.len() > NGINX_MANAGED_CONFIG_MAX_BYTES {
        return Err(OpsError::Rejected("protected_resource_required"));
    }
    if !managed_config_bytes_supported(&bytes) {
        return Err(OpsError::Rejected("invalid_encoding"));
    }
    let content = String::from_utf8(bytes).map_err(|_| OpsError::Rejected("invalid_encoding"))?;
    let mode = metadata_mode(&metadata);
    let uid = metadata_uid(&metadata);
    let gid = metadata_gid(&metadata);
    Ok(ManagedConfigResource {
        adapter: ManagedConfigAdapter::Nginx,
        resource_id: site.site_id,
        display_name: site.basename.clone(),
        root: paths.nginx_available.clone(),
        basename: site.basename,
        content_digest: sha256_digest(content.as_bytes()),
        metadata_digest: managed_metadata_digest(mode, uid, gid),
        content,
        mode,
        uid,
        gid,
    })
}

pub fn replace_managed_config(
    paths: &OpsPaths,
    expected: &ManagedConfigResource,
    content: &str,
) -> Result<ManagedConfigResource, OpsError> {
    let current = discover_managed_config(paths, &expected.resource_id)?;
    if current.content_digest != expected.content_digest
        || current.metadata_digest != expected.metadata_digest
    {
        return Err(OpsError::Rejected("stale_resource"));
    }
    if content.len() > expected.adapter.maximum_bytes() {
        return Err(OpsError::Rejected("size_limit"));
    }
    if !managed_config_bytes_supported(content.as_bytes()) {
        return Err(OpsError::Rejected("invalid_encoding"));
    }
    atomic_replace(
        &expected.root,
        &expected.basename,
        content,
        expected.mode,
        expected.uid,
        expected.gid,
    )?;
    discover_managed_config(paths, &expected.resource_id)
}

pub fn restore_managed_config(
    paths: &OpsPaths,
    resource_id: &str,
    basename: &str,
    content: &str,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<ManagedConfigResource, OpsError> {
    let current = discover_managed_config(paths, resource_id)?;
    if current.basename != basename || content.len() > current.adapter.maximum_bytes() {
        return Err(OpsError::Rejected("resource_identity_mismatch"));
    }
    atomic_replace(&current.root, basename, content, mode, uid, gid)?;
    discover_managed_config(paths, resource_id)
}

pub fn replace_protected_config(
    paths: &OpsPaths,
    expected: &ManagedConfigResource,
    content: &str,
) -> Result<ManagedConfigResource, OpsError> {
    let current = discover_protected_config(paths, &expected.resource_id)?;
    if current.basename != expected.basename
        || current.content_digest != expected.content_digest
        || current.metadata_digest != expected.metadata_digest
    {
        return Err(OpsError::Rejected("stale_resource"));
    }
    if content.len() > NGINX_MANAGED_CONFIG_MAX_BYTES
        || !managed_config_bytes_supported(content.as_bytes())
        || !jw_contracts::nginx_management_config(content.as_bytes())
    {
        return Err(OpsError::Rejected("protected_config_invalid"));
    }
    atomic_replace(
        &expected.root,
        &expected.basename,
        content,
        expected.mode,
        expected.uid,
        expected.gid,
    )?;
    discover_protected_config(paths, &expected.resource_id)
}

pub fn restore_protected_config(
    paths: &OpsPaths,
    site_id: &str,
    basename: &str,
    content: &str,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<ManagedConfigResource, OpsError> {
    let current = discover_protected_config(paths, site_id)?;
    if current.basename != basename || !jw_contracts::nginx_management_config(content.as_bytes()) {
        return Err(OpsError::Rejected("resource_identity_mismatch"));
    }
    atomic_replace(&current.root, basename, content, mode, uid, gid)?;
    let restored = discover_protected_config(paths, site_id)?;
    if restored.mode == mode && restored.uid == uid && restored.gid == gid {
        Ok(restored)
    } else {
        Err(OpsError::Rejected("metadata_read_back_failed"))
    }
}

fn atomic_replace(
    root: &Path,
    basename: &str,
    content: &str,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<(), OpsError> {
    let suffix = random_suffix()?;
    let temporary = root.join(format!(".jw-agent-{suffix}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if let Err(error) = set_file_mode(&file, mode & 0o7777) {
        let _cleanup = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = set_file_owner(&file, uid, gid) {
        let _cleanup = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = file
        .write_all(content.as_bytes())
        .and_then(|()| file.sync_all())
    {
        let _cleanup = std::fs::remove_file(&temporary);
        return Err(OpsError::Filesystem(error.to_string()));
    }
    let destination = root.join(basename);
    if let Err(error) = std::fs::rename(&temporary, &destination) {
        let _cleanup = std::fs::remove_file(&temporary);
        return Err(OpsError::Filesystem(error.to_string()));
    }
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    Ok(())
}

fn random_suffix() -> Result<String, OpsError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|error| OpsError::Storage(error.to_string()))?;
    Ok(format!("{:016x}", u64::from_le_bytes(bytes)))
}

#[cfg(unix)]
fn metadata_mode(metadata: &std::fs::Metadata) -> u32 {
    metadata.mode() & 0o7777
}

#[cfg(not(unix))]
fn metadata_mode(_metadata: &std::fs::Metadata) -> u32 {
    0o600
}

#[cfg(unix)]
fn metadata_uid(metadata: &std::fs::Metadata) -> u32 {
    metadata.uid()
}

#[cfg(not(unix))]
fn metadata_uid(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn metadata_gid(metadata: &std::fs::Metadata) -> u32 {
    metadata.gid()
}

#[cfg(not(unix))]
fn metadata_gid(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(target_os = "linux")]
fn set_file_owner(file: &File, uid: u32, gid: u32) -> Result<(), OpsError> {
    use nix::unistd::{Gid, Uid, fchown};

    let metadata = file
        .metadata()
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if metadata.uid() == uid && metadata.gid() == gid {
        return Ok(());
    }
    fchown(file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
        .map_err(|error| OpsError::Filesystem(error.to_string()))
}

#[cfg(not(target_os = "linux"))]
fn set_file_owner(_file: &File, _uid: u32, _gid: u32) -> Result<(), OpsError> {
    Ok(())
}

#[cfg(test)]
mod tests;
