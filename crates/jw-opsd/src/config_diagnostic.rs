use std::path::{Path, PathBuf};

use jw_contracts::{
    APACHE_TREE_CONFIG_ADAPTER_ID, APACHE_TREE_RESOURCE_PREFIX,
    MANAGED_CONFIG_DIAGNOSTIC_MAX_ENTRIES, ManagedConfigDiagnosticSeverity,
    ManagedConfigDiagnosticView, NGINX_TREE_CONFIG_ADAPTER_ID, NGINX_TREE_RESOURCE_PREFIX,
    PHP_FPM_CONFIG_ADAPTER_ID, PHP_FPM_GLOBAL_CONFIG_ADAPTER_ID,
    managed_service_config_resource_id, php_fpm_config_resource_id,
    php_fpm_pool_config_resource_id,
};

use crate::apache_diagnostic::parse_apache_config_diagnostics;
use crate::config::OpsPaths;
use crate::managed_config::{
    ManagedConfigAdapter, ManagedConfigResource, safe_tree_relative_path, secret_tree_resource,
};
use crate::nginx_diagnostic::parse_nginx_config_diagnostics;
use crate::php_fpm_diagnostic::parse_php_fpm_config_diagnostics;
use crate::runner::{CommandClass, CommandEvidence};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParsedSeverity {
    Error,
    Warning,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedConfigDiagnostic {
    pub path: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub severity: ParsedSeverity,
    pub code: &'static str,
    pub message: &'static str,
}

pub(crate) fn validator_output(evidence: &CommandEvidence) -> String {
    let mut value = String::from_utf8_lossy(&evidence.stderr.captured).into_owned();
    value.push('\n');
    value.push_str(&String::from_utf8_lossy(&evidence.stdout.captured));
    value
}

pub(crate) fn generic_validator_diagnostic(
    code: &'static str,
    message: &'static str,
) -> ParsedConfigDiagnostic {
    ParsedConfigDiagnostic {
        path: None,
        line: None,
        column: None,
        severity: ParsedSeverity::Error,
        code,
        message,
    }
}

pub(crate) fn managed_config_diagnostics(
    paths: &OpsPaths,
    resource: &ManagedConfigResource,
    evidence: &CommandEvidence,
    changed_lines: &[u32],
    proposed_content: &str,
) -> Vec<ManagedConfigDiagnosticView> {
    let parsed = match resource.adapter {
        ManagedConfigAdapter::Nginx
        | ManagedConfigAdapter::NginxTree
        | ManagedConfigAdapter::NginxMain
        | ManagedConfigAdapter::NginxConfD => parse_nginx_config_diagnostics(evidence),
        ManagedConfigAdapter::ApacheTree
        | ManagedConfigAdapter::ApacheMain
        | ManagedConfigAdapter::ApachePorts
        | ManagedConfigAdapter::ApacheConf
        | ManagedConfigAdapter::ApacheSite => parse_apache_config_diagnostics(evidence),
        ManagedConfigAdapter::PhpFpm83Ini
        | ManagedConfigAdapter::PhpFpm83Global
        | ManagedConfigAdapter::PhpFpm83PoolWww
        | ManagedConfigAdapter::PhpFpm83Pool => parse_php_fpm_config_diagnostics(evidence),
    };
    parsed
        .into_iter()
        .take(MANAGED_CONFIG_DIAGNOSTIC_MAX_ENTRIES)
        .filter_map(|diagnostic| {
            let mapped = diagnostic
                .path
                .as_deref()
                .and_then(|path| map_diagnostic_path(paths, resource, Path::new(path)));
            let location_allowed = diagnostic.path.is_none() || mapped.is_some();
            let related_changed_lines = diagnostic
                .line
                .filter(|line| {
                    mapped
                        .as_ref()
                        .is_some_and(|value| value.resource_id == resource.resource_id)
                        && changed_lines.contains(line)
                })
                .into_iter()
                .collect();
            let cause_candidate_lines = diagnostic.line.map_or_else(Vec::new, |reported_line| {
                nginx_cause_candidate_lines(
                    resource,
                    mapped.as_ref(),
                    diagnostic.code,
                    reported_line,
                    changed_lines,
                    proposed_content,
                )
            });
            let value = ManagedConfigDiagnosticView {
                service: String::from(service_key(resource.adapter)),
                validator: String::from(validator_id(resource.adapter)),
                resource_id: mapped.as_ref().map(|value| value.resource_id.clone()),
                masked_path: mapped.as_ref().map(|value| value.masked_path.clone()),
                line: diagnostic.line.filter(|_| location_allowed),
                column: diagnostic.column.filter(|_| location_allowed),
                severity: match diagnostic.severity {
                    ParsedSeverity::Error => ManagedConfigDiagnosticSeverity::Error,
                    ParsedSeverity::Warning => ManagedConfigDiagnosticSeverity::Warning,
                },
                code: String::from(diagnostic.code),
                message: String::from(diagnostic.message),
                related_changed_lines,
                cause_candidate_lines,
            };
            value.validate_shape().is_ok().then_some(value)
        })
        .collect()
}

fn nginx_cause_candidate_lines(
    resource: &ManagedConfigResource,
    mapped: Option<&MappedResource>,
    code: &str,
    reported_line: u32,
    changed_lines: &[u32],
    proposed_content: &str,
) -> Vec<u32> {
    const LOOKBACK_LINES: u32 = 8;
    if !matches!(
        resource.adapter,
        ManagedConfigAdapter::Nginx
            | ManagedConfigAdapter::NginxTree
            | ManagedConfigAdapter::NginxMain
            | ManagedConfigAdapter::NginxConfD
    ) || !matches!(code, "unknown_directive" | "unexpected_token")
        || mapped.is_none_or(|value| value.resource_id != resource.resource_id)
    {
        return Vec::new();
    }
    changed_lines
        .iter()
        .copied()
        .filter(|line| {
            *line < reported_line
                && reported_line.saturating_sub(*line) <= LOOKBACK_LINES
                && nginx_line_looks_incomplete(proposed_content, *line)
        })
        .max()
        .into_iter()
        .collect()
}

fn nginx_line_looks_incomplete(content: &str, line: u32) -> bool {
    let Some(index) = line
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    let Some(value) = content.lines().nth(index) else {
        return false;
    };
    let value = value.trim();
    !value.is_empty()
        && !value.starts_with('#')
        && !value.ends_with(';')
        && !value.ends_with('{')
        && !value.ends_with('}')
}

fn service_key(adapter: ManagedConfigAdapter) -> &'static str {
    match adapter {
        ManagedConfigAdapter::Nginx
        | ManagedConfigAdapter::NginxTree
        | ManagedConfigAdapter::NginxMain
        | ManagedConfigAdapter::NginxConfD => "nginx",
        ManagedConfigAdapter::ApacheTree
        | ManagedConfigAdapter::ApacheMain
        | ManagedConfigAdapter::ApachePorts
        | ManagedConfigAdapter::ApacheConf
        | ManagedConfigAdapter::ApacheSite => "apache",
        ManagedConfigAdapter::PhpFpm83Ini
        | ManagedConfigAdapter::PhpFpm83Global
        | ManagedConfigAdapter::PhpFpm83PoolWww
        | ManagedConfigAdapter::PhpFpm83Pool => "php_fpm",
    }
}

fn validator_id(adapter: ManagedConfigAdapter) -> &'static str {
    let class = adapter.config_test();
    match class {
        CommandClass::NginxConfigTest => "nginx_config_test",
        CommandClass::ApacheConfigTest => "apache_config_test",
        CommandClass::PhpFpm83ConfigTest => "php_fpm_83_config_test",
        _ => "managed_config_test",
    }
}

struct MappedResource {
    resource_id: String,
    masked_path: String,
}

fn map_diagnostic_path(
    paths: &OpsPaths,
    resource: &ManagedConfigResource,
    reported: &Path,
) -> Option<MappedResource> {
    let selected = selected_resource_path(paths, resource)?;
    let selected_or_alias =
        reported == selected || active_alias_matches(paths, resource.adapter, &selected, reported);
    let mapped_path = if selected_or_alias {
        selected.as_path()
    } else {
        reported
    };
    let mut mapped = map_reported_path(paths, resource.adapter, mapped_path)?;
    if selected_or_alias {
        mapped.resource_id.clone_from(&resource.resource_id);
    }
    Some(mapped)
}

fn selected_resource_path(paths: &OpsPaths, resource: &ManagedConfigResource) -> Option<PathBuf> {
    if matches!(
        resource.adapter,
        ManagedConfigAdapter::NginxTree | ManagedConfigAdapter::ApacheTree
    ) {
        service_root(paths, resource.adapter).map(|root| root.join(&resource.display_name))
    } else {
        Some(resource.root.join(&resource.basename))
    }
}

fn active_alias_matches(
    paths: &OpsPaths,
    adapter: ManagedConfigAdapter,
    selected: &Path,
    reported: &Path,
) -> bool {
    let aliases = match adapter {
        ManagedConfigAdapter::Nginx | ManagedConfigAdapter::NginxTree => {
            [Some((&paths.nginx_available, &paths.nginx_enabled)), None]
        }
        ManagedConfigAdapter::ApacheTree | ManagedConfigAdapter::ApacheSite => [
            Some((&paths.apache_sites_available, &paths.apache_sites_enabled)),
            Some((&paths.apache_conf_available, &paths.apache_conf_enabled)),
        ],
        _ => [None, None],
    };
    aliases.into_iter().flatten().any(|(available, enabled)| {
        selected
            .strip_prefix(available)
            .ok()
            .is_some_and(|relative| enabled.join(relative) == reported)
    })
}

fn map_reported_path(
    paths: &OpsPaths,
    adapter: ManagedConfigAdapter,
    reported: &Path,
) -> Option<MappedResource> {
    let root = service_root(paths, adapter)?;
    let relative = reported.strip_prefix(&root).ok()?;
    let relative = safe_tree_relative_path(relative).ok()?;
    if secret_tree_resource(&relative) {
        return None;
    }
    let (resource_id, masked_path) = match adapter {
        ManagedConfigAdapter::Nginx
        | ManagedConfigAdapter::NginxTree
        | ManagedConfigAdapter::NginxMain
        | ManagedConfigAdapter::NginxConfD => (
            managed_service_config_resource_id(
                NGINX_TREE_RESOURCE_PREFIX,
                NGINX_TREE_CONFIG_ADAPTER_ID,
                &relative,
            ),
            format!("/etc/nginx/{relative}"),
        ),
        ManagedConfigAdapter::ApacheTree
        | ManagedConfigAdapter::ApacheMain
        | ManagedConfigAdapter::ApachePorts
        | ManagedConfigAdapter::ApacheConf
        | ManagedConfigAdapter::ApacheSite => (
            managed_service_config_resource_id(
                APACHE_TREE_RESOURCE_PREFIX,
                APACHE_TREE_CONFIG_ADAPTER_ID,
                &relative,
            ),
            format!("/etc/apache2/{relative}"),
        ),
        ManagedConfigAdapter::PhpFpm83Ini => {
            if relative != "php.ini" {
                return None;
            }
            (
                php_fpm_config_resource_id(PHP_FPM_CONFIG_ADAPTER_ID),
                String::from("/etc/php/8.3/fpm/php.ini"),
            )
        }
        ManagedConfigAdapter::PhpFpm83Global => {
            if relative != "php-fpm.conf" {
                return None;
            }
            (
                php_fpm_config_resource_id(PHP_FPM_GLOBAL_CONFIG_ADAPTER_ID),
                String::from("/etc/php/8.3/fpm/php-fpm.conf"),
            )
        }
        ManagedConfigAdapter::PhpFpm83PoolWww | ManagedConfigAdapter::PhpFpm83Pool => {
            let basename = relative.strip_prefix("pool.d/")?;
            if basename.contains('/') {
                return None;
            }
            (
                php_fpm_pool_config_resource_id(basename),
                format!("/etc/php/8.3/fpm/pool.d/{basename}"),
            )
        }
    };
    Some(MappedResource {
        resource_id,
        masked_path,
    })
}

fn service_root(paths: &OpsPaths, adapter: ManagedConfigAdapter) -> Option<PathBuf> {
    match adapter {
        ManagedConfigAdapter::Nginx
        | ManagedConfigAdapter::NginxTree
        | ManagedConfigAdapter::NginxMain
        | ManagedConfigAdapter::NginxConfD => paths.nginx_main.parent().map(Path::to_path_buf),
        ManagedConfigAdapter::ApacheTree
        | ManagedConfigAdapter::ApacheMain
        | ManagedConfigAdapter::ApachePorts
        | ManagedConfigAdapter::ApacheConf
        | ManagedConfigAdapter::ApacheSite => paths.apache_main.parent().map(Path::to_path_buf),
        ManagedConfigAdapter::PhpFpm83Ini
        | ManagedConfigAdapter::PhpFpm83Global
        | ManagedConfigAdapter::PhpFpm83PoolWww
        | ManagedConfigAdapter::PhpFpm83Pool => paths.php_fpm_ini.parent().map(Path::to_path_buf),
    }
}

#[cfg(test)]
mod tests {
    use jw_contracts::{
        NGINX_TREE_CONFIG_ADAPTER_ID, NGINX_TREE_RESOURCE_PREFIX,
        managed_service_config_resource_id,
    };

    use crate::managed_config::ManagedConfigResource;
    use crate::runner::{CommandClass, CommandEvidence, StreamEvidence};

    use super::{ManagedConfigAdapter, OpsPaths, managed_config_diagnostics};

    #[test]
    fn maps_native_include_path_to_opaque_resource_and_changed_line() {
        let paths = OpsPaths::default();
        let expected_resource_id = managed_service_config_resource_id(
            NGINX_TREE_RESOURCE_PREFIX,
            NGINX_TREE_CONFIG_ADAPTER_ID,
            "conf.d/example.conf",
        );
        let resource = ManagedConfigResource {
            adapter: ManagedConfigAdapter::NginxTree,
            resource_id: expected_resource_id.clone(),
            basename: String::from("example.conf"),
            display_name: String::from("conf.d/example.conf"),
            root: std::path::PathBuf::from("/etc/nginx"),
            content: String::from("server {}\n"),
            content_digest: jw_contracts::sha256_digest(b"server {}\n"),
            metadata_digest: jw_contracts::sha256_digest(b"metadata"),
            mode: 0o644,
            uid: 0,
            gid: 0,
        };
        let diagnostics = managed_config_diagnostics(
            &paths,
            &resource,
            &evidence(
                b"nginx: [emerg] unknown directive \"bad\" in /etc/nginx/conf.d/example.conf:13\n",
            ),
            &[13],
            "server {}\n",
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].resource_id.as_deref(),
            Some(expected_resource_id.as_str())
        );
        assert_eq!(
            diagnostics[0].masked_path.as_deref(),
            Some("/etc/nginx/conf.d/example.conf")
        );
        assert_eq!(diagnostics[0].line, Some(13));
        assert_eq!(diagnostics[0].related_changed_lines, vec![13]);
        assert!(diagnostics[0].cause_candidate_lines.is_empty());
    }

    #[test]
    fn maps_active_symlink_location_back_to_the_selected_source() {
        let paths = OpsPaths::default();
        let resource = ManagedConfigResource {
            adapter: ManagedConfigAdapter::NginxTree,
            resource_id: String::from("ngf_0123456789abcdef01234567"),
            basename: String::from("example.conf"),
            display_name: String::from("sites-available/example.conf"),
            root: std::path::PathBuf::from("/etc/nginx/sites-available"),
            content: String::from("server {}\n"),
            content_digest: jw_contracts::sha256_digest(b"server {}\n"),
            metadata_digest: jw_contracts::sha256_digest(b"metadata"),
            mode: 0o644,
            uid: 0,
            gid: 0,
        };
        let diagnostics = managed_config_diagnostics(
            &paths,
            &resource,
            &evidence(
                b"nginx: [emerg] unknown directive \"bad\" in /etc/nginx/sites-enabled/example.conf:13\n",
            ),
            &[13],
            "server {}\n",
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].resource_id.as_deref(),
            Some("ngf_0123456789abcdef01234567")
        );
        assert_eq!(
            diagnostics[0].masked_path.as_deref(),
            Some("/etc/nginx/sites-available/example.conf")
        );
        assert_eq!(diagnostics[0].related_changed_lines, vec![13]);
        assert!(diagnostics[0].cause_candidate_lines.is_empty());
    }

    #[test]
    fn does_not_relate_an_included_resource_line_to_the_selected_diff() {
        let paths = OpsPaths::default();
        let diagnostics = managed_config_diagnostics(
            &paths,
            &resource(),
            &evidence(
                b"nginx: [emerg] unknown directive \"bad\" in /etc/nginx/conf.d/example.conf:13\n",
            ),
            &[13],
            "server {}\n",
        );
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].related_changed_lines.is_empty());
        assert!(diagnostics[0].cause_candidate_lines.is_empty());
    }

    #[test]
    fn does_not_expose_location_outside_managed_root() {
        let diagnostics = managed_config_diagnostics(
            &OpsPaths::default(),
            &resource(),
            &evidence(b"nginx: [emerg] failure in /tmp/private.conf:19\n"),
            &[19],
            "events {}\n",
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].resource_id, None);
        assert_eq!(diagnostics[0].masked_path, None);
        assert_eq!(diagnostics[0].line, None);
        assert_eq!(diagnostics[0].column, None);
    }

    #[test]
    fn preserves_the_native_line_and_marks_one_incomplete_prior_changed_line() {
        let content = [
            "events {}",
            "http {",
            "    include mime.types;",
            "    default_type application/octet-stream;",
            "    # unchanged",
            "    # unchanged",
            "    # unchanged",
            "    # unchanged",
            "    # unchanged",
            "    # unchanged",
            "    # unchanged",
            "    # unchanged",
            "    accidental_text",
            "    ##",
            "    # Basic Settings",
            "    ##",
            "",
            "    sendfile on;",
            "}",
        ]
        .join("\n");
        let diagnostics = managed_config_diagnostics(
            &OpsPaths::default(),
            &resource(),
            &evidence(
                b"nginx: [emerg] unknown directive \"accidental_text\" in /etc/nginx/nginx.conf:18\n",
            ),
            &[13],
            &content,
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].line, Some(18));
        assert!(diagnostics[0].related_changed_lines.is_empty());
        assert_eq!(diagnostics[0].cause_candidate_lines, vec![13]);
    }

    #[test]
    fn does_not_guess_a_prior_line_outside_the_bounded_window() {
        let content = "accidental_text\n\n\n\n\n\n\n\n\nsendfile on;\n";
        let diagnostics = managed_config_diagnostics(
            &OpsPaths::default(),
            &resource(),
            &evidence(b"nginx: [emerg] unexpected token in /etc/nginx/nginx.conf:10\n"),
            &[1],
            content,
        );
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].cause_candidate_lines.is_empty());
    }

    fn resource() -> ManagedConfigResource {
        ManagedConfigResource {
            adapter: ManagedConfigAdapter::NginxTree,
            resource_id: String::from("ngf_0123456789abcdef01234567"),
            basename: String::from("nginx.conf"),
            display_name: String::from("nginx.conf"),
            root: std::path::PathBuf::from("/etc/nginx"),
            content: String::from("events {}\n"),
            content_digest: jw_contracts::sha256_digest(b"events {}\n"),
            metadata_digest: jw_contracts::sha256_digest(b"metadata"),
            mode: 0o644,
            uid: 0,
            gid: 0,
        }
    }

    fn evidence(stderr: &[u8]) -> CommandEvidence {
        CommandEvidence {
            class: CommandClass::NginxConfigTest,
            success: false,
            exit_code: Some(1),
            timed_out: false,
            stdout: StreamEvidence {
                digest: String::from("sha256:stdout"),
                captured: Vec::new(),
                truncated: false,
            },
            stderr: StreamEvidence {
                digest: String::from("sha256:stderr"),
                captured: stderr.to_vec(),
                truncated: false,
            },
        }
    }
}
