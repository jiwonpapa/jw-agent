use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use jw_contracts::{
    AssuranceLevel, AssuranceView, CertbotIssuePlanInput, CertificateEnvironment,
    CertificateInventoryView, CertificateSummaryView, NginxSiteState, OPERATION_SCHEMA_VERSION,
    RollbackSupport, sha256_digest, validate_domain,
};
use serde::Deserialize;
use serde::Serialize;

use crate::config::OpsPaths;
use crate::error::OpsError;
use crate::managed_config::{ManagedConfigResource, discover_protected_config};
use crate::nginx::{NginxSite, discover_site, read_available_content};
use crate::runner::{CommandClass, OperationRunner};

const CERTIFICATE_MAX_BYTES: u64 = 256 * 1_024;
const COMMAND_OUTPUT_MAX_BYTES: usize = 64 * 1_024;
const OPENSSL_TIMEOUT: Duration = Duration::from_secs(5);
const ACME_CHALLENGE_INCLUDE: &[u8] = b"include /usr/share/jw-agent/nginx/acme-challenge.conf;";

pub const CERTBOT_ISSUE_IMPACT: [&str; 4] = [
    "staging은 Let’s Encrypt 시험 CA에 실제 challenge를 요청하지만 인증서를 저장하지 않습니다.",
    "production은 공개 CA 발급·rate-limit 기록을 만들며 이 외부 효과는 원복할 수 없습니다.",
    "이번 작업은 인증서 발급까지만 수행하고 Nginx TLS 연결은 별도 G2 승인으로 남깁니다.",
    "실행 결과 원문과 계정 이메일은 감사 로그에 남기지 않고 digest와 마스킹 값만 기록합니다.",
];

pub const CERTBOT_ISSUE_RECOVERY_PATH: [&str; 3] = [
    "SSH에서 certbot certificates와 해당 domain의 renewal 상태를 확인합니다.",
    "감사 영수증의 environment·command class·exit·timeout digest를 확인합니다.",
    "발급 성공 후에는 별도 TLS attach 계획을 만들고, 실패하면 DNS·80 포트·webroot를 수정한 뒤 새 계획을 만듭니다.",
];

pub const CERTBOT_RENEW_IMPACT: [&str; 3] = [
    "Certbot이 ACME staging 서버에 실제 갱신 challenge를 요청할 수 있습니다.",
    "인증서 교체를 적용하지 않는 dry-run이지만 외부 CA 통신과 challenge 요청은 되돌릴 수 없습니다.",
    "실행은 최대 12분 걸릴 수 있으며 결과 원문 대신 digest와 상태만 기록합니다.",
];

pub const CERTBOT_RENEW_RECOVERY_PATH: [&str; 3] = [
    "SSH로 certbot.timer와 Nginx 상태를 확인합니다.",
    "감사 영수증의 command class·exit·timeout digest를 확인합니다.",
    "중단된 dry-run은 새 계획과 재인증으로 다시 실행합니다.",
];

pub const CERTBOT_ATTACH_IMPACT: [&str; 4] = [
    "보호된 JW Agent Nginx vhost의 ssl_certificate 두 지시문만 표준 Certbot lineage로 교체합니다.",
    "nginx -t 통과 뒤 nginx.service를 reload하며 연결이 잠시 재수립될 수 있습니다.",
    "SNI TLS 응답 지문·Nginx active·certbot.timer·renewal 설정을 모두 다시 확인합니다.",
    "교체·문법·reload·TLS 검증 실패 시 Nginx 파일 원본 bytes·owner·mode를 자동 복원합니다.",
];

pub const CERTBOT_ATTACH_RECOVERY_PATH: [&str; 4] = [
    "SSH로 서버에 접속합니다.",
    "JW Agent receipt의 operation ID와 rollback 결과를 확인합니다.",
    "보호된 관리 vhost의 ssl_certificate 지시문과 snapshot을 비교합니다.",
    "nginx -t와 로컬 SNI TLS 지문을 확인한 뒤 nginx.service를 reload합니다.",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertbotRenewPlanPayload {
    pub inventory_digest: String,
    pub timer_enabled: bool,
    pub timer_active: bool,
    pub certificate_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertbotIssuePlanPayload {
    pub primary_domain: String,
    pub domains: Vec<String>,
    pub account_email_proposal_relative_path: String,
    pub account_email_proposal_digest: String,
    pub masked_account_email: String,
    pub environment: CertificateEnvironment,
    pub site_id: String,
    pub site_digest: String,
    pub inventory_digest: String,
    pub preflight_observed_at_ms: i64,
    pub resolved_addresses: Vec<String>,
    pub local_port_80_reachable: bool,
    pub local_port_443_reachable: bool,
    pub staging_evidence_valid: bool,
    pub staging_evidence_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertbotAttachPlanPayload {
    pub primary_domain: String,
    pub site_id: String,
    pub site_digest: String,
    pub metadata_digest: String,
    pub inventory_digest: String,
    pub certificate_fingerprint: String,
    pub sans: Vec<String>,
    pub not_after: String,
    pub current_certificate_path: String,
    pub target_certificate_path: String,
    pub proposed_content_digest: String,
    pub timer_enabled: bool,
    pub timer_active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsAttachmentResource {
    pub config: ManagedConfigResource,
    pub proposed_content: String,
    pub proposed_content_digest: String,
    pub current_certificate_path: String,
    pub target_certificate_path: String,
}

pub fn prepare_tls_attachment(
    paths: &OpsPaths,
    primary_domain: &str,
    site_id: &str,
    expected_site_digest: &str,
) -> Result<TlsAttachmentResource, OpsError> {
    validate_domain(primary_domain).map_err(OpsError::Rejected)?;
    let config = discover_protected_config(paths, site_id)?;
    if config.content_digest != expected_site_digest {
        return Err(OpsError::Rejected("stale_site"));
    }
    if !server_names_cover(config.content.as_bytes(), &[primary_domain.to_owned()]) {
        return Err(OpsError::Rejected("invalid_domain"));
    }
    let fullchain = paths
        .letsencrypt_live
        .join(primary_domain)
        .join("fullchain.pem");
    let private_key = paths
        .letsencrypt_live
        .join(primary_domain)
        .join("privkey.pem");
    let fullchain_text = fullchain
        .to_str()
        .ok_or(OpsError::Rejected("certificate_path_policy"))?;
    let private_key_text = private_key
        .to_str()
        .ok_or(OpsError::Rejected("certificate_path_policy"))?;
    if fullchain_text
        .bytes()
        .any(|byte| byte.is_ascii_whitespace())
        || private_key_text
            .bytes()
            .any(|byte| byte.is_ascii_whitespace())
    {
        return Err(OpsError::Rejected("certificate_path_policy"));
    }
    let (proposed_content, current_certificate_path) =
        replace_tls_directives(&config.content, fullchain_text, private_key_text)?;
    Ok(TlsAttachmentResource {
        proposed_content_digest: sha256_digest(proposed_content.as_bytes()),
        target_certificate_path: format!("…/live/{primary_domain}/fullchain.pem"),
        current_certificate_path,
        config,
        proposed_content,
    })
}

fn replace_tls_directives(
    content: &str,
    fullchain: &str,
    private_key: &str,
) -> Result<(String, String), OpsError> {
    let mut certificate_count = 0_u8;
    let mut private_key_count = 0_u8;
    let mut current_certificate_path: Option<String> = None;
    let mut output = String::with_capacity(content.len().saturating_add(128));
    for line in content.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let bare = match line.strip_suffix('\n') {
            Some(value) => value,
            None => line,
        };
        let trimmed = bare.trim();
        let indentation_len = bare.len().saturating_sub(bare.trim_start().len());
        let indentation = &bare[..indentation_len];
        if let Some(value) = directive_value(trimmed, "ssl_certificate") {
            certificate_count = certificate_count.saturating_add(1);
            current_certificate_path = Some(mask_path(value));
            output.push_str(indentation);
            output.push_str("ssl_certificate ");
            output.push_str(fullchain);
            output.push(';');
        } else if directive_value(trimmed, "ssl_certificate_key").is_some() {
            private_key_count = private_key_count.saturating_add(1);
            output.push_str(indentation);
            output.push_str("ssl_certificate_key ");
            output.push_str(private_key);
            output.push(';');
        } else {
            output.push_str(bare);
        }
        if has_newline {
            output.push('\n');
        }
    }
    if certificate_count != 1 || private_key_count != 1 {
        return Err(OpsError::Rejected("attach_unsupported"));
    }
    Ok((
        output,
        current_certificate_path.ok_or(OpsError::Rejected("attach_unsupported"))?,
    ))
}

fn directive_value<'a>(line: &'a str, directive: &str) -> Option<&'a str> {
    let rest = line
        .strip_prefix(directive)?
        .strip_prefix(char::is_whitespace)?;
    let value = rest.trim().strip_suffix(';')?.trim();
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        None
    } else {
        Some(value)
    }
}

fn mask_path(value: &str) -> String {
    let components: Vec<_> = Path::new(value)
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    if components.len() >= 3 {
        format!(
            "…/{}",
            components[components.len().saturating_sub(3)..].join("/")
        )
    } else {
        Path::new(value)
            .file_name()
            .and_then(|name| name.to_str())
            .map_or_else(
                || String::from("…/certificate.pem"),
                |name| format!("…/{name}"),
            )
    }
}

pub fn validate_issue_preconditions(
    paths: &OpsPaths,
    input: &CertbotIssuePlanInput,
    now_ms: i64,
) -> Result<NginxSite, OpsError> {
    input.validate(now_ms).map_err(OpsError::Rejected)?;
    let request = &input.request;
    validate_issue_site(
        paths,
        &request.site_id,
        &request.expected_site_digest,
        &request.domains(),
    )
}

pub fn validate_issue_site(
    paths: &OpsPaths,
    site_id: &str,
    expected_site_digest: &str,
    domains: &[String],
) -> Result<NginxSite, OpsError> {
    let site = discover_site(paths, site_id)?;
    if !site.protected || site.state != NginxSiteState::Enabled {
        return Err(OpsError::Rejected("unsupported_environment"));
    }
    if site.available_digest != expected_site_digest {
        return Err(OpsError::Rejected("stale_site"));
    }
    let (content, _, _) = read_available_content(paths, &site.basename)?;
    if !contains_bytes(&content, ACME_CHALLENGE_INCLUDE) || !server_names_cover(&content, domains) {
        return Err(OpsError::Rejected("wrong_webroot"));
    }
    validate_directory(&paths.acme_webroot, paths.enforce_root_ownership)
        .map_err(|_| OpsError::Rejected("wrong_webroot"))?;
    Ok(site)
}

fn server_names_cover(content: &[u8], expected: &[String]) -> bool {
    let Ok(text) = std::str::from_utf8(content) else {
        return false;
    };
    let mut names = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(value) = trimmed
            .strip_prefix("server_name ")
            .and_then(|value| value.strip_suffix(';'))
        else {
            continue;
        };
        for name in value.split_ascii_whitespace() {
            if validate_domain(name).is_ok() {
                names.push(name.to_owned());
            }
        }
    }
    names.sort();
    names.dedup();
    expected
        .iter()
        .all(|domain| names.binary_search(domain).is_ok())
}

fn contains_bytes(value: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && value.windows(needle.len()).any(|window| window == needle)
}

#[must_use]
pub fn mask_account_email(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return String::from("***");
    };
    let first: String = local.chars().take(1).collect();
    format!("{first}***@{domain}")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InventoryDigest<'a> {
    certbot_installed: bool,
    timer_enabled: bool,
    timer_active: bool,
    certificates: &'a [CertificateSummaryView],
    problems: &'a [String],
}

pub fn certificate_inventory(
    paths: &OpsPaths,
    runner: &dyn OperationRunner,
    now_ms: i64,
) -> Result<CertificateInventoryView, OpsError> {
    let certbot_installed = paths.certbot_executable.is_file();
    let timer_enabled = runner
        .run(CommandClass::CertbotTimerEnabled)
        .is_ok_and(|evidence| evidence.success);
    let timer_active = runner
        .run(CommandClass::CertbotTimerActive)
        .is_ok_and(|evidence| evidence.success);
    let (certificates, mut problems) = discover_certificates(paths)?;
    if !certbot_installed {
        problems.push(String::from("certbot_not_installed"));
    }
    if !timer_enabled {
        problems.push(String::from("certbot_timer_disabled"));
    }
    if !timer_active {
        problems.push(String::from("certbot_timer_inactive"));
    }
    problems.sort();
    problems.dedup();
    let digest_bytes = serde_json::to_vec(&InventoryDigest {
        certbot_installed,
        timer_enabled,
        timer_active,
        certificates: &certificates,
        problems: &problems,
    })
    .map_err(|error| OpsError::Storage(error.to_string()))?;
    Ok(CertificateInventoryView {
        schema_version: OPERATION_SCHEMA_VERSION,
        observed_at: format_time(now_ms)?,
        certbot_installed,
        timer_enabled,
        timer_active,
        inventory_digest: sha256_digest(&digest_bytes),
        certificates,
        problems,
        issue_operation_type: None,
        renew_test_operation_type: None,
        attach_operation_type: None,
        assurance: inventory_assurance(),
    })
}

fn discover_certificates(
    paths: &OpsPaths,
) -> Result<(Vec<CertificateSummaryView>, Vec<String>), OpsError> {
    if !paths.letsencrypt_renewal.exists() {
        return Ok((Vec::new(), Vec::new()));
    }
    validate_directory(&paths.letsencrypt_renewal, paths.enforce_root_ownership)?;
    let entries = fs::read_dir(&paths.letsencrypt_renewal)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    let mut domains = Vec::new();
    let mut problems = Vec::new();
    for entry_result in entries {
        let entry = entry_result.map_err(|error| OpsError::Filesystem(error.to_string()))?;
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some(domain) = file_name.strip_suffix(".conf") else {
            continue;
        };
        if validate_domain(domain).is_err() {
            problems.push(String::from("invalid_renewal_lineage_name"));
            continue;
        }
        domains.push(domain.to_owned());
    }
    domains.sort();
    domains.dedup();
    let mut certificates = Vec::new();
    for domain in domains {
        match inspect_lineage(paths, &domain) {
            Ok(certificate) => certificates.push(certificate),
            Err(_) => problems.push(format!("certificate_invalid:{domain}")),
        }
    }
    Ok((certificates, problems))
}

fn inspect_lineage(paths: &OpsPaths, domain: &str) -> Result<CertificateSummaryView, OpsError> {
    let renewal_path = paths.letsencrypt_renewal.join(format!("{domain}.conf"));
    validate_regular_file(&renewal_path, paths.enforce_root_ownership, 64 * 1_024)?;
    let renewal = fs::read_to_string(&renewal_path)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    let live = paths.letsencrypt_live.join(domain);
    validate_directory(&paths.letsencrypt_live, paths.enforce_root_ownership)?;
    validate_directory(&paths.letsencrypt_archive, paths.enforce_root_ownership)?;
    validate_directory(&live, paths.enforce_root_ownership)?;
    validate_directory(
        &paths.letsencrypt_archive.join(domain),
        paths.enforce_root_ownership,
    )?;
    let fullchain = live.join("fullchain.pem");
    let private_key = live.join("privkey.pem");
    validate_lineage_target(paths, domain, &fullchain, false)?;
    validate_lineage_target(paths, domain, &private_key, true)?;
    let output = inspect_x509(&fullchain)?;
    let (fingerprint_sha256, not_after, mut sans) = parse_x509_output(&output)?;
    sans.sort();
    sans.dedup();
    if !sans.iter().any(|value| value == domain) {
        return Err(OpsError::Rejected("certificate_invalid"));
    }
    let webroot_authenticator = renewal
        .lines()
        .any(|line| line.trim() == "authenticator = webroot");
    let managed_webroot = renewal
        .lines()
        .any(|line| line.trim() == "webroot_path = /var/lib/jw-agent/acme-webroot");
    Ok(CertificateSummaryView {
        primary_domain: domain.to_owned(),
        sans,
        not_after,
        fingerprint_sha256,
        certificate_path: format!("…/live/{domain}/fullchain.pem"),
        private_key_present: true,
        renewal_config_present: true,
        webroot_managed: webroot_authenticator && managed_webroot,
    })
}

fn validate_lineage_target(
    paths: &OpsPaths,
    domain: &str,
    path: &Path,
    private_key: bool,
) -> Result<(), OpsError> {
    let link_metadata =
        fs::symlink_metadata(path).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if !link_metadata.file_type().is_symlink() {
        return Err(OpsError::Rejected("certificate_path_policy"));
    }
    let target = fs::canonicalize(path).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    let archive = fs::canonicalize(paths.letsencrypt_archive.join(domain))
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    let archive_root = fs::canonicalize(&paths.letsencrypt_archive)
        .map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if !archive.starts_with(&archive_root) || !target.starts_with(&archive) {
        return Err(OpsError::Rejected("certificate_path_policy"));
    }
    let metadata =
        fs::metadata(&target).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > CERTIFICATE_MAX_BYTES {
        return Err(OpsError::Rejected("certificate_invalid"));
    }
    #[cfg(unix)]
    if paths.enforce_root_ownership
        && (metadata.uid() != 0 || (private_key && metadata.mode() & 0o077 != 0))
    {
        return Err(OpsError::Rejected("certificate_path_policy"));
    }
    Ok(())
}

fn inspect_x509(path: &Path) -> Result<String, OpsError> {
    #[cfg(target_os = "macos")]
    let executable = "/opt/homebrew/bin/openssl";
    #[cfg(not(target_os = "macos"))]
    let executable = "/usr/bin/openssl";
    let mut command = Command::new(executable);
    command
        .args(["x509", "-in"])
        .arg(path)
        .args([
            "-noout",
            "-fingerprint",
            "-sha256",
            "-enddate",
            "-checkend",
            "0",
            "-ext",
            "subjectAltName",
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| OpsError::Command(error.to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| OpsError::Command(String::from("openssl stdout unavailable")))?;
    let reader = std::thread::spawn(move || read_bounded(stdout));
    let started = Instant::now();
    let status = loop {
        match child
            .try_wait()
            .map_err(|error| OpsError::Command(error.to_string()))?
        {
            Some(status) => break status,
            None if started.elapsed() < OPENSSL_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(20));
            }
            None => {
                child
                    .kill()
                    .map_err(|error| OpsError::Command(error.to_string()))?;
                let _status = child
                    .wait()
                    .map_err(|error| OpsError::Command(error.to_string()))?;
                return Err(OpsError::Rejected("certificate_inspection_timeout"));
            }
        }
    };
    let bytes = join_reader(reader)?;
    if !status.success() {
        return Err(OpsError::Rejected("certificate_invalid"));
    }
    String::from_utf8(bytes).map_err(|_| OpsError::Rejected("certificate_invalid"))
}

fn read_bounded<R: Read>(mut reader: R) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4 * 1_024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        if output.len().saturating_add(count) > COMMAND_OUTPUT_MAX_BYTES {
            return Err(String::from("openssl output limit exceeded"));
        }
        output.extend_from_slice(&buffer[..count]);
    }
    Ok(output)
}

fn join_reader(handle: JoinHandle<Result<Vec<u8>, String>>) -> Result<Vec<u8>, OpsError> {
    handle
        .join()
        .map_err(|_| OpsError::Command(String::from("openssl reader failed")))?
        .map_err(OpsError::Command)
}

fn parse_x509_output(output: &str) -> Result<(String, String, Vec<String>), OpsError> {
    let mut fingerprint: Option<String> = None;
    let mut not_after: Option<String> = None;
    let mut sans = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed
            .strip_prefix("sha256 Fingerprint=")
            .or_else(|| trimmed.strip_prefix("SHA256 Fingerprint="))
        {
            let hex = value.replace(':', "").to_ascii_lowercase();
            if hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                fingerprint = Some(format!("sha256:{hex}"));
            }
        }
        if let Some(value) = trimmed.strip_prefix("notAfter=") {
            not_after = Some(value.to_owned());
        }
        for item in trimmed.split(',') {
            if let Some(domain) = item.trim().strip_prefix("DNS:")
                && validate_domain(domain).is_ok()
            {
                sans.push(domain.to_owned());
            }
        }
    }
    match (fingerprint, not_after) {
        (Some(fingerprint), Some(not_after)) if !sans.is_empty() => {
            Ok((fingerprint, not_after, sans))
        }
        _ => Err(OpsError::Rejected("certificate_invalid")),
    }
}

fn validate_directory(path: &Path, enforce_root: bool) -> Result<(), OpsError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(OpsError::Rejected("certificate_path_policy"));
    }
    #[cfg(unix)]
    if enforce_root && (metadata.uid() != 0 || metadata.mode() & 0o022 != 0) {
        return Err(OpsError::Rejected("certificate_path_policy"));
    }
    Ok(())
}

fn validate_regular_file(path: &Path, enforce_root: bool, max: u64) -> Result<(), OpsError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| OpsError::Filesystem(error.to_string()))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > max
    {
        return Err(OpsError::Rejected("certificate_path_policy"));
    }
    #[cfg(unix)]
    if enforce_root && (metadata.uid() != 0 || metadata.mode() & 0o022 != 0) {
        return Err(OpsError::Rejected("certificate_path_policy"));
    }
    Ok(())
}

fn format_time(milliseconds: i64) -> Result<String, OpsError> {
    let nanoseconds = i128::from(milliseconds).saturating_mul(1_000_000);
    let value = time::OffsetDateTime::from_unix_timestamp_nanos(nanoseconds)
        .map_err(|error| OpsError::Storage(error.to_string()))?;
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| OpsError::Storage(error.to_string()))
}

fn inventory_assurance() -> AssuranceView {
    AssuranceView {
        level: AssuranceLevel::G0ObserveOnly,
        rollback_support: RollbackSupport::NotApplicable,
        operation_available: false,
        scope: vec![String::from(
            "certificate SAN·만료·fingerprint와 Certbot timer 상태만 조회합니다.",
        )],
        excluded_effects: vec![String::from(
            "private key·ACME account secret·certificate 원문을 읽거나 반환하지 않습니다.",
        )],
        apply_verifier: Vec::new(),
        rollback_verifier: Vec::new(),
        reason: Some(String::from(
            "발급·attach 작업은 P2C operation fault gate 전까지 차단됩니다.",
        )),
    }
}

#[must_use]
pub fn renew_test_assurance() -> AssuranceView {
    AssuranceView {
        level: AssuranceLevel::G1VerifiedAction,
        rollback_support: RollbackSupport::NotGuaranteed,
        operation_available: true,
        scope: vec![String::from(
            "고정된 certbot renew --dry-run만 one-shot network runner에서 실행합니다.",
        )],
        excluded_effects: vec![String::from(
            "CA challenge·rate-limit 기록 같은 외부 효과는 원복할 수 없습니다.",
        )],
        apply_verifier: vec![
            String::from("Certbot exit와 timeout 상태를 digest-only 증거로 검증합니다."),
            String::from("certbot.timer와 sanitized certificate inventory를 다시 읽습니다."),
        ],
        rollback_verifier: Vec::new(),
        reason: Some(String::from(
            "로컬 설정을 바꾸지 않는 외부 갱신 검증이므로 자동 원복 대상이 없습니다.",
        )),
    }
}

#[must_use]
pub fn issue_assurance() -> AssuranceView {
    AssuranceView {
        level: AssuranceLevel::G1VerifiedAction,
        rollback_support: RollbackSupport::NotGuaranteed,
        operation_available: true,
        scope: vec![String::from(
            "canonical domain에 대해 고정 webroot Certbot staging 또는 production 발급만 실행합니다.",
        )],
        excluded_effects: vec![
            String::from("CA challenge·계정·발급·rate-limit 기록은 원복할 수 없습니다."),
            String::from("Nginx TLS 연결은 이 작업에 포함하지 않고 별도 G2 계획으로 수행합니다."),
        ],
        apply_verifier: vec![
            String::from("staging은 비저장 dry-run exit와 timeout을 digest-only로 확인합니다."),
            String::from(
                "production은 표준 lineage의 SAN·fingerprint·webroot renewal 설정을 다시 읽습니다.",
            ),
        ],
        rollback_verifier: Vec::new(),
        reason: Some(String::from(
            "외부 CA 효과는 되돌릴 수 없어 발급 결과 검증만 보장합니다.",
        )),
    }
}

#[must_use]
pub fn attach_assurance() -> AssuranceView {
    AssuranceView {
        level: AssuranceLevel::G2ReversibleConfig,
        rollback_support: RollbackSupport::AutomaticBounded,
        operation_available: true,
        scope: vec![String::from(
            "보호된 관리 vhost의 인증서·개인키 지시문 두 개와 Nginx reload만 변경합니다.",
        )],
        excluded_effects: vec![String::from(
            "인증서 발급·폐기·DNS·firewall·다른 Nginx 파일은 변경하거나 원복하지 않습니다.",
        )],
        apply_verifier: vec![
            String::from("nginx -t, reload, active 상태를 확인합니다."),
            String::from("127.0.0.1:443 SNI 응답의 인증서 SHA-256 지문을 확인합니다."),
            String::from("Certbot lineage·renewal config·timer 상태를 다시 읽습니다."),
        ],
        rollback_verifier: vec![
            String::from("snapshot의 원본 bytes·owner·mode를 복원합니다."),
            String::from("복원 뒤 nginx -t, reload, active 상태를 다시 확인합니다."),
        ],
        reason: Some(String::from(
            "로컬 Nginx 설정 범위만 자동 원복하며 이미 발생한 CA 외부 효과는 포함하지 않습니다.",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_x509_output;

    #[test]
    fn parses_only_bounded_public_certificate_metadata() -> Result<(), String> {
        let output = "sha256 Fingerprint=AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA\nnotAfter=2026-10-20 12:00:00Z\nX509v3 Subject Alternative Name:\n    DNS:example.com, DNS:www.example.com\n";
        let (fingerprint, not_after, sans) =
            parse_x509_output(output).map_err(|error| error.to_string())?;
        assert_eq!(fingerprint, format!("sha256:{}", "aa".repeat(32)));
        assert_eq!(not_after, "2026-10-20 12:00:00Z");
        assert_eq!(sans, vec!["example.com", "www.example.com"]);
        Ok(())
    }
}
