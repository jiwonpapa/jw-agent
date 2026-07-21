use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use jw_contracts::{
    AssuranceLevel, AssuranceView, CertificateInventoryView, CertificateSummaryView,
    OPERATION_SCHEMA_VERSION, RollbackSupport, sha256_digest, validate_domain,
};
use serde::Serialize;

use crate::config::OpsPaths;
use crate::error::OpsError;
use crate::runner::{CommandClass, OperationRunner};

const CERTIFICATE_MAX_BYTES: u64 = 256 * 1_024;
const COMMAND_OUTPUT_MAX_BYTES: usize = 64 * 1_024;
const OPENSSL_TIMEOUT: Duration = Duration::from_secs(5);

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
    let certbot_installed = Path::new("/usr/bin/certbot").is_file();
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
    let mut command = Command::new("/usr/bin/openssl");
    command
        .args(["x509", "-in"])
        .arg(path)
        .args([
            "-noout",
            "-fingerprint",
            "-sha256",
            "-enddate",
            "-dateopt",
            "iso_8601",
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
