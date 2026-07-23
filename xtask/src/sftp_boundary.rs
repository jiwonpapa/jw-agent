use super::*;

pub(super) fn gate_p2_sftp_boundary(root: &Path, _timeout: Duration) -> Result<(), String> {
    let root_manifest = read_text(&root.join("Cargo.toml"))?;
    let agent_manifest = read_text(&root.join("crates/jw-agentd/Cargo.toml"))?;
    let package_control = read_text(&root.join("packaging/debian/control"))?;
    let spec = read_text(&root.join("docs/90-specs/access/openssh-sftp-readonly-v1.md"))?;
    let upload_spec =
        read_text(&root.join("docs/90-specs/access/openssh-sftp-atomic-upload-v1.md"))?;
    let session = read_text(&root.join("crates/jw-agentd/src/file_session.rs"))?;
    let openssh = read_text(&root.join("crates/jw-agentd/src/openssh.rs"))?;
    let protocol = read_text(&root.join("crates/jw-agentd/src/sftp_protocol.rs"))?;
    let contract = read_text(&root.join("crates/jw-contracts/src/files.rs"))?;
    let audit = read_text(&root.join("crates/jw-agentd/migrations/0003_file_audit.sql"))?;
    let upload_audit =
        read_text(&root.join("crates/jw-agentd/migrations/0004_file_upload_audit.sql"))?;
    let edge = read_text(&root.join("packaging/nginx/jw-agent-management.conf.template"))?;
    let mut failures = Vec::new();

    for (content, needle, label) in [
        (&spec, "Status: Accepted", "Accepted SFTP spec"),
        (
            &upload_spec,
            "Status: Accepted",
            "Accepted atomic upload spec",
        ),
        (
            &package_control,
            "openssh-client",
            "OpenSSH package dependency",
        ),
        (
            &openssh,
            "OsString::from(\"-s\")",
            "fixed SSH subsystem mode",
        ),
        (&openssh, "OsString::from(\"sftp\")", "fixed SFTP subsystem"),
        (&openssh, "RequestTTY=no", "PTY denial"),
        (&openssh, "StrictHostKeyChecking=yes", "strict host key"),
        (
            &openssh,
            "OsString::from(LOOPBACK_HOST)",
            "fixed loopback destination",
        ),
        (
            &contract,
            "FILE_IDLE_TIMEOUT_SECONDS: u64 = 0",
            "route-independent file session lifetime",
        ),
        (
            &session,
            "authenticate_session(",
            "login-bound file session lifetime",
        ),
        (&protocol, "SSH_FXP_REALPATH", "server canonical path check"),
        (&protocol, "FILE_MAX_LIST_ENTRIES", "directory entry bound"),
        (&protocol, "FILE_MAX_TEXT_BYTES", "text bound"),
        (&protocol, "FILE_MAX_DOWNLOAD_BYTES", "download bound"),
        (&protocol, "SSH_FXP_WRITE", "bounded SFTP write message"),
        (
            &protocol,
            "open_write_exclusive",
            "exclusive temporary create",
        ),
        (&protocol, "EXTENSION_FSYNC", "OpenSSH fsync extension"),
        (
            &protocol,
            "EXTENSION_POSIX_RENAME",
            "OpenSSH atomic rename extension",
        ),
        (&session, "plan_upload", "memory-only upload plan"),
        (&contract, "FILE_UPLOAD_PLAN_TTL_SECONDS", "upload plan TTL"),
        (&contract, "validate_file_path", "relative path validator"),
        (&audit, "path_digest BLOB", "path digest audit"),
        (&audit, "file_access_events", "file access audit table"),
        (&upload_audit, "file_uploads", "file upload audit table"),
        (
            &edge,
            "location = /api/v1/files/upload",
            "exact upload edge route",
        ),
        (&edge, "client_max_body_size 8m;", "bounded upload body"),
    ] {
        if !content.contains(needle) {
            failures.push(format!("missing {label}"));
        }
    }
    for forbidden in [
        "SSH_FXP_RENAME",
        "SSH_FXP_MKDIR",
        "SSH_FXP_RMDIR",
        "SSH_FXP_SETSTAT",
        "SSH_FXP_FSETSTAT",
        "SSH_FXP_SYMLINK",
    ] {
        if protocol.contains(forbidden) {
            failures.push(format!(
                "read-only SFTP client contains forbidden {forbidden}"
            ));
        }
    }
    if root_manifest.contains("russh") || agent_manifest.contains("russh") {
        failures.push(String::from(
            "Rust SSH stack is forbidden for the local MVP",
        ));
    }
    for forbidden in ["path TEXT", "content", "password", "token", "file_body"] {
        if audit.contains(forbidden) || upload_audit.contains(forbidden) {
            failures.push(format!(
                "file audit schema contains forbidden {forbidden} field"
            ));
        }
    }
    let opsd = root.join("crates/jw-opsd/src");
    for file in regular_files(&opsd)? {
        if file.extension() == Some(OsStr::new("rs")) {
            let content = read_text(&file)?;
            if content.contains("SftpProtocol")
                || content.contains("FilePathRequest")
                || content.contains("SSH_FXP_")
            {
                failures.push(format!(
                    "root helper gained SFTP surface in {}",
                    display_relative(root, &file)
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}
