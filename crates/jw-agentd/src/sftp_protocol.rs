use std::time::Duration;

use jw_contracts::{
    FILE_MAX_DOWNLOAD_BYTES, FILE_MAX_LIST_ENTRIES, FILE_MAX_PATH_BYTES, FILE_MAX_TEXT_BYTES,
    FILE_MAX_UPLOAD_BYTES, FileEntryView, FileKind, FileListView, FileStatView, FileTextView,
    FileUploadTargetState, is_reserved_upload_name, sha256_digest, validate_file_path,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{ChildStdin, ChildStdout};
use tokio::time::timeout;

const SFTP_VERSION: u32 = 3;
const PACKET_MAX_BYTES: usize = 256 * 1_024;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const READ_CHUNK_BYTES: u32 = 32 * 1_024;
const SSH_FXF_READ: u32 = 0x0000_0001;
const SSH_FXF_WRITE: u32 = 0x0000_0002;
const SSH_FXF_CREAT: u32 = 0x0000_0008;
const SSH_FXF_EXCL: u32 = 0x0000_0020;
const SSH_FILEXFER_ATTR_SIZE: u32 = 0x0000_0001;
const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x0000_0002;
const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x0000_0004;
const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x0000_0008;
const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x8000_0000;

const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;
const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_LSTAT: u8 = 7;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REALPATH: u8 = 16;
const SSH_FXP_STAT: u8 = 17;
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_DATA: u8 = 103;
const SSH_FXP_NAME: u8 = 104;
const SSH_FXP_ATTRS: u8 = 105;
const SSH_FXP_EXTENDED: u8 = 200;

const EXTENSION_FSYNC: &str = "fsync@openssh.com";
const EXTENSION_POSIX_RENAME: &str = "posix-rename@openssh.com";

const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;
const SSH_FX_NO_SUCH_FILE: u32 = 2;
const SSH_FX_PERMISSION_DENIED: u32 = 3;
const SSH_FX_BAD_MESSAGE: u32 = 5;
const SSH_FX_OP_UNSUPPORTED: u32 = 8;

pub struct SftpProtocol {
    input: ChildStdin,
    output: ChildStdout,
    next_request_id: u32,
    home: String,
    supports_fsync: bool,
    supports_posix_rename: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadPrecondition {
    pub target_state: FileUploadTargetState,
    pub digest: Option<String>,
    pub size_bytes: u64,
    pub permissions: u32,
}

struct UploadInspection {
    precondition: UploadPrecondition,
    canonical_parent: String,
    canonical_target: String,
}

impl SftpProtocol {
    pub async fn initialize(input: ChildStdin, output: ChildStdout) -> Result<Self, String> {
        let mut protocol = Self {
            input,
            output,
            next_request_id: 1,
            home: String::new(),
            supports_fsync: false,
            supports_posix_rename: false,
        };
        protocol
            .send_packet(SSH_FXP_INIT, &SFTP_VERSION.to_be_bytes())
            .await?;
        let packet = protocol.read_packet().await?;
        if packet.kind != SSH_FXP_VERSION {
            return Err(String::from("sftp_protocol_error"));
        }
        let mut cursor = Cursor::new(&packet.payload);
        if cursor.u32()? != SFTP_VERSION {
            return Err(String::from("sftp_version_unsupported"));
        }
        let mut extension_count = 0_u8;
        while !cursor.remaining().is_empty() {
            extension_count = extension_count
                .checked_add(1)
                .ok_or_else(|| String::from("sftp_protocol_error"))?;
            if extension_count > 32 {
                return Err(String::from("sftp_protocol_error"));
            }
            let name = cursor.string()?;
            let _data = cursor.bytes()?;
            if name == EXTENSION_FSYNC {
                protocol.supports_fsync = true;
            } else if name == EXTENSION_POSIX_RENAME {
                protocol.supports_posix_rename = true;
            }
        }
        cursor.finish()?;
        let home = protocol.realpath_raw(".").await?;
        validate_canonical_root(&home)?;
        protocol.home = home;
        Ok(protocol)
    }

    pub fn home(&self) -> &str {
        &self.home
    }

    pub fn supports_atomic_upload(&self) -> bool {
        self.supports_fsync && self.supports_posix_rename
    }

    pub async fn list(&mut self, path: &str) -> Result<FileListView, String> {
        let canonical = self.resolve(path).await?;
        let attrs = self.stat_raw(&canonical).await?;
        if kind(&attrs) != FileKind::Directory {
            return Err(String::from("not_directory"));
        }
        let handle = self.open_directory(&canonical).await?;
        let result = self.read_directory(path, &handle).await;
        let _closed = self.close_handle(&handle).await;
        result
    }

    pub async fn stat(&mut self, path: &str) -> Result<FileStatView, String> {
        let canonical = self.resolve(path).await?;
        let attrs = self.stat_raw(&canonical).await?;
        Ok(FileStatView {
            path: path.to_owned(),
            kind: kind(&attrs),
            size_bytes: attrs.size,
            modified_at_unix_seconds: attrs.modified,
            permissions: attrs.permissions,
        })
    }

    pub async fn read_text(&mut self, path: &str) -> Result<FileTextView, String> {
        let bytes = self
            .read_file(path, FILE_MAX_TEXT_BYTES, "text_too_large")
            .await?;
        if bytes.contains(&0) {
            return Err(String::from("binary_text"));
        }
        let content = String::from_utf8(bytes).map_err(|_| String::from("binary_text"))?;
        let size_bytes = u64::try_from(content.len()).map_err(|_| String::from("size_overflow"))?;
        let line_ending = if content.contains("\r\n") {
            "crlf"
        } else if content.contains('\n') {
            "lf"
        } else {
            "none"
        };
        Ok(FileTextView {
            path: path.to_owned(),
            digest: sha256_digest(content.as_bytes()),
            content,
            size_bytes,
            line_ending: line_ending.to_owned(),
        })
    }

    pub async fn download(&mut self, path: &str) -> Result<Vec<u8>, String> {
        self.read_file(path, FILE_MAX_DOWNLOAD_BYTES, "download_too_large")
            .await
    }

    pub async fn inspect_upload(&mut self, path: &str) -> Result<UploadPrecondition, String> {
        if !self.supports_atomic_upload() {
            return Err(String::from("sftp_write_extension_unavailable"));
        }
        self.inspect_upload_raw(path)
            .await
            .map(|inspection| inspection.precondition)
    }

    pub async fn atomic_upload(
        &mut self,
        path: &str,
        expected: &UploadPrecondition,
        bytes: &[u8],
        temporary_suffix: &str,
    ) -> Result<UploadPrecondition, String> {
        if !self.supports_atomic_upload() {
            return Err(String::from("sftp_write_extension_unavailable"));
        }
        if u64::try_from(bytes.len()).map_or(true, |size| size > FILE_MAX_UPLOAD_BYTES) {
            return Err(String::from("upload_too_large"));
        }
        if temporary_suffix.len() != 32
            || !temporary_suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(String::from("upload_temporary_invalid"));
        }

        let current = self.inspect_upload_raw(path).await?;
        if current.precondition != *expected {
            return Err(String::from("target_changed"));
        }
        let temporary = format!(
            "{}/.jw-agent-upload-{temporary_suffix}.tmp",
            current.canonical_parent
        );
        let handle = self
            .open_write_exclusive(&temporary, expected.permissions)
            .await?;
        let write_result = self.write_handle(&handle, bytes).await;
        let fsync_result = if write_result.is_ok() {
            self.fsync_handle(&handle).await
        } else {
            Ok(())
        };
        let close_result = self.close_handle(&handle).await;
        if let Err(reason) = write_result.and(fsync_result).and(close_result) {
            return self.cleanup_temporary(&temporary, reason).await;
        }

        let rename_result = self
            .posix_rename(&temporary, &current.canonical_target)
            .await;
        let after = self.inspect_upload_raw(path).await;
        let expected_digest = sha256_digest(bytes);
        let expected_size =
            u64::try_from(bytes.len()).map_err(|_| String::from("size_overflow"))?;
        if let Ok(inspection) = &after
            && inspection.precondition.digest.as_deref() == Some(expected_digest.as_str())
            && inspection.precondition.size_bytes == expected_size
            && inspection.precondition.permissions == expected.permissions
        {
            return Ok(inspection.precondition.clone());
        }

        if let Err(reason) = rename_result
            && after
                .as_ref()
                .is_ok_and(|inspection| inspection.precondition == current.precondition)
        {
            return self.cleanup_temporary(&temporary, reason).await;
        }
        let _cleanup = self.remove_if_present(&temporary).await;
        Err(String::from("manual_recovery_required"))
    }

    async fn read_file(
        &mut self,
        path: &str,
        max_bytes: u64,
        too_large: &str,
    ) -> Result<Vec<u8>, String> {
        let canonical = self.resolve(path).await?;
        self.read_canonical_file(&canonical, max_bytes, too_large)
            .await
    }

    async fn read_canonical_file(
        &mut self,
        canonical: &str,
        max_bytes: u64,
        too_large: &str,
    ) -> Result<Vec<u8>, String> {
        let attrs = self.stat_raw(canonical).await?;
        if kind(&attrs) != FileKind::Regular {
            return Err(String::from("not_regular_file"));
        }
        if attrs.size.is_some_and(|size| size > max_bytes) {
            return Err(too_large.to_owned());
        }
        let handle = self.open_read(canonical).await?;
        let result = self.read_handle(&handle, max_bytes, too_large).await;
        let _closed = self.close_handle(&handle).await;
        result
    }

    async fn inspect_upload_raw(&mut self, path: &str) -> Result<UploadInspection, String> {
        validate_file_path(path).map_err(str::to_owned)?;
        if path.is_empty() {
            return Err(String::from("upload_path_invalid"));
        }
        let (parent, basename) = path.rsplit_once('/').map_or(("", path), |value| value);
        validate_entry_name(basename)?;
        if is_reserved_upload_name(basename) {
            return Err(String::from("upload_path_invalid"));
        }
        let canonical_parent = self.resolve(parent).await?;
        let parent_attrs = self.stat_raw(&canonical_parent).await?;
        if kind(&parent_attrs) != FileKind::Directory {
            return Err(String::from("not_directory"));
        }
        let canonical_target = format!("{canonical_parent}/{basename}");
        let attrs = match self.lstat_raw(&canonical_target).await {
            Ok(attrs) => attrs,
            Err(reason) if reason == "not_found" => {
                return Ok(UploadInspection {
                    precondition: UploadPrecondition {
                        target_state: FileUploadTargetState::Create,
                        digest: None,
                        size_bytes: 0,
                        permissions: 0o600,
                    },
                    canonical_parent,
                    canonical_target,
                });
            }
            Err(reason) => return Err(reason),
        };
        match kind(&attrs) {
            FileKind::SymbolicLink => return Err(String::from("target_symlink_denied")),
            FileKind::Regular => {}
            _ => return Err(String::from("target_type_unsupported")),
        }
        let permissions = attrs
            .permissions
            .map(|value| value & 0o777)
            .ok_or_else(|| String::from("target_metadata_incomplete"))?;
        let bytes = self
            .read_canonical_file(
                &canonical_target,
                FILE_MAX_UPLOAD_BYTES,
                "upload_target_too_large",
            )
            .await?;
        let size_bytes = u64::try_from(bytes.len()).map_err(|_| String::from("size_overflow"))?;
        Ok(UploadInspection {
            precondition: UploadPrecondition {
                target_state: FileUploadTargetState::Replace,
                digest: Some(sha256_digest(&bytes)),
                size_bytes,
                permissions,
            },
            canonical_parent,
            canonical_target,
        })
    }

    async fn read_handle(
        &mut self,
        handle: &[u8],
        max_bytes: u64,
        too_large: &str,
    ) -> Result<Vec<u8>, String> {
        let capacity = usize::try_from(max_bytes.min(256 * 1_024))
            .map_err(|_| String::from("size_overflow"))?;
        let mut bytes = Vec::with_capacity(capacity);
        let mut offset = 0_u64;
        loop {
            let id = self.request_id()?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&id.to_be_bytes());
            push_bytes(&mut payload, handle)?;
            payload.extend_from_slice(&offset.to_be_bytes());
            payload.extend_from_slice(&READ_CHUNK_BYTES.to_be_bytes());
            self.send_packet(SSH_FXP_READ, &payload).await?;
            let packet = self.response(id).await?;
            match packet.kind {
                SSH_FXP_DATA => {
                    let mut cursor = Cursor::new(&packet.payload);
                    let data = cursor.bytes()?;
                    cursor.finish()?;
                    if data.is_empty() {
                        return Err(String::from("sftp_protocol_error"));
                    }
                    let next = offset
                        .checked_add(
                            u64::try_from(data.len()).map_err(|_| String::from("size_overflow"))?,
                        )
                        .ok_or_else(|| String::from("size_overflow"))?;
                    if next > max_bytes {
                        return Err(too_large.to_owned());
                    }
                    bytes.extend_from_slice(data);
                    offset = next;
                }
                SSH_FXP_STATUS => {
                    let status = parse_status(&packet.payload)?;
                    if status == SSH_FX_EOF {
                        return Ok(bytes);
                    }
                    return Err(status_error(status));
                }
                _ => return Err(String::from("sftp_protocol_error")),
            }
        }
    }

    async fn resolve(&mut self, path: &str) -> Result<String, String> {
        validate_file_path(path).map_err(str::to_owned)?;
        let candidate = if path.is_empty() {
            self.home.clone()
        } else {
            format!("{}/{path}", self.home)
        };
        let canonical = self.realpath_raw(&candidate).await?;
        if canonical != self.home
            && !canonical
                .strip_prefix(&self.home)
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Err(String::from("path_outside_home"));
        }
        Ok(canonical)
    }

    async fn realpath_raw(&mut self, path: &str) -> Result<String, String> {
        let id = self.request_id()?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.to_be_bytes());
        push_string(&mut payload, path)?;
        self.send_packet(SSH_FXP_REALPATH, &payload).await?;
        let packet = self.response(id).await?;
        if packet.kind == SSH_FXP_STATUS {
            return Err(status_error(parse_status(&packet.payload)?));
        }
        if packet.kind != SSH_FXP_NAME {
            return Err(String::from("sftp_protocol_error"));
        }
        let names = parse_names(&packet.payload)?;
        if names.len() != 1 {
            return Err(String::from("sftp_protocol_error"));
        }
        names
            .into_iter()
            .next()
            .map(|entry| entry.filename)
            .ok_or_else(|| String::from("sftp_protocol_error"))
    }

    async fn stat_raw(&mut self, canonical: &str) -> Result<Attrs, String> {
        self.attrs_request(SSH_FXP_STAT, canonical).await
    }

    async fn lstat_raw(&mut self, canonical: &str) -> Result<Attrs, String> {
        self.attrs_request(SSH_FXP_LSTAT, canonical).await
    }

    async fn attrs_request(&mut self, kind: u8, canonical: &str) -> Result<Attrs, String> {
        let id = self.request_id()?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.to_be_bytes());
        push_string(&mut payload, canonical)?;
        self.send_packet(kind, &payload).await?;
        let packet = self.response(id).await?;
        match packet.kind {
            SSH_FXP_ATTRS => {
                let mut cursor = Cursor::new(&packet.payload);
                let attrs = parse_attrs(&mut cursor)?;
                cursor.finish()?;
                Ok(attrs)
            }
            SSH_FXP_STATUS => Err(status_error(parse_status(&packet.payload)?)),
            _ => Err(String::from("sftp_protocol_error")),
        }
    }

    async fn open_directory(&mut self, canonical: &str) -> Result<Vec<u8>, String> {
        let id = self.request_id()?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.to_be_bytes());
        push_string(&mut payload, canonical)?;
        self.send_packet(SSH_FXP_OPENDIR, &payload).await?;
        self.handle_response(id).await
    }

    async fn read_directory(&mut self, path: &str, handle: &[u8]) -> Result<FileListView, String> {
        let mut entries = Vec::new();
        loop {
            let id = self.request_id()?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&id.to_be_bytes());
            push_bytes(&mut payload, handle)?;
            self.send_packet(SSH_FXP_READDIR, &payload).await?;
            let packet = self.response(id).await?;
            match packet.kind {
                SSH_FXP_NAME => {
                    for entry in parse_names(&packet.payload)? {
                        if matches!(entry.filename.as_str(), "." | "..") {
                            continue;
                        }
                        validate_entry_name(&entry.filename)?;
                        if entries.len() >= FILE_MAX_LIST_ENTRIES {
                            return Ok(FileListView {
                                path: path.to_owned(),
                                entries,
                                truncated: true,
                            });
                        }
                        let logical = if path.is_empty() {
                            entry.filename.clone()
                        } else {
                            format!("{path}/{}", entry.filename)
                        };
                        entries.push(FileEntryView {
                            name: entry.filename,
                            path: logical,
                            kind: kind(&entry.attrs),
                            size_bytes: entry.attrs.size,
                            modified_at_unix_seconds: entry.attrs.modified,
                            permissions: entry.attrs.permissions,
                        });
                    }
                }
                SSH_FXP_STATUS => {
                    let status = parse_status(&packet.payload)?;
                    if status == SSH_FX_EOF {
                        entries.sort_by(|left, right| {
                            (left.kind != FileKind::Directory, left.name.to_lowercase()).cmp(&(
                                right.kind != FileKind::Directory,
                                right.name.to_lowercase(),
                            ))
                        });
                        return Ok(FileListView {
                            path: path.to_owned(),
                            entries,
                            truncated: false,
                        });
                    }
                    return Err(status_error(status));
                }
                _ => return Err(String::from("sftp_protocol_error")),
            }
        }
    }

    async fn open_read(&mut self, canonical: &str) -> Result<Vec<u8>, String> {
        let id = self.request_id()?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.to_be_bytes());
        push_string(&mut payload, canonical)?;
        payload.extend_from_slice(&SSH_FXF_READ.to_be_bytes());
        payload.extend_from_slice(&0_u32.to_be_bytes());
        self.send_packet(SSH_FXP_OPEN, &payload).await?;
        self.handle_response(id).await
    }

    async fn open_write_exclusive(
        &mut self,
        canonical: &str,
        permissions: u32,
    ) -> Result<Vec<u8>, String> {
        let id = self.request_id()?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.to_be_bytes());
        push_string(&mut payload, canonical)?;
        payload.extend_from_slice(&(SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL).to_be_bytes());
        payload.extend_from_slice(&SSH_FILEXFER_ATTR_PERMISSIONS.to_be_bytes());
        payload.extend_from_slice(&(permissions & 0o777).to_be_bytes());
        self.send_packet(SSH_FXP_OPEN, &payload).await?;
        self.handle_response(id).await
    }

    async fn write_handle(&mut self, handle: &[u8], bytes: &[u8]) -> Result<(), String> {
        let mut offset = 0_u64;
        for chunk in bytes
            .chunks(usize::try_from(READ_CHUNK_BYTES).map_err(|_| String::from("size_overflow"))?)
        {
            let id = self.request_id()?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&id.to_be_bytes());
            push_bytes(&mut payload, handle)?;
            payload.extend_from_slice(&offset.to_be_bytes());
            push_bytes(&mut payload, chunk)?;
            self.send_packet(SSH_FXP_WRITE, &payload).await?;
            self.require_ok_status(id, "sftp_write_failed").await?;
            offset = offset
                .checked_add(u64::try_from(chunk.len()).map_err(|_| String::from("size_overflow"))?)
                .ok_or_else(|| String::from("size_overflow"))?;
        }
        Ok(())
    }

    async fn fsync_handle(&mut self, handle: &[u8]) -> Result<(), String> {
        let id = self.request_id()?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.to_be_bytes());
        push_string(&mut payload, EXTENSION_FSYNC)?;
        push_bytes(&mut payload, handle)?;
        self.send_packet(SSH_FXP_EXTENDED, &payload).await?;
        self.require_ok_status(id, "sftp_fsync_failed").await
    }

    async fn posix_rename(&mut self, source: &str, target: &str) -> Result<(), String> {
        let id = self.request_id()?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.to_be_bytes());
        push_string(&mut payload, EXTENSION_POSIX_RENAME)?;
        push_string(&mut payload, source)?;
        push_string(&mut payload, target)?;
        self.send_packet(SSH_FXP_EXTENDED, &payload).await?;
        self.require_ok_status(id, "sftp_rename_failed").await
    }

    async fn remove_if_present(&mut self, canonical: &str) -> Result<(), String> {
        let id = self.request_id()?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.to_be_bytes());
        push_string(&mut payload, canonical)?;
        self.send_packet(SSH_FXP_REMOVE, &payload).await?;
        let packet = self.response(id).await?;
        if packet.kind != SSH_FXP_STATUS {
            return Err(String::from("sftp_protocol_error"));
        }
        match parse_status(&packet.payload)? {
            SSH_FX_OK | SSH_FX_NO_SUCH_FILE => Ok(()),
            status => Err(status_error(status)),
        }
    }

    async fn cleanup_temporary<T>(&mut self, path: &str, reason: String) -> Result<T, String> {
        if self.remove_if_present(path).await.is_err() {
            Err(String::from("temporary_cleanup_failed"))
        } else {
            Err(reason)
        }
    }

    async fn require_ok_status(&mut self, id: u32, fallback: &str) -> Result<(), String> {
        let packet = self.response(id).await?;
        if packet.kind != SSH_FXP_STATUS {
            return Err(String::from("sftp_protocol_error"));
        }
        let status = parse_status(&packet.payload)?;
        if status == SSH_FX_OK {
            Ok(())
        } else if status == SSH_FX_OP_UNSUPPORTED {
            Err(String::from("sftp_write_extension_unavailable"))
        } else {
            let mapped = status_error(status);
            if mapped == "sftp_failure" {
                Err(fallback.to_owned())
            } else {
                Err(mapped)
            }
        }
    }

    async fn handle_response(&mut self, id: u32) -> Result<Vec<u8>, String> {
        let packet = self.response(id).await?;
        match packet.kind {
            SSH_FXP_HANDLE => {
                let mut cursor = Cursor::new(&packet.payload);
                let handle = cursor.bytes()?.to_vec();
                cursor.finish()?;
                if handle.is_empty() || handle.len() > 256 {
                    return Err(String::from("sftp_protocol_error"));
                }
                Ok(handle)
            }
            SSH_FXP_STATUS => Err(status_error(parse_status(&packet.payload)?)),
            _ => Err(String::from("sftp_protocol_error")),
        }
    }

    async fn close_handle(&mut self, handle: &[u8]) -> Result<(), String> {
        let id = self.request_id()?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.to_be_bytes());
        push_bytes(&mut payload, handle)?;
        self.send_packet(SSH_FXP_CLOSE, &payload).await?;
        let packet = self.response(id).await?;
        if packet.kind != SSH_FXP_STATUS || parse_status(&packet.payload)? != SSH_FX_OK {
            return Err(String::from("sftp_close_failed"));
        }
        Ok(())
    }

    async fn response(&mut self, expected_id: u32) -> Result<Packet, String> {
        let packet = self.read_packet().await?;
        let mut cursor = Cursor::new(&packet.payload);
        if cursor.u32()? != expected_id {
            return Err(String::from("sftp_protocol_error"));
        }
        Ok(Packet {
            kind: packet.kind,
            payload: cursor.remaining().to_vec(),
        })
    }

    async fn send_packet(&mut self, kind: u8, payload: &[u8]) -> Result<(), String> {
        let length = payload
            .len()
            .checked_add(1)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| String::from("sftp_packet_too_large"))?;
        if usize::try_from(length).map_err(|_| String::from("sftp_packet_too_large"))?
            > PACKET_MAX_BYTES
        {
            return Err(String::from("sftp_packet_too_large"));
        }
        let mut packet = Vec::with_capacity(payload.len() + 5);
        packet.extend_from_slice(&length.to_be_bytes());
        packet.push(kind);
        packet.extend_from_slice(payload);
        timeout(OPERATION_TIMEOUT, self.input.write_all(&packet))
            .await
            .map_err(|_| String::from("sftp_timeout"))?
            .map_err(|_| String::from("sftp_write_failed"))?;
        timeout(OPERATION_TIMEOUT, self.input.flush())
            .await
            .map_err(|_| String::from("sftp_timeout"))?
            .map_err(|_| String::from("sftp_write_failed"))
    }

    async fn read_packet(&mut self) -> Result<Packet, String> {
        let mut length_bytes = [0_u8; 4];
        timeout(OPERATION_TIMEOUT, self.output.read_exact(&mut length_bytes))
            .await
            .map_err(|_| String::from("sftp_timeout"))?
            .map_err(|_| String::from("sftp_read_failed"))?;
        let length = usize::try_from(u32::from_be_bytes(length_bytes))
            .map_err(|_| String::from("sftp_protocol_error"))?;
        if !(1..=PACKET_MAX_BYTES).contains(&length) {
            return Err(String::from("sftp_packet_too_large"));
        }
        let mut bytes = vec![0_u8; length];
        timeout(OPERATION_TIMEOUT, self.output.read_exact(&mut bytes))
            .await
            .map_err(|_| String::from("sftp_timeout"))?
            .map_err(|_| String::from("sftp_read_failed"))?;
        Ok(Packet {
            kind: bytes[0],
            payload: bytes[1..].to_vec(),
        })
    }

    fn request_id(&mut self) -> Result<u32, String> {
        let id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or_else(|| String::from("sftp_request_id_exhausted"))?;
        Ok(id)
    }
}

struct Packet {
    kind: u8,
    payload: Vec<u8>,
}

#[derive(Default)]
struct Attrs {
    size: Option<u64>,
    permissions: Option<u32>,
    modified: Option<u32>,
}

struct NameEntry {
    filename: String,
    attrs: Attrs,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4)?;
        let array: [u8; 4] = bytes
            .try_into()
            .map_err(|_| String::from("sftp_protocol_error"))?;
        Ok(u32::from_be_bytes(array))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        let array: [u8; 8] = bytes
            .try_into()
            .map_err(|_| String::from("sftp_protocol_error"))?;
        Ok(u64::from_be_bytes(array))
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| String::from("sftp_protocol_error"))?;
        self.take(length)
    }

    fn string(&mut self) -> Result<String, String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| String::from("sftp_non_utf8_name"))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| String::from("sftp_protocol_error"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| String::from("sftp_protocol_error"))?;
        self.position = end;
        Ok(value)
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    fn finish(&self) -> Result<(), String> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(String::from("sftp_protocol_error"))
        }
    }
}

fn parse_names(payload: &[u8]) -> Result<Vec<NameEntry>, String> {
    let mut cursor = Cursor::new(payload);
    let count = usize::try_from(cursor.u32()?).map_err(|_| String::from("sftp_protocol_error"))?;
    if count > FILE_MAX_LIST_ENTRIES.saturating_add(2) {
        return Err(String::from("sftp_list_limit_exceeded"));
    }
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        let filename = cursor.string()?;
        let _longname = cursor.bytes()?;
        let attrs = parse_attrs(&mut cursor)?;
        names.push(NameEntry { filename, attrs });
    }
    cursor.finish()?;
    Ok(names)
}

fn parse_attrs(cursor: &mut Cursor<'_>) -> Result<Attrs, String> {
    let flags = cursor.u32()?;
    let known_flags = SSH_FILEXFER_ATTR_SIZE
        | SSH_FILEXFER_ATTR_UIDGID
        | SSH_FILEXFER_ATTR_PERMISSIONS
        | SSH_FILEXFER_ATTR_ACMODTIME
        | SSH_FILEXFER_ATTR_EXTENDED;
    if flags & !known_flags != 0 {
        return Err(String::from("sftp_protocol_error"));
    }
    let size = if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
        Some(cursor.u64()?)
    } else {
        None
    };
    if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
        let _uid = cursor.u32()?;
        let _gid = cursor.u32()?;
    }
    let permissions = if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
        Some(cursor.u32()?)
    } else {
        None
    };
    let modified = if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
        let _accessed = cursor.u32()?;
        Some(cursor.u32()?)
    } else {
        None
    };
    if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
        let count = cursor.u32()?;
        if count > 32 {
            return Err(String::from("sftp_protocol_error"));
        }
        for _ in 0..count {
            let _kind = cursor.bytes()?;
            let _data = cursor.bytes()?;
        }
    }
    Ok(Attrs {
        size,
        permissions,
        modified,
    })
}

fn parse_status(payload: &[u8]) -> Result<u32, String> {
    let mut cursor = Cursor::new(payload);
    let status = cursor.u32()?;
    let _message = cursor.bytes()?;
    let _language = cursor.bytes()?;
    cursor.finish()?;
    Ok(status)
}

fn status_error(status: u32) -> String {
    match status {
        SSH_FX_NO_SUCH_FILE => String::from("not_found"),
        SSH_FX_PERMISSION_DENIED => String::from("permission_denied"),
        SSH_FX_BAD_MESSAGE => String::from("sftp_bad_message"),
        SSH_FX_OP_UNSUPPORTED => String::from("sftp_operation_unsupported"),
        _ => String::from("sftp_failure"),
    }
}

fn kind(attrs: &Attrs) -> FileKind {
    match attrs.permissions.map(|value| value & 0o170_000) {
        Some(0o040_000) => FileKind::Directory,
        Some(0o100_000) => FileKind::Regular,
        Some(0o120_000) => FileKind::SymbolicLink,
        _ => FileKind::Other,
    }
}

fn validate_canonical_root(root: &str) -> Result<(), String> {
    if !root.starts_with('/')
        || root == "/"
        || root.ends_with('/')
        || root.len() > FILE_MAX_PATH_BYTES
        || root
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(String::from("sftp_home_invalid"));
    }
    Ok(())
}

fn validate_entry_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > jw_contracts::FILE_MAX_COMPONENT_BYTES
        || name.contains('/')
        || name
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(String::from("sftp_unsafe_name"));
    }
    Ok(())
}

fn push_string(output: &mut Vec<u8>, value: &str) -> Result<(), String> {
    push_bytes(output, value.as_bytes())
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| String::from("sftp_packet_too_large"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Cursor, kind, parse_attrs, validate_canonical_root, validate_entry_name};
    use jw_contracts::FileKind;

    #[test]
    fn parser_rejects_truncated_attributes() {
        let mut cursor = Cursor::new(&[0, 0, 0, 1, 0, 0]);
        assert!(parse_attrs(&mut cursor).is_err());
    }

    #[test]
    fn kind_uses_posix_type_bits() -> Result<(), String> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4_u32.to_be_bytes());
        bytes.extend_from_slice(&0o100_640_u32.to_be_bytes());
        let attrs = parse_attrs(&mut Cursor::new(&bytes))?;
        assert_eq!(kind(&attrs), FileKind::Regular);
        Ok(())
    }

    #[test]
    fn root_and_entry_names_are_fail_closed() {
        assert!(validate_canonical_root("/home/operator").is_ok());
        assert!(validate_canonical_root("/").is_err());
        assert!(validate_entry_name("report.txt").is_ok());
        assert!(validate_entry_name("../outside").is_err());
        assert!(validate_entry_name("bad\nname").is_err());
    }
}
