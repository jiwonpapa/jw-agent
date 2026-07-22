use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jw_contracts::{
    FILE_IDLE_TIMEOUT_SECONDS, FILE_MAX_LIFETIME_SECONDS, FILE_MAX_UPLOAD_BYTES,
    FILE_SESSION_TOKEN_BYTES, FILE_UPLOAD_PLAN_TOKEN_BYTES, FILE_UPLOAD_PLAN_TTL_SECONDS,
    FileListView, FileStatView, FileTextView, FileUploadTargetState, IngressChannel, SecretString,
    Subject, sha256_digest, validate_digest,
};
use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};
use tokio::time::timeout;
use zeroize::{Zeroize, Zeroizing};

use crate::openssh::{self, OpenSshMode};
use crate::session::FileUploadPlanAudit;
use crate::sftp_protocol::{SftpProtocol, UploadPrecondition};
use crate::{AgentConfig, SessionStore, terminal_runtime_available};

const TOKEN_BYTES: usize = 32;
const MAX_GLOBAL_SESSIONS: usize = 8;
const AUTH_TIMEOUT: Duration = Duration::from_secs(8);
const PROCESS_EXIT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Default)]
pub struct FileBroker {
    inner: Arc<Mutex<FileState>>,
}

#[derive(Default)]
struct FileState {
    sessions: HashMap<[u8; 32], Arc<FileSession>>,
    opening: Vec<[u8; 32]>,
    upload_plans: HashMap<[u8; 32], UploadPlan>,
}

pub struct FileSessionIssue<'a> {
    pub jw_session_token: &'a str,
    pub subject: Subject,
    pub ingress: IngressChannel,
    pub origin: String,
    pub password: SecretString,
    pub now_unix_ms: i64,
}

pub struct IssuedFileSession {
    pub token: SecretString,
    pub session_id: String,
    pub expires_at_unix_ms: i64,
}

pub struct IssuedUploadPlan {
    pub token: SecretString,
    pub expires_at_unix_ms: i64,
    pub path: String,
    pub target_state: FileUploadTargetState,
    pub before_digest: Option<String>,
    pub after_digest: String,
    pub content_bytes: u64,
}

pub struct AppliedUpload {
    pub path: String,
    pub target_state: FileUploadTargetState,
    pub digest: String,
    pub content_bytes: u64,
}

pub struct FileLease {
    session: Arc<FileSession>,
}

struct FileSession {
    session_id: String,
    jw_session_binding: [u8; 32],
    ingress: IngressChannel,
    origin: String,
    started: Instant,
    last_activity: Mutex<Instant>,
    close_reason: Mutex<String>,
    runtime: tokio::sync::Mutex<SftpRuntime>,
    store: SessionStore,
    revoked: AtomicBool,
}

struct UploadPlan {
    upload_id: String,
    file_session_id: String,
    jw_session_binding: [u8; 32],
    path: String,
    precondition: UploadPrecondition,
    after_digest: String,
    content_bytes: u64,
    expires_at: Instant,
    store: SessionStore,
    audit_handed_off: bool,
}

pub struct FileUploadLease {
    session: Arc<FileSession>,
    plan: UploadPlan,
    finished: bool,
}

struct SftpRuntime {
    protocol: SftpProtocol,
    _child: Child,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileSessionError {
    Busy,
    Expired,
    Invalid,
    Storage,
    Connection(String),
    Operation(String),
}

impl Drop for FileSession {
    fn drop(&mut self) {
        let reason = self
            .close_reason
            .lock()
            .map_or_else(|_| String::from("audit_unavailable"), |value| value.clone());
        let now = unix_milliseconds().map_or(0, std::convert::identity);
        if self
            .store
            .record_file_session_finish(&self.session_id, &reason, now)
            .is_err()
        {
            eprintln!(
                "jw-agentd file session audit finalize failed session={}",
                self.session_id
            );
        }
    }
}

impl Drop for UploadPlan {
    fn drop(&mut self) {
        if self.audit_handed_off {
            return;
        }
        let now = unix_milliseconds().map_or(0, std::convert::identity);
        let _audit =
            self.store
                .record_file_upload_finish(&self.upload_id, "failed", "plan_abandoned", now);
    }
}

impl Drop for FileUploadLease {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let now = unix_milliseconds().map_or(0, std::convert::identity);
        let _audit = self.plan.store.record_file_upload_finish(
            &self.plan.upload_id,
            "manual_check",
            "request_dropped",
            now,
        );
    }
}

impl FileBroker {
    pub async fn issue(
        &self,
        issue: FileSessionIssue<'_>,
        config: &AgentConfig,
        store: &SessionStore,
    ) -> Result<IssuedFileSession, FileSessionError> {
        terminal_runtime_available(config)
            .map_err(|reason| FileSessionError::Connection(reason.to_owned()))?;
        let binding = session_binding(issue.jw_session_token);
        let session_id = random_session_id().map_err(|_| FileSessionError::Storage)?;
        let token = random_token().map_err(|_| FileSessionError::Storage)?;
        {
            let mut state = self.inner.lock().map_err(|_| FileSessionError::Storage)?;
            cleanup_expired(&mut state);
            if state.opening.contains(&binding)
                || state
                    .sessions
                    .values()
                    .any(|session| session.jw_session_binding == binding)
                || state.sessions.len().saturating_add(state.opening.len()) >= MAX_GLOBAL_SESSIONS
            {
                return Err(FileSessionError::Busy);
            }
            state.opening.push(binding);
        }

        if store
            .record_file_session_start(
                &session_id,
                &issue.subject,
                issue.ingress,
                issue.now_unix_ms,
            )
            .is_err()
        {
            self.release_opening(&binding)?;
            return Err(FileSessionError::Storage);
        }

        let runtime = match prepare_sftp(config, &issue.subject, issue.password, &session_id).await
        {
            Ok(runtime) => runtime,
            Err(reason) => {
                let now = unix_milliseconds().map_or(issue.now_unix_ms, std::convert::identity);
                let audit_result = store.record_file_session_finish(
                    &session_id,
                    connection_close_reason(&reason),
                    now,
                );
                let release_result = self.release_opening(&binding);
                if audit_result.is_err() || release_result.is_err() {
                    return Err(FileSessionError::Storage);
                }
                return Err(FileSessionError::Connection(reason));
            }
        };
        self.release_opening(&binding)?;

        let token_digest = token_digest(token.as_bytes());
        let session = Arc::new(FileSession {
            session_id: session_id.clone(),
            jw_session_binding: binding,
            ingress: issue.ingress,
            origin: issue.origin,
            started: Instant::now(),
            last_activity: Mutex::new(Instant::now()),
            close_reason: Mutex::new(String::from("broker_dropped")),
            runtime: tokio::sync::Mutex::new(runtime),
            store: store.clone(),
            revoked: AtomicBool::new(false),
        });
        {
            let mut state = self.inner.lock().map_err(|_| FileSessionError::Storage)?;
            cleanup_expired(&mut state);
            if state
                .sessions
                .values()
                .any(|active| active.jw_session_binding == binding)
                || state.sessions.len() >= MAX_GLOBAL_SESSIONS
            {
                set_close_reason(&session, "session_race_rejected");
                return Err(FileSessionError::Busy);
            }
            state.sessions.insert(token_digest, session);
        }
        self.schedule_expiry(token_digest, &session_id);
        let expires_at_unix_ms = issue.now_unix_ms.saturating_add(
            i64::try_from(FILE_MAX_LIFETIME_SECONDS.saturating_mul(1_000))
                .map_err(|_| FileSessionError::Storage)?,
        );
        Ok(IssuedFileSession {
            token: SecretString::new(token.to_string()),
            session_id,
            expires_at_unix_ms,
        })
    }

    fn release_opening(&self, binding: &[u8; 32]) -> Result<(), FileSessionError> {
        let mut state = self.inner.lock().map_err(|_| FileSessionError::Storage)?;
        state.opening.retain(|candidate| candidate != binding);
        Ok(())
    }

    pub fn acquire(
        &self,
        token: &str,
        jw_session_token: &str,
        ingress: IngressChannel,
        origin: &str,
    ) -> Result<FileLease, FileSessionError> {
        if !valid_token_shape(token) {
            return Err(FileSessionError::Invalid);
        }
        let digest = token_digest(token.as_bytes());
        let binding = session_binding(jw_session_token);
        let mut state = self.inner.lock().map_err(|_| FileSessionError::Storage)?;
        cleanup_expired(&mut state);
        let Some(session) = state.sessions.get(&digest).cloned() else {
            return Err(FileSessionError::Invalid);
        };
        if session.jw_session_binding != binding
            || session.ingress != ingress
            || session.origin != origin
        {
            return Err(FileSessionError::Invalid);
        }
        if session_expired(&session) {
            state.sessions.remove(&digest);
            set_close_reason(&session, "session_expired");
            return Err(FileSessionError::Expired);
        }
        session
            .last_activity
            .lock()
            .map_err(|_| FileSessionError::Storage)?
            .clone_from(&Instant::now());
        Ok(FileLease { session })
    }

    pub async fn plan_upload(
        &self,
        lease: &FileLease,
        path: &str,
        content_bytes: u64,
        after_digest: &str,
        overwrite_confirmed: bool,
        now_unix_ms: i64,
    ) -> Result<IssuedUploadPlan, FileSessionError> {
        lease.ensure_active()?;
        if content_bytes > FILE_MAX_UPLOAD_BYTES || validate_digest(after_digest).is_err() {
            return Err(FileSessionError::Operation(String::from(
                "upload_plan_invalid",
            )));
        }
        {
            let mut state = self.inner.lock().map_err(|_| FileSessionError::Storage)?;
            cleanup_expired(&mut state);
            if state
                .upload_plans
                .values()
                .any(|plan| plan.file_session_id == lease.session.session_id)
            {
                return Err(FileSessionError::Busy);
            }
        }
        let precondition = {
            let mut runtime = lease.session.runtime.lock().await;
            runtime
                .protocol
                .inspect_upload(path)
                .await
                .map_err(FileSessionError::Operation)?
        };
        if precondition.target_state == FileUploadTargetState::Replace && !overwrite_confirmed {
            return Err(FileSessionError::Operation(String::from(
                "overwrite_confirmation_required",
            )));
        }
        lease.ensure_active()?;
        let upload_id = random_session_id().map_err(|_| FileSessionError::Storage)?;
        let token = random_token().map_err(|_| FileSessionError::Storage)?;
        let target_state = match precondition.target_state {
            FileUploadTargetState::Create => "create",
            FileUploadTargetState::Replace => "replace",
        };
        lease
            .session
            .store
            .record_file_upload_plan(&FileUploadPlanAudit {
                upload_id: &upload_id,
                session_id: &lease.session.session_id,
                path,
                target_state,
                before_digest: precondition.digest.as_deref(),
                after_digest,
                byte_count: content_bytes,
                now_unix_ms,
            })
            .map_err(|_| FileSessionError::Storage)?;
        let plan = UploadPlan {
            upload_id,
            file_session_id: lease.session.session_id.clone(),
            jw_session_binding: lease.session.jw_session_binding,
            path: path.to_owned(),
            precondition: precondition.clone(),
            after_digest: after_digest.to_owned(),
            content_bytes,
            expires_at: Instant::now() + Duration::from_secs(FILE_UPLOAD_PLAN_TTL_SECONDS),
            store: lease.session.store.clone(),
            audit_handed_off: false,
        };
        let token_digest = upload_plan_token_digest(token.as_bytes());
        {
            let mut state = self.inner.lock().map_err(|_| FileSessionError::Storage)?;
            cleanup_expired(&mut state);
            let session_is_active = state.sessions.values().any(|session| {
                session.session_id == lease.session.session_id
                    && !session.revoked.load(Ordering::Acquire)
            });
            if !session_is_active
                || state
                    .upload_plans
                    .values()
                    .any(|active| active.file_session_id == lease.session.session_id)
            {
                return Err(FileSessionError::Busy);
            }
            state.upload_plans.insert(token_digest, plan);
        }
        let ttl_ms = i64::try_from(FILE_UPLOAD_PLAN_TTL_SECONDS.saturating_mul(1_000))
            .map_err(|_| FileSessionError::Storage)?;
        Ok(IssuedUploadPlan {
            token: SecretString::new(token.to_string()),
            expires_at_unix_ms: now_unix_ms.saturating_add(ttl_ms),
            path: path.to_owned(),
            target_state: precondition.target_state,
            before_digest: precondition.digest,
            after_digest: after_digest.to_owned(),
            content_bytes,
        })
    }

    pub fn begin_upload(
        &self,
        lease: FileLease,
        plan_token: &str,
        now_unix_ms: i64,
    ) -> Result<FileUploadLease, FileSessionError> {
        lease.ensure_active()?;
        if !valid_upload_plan_token_shape(plan_token) {
            return Err(FileSessionError::Invalid);
        }
        let digest = upload_plan_token_digest(plan_token.as_bytes());
        let mut plan = {
            let mut state = self.inner.lock().map_err(|_| FileSessionError::Storage)?;
            cleanup_expired(&mut state);
            state
                .upload_plans
                .remove(&digest)
                .ok_or(FileSessionError::Invalid)?
        };
        if plan.file_session_id != lease.session.session_id
            || plan.jw_session_binding != lease.session.jw_session_binding
            || Instant::now() >= plan.expires_at
        {
            return Err(FileSessionError::Invalid);
        }
        plan.store
            .record_file_upload_start(&plan.upload_id, now_unix_ms)
            .map_err(|_| FileSessionError::Storage)?;
        plan.audit_handed_off = true;
        Ok(FileUploadLease {
            session: lease.session,
            plan,
            finished: false,
        })
    }

    pub fn close(
        &self,
        token: &str,
        jw_session_token: &str,
        ingress: IngressChannel,
        origin: &str,
    ) -> Result<(), FileSessionError> {
        if !valid_token_shape(token) {
            return Err(FileSessionError::Invalid);
        }
        let digest = token_digest(token.as_bytes());
        let binding = session_binding(jw_session_token);
        let mut state = self.inner.lock().map_err(|_| FileSessionError::Storage)?;
        let Some(session) = state.sessions.get(&digest) else {
            return Err(FileSessionError::Invalid);
        };
        if session.jw_session_binding != binding
            || session.ingress != ingress
            || session.origin != origin
        {
            return Err(FileSessionError::Invalid);
        }
        let removed = state.sessions.remove(&digest);
        if let Some(session) = removed {
            set_close_reason(&session, "user_closed");
        }
        Ok(())
    }

    pub fn revoke_session(&self, jw_session_token: &str) {
        let binding = session_binding(jw_session_token);
        if let Ok(mut state) = self.inner.lock() {
            let digests: Vec<[u8; 32]> = state
                .sessions
                .iter()
                .filter_map(|(digest, session)| {
                    (session.jw_session_binding == binding).then_some(*digest)
                })
                .collect();
            for digest in digests {
                if let Some(session) = state.sessions.remove(&digest) {
                    set_close_reason(&session, "session_revoked");
                }
            }
            state
                .upload_plans
                .retain(|_, plan| plan.jw_session_binding != binding);
            state.opening.retain(|candidate| candidate != &binding);
        }
    }

    pub fn revoke_all(&self) {
        if let Ok(mut state) = self.inner.lock() {
            for session in state.sessions.values() {
                set_close_reason(session, "all_sessions_revoked");
            }
            state.sessions.clear();
            state.upload_plans.clear();
            state.opening.clear();
        }
    }

    fn schedule_expiry(&self, digest: [u8; 32], session_id: &str) {
        let broker = self.clone();
        let expected_id = session_id.to_owned();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(FILE_IDLE_TIMEOUT_SECONDS)).await;
                let mut state = match broker.inner.lock() {
                    Ok(state) => state,
                    Err(_) => return,
                };
                let Some(session) = state.sessions.get(&digest) else {
                    return;
                };
                if session.session_id != expected_id {
                    return;
                }
                if session_expired(session) {
                    if let Some(expired) = state.sessions.remove(&digest) {
                        set_close_reason(&expired, "session_expired");
                    }
                    return;
                }
            }
        });
    }
}

impl FileLease {
    pub fn session_id(&self) -> &str {
        &self.session.session_id
    }

    pub async fn list(&self, path: &str) -> Result<FileListView, FileSessionError> {
        self.ensure_active()?;
        let mut runtime = self.session.runtime.lock().await;
        let result = runtime.protocol.list(path).await;
        self.audit(
            "list",
            path,
            result.as_ref().map_or(0, |view| view.entries.len() as u64),
            &result,
        )?;
        result.map_err(FileSessionError::Operation)
    }

    pub async fn stat(&self, path: &str) -> Result<FileStatView, FileSessionError> {
        self.ensure_active()?;
        let mut runtime = self.session.runtime.lock().await;
        let result = runtime.protocol.stat(path).await;
        self.audit("stat", path, 0, &result)?;
        result.map_err(FileSessionError::Operation)
    }

    pub async fn read_text(&self, path: &str) -> Result<FileTextView, FileSessionError> {
        self.ensure_active()?;
        let mut runtime = self.session.runtime.lock().await;
        let result = runtime.protocol.read_text(path).await;
        let bytes = result.as_ref().map_or(0, |view| view.size_bytes);
        self.audit("read", path, bytes, &result)?;
        result.map_err(FileSessionError::Operation)
    }

    pub async fn download(&self, path: &str) -> Result<Vec<u8>, FileSessionError> {
        self.ensure_active()?;
        let mut runtime = self.session.runtime.lock().await;
        let result = runtime.protocol.download(path).await;
        let bytes = result.as_ref().map_or(0, |value| value.len() as u64);
        self.audit("download", path, bytes, &result)?;
        result.map_err(FileSessionError::Operation)
    }

    fn audit<T>(
        &self,
        action: &str,
        path: &str,
        bytes: u64,
        result: &Result<T, String>,
    ) -> Result<(), FileSessionError> {
        let result_value = match result {
            Ok(_) => "ok",
            Err(reason) if reason.len() <= 64 => reason,
            Err(_) => "internal_error",
        };
        let now = unix_milliseconds().map_or(0, std::convert::identity);
        self.session
            .store
            .record_file_access(
                &self.session.session_id,
                action,
                path,
                bytes,
                result_value,
                now,
            )
            .map_err(|_| FileSessionError::Storage)
    }

    fn ensure_active(&self) -> Result<(), FileSessionError> {
        if self.session.revoked.load(Ordering::Acquire) {
            return Err(FileSessionError::Invalid);
        }
        if session_expired(&self.session) {
            return Err(FileSessionError::Expired);
        }
        Ok(())
    }
}

impl FileUploadLease {
    pub fn expected_content_bytes(&self) -> u64 {
        self.plan.content_bytes
    }

    pub async fn apply(mut self, bytes: Vec<u8>) -> Result<AppliedUpload, FileSessionError> {
        if let Err(error) = self.ensure_active() {
            return Err(self.finish_error(error, "session_rejected"));
        }
        let actual_size = match u64::try_from(bytes.len()) {
            Ok(value) => value,
            Err(_) => {
                return Err(self.finish_error(
                    FileSessionError::Operation(String::from("upload_too_large")),
                    "upload_too_large",
                ));
            }
        };
        if actual_size != self.plan.content_bytes {
            return Err(self.finish_error(
                FileSessionError::Operation(String::from("upload_length_mismatch")),
                "upload_length_mismatch",
            ));
        }
        let actual_digest = sha256_digest(&bytes);
        if actual_digest != self.plan.after_digest {
            return Err(self.finish_error(
                FileSessionError::Operation(String::from("upload_digest_mismatch")),
                "upload_digest_mismatch",
            ));
        }
        let temporary_suffix = match random_session_id() {
            Ok(value) => value,
            Err(_) => {
                return Err(self.finish_error(FileSessionError::Storage, "random_unavailable"));
            }
        };
        let result = {
            let mut runtime = self.session.runtime.lock().await;
            runtime
                .protocol
                .atomic_upload(
                    &self.plan.path,
                    &self.plan.precondition,
                    &bytes,
                    &temporary_suffix,
                )
                .await
        };
        match result {
            Ok(verified) => {
                let now = unix_milliseconds().map_or(0, std::convert::identity);
                if self
                    .plan
                    .store
                    .record_file_upload_finish(&self.plan.upload_id, "verified", "ok", now)
                    .is_err()
                {
                    return Err(FileSessionError::Storage);
                }
                self.finished = true;
                let digest = match verified.digest {
                    Some(digest) => digest,
                    None => actual_digest,
                };
                Ok(AppliedUpload {
                    path: self.plan.path.clone(),
                    target_state: self.plan.precondition.target_state,
                    digest,
                    content_bytes: actual_size,
                })
            }
            Err(reason) => {
                let state = if reason == "manual_recovery_required"
                    || reason == "temporary_cleanup_failed"
                {
                    "manual_check"
                } else {
                    "failed"
                };
                let error = FileSessionError::Operation(reason.clone());
                Err(self.finish_error_with_state(error, state, &reason))
            }
        }
    }

    pub fn reject(mut self, reason: &str) -> FileSessionError {
        self.finish_error(
            FileSessionError::Operation(reason.to_owned()),
            bounded_audit_reason(reason),
        )
    }

    fn ensure_active(&self) -> Result<(), FileSessionError> {
        if self.session.revoked.load(Ordering::Acquire) {
            return Err(FileSessionError::Invalid);
        }
        if session_expired(&self.session) {
            return Err(FileSessionError::Expired);
        }
        Ok(())
    }

    fn finish_error(&mut self, error: FileSessionError, reason: &str) -> FileSessionError {
        self.finish_error_with_state(error, "failed", reason)
    }

    fn finish_error_with_state(
        &mut self,
        error: FileSessionError,
        state: &str,
        reason: &str,
    ) -> FileSessionError {
        let now = unix_milliseconds().map_or(0, std::convert::identity);
        if self
            .plan
            .store
            .record_file_upload_finish(
                &self.plan.upload_id,
                state,
                bounded_audit_reason(reason),
                now,
            )
            .is_err()
        {
            return FileSessionError::Storage;
        }
        self.finished = true;
        error
    }
}

async fn prepare_sftp(
    config: &AgentConfig,
    subject: &Subject,
    password: SecretString,
    session_id: &str,
) -> Result<SftpRuntime, String> {
    let fifo_path = askpass_path(config, session_id)?;
    mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR)
        .map_err(|_| String::from("askpass_channel_failed"))?;
    let mut keeper = match OpenOptions::new().read(true).write(true).open(&fifo_path) {
        Ok(channel) => channel,
        Err(_) => {
            let _cleanup = fs::remove_file(&fifo_path);
            return Err(String::from("askpass_channel_failed"));
        }
    };
    if keeper
        .write_all(password.expose().as_bytes())
        .and_then(|()| keeper.write_all(b"\n"))
        .and_then(|()| keeper.flush())
        .is_err()
    {
        let _cleanup = fs::remove_file(&fifo_path);
        return Err(String::from("askpass_channel_failed"));
    }
    drop(password);

    let mut command = sftp_command(config, &subject.username, &fifo_path);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            let _cleanup = fs::remove_file(&fifo_path);
            return Err(String::from("openssh_client_unavailable"));
        }
    };
    let input = child
        .stdin
        .take()
        .ok_or_else(|| String::from("sftp_pipe_unavailable"))?;
    let output = child
        .stdout
        .take()
        .ok_or_else(|| String::from("sftp_pipe_unavailable"))?;
    let mut keeper_task = tokio::spawn(hold_askpass_channel(fifo_path.clone(), keeper));
    let protocol = match timeout(AUTH_TIMEOUT, SftpProtocol::initialize(input, output)).await {
        Ok(Ok(protocol)) => protocol,
        Ok(Err(reason)) => {
            cleanup_failed_child(&mut child, &fifo_path, &mut keeper_task).await;
            return Err(if reason == "sftp_read_failed" {
                String::from("openssh_authentication_failed")
            } else {
                reason
            });
        }
        Err(_) => {
            cleanup_failed_child(&mut child, &fifo_path, &mut keeper_task).await;
            return Err(String::from("openssh_authentication_timeout"));
        }
    };
    match timeout(Duration::from_secs(1), &mut keeper_task).await {
        Ok(Ok(())) => {}
        _ => {
            cleanup_failed_child(&mut child, &fifo_path, &mut keeper_task).await;
            return Err(String::from("askpass_channel_failed"));
        }
    }
    Ok(SftpRuntime {
        protocol,
        _child: child,
    })
}

fn sftp_command(config: &AgentConfig, username: &str, fifo_path: &Path) -> Command {
    let mut command = Command::new(&config.ssh_executable);
    command
        .args(openssh::arguments(
            &config.ssh_known_hosts,
            username,
            OpenSshMode::Sftp,
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    openssh::configure_askpass(
        &mut command,
        &config.askpass_executable,
        fifo_path,
        OpenSshMode::Sftp,
    );
    command
}

async fn cleanup_failed_child(
    child: &mut Child,
    fifo_path: &Path,
    keeper_task: &mut tokio::task::JoinHandle<()>,
) {
    keeper_task.abort();
    let _cleanup = fs::remove_file(fifo_path);
    let _kill = child.start_kill();
    let _waited = timeout(PROCESS_EXIT_TIMEOUT, child.wait()).await;
}

async fn hold_askpass_channel(path: PathBuf, keeper: fs::File) {
    let deadline = Instant::now() + AUTH_TIMEOUT;
    while Instant::now() < deadline && path.exists() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    drop(keeper);
    if path.exists() {
        let _cleanup = fs::remove_file(path);
    }
}

fn askpass_path(config: &AgentConfig, session_id: &str) -> Result<PathBuf, String> {
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(String::from("file_session_id_invalid"));
    }
    Ok(config
        .askpass_directory
        .join(format!("askpass-{session_id}.fifo")))
}

fn cleanup_expired(state: &mut FileState) {
    let expired: Vec<[u8; 32]> = state
        .sessions
        .iter()
        .filter_map(|(digest, session)| session_expired(session).then_some(*digest))
        .collect();
    for digest in expired {
        if let Some(session) = state.sessions.remove(&digest) {
            set_close_reason(&session, "session_expired");
        }
    }
    let active_session_ids: Vec<String> = state
        .sessions
        .values()
        .map(|session| session.session_id.clone())
        .collect();
    state.upload_plans.retain(|_, plan| {
        Instant::now() < plan.expires_at && active_session_ids.contains(&plan.file_session_id)
    });
}

fn session_expired(session: &FileSession) -> bool {
    if session.started.elapsed() >= Duration::from_secs(FILE_MAX_LIFETIME_SECONDS) {
        return true;
    }
    session.last_activity.lock().map_or(true, |last| {
        last.elapsed() >= Duration::from_secs(FILE_IDLE_TIMEOUT_SECONDS)
    })
}

fn set_close_reason(session: &FileSession, reason: &str) {
    session.revoked.store(true, Ordering::Release);
    if let Ok(mut value) = session.close_reason.lock() {
        *value = reason.to_owned();
    }
}

fn connection_close_reason(reason: &str) -> &str {
    if !reason.is_empty() && reason.len() <= 64 {
        reason
    } else {
        "openssh_connection_failed"
    }
}

fn random_token() -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new([0_u8; TOKEN_BYTES]);
    getrandom::fill(bytes.as_mut()).map_err(|_| String::from("secure random unavailable"))?;
    let encoded = URL_SAFE_NO_PAD.encode(bytes.as_ref());
    bytes.zeroize();
    Ok(Zeroizing::new(encoded))
}

fn random_session_id() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| String::from("secure random unavailable"))?;
    let mut output = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}")
            .map_err(|_| String::from("identifier encoding failed"))?;
    }
    Ok(output)
}

fn session_binding(token: &str) -> [u8; 32] {
    digest_with_domain(b"jw-agent/file-jw-session/v1\0", token.as_bytes())
}

fn token_digest(token: &[u8]) -> [u8; 32] {
    digest_with_domain(b"jw-agent/file-session-token/v1\0", token)
}

fn upload_plan_token_digest(token: &[u8]) -> [u8; 32] {
    digest_with_domain(b"jw-agent/file-upload-plan/v1\0", token)
}

fn digest_with_domain(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().into()
}

fn valid_token_shape(token: &str) -> bool {
    token.len() == FILE_SESSION_TOKEN_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn valid_upload_plan_token_shape(token: &str) -> bool {
    token.len() == FILE_UPLOAD_PLAN_TOKEN_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn bounded_audit_reason(reason: &str) -> &str {
    if !reason.is_empty() && reason.len() <= 64 {
        reason
    } else {
        "internal_error"
    }
}

fn unix_milliseconds() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| String::from("system clock is before Unix epoch"))?;
    i64::try_from(duration.as_millis()).map_err(|_| String::from("system clock overflow"))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use crate::AgentConfig;

    use super::{
        askpass_path, bounded_audit_reason, connection_close_reason, session_binding, sftp_command,
        token_digest, upload_plan_token_digest, valid_token_shape, valid_upload_plan_token_shape,
    };

    #[test]
    fn token_domain_and_shape_are_distinct() {
        let token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(valid_token_shape(token));
        assert_ne!(session_binding(token), token_digest(token.as_bytes()));
        assert_ne!(
            upload_plan_token_digest(token.as_bytes()),
            token_digest(token.as_bytes())
        );
        assert!(valid_upload_plan_token_shape(token));
        assert!(!valid_token_shape("short"));
        assert!(!valid_token_shape(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+"
        ));
        assert!(!valid_upload_plan_token_shape(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/"
        ));
    }

    #[test]
    fn sftp_command_is_fixed_to_loopback_read_only_subsystem() -> Result<(), String> {
        let config = test_config()?;
        let command = sftp_command(
            &config,
            "operator",
            Path::new("/run/jw-agent/askpass/askpass-0123456789abcdef0123456789abcdef.fifo"),
        );
        let arguments: Vec<String> = command
            .as_std()
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            command.as_std().get_program(),
            config.ssh_executable.as_os_str()
        );
        assert!(arguments.windows(2).any(|pair| pair == ["-l", "operator"]));
        assert!(arguments.windows(2).any(|pair| pair == ["-s", "-p"]));
        assert_eq!(
            arguments
                .get(arguments.len().saturating_sub(2))
                .map(String::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(arguments.last().map(String::as_str), Some("sftp"));
        assert!(
            arguments
                .iter()
                .any(|value| value == "ClearAllForwardings=yes")
        );
        assert!(arguments.iter().any(|value| value == "RequestTTY=no"));
        assert!(!arguments.iter().any(|value| value.contains("secret")));
        Ok(())
    }

    #[test]
    fn askpass_path_and_audit_reason_are_bounded() -> Result<(), String> {
        let config = test_config()?;
        let valid = askpass_path(&config, "0123456789abcdef0123456789abcdef")?;
        assert_eq!(
            valid,
            PathBuf::from("/run/jw-agent/askpass/askpass-0123456789abcdef0123456789abcdef.fifo")
        );
        assert!(askpass_path(&config, "../outside").is_err());
        assert!(askpass_path(&config, "0123456789ABCDEF0123456789ABCDEF").is_err());
        assert_eq!(bounded_audit_reason("target_changed"), "target_changed");
        assert_eq!(bounded_audit_reason(""), "internal_error");
        assert_eq!(bounded_audit_reason(&"x".repeat(65)), "internal_error");
        assert_eq!(
            connection_close_reason(&"x".repeat(65)),
            "openssh_connection_failed"
        );
        Ok(())
    }

    fn test_config() -> Result<AgentConfig, String> {
        Ok(AgentConfig {
            recovery_address: "127.0.0.1:8787"
                .parse()
                .map_err(|_| String::from("test address invalid"))?,
            recovery_origin: String::from("http://127.0.0.1:8787"),
            public_host: None,
            public_addresses: Vec::new(),
            proxy_socket: PathBuf::new(),
            auth_socket: PathBuf::new(),
            ops_socket: PathBuf::new(),
            database: PathBuf::new(),
            web_root: PathBuf::new(),
            ssh_executable: PathBuf::from("/usr/bin/ssh"),
            ssh_known_hosts: PathBuf::from("/etc/jw-agent/ssh_known_hosts"),
            askpass_executable: PathBuf::from("/usr/lib/jw-agent/jw-agentd"),
            askpass_directory: PathBuf::from("/run/jw-agent/askpass"),
            stty_executable: PathBuf::from("/usr/bin/stty"),
            setsid_executable: PathBuf::from("/usr/bin/setsid"),
            auth_timeout: Duration::from_secs(8),
            operation_timeout: Duration::from_secs(60),
        })
    }
}
