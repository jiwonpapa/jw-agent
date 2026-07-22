use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE,
    COOKIE, HOST, ORIGIN, REFERRER_POLICY, SET_COOKIE, STRICT_TRANSPORT_SECURITY,
    X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use futures_core::Stream;
use jw_contracts::{
    AccessSettingsView, AdditionalAuthPolicy, AdditionalAuthProviderStatus, AssuranceLevel,
    AssuranceView, AuthFailureClass, AuthPurpose, AuthRequest, AuthResult,
    CERTBOT_ATTACH_OPERATION, CERTBOT_ISSUE_OPERATION, CERTBOT_RENEW_TEST_OPERATION,
    CapabilityStatus, CapabilityView, CertbotAttachApprovalRequest, CertbotAttachPlanRequest,
    CertbotAttachPlanView, CertbotIssueApprovalRequest, CertbotIssuePlanInput,
    CertbotIssuePlanRequest, CertbotIssuePlanView, CertbotIssuePreflightEvidence,
    CertbotRenewTestApprovalRequest, CertbotRenewTestPlanRequest, CertbotRenewTestPlanView,
    CertificateInventoryView, CertificateSummaryView, FILE_MAX_DOWNLOAD_BYTES,
    FILE_MAX_UPLOAD_BYTES, FileCapabilityView, FileEntryView, FileKind, FileLimitsView,
    FileListView, FilePathRequest, FileSessionCloseRequest, FileSessionRequest, FileSessionView,
    FileStatView, FileTextView, FileUploadPlanRequest, FileUploadPlanView, FileUploadResultView,
    HealthStatus, HealthView, IPC_PROTOCOL_VERSION, IngressChannel, IntegrationCatalogView,
    LoginRequest, MANAGED_CONFIG_OPERATION, ManagedConfigApprovalRequest, ManagedConfigPlanRequest,
    ManagedConfigPlanView, ManagedConfigResourceView, NGINX_SITE_STATE_OPERATION,
    NginxSiteStatePlanRequest, NginxSiteStatePlanView, NginxSitesView, ObservationStatus,
    OperationAcceptedView, OperationApprovalRequest, OperationReceiptView,
    OperationStageEvidenceView, ProblemDetails, ReauthPurpose, ReauthRequest, ReauthView, Role,
    RollbackSupport, ServiceAction, ServiceCategory, ServiceRuntimeState, ServiceSummary,
    ServiceSupport, ServiceVisibility, ServicesView, SessionView, Subject,
    TERMINAL_MAX_FRAME_BYTES, TERMINAL_MAX_OUTPUT_BUFFER_BYTES, TerminalCapabilityView,
    TerminalLimitsView, TerminalTicketRequest, TerminalTicketView, UpdateAdditionalAuthRequest,
};
use sha2::{Digest, Sha256};
use tower_http::services::{ServeDir, ServeFile};
use utoipa::OpenApi;
use zeroize::Zeroizing;

use crate::file_session::{FileBroker, FileSessionError, FileSessionIssue};
use crate::integration_catalog::{IntegrationObservationProfile, observe_integrations};
use crate::observation::{ObservationProfile, observe_host, observe_nginx_with_mutation_gate};
use crate::ops_client::OpsBrokerError;
use crate::service_inventory::{ServiceObservationProfile, observe_services};
use crate::session::{OperationClaimError, PolicyUpdateError};
use crate::terminal::{
    TerminalBroker, TerminalTicketError, TerminalTicketIssue, terminal_runtime_available,
};
use crate::terminal_session::run_terminal;
use crate::{AgentConfig, AuthBroker, OpsBroker, SessionStore};

const API_BODY_MAX_BYTES: usize = 64 * 1_024;
const CLIENT_ADDRESS_HEADER: &str = "x-jw-client-address";
const CSRF_HEADER: &str = "x-csrf-token";
const FILE_SESSION_HEADER: &str = "x-jw-file-session";
const FILE_UPLOAD_PLAN_HEADER: &str = "x-jw-upload-plan";
const AUTH_WINDOW: Duration = Duration::from_secs(60);
const AUTH_GLOBAL_LIMIT: u32 = 60;
const AUTH_SOURCE_LIMIT: u32 = 20;
const AUTH_SUBJECT_LIMIT: u32 = 6;
const AUTH_KEY_LIMIT: usize = 2_048;

#[derive(Clone)]
pub struct AppState {
    pub config: AgentConfig,
    pub channel: IngressChannel,
    pub store: SessionStore,
    pub auth: Arc<dyn AuthBroker>,
    pub ops: Arc<dyn OpsBroker>,
    pub terminal: TerminalBroker,
    pub files: FileBroker,
    auth_limiter: AuthLimiter,
}

impl AppState {
    #[must_use]
    pub fn new(
        config: AgentConfig,
        channel: IngressChannel,
        store: SessionStore,
        auth: Arc<dyn AuthBroker>,
        ops: Arc<dyn OpsBroker>,
    ) -> Self {
        Self {
            config,
            channel,
            store,
            auth,
            ops,
            terminal: TerminalBroker::default(),
            files: FileBroker::default(),
            auth_limiter: AuthLimiter::default(),
        }
    }

    #[must_use]
    pub fn with_terminal_broker(mut self, terminal: TerminalBroker) -> Self {
        self.terminal = terminal;
        self
    }

    #[must_use]
    pub fn with_file_broker(mut self, files: FileBroker) -> Self {
        self.files = files;
        self
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        health,
        login,
        logout,
        session,
        reauthenticate,
        host,
        capabilities,
        services,
        nginx_sites,
        certificates,
        plan_certbot_issue,
        approve_certbot_issue,
        plan_certbot_renew_test,
        approve_certbot_renew_test,
        plan_certbot_attach,
        approve_certbot_attach,
        integrations,
        access_settings,
        update_additional_auth,
        plan_nginx_site_state,
        approve_nginx_site_state,
        managed_config_resource,
        plan_managed_config,
        approve_managed_config,
        operation_events,
        operation_receipt,
        terminal_capability,
        issue_terminal_ticket,
        file_capability,
        create_file_session,
        close_file_session,
        list_files,
        stat_file,
        read_text_file,
        download_file,
        plan_file_upload,
        apply_file_upload,
    ),
    components(schemas(
        AccessSettingsView,
        AdditionalAuthProviderStatus,
        jw_contracts::AdditionalAuthPolicy,
        CapabilityStatus,
        CapabilityView,
        HealthStatus,
        HealthView,
        IngressChannel,
        LoginRequest,
        jw_contracts::HostObservation,
        jw_contracts::MemoryObservation,
        jw_contracts::DiskObservation,
        NginxSitesView,
        CertificateInventoryView,
        CertificateSummaryView,
        CertbotIssuePlanRequest,
        CertbotIssuePlanView,
        CertbotIssueApprovalRequest,
        CertbotRenewTestPlanRequest,
        CertbotRenewTestPlanView,
        CertbotRenewTestApprovalRequest,
        CertbotAttachPlanRequest,
        CertbotAttachPlanView,
        CertbotAttachApprovalRequest,
        jw_contracts::NginxSiteObservation,
        jw_contracts::NginxSiteState,
        NginxSiteStatePlanRequest,
        NginxSiteStatePlanView,
        ManagedConfigResourceView,
        ManagedConfigPlanRequest,
        ManagedConfigPlanView,
        ManagedConfigApprovalRequest,
        jw_contracts::ManagedConfigApprovalIntent,
        ServiceAction,
        ServiceCategory,
        ServiceRuntimeState,
        OperationAcceptedView,
        OperationApprovalRequest,
        OperationReceiptView,
        jw_contracts::OperationStage,
        jw_contracts::OperationStageEvidenceView,
        AssuranceLevel,
        AssuranceView,
        RollbackSupport,
        IntegrationCatalogView,
        jw_contracts::IntegrationCategory,
        jw_contracts::IntegrationId,
        jw_contracts::IntegrationInstallStatus,
        jw_contracts::IntegrationLifecycleStatus,
        jw_contracts::IntegrationView,
        ObservationStatus,
        ProblemDetails,
        ReauthPurpose,
        ReauthRequest,
        ReauthView,
        jw_contracts::Role,
        ServiceSummary,
        ServiceSupport,
        ServiceVisibility,
        ServicesView,
        SessionView,
        jw_contracts::Subject,
        UpdateAdditionalAuthRequest,
        TerminalCapabilityView,
        TerminalLimitsView,
        TerminalTicketRequest,
        TerminalTicketView,
        FileCapabilityView,
        FileLimitsView,
        FileSessionRequest,
        FileSessionView,
        FileSessionCloseRequest,
        FilePathRequest,
        FileEntryView,
        FileKind,
        FileListView,
        FileStatView,
        FileTextView,
        FileUploadPlanRequest,
        FileUploadPlanView,
        FileUploadResultView,
        jw_contracts::FileUploadTargetState,
    )),
    tags((name = "jw-agent", description = "JW Agent local management API"))
)]
pub struct ApiDoc;

pub fn build_router(state: AppState) -> Router {
    let web_root = state.config.web_root.clone();
    let index = web_root.join("index.html");
    let static_files = ServeDir::new(web_root).fallback(ServeFile::new(index));

    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/session", get(session))
        .route("/api/v1/auth/reauth", post(reauthenticate))
        .route("/api/v1/terminal", get(terminal_capability))
        .route("/api/v1/terminal/tickets", post(issue_terminal_ticket))
        .route("/api/v1/terminal/connect", get(connect_terminal))
        .route("/api/v1/files", get(file_capability))
        .route("/api/v1/files/sessions", post(create_file_session))
        .route("/api/v1/files/sessions/close", post(close_file_session))
        .route("/api/v1/files/list", post(list_files))
        .route("/api/v1/files/stat", post(stat_file))
        .route("/api/v1/files/read", post(read_text_file))
        .route("/api/v1/files/download", post(download_file))
        .route("/api/v1/files/upload/plans", post(plan_file_upload))
        .route("/api/v1/files/upload", post(apply_file_upload))
        .route("/api/v1/host", get(host))
        .route("/api/v1/capabilities", get(capabilities))
        .route("/api/v1/services", get(services))
        .route("/api/v1/services/nginx/sites", get(nginx_sites))
        .route("/api/v1/certificates", get(certificates))
        .route(
            "/api/v1/operations/certbot/issue/plans",
            post(plan_certbot_issue),
        )
        .route(
            "/api/v1/operations/certbot/issue/approvals",
            post(approve_certbot_issue),
        )
        .route(
            "/api/v1/operations/certbot/renew-test/plans",
            post(plan_certbot_renew_test),
        )
        .route(
            "/api/v1/operations/certbot/renew-test/approvals",
            post(approve_certbot_renew_test),
        )
        .route(
            "/api/v1/operations/certbot/attach/plans",
            post(plan_certbot_attach),
        )
        .route(
            "/api/v1/operations/certbot/attach/approvals",
            post(approve_certbot_attach),
        )
        .route(
            "/api/v1/operations/nginx/site-state/plans",
            post(plan_nginx_site_state),
        )
        .route(
            "/api/v1/operations/nginx/site-state/approvals",
            post(approve_nginx_site_state),
        )
        .route(
            "/api/v1/config-resources/{resource_id}",
            get(managed_config_resource),
        )
        .route(
            "/api/v1/operations/service/config-file/plans",
            post(plan_managed_config),
        )
        .route(
            "/api/v1/operations/service/config-file/approvals",
            post(approve_managed_config),
        )
        .route(
            "/api/v1/operations/{operation_id}/events",
            get(operation_events),
        )
        .route("/api/v1/operations/{operation_id}", get(operation_receipt))
        .route("/api/v1/integrations", get(integrations))
        .route("/api/v1/settings/access", get(access_settings))
        .route(
            "/api/v1/settings/access/additional-auth",
            put(update_additional_auth),
        )
        .fallback_service(static_files)
        .layer(DefaultBodyLimit::max(API_BODY_MAX_BYTES))
        .layer(from_fn_with_state(state.clone(), request_guard))
        .with_state(state)
}

#[utoipa::path(get, path = "/api/v1/health", responses(
    (status = 200, description = "Agent health", body = HealthView),
    (status = 400, description = "Ingress policy rejected", body = ProblemDetails)
))]
async fn health(State(state): State<AppState>) -> Json<HealthView> {
    let pam = if state.auth.platform_supported() {
        CapabilityStatus::Available
    } else {
        CapabilityStatus::Unavailable
    };
    // Health is unauthenticated and must not activate a root helper per request.
    // The authenticated capabilities endpoint performs the live UDS handshake.
    let opsd = if state.config.ops_socket.exists() {
        CapabilityStatus::Available
    } else {
        CapabilityStatus::Unavailable
    };
    let status = if pam == CapabilityStatus::Available && opsd == CapabilityStatus::Available {
        HealthStatus::Ok
    } else {
        HealthStatus::Degraded
    };
    Json(HealthView {
        status,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        ingress: state.channel,
        pam,
        opsd,
    })
}

#[utoipa::path(post, path = "/api/v1/auth/login", request_body = LoginRequest, responses(
    (status = 200, description = "Authenticated session", body = SessionView),
    (status = 401, description = "Generic authentication failure", body = ProblemDetails),
    (status = 429, description = "Authentication rate limited", body = ProblemDetails),
    (status = 503, description = "PAM unavailable", body = ProblemDetails)
))]
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<LoginRequest>,
) -> Result<Response, ApiProblem> {
    let prior_token = session_cookie(&state, &headers)?;
    let now = unix_milliseconds()?;
    let source = request_source(&state, &headers)?;
    state.auth_limiter.consume(&source, &input.username)?;
    let request_id = random_identifier()?;
    let auth_request = AuthRequest {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: request_id.clone(),
        deadline_unix_ms: deadline(now, state.config.auth_timeout),
        username: input.username,
        password: input.password,
        remote_address: Some(source),
        purpose: AuthPurpose::Login,
    };
    let response = state
        .auth
        .authenticate(auth_request)
        .await
        .map_err(|_| ApiProblem::unavailable("authentication_unavailable"))?;
    validate_auth_response(&response, &request_id)?;
    let subject = match response.result {
        AuthResult::Authenticated { subject, .. } => subject,
        AuthResult::Failed { class } => return Err(auth_failure(class)),
    };
    let issued = state
        .store
        .issue_session(&subject, state.channel, now)
        .map_err(|_| ApiProblem::internal())?;
    if let Some(prior) = prior_token
        && {
            state.terminal.revoke_session(prior.as_str());
            state.files.revoke_session(prior.as_str());
            state.store.revoke_session(prior.as_str(), now).is_err()
        }
    {
        let _cleanup = state.store.revoke_session(issued.token(), now);
        return Err(ApiProblem::internal());
    }
    let mut api_response = Json(issued.view.clone()).into_response();
    set_session_cookie(&state, issued.token(), &mut api_response)?;
    Ok(api_response)
}

#[utoipa::path(get, path = "/api/v1/auth/session", responses(
    (status = 200, description = "Current session", body = SessionView),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionView>, ApiProblem> {
    let (_, view) = current_session(&state, &headers, unix_milliseconds()?)?;
    Ok(Json(view))
}

#[utoipa::path(post, path = "/api/v1/auth/logout", responses(
    (status = 204, description = "Session revoked"),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "CSRF rejected", body = ProblemDetails)
))]
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiProblem> {
    let now = unix_milliseconds()?;
    let (token, _) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    state
        .store
        .revoke_session(token.as_str(), now)
        .map_err(|_| ApiProblem::internal())?;
    state.terminal.revoke_session(token.as_str());
    state.files.revoke_session(token.as_str());
    let mut response = StatusCode::NO_CONTENT.into_response();
    clear_session_cookie(&state, &mut response)?;
    Ok(response)
}

#[utoipa::path(post, path = "/api/v1/auth/reauth", request_body = ReauthRequest, responses(
    (status = 200, description = "Rotated session and single-use reauthentication claim", body = ReauthView),
    (status = 401, description = "Generic authentication failure", body = ProblemDetails),
    (status = 403, description = "CSRF or subject mismatch", body = ProblemDetails),
    (status = 429, description = "Authentication rate limited", body = ProblemDetails)
))]
async fn reauthenticate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ReauthRequest>,
) -> Result<Response, ApiProblem> {
    let now = unix_milliseconds()?;
    let (old_token, current) = current_session(&state, &headers, now)?;
    require_csrf(&headers, old_token.as_str())?;
    let source = request_source(&state, &headers)?;
    state
        .auth_limiter
        .consume(&source, &current.subject.username)?;
    let request_id = random_identifier()?;
    let context_digest = reauth_context(&input.purpose);
    let auth_request = AuthRequest {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: request_id.clone(),
        deadline_unix_ms: deadline(now, state.config.auth_timeout),
        username: current.subject.username.clone(),
        password: input.password,
        remote_address: Some(source),
        purpose: AuthPurpose::StepUp { context_digest },
    };
    let response = state
        .auth
        .authenticate(auth_request)
        .await
        .map_err(|_| ApiProblem::unavailable("authentication_unavailable"))?;
    validate_auth_response(&response, &request_id)?;
    let subject = match response.result {
        AuthResult::Authenticated { subject, .. } => subject,
        AuthResult::Failed { class } => return Err(auth_failure(class)),
    };
    if subject.uid != current.subject.uid || subject.username != current.subject.username {
        return Err(ApiProblem::forbidden("reauth_subject_mismatch"));
    }

    let issued = state
        .store
        .issue_session(&subject, state.channel, now)
        .map_err(|_| ApiProblem::internal())?;
    let claim = match state
        .store
        .issue_reauth_claim(issued.token(), &subject, &input.purpose, now)
    {
        Ok(claim) => claim,
        Err(_) => {
            let _cleanup = state.store.revoke_session(issued.token(), now);
            return Err(ApiProblem::internal());
        }
    };
    state.terminal.revoke_session(old_token.as_str());
    state.files.revoke_session(old_token.as_str());
    if state.store.revoke_session(old_token.as_str(), now).is_err() {
        let _cleanup = state.store.revoke_session(issued.token(), now);
        return Err(ApiProblem::internal());
    }
    let view = ReauthView {
        session: issued.view.clone(),
        reauth_token: claim.token().to_owned(),
        expires_at: claim.expires_at,
    };
    let mut api_response = Json(view).into_response();
    set_session_cookie(&state, issued.token(), &mut api_response)?;
    Ok(api_response)
}

#[utoipa::path(get, path = "/api/v1/terminal", responses(
    (status = 200, description = "Non-root OpenSSH terminal capability", body = TerminalCapabilityView),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
async fn terminal_capability(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TerminalCapabilityView>, ApiProblem> {
    let (_, session) = current_session(&state, &headers, unix_milliseconds()?)?;
    let reason = terminal_gate_reason(&state, &session);
    Ok(Json(TerminalCapabilityView {
        available: reason.is_none(),
        reason: reason.clone(),
        username: session.subject.username,
        assurance: terminal_assurance(reason),
        limits: TerminalLimitsView::default(),
    }))
}

#[utoipa::path(post, path = "/api/v1/terminal/tickets", request_body = TerminalTicketRequest, responses(
    (status = 201, description = "Single-use terminal WebSocket ticket", body = TerminalTicketView),
    (status = 400, description = "Invalid dimensions or missing risk confirmation", body = ProblemDetails),
    (status = 401, description = "Authentication failed", body = ProblemDetails),
    (status = 403, description = "Role, Origin, CSRF, or subject rejected", body = ProblemDetails),
    (status = 409, description = "Terminal unavailable or already active", body = ProblemDetails),
    (status = 428, description = "Configured additional authentication is unavailable", body = ProblemDetails)
))]
async fn issue_terminal_ticket(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<TerminalTicketRequest>,
) -> Result<(StatusCode, Json<TerminalTicketView>), ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (session_token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, session_token.as_str())?;
    let origin = require_exact_origin(&state, &headers)?;
    if session.additional_auth_policy != AdditionalAuthPolicy::Disabled {
        return Err(ApiProblem::new(
            StatusCode::PRECONDITION_REQUIRED,
            "additional_authentication_unavailable",
        ));
    }
    if terminal_gate_reason(&state, &session).is_some() {
        return Err(ApiProblem::new(
            StatusCode::CONFLICT,
            "terminal_unavailable",
        ));
    }
    let source = request_source(&state, &headers)?;
    state
        .auth_limiter
        .consume(&source, &session.subject.username)?;

    let ssh_password = jw_contracts::SecretString::new(input.password.expose().to_owned());
    let request_id = random_identifier()?;
    let auth_request = AuthRequest {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: request_id.clone(),
        deadline_unix_ms: deadline(now, state.config.auth_timeout),
        username: session.subject.username.clone(),
        password: input.password,
        remote_address: Some(source),
        purpose: AuthPurpose::StepUp {
            context_digest: String::from("terminal"),
        },
    };
    let response = state
        .auth
        .authenticate(auth_request)
        .await
        .map_err(|_| ApiProblem::unavailable("authentication_unavailable"))?;
    validate_auth_response(&response, &request_id)?;
    let authenticated = match response.result {
        AuthResult::Authenticated { subject, .. } => subject,
        AuthResult::Failed { class } => return Err(auth_failure(class)),
    };
    if authenticated.uid == 0
        || authenticated.uid != session.subject.uid
        || authenticated.username != session.subject.username
        || authenticated.role != session.subject.role
        || authenticated.role == Role::Viewer
    {
        return Err(ApiProblem::forbidden("terminal_subject_mismatch"));
    }

    let issued = state
        .terminal
        .issue(TerminalTicketIssue {
            session_token: session_token.as_str(),
            subject: authenticated,
            ingress: state.channel,
            origin,
            password: ssh_password,
            rows: input.rows,
            cols: input.cols,
            now_unix_ms: now,
        })
        .map_err(map_terminal_ticket_error)?;
    state
        .terminal
        .schedule_expiry(issued.ticket.expose())
        .map_err(map_terminal_ticket_error)?;
    let view = TerminalTicketView {
        ticket: issued.ticket,
        expires_at: format_unix_ms(issued.expires_at_unix_ms)?,
        websocket_path: String::from("/api/v1/terminal/connect"),
        assurance: terminal_assurance(None),
        limits: TerminalLimitsView::default(),
    };
    Ok((StatusCode::CREATED, Json(view)))
}

async fn connect_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiProblem> {
    let origin = require_exact_origin(&state, &headers)?;
    let now = unix_milliseconds()?;
    let (session_token, session) = current_session(&state, &headers, now)?;
    if terminal_gate_reason(&state, &session).is_some() {
        return Err(ApiProblem::new(
            StatusCode::CONFLICT,
            "terminal_unavailable",
        ));
    }
    let ticket = websocket_ticket(&headers)?;
    let lease = state
        .terminal
        .consume(
            ticket.as_str(),
            session_token.as_str(),
            state.channel,
            &origin,
        )
        .map_err(map_terminal_ticket_error)?;
    let config = state.config.clone();
    let store = state.store.clone();
    Ok(websocket
        .protocols(["jw-terminal-v1"])
        .max_frame_size(TERMINAL_MAX_FRAME_BYTES)
        .max_message_size(TERMINAL_MAX_FRAME_BYTES)
        .write_buffer_size(64 * 1_024)
        .max_write_buffer_size(TERMINAL_MAX_OUTPUT_BUFFER_BYTES)
        .on_upgrade(move |socket| async move {
            let summary = run_terminal(socket, lease, config, store).await;
            eprintln!(
                "jw-agentd terminal session={} reason={} bytes_in={} bytes_out={}",
                summary.session_id, summary.reason, summary.bytes_in, summary.bytes_out
            );
        }))
}

fn terminal_gate_reason(state: &AppState, session: &SessionView) -> Option<String> {
    if session.subject.uid == 0 || session.subject.role == Role::Viewer {
        return Some(String::from("현재 계정은 터미널 세션을 열 수 없습니다."));
    }
    if session.additional_auth_policy != AdditionalAuthPolicy::Disabled {
        return Some(String::from(
            "설정된 추가 인증 provider가 아직 없어 터미널이 차단되었습니다.",
        ));
    }
    terminal_runtime_available(&state.config)
        .err()
        .map(str::to_owned)
}

fn terminal_assurance(reason: Option<String>) -> AssuranceView {
    AssuranceView {
        level: AssuranceLevel::G1VerifiedAction,
        rollback_support: RollbackSupport::NotGuaranteed,
        operation_available: reason.is_none(),
        scope: vec![String::from(
            "현재 로그인한 non-root Linux 계정의 제한 시간 OpenSSH 세션",
        )],
        excluded_effects: vec![
            String::from("터미널에서 실행한 명령과 외부 효과의 자동 원복"),
            String::from("root 로그인과 sudo 비밀번호 자동 입력"),
        ],
        apply_verifier: vec![
            String::from("PAM 재인증과 canonical UID/username 일치"),
            String::from("고정 loopback 대상과 strict OpenSSH host key"),
        ],
        rollback_verifier: vec![String::from(
            "자동 원복 없음; 세션 종료 후 감사 메타데이터만 보존",
        )],
        reason,
    }
}

fn require_exact_origin(state: &AppState, headers: &HeaderMap) -> Result<String, ApiProblem> {
    let origin = headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiProblem::forbidden("origin_required"))?;
    if origin != state.config.expected_origin(state.channel) {
        return Err(ApiProblem::forbidden("origin_rejected"));
    }
    Ok(origin.to_owned())
}

fn websocket_ticket(headers: &HeaderMap) -> Result<Zeroizing<String>, ApiProblem> {
    let protocols = headers
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiProblem::unauthorized("terminal_ticket_required"))?;
    if protocols.len() > 256 {
        return Err(ApiProblem::bad_request("terminal_protocol_invalid"));
    }
    let mut version_seen = false;
    let mut ticket = None;
    for protocol in protocols.split(',').map(str::trim) {
        if protocol == "jw-terminal-v1" {
            version_seen = true;
        } else if let Some(value) = protocol.strip_prefix("ticket.")
            && ticket.replace(value).is_some()
        {
            return Err(ApiProblem::bad_request("terminal_protocol_invalid"));
        }
    }
    if !version_seen {
        return Err(ApiProblem::bad_request("terminal_protocol_invalid"));
    }
    ticket
        .map(|value| Zeroizing::new(value.to_owned()))
        .ok_or_else(|| ApiProblem::unauthorized("terminal_ticket_required"))
}

fn map_terminal_ticket_error(error: TerminalTicketError) -> ApiProblem {
    match error {
        TerminalTicketError::Busy => ApiProblem::new(StatusCode::CONFLICT, "terminal_busy"),
        TerminalTicketError::Expired => ApiProblem::unauthorized("terminal_ticket_expired"),
        TerminalTicketError::Invalid => ApiProblem::unauthorized("terminal_ticket_rejected"),
        TerminalTicketError::Storage => ApiProblem::internal(),
    }
}

#[utoipa::path(get, path = "/api/v1/files", responses(
    (status = 200, description = "Home-scoped read-only OpenSSH SFTP capability", body = FileCapabilityView),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
async fn file_capability(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<FileCapabilityView>, ApiProblem> {
    let (_, session) = current_session(&state, &headers, unix_milliseconds()?)?;
    let reason = file_gate_reason(&state, &session);
    Ok(Json(FileCapabilityView {
        available: reason.is_none(),
        reason: reason.clone(),
        username: session.subject.username,
        root_label: String::from("~"),
        assurance: file_assurance(reason.clone()),
        upload_assurance: file_upload_assurance(reason),
        limits: FileLimitsView::default(),
    }))
}

#[utoipa::path(post, path = "/api/v1/files/sessions", request_body = FileSessionRequest, responses(
    (status = 201, description = "Authenticated memory-only SFTP session", body = FileSessionView),
    (status = 400, description = "Invalid password or confirmation", body = ProblemDetails),
    (status = 401, description = "Authentication failed", body = ProblemDetails),
    (status = 403, description = "Role, Origin, CSRF, or subject rejected", body = ProblemDetails),
    (status = 409, description = "File session unavailable or busy", body = ProblemDetails)
))]
async fn create_file_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<FileSessionRequest>,
) -> Result<(StatusCode, Json<FileSessionView>), ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (jw_session_token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, jw_session_token.as_str())?;
    let origin = require_exact_origin(&state, &headers)?;
    if session.additional_auth_policy != AdditionalAuthPolicy::Disabled {
        return Err(ApiProblem::new(
            StatusCode::PRECONDITION_REQUIRED,
            "additional_authentication_unavailable",
        ));
    }
    if file_gate_reason(&state, &session).is_some() {
        return Err(ApiProblem::new(StatusCode::CONFLICT, "files_unavailable"));
    }
    let source = request_source(&state, &headers)?;
    state
        .auth_limiter
        .consume(&source, &session.subject.username)?;
    let ssh_password = jw_contracts::SecretString::new(input.password.expose().to_owned());
    let request_id = random_identifier()?;
    let auth_request = AuthRequest {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: request_id.clone(),
        deadline_unix_ms: deadline(now, state.config.auth_timeout),
        username: session.subject.username.clone(),
        password: input.password,
        remote_address: Some(source),
        purpose: AuthPurpose::StepUp {
            context_digest: String::from("files_read_only"),
        },
    };
    let response = state
        .auth
        .authenticate(auth_request)
        .await
        .map_err(|_| ApiProblem::unavailable("authentication_unavailable"))?;
    validate_auth_response(&response, &request_id)?;
    let authenticated = match response.result {
        AuthResult::Authenticated { subject, .. } => subject,
        AuthResult::Failed { class } => return Err(auth_failure(class)),
    };
    if authenticated.uid == 0
        || authenticated.uid != session.subject.uid
        || authenticated.username != session.subject.username
        || authenticated.role != session.subject.role
        || authenticated.role == Role::Viewer
    {
        return Err(ApiProblem::forbidden("file_subject_mismatch"));
    }
    let issued = state
        .files
        .issue(
            FileSessionIssue {
                jw_session_token: jw_session_token.as_str(),
                subject: authenticated,
                ingress: state.channel,
                origin,
                password: ssh_password,
                now_unix_ms: now,
            },
            &state.config,
            &state.store,
        )
        .await
        .map_err(map_file_session_error)?;
    let view = FileSessionView {
        session_token: issued.token,
        expires_at: format_unix_ms(issued.expires_at_unix_ms)?,
        root_label: String::from("~"),
        assurance: file_assurance(None),
        limits: FileLimitsView::default(),
    };
    Ok((StatusCode::CREATED, Json(view)))
}

#[utoipa::path(post, path = "/api/v1/files/sessions/close", request_body = FileSessionCloseRequest, responses(
    (status = 204, description = "File session closed"),
    (status = 401, description = "Session rejected", body = ProblemDetails),
    (status = 403, description = "Origin or CSRF rejected", body = ProblemDetails)
))]
async fn close_file_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<FileSessionCloseRequest>,
) -> Result<Response, ApiProblem> {
    let now = unix_milliseconds()?;
    let (jw_session_token, _) = current_session(&state, &headers, now)?;
    require_csrf(&headers, jw_session_token.as_str())?;
    let origin = require_exact_origin(&state, &headers)?;
    state
        .files
        .close(
            input.session_token.expose(),
            jw_session_token.as_str(),
            state.channel,
            &origin,
        )
        .map_err(map_file_session_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[utoipa::path(post, path = "/api/v1/files/list", request_body = FilePathRequest, responses(
    (status = 200, description = "Bounded home directory listing", body = FileListView),
    (status = 400, description = "Path rejected", body = ProblemDetails),
    (status = 401, description = "Session rejected", body = ProblemDetails)
))]
async fn list_files(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<FilePathRequest>,
) -> Result<Json<FileListView>, ApiProblem> {
    let lease = acquire_file_lease(&state, &headers, &input)?;
    lease
        .list(&input.path)
        .await
        .map(Json)
        .map_err(map_file_session_error)
}

#[utoipa::path(post, path = "/api/v1/files/stat", request_body = FilePathRequest, responses(
    (status = 200, description = "Home-scoped file metadata", body = FileStatView),
    (status = 400, description = "Path rejected", body = ProblemDetails),
    (status = 401, description = "Session rejected", body = ProblemDetails)
))]
async fn stat_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<FilePathRequest>,
) -> Result<Json<FileStatView>, ApiProblem> {
    let lease = acquire_file_lease(&state, &headers, &input)?;
    lease
        .stat(&input.path)
        .await
        .map(Json)
        .map_err(map_file_session_error)
}

#[utoipa::path(post, path = "/api/v1/files/read", request_body = FilePathRequest, responses(
    (status = 200, description = "Bounded UTF-8 text file", body = FileTextView),
    (status = 400, description = "Path or text rejected", body = ProblemDetails),
    (status = 401, description = "Session rejected", body = ProblemDetails),
    (status = 413, description = "Text limit exceeded", body = ProblemDetails)
))]
async fn read_text_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<FilePathRequest>,
) -> Result<Json<FileTextView>, ApiProblem> {
    let lease = acquire_file_lease(&state, &headers, &input)?;
    lease
        .read_text(&input.path)
        .await
        .map(Json)
        .map_err(map_file_session_error)
}

#[utoipa::path(post, path = "/api/v1/files/download", request_body = FilePathRequest, responses(
    (status = 200, description = "Bounded binary download", body = String, content_type = "application/octet-stream"),
    (status = 400, description = "Path rejected", body = ProblemDetails),
    (status = 401, description = "Session rejected", body = ProblemDetails),
    (status = 413, description = "Download limit exceeded", body = ProblemDetails)
))]
async fn download_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<FilePathRequest>,
) -> Result<Response, ApiProblem> {
    let lease = acquire_file_lease(&state, &headers, &input)?;
    let bytes = lease
        .download(&input.path)
        .await
        .map_err(map_file_session_error)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > FILE_MAX_DOWNLOAD_BYTES) {
        return Err(ApiProblem::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "download_too_large",
        ));
    }
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"jw-agent-download\""),
    );
    Ok(response)
}

#[utoipa::path(post, path = "/api/v1/files/upload/plans", request_body = FileUploadPlanRequest, responses(
    (status = 201, description = "PAM-approved single-use atomic upload plan", body = FileUploadPlanView),
    (status = 400, description = "Path, digest, size, or confirmation rejected", body = ProblemDetails),
    (status = 401, description = "Authentication or file session rejected", body = ProblemDetails),
    (status = 403, description = "Subject, Origin, CSRF, or home boundary rejected", body = ProblemDetails),
    (status = 409, description = "Target conflict or upload unavailable", body = ProblemDetails)
))]
async fn plan_file_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<FileUploadPlanRequest>,
) -> Result<(StatusCode, Json<FileUploadPlanView>), ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (jw_session_token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, jw_session_token.as_str())?;
    let origin = require_exact_origin(&state, &headers)?;
    if session.additional_auth_policy != AdditionalAuthPolicy::Disabled {
        return Err(ApiProblem::new(
            StatusCode::PRECONDITION_REQUIRED,
            "additional_authentication_unavailable",
        ));
    }
    if file_gate_reason(&state, &session).is_some() {
        return Err(ApiProblem::new(StatusCode::CONFLICT, "files_unavailable"));
    }
    let source = request_source(&state, &headers)?;
    state
        .auth_limiter
        .consume(&source, &session.subject.username)?;
    let context_digest = jw_contracts::sha256_digest(
        format!(
            "jw-agent/file-upload-plan/v1\0{}\0{}\0{}\0{}",
            session.subject.uid, input.path, input.content_bytes, input.content_digest
        )
        .as_bytes(),
    );
    let request_id = random_identifier()?;
    let auth_request = AuthRequest {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: request_id.clone(),
        deadline_unix_ms: deadline(now, state.config.auth_timeout),
        username: session.subject.username.clone(),
        password: input.password,
        remote_address: Some(source),
        purpose: AuthPurpose::StepUp { context_digest },
    };
    let response = state
        .auth
        .authenticate(auth_request)
        .await
        .map_err(|_| ApiProblem::unavailable("authentication_unavailable"))?;
    validate_auth_response(&response, &request_id)?;
    let authenticated = match response.result {
        AuthResult::Authenticated { subject, .. } => subject,
        AuthResult::Failed { class } => return Err(auth_failure(class)),
    };
    if authenticated.uid == 0
        || authenticated.uid != session.subject.uid
        || authenticated.username != session.subject.username
        || authenticated.role != session.subject.role
        || authenticated.role == Role::Viewer
    {
        return Err(ApiProblem::forbidden("file_subject_mismatch"));
    }
    let lease = state
        .files
        .acquire(
            input.session_token.expose(),
            jw_session_token.as_str(),
            state.channel,
            &origin,
        )
        .map_err(map_file_session_error)?;
    let issued = state
        .files
        .plan_upload(
            &lease,
            &input.path,
            input.content_bytes,
            &input.content_digest,
            input.overwrite_confirmed,
            now,
        )
        .await
        .map_err(map_file_session_error)?;
    Ok((
        StatusCode::CREATED,
        Json(FileUploadPlanView {
            plan_token: issued.token,
            expires_at: format_unix_ms(issued.expires_at_unix_ms)?,
            path: issued.path,
            target_state: issued.target_state,
            before_digest: issued.before_digest,
            after_digest: issued.after_digest,
            content_bytes: issued.content_bytes,
            assurance: file_upload_assurance(None),
        }),
    ))
}

#[utoipa::path(post, path = "/api/v1/files/upload", request_body(content = Vec<u8>, content_type = "application/octet-stream"), responses(
    (status = 200, description = "Atomic upload verified by size and SHA-256", body = FileUploadResultView),
    (status = 400, description = "Content type, length, or digest rejected", body = ProblemDetails),
    (status = 401, description = "Session or single-use plan rejected", body = ProblemDetails),
    (status = 409, description = "Target changed or manual recovery required", body = ProblemDetails),
    (status = 413, description = "Upload limit exceeded", body = ProblemDetails)
))]
async fn apply_file_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<FileUploadResultView>, ApiProblem> {
    let now = unix_milliseconds()?;
    let (jw_session_token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, jw_session_token.as_str())?;
    let origin = require_exact_origin(&state, &headers)?;
    if file_gate_reason(&state, &session).is_some() {
        return Err(ApiProblem::new(StatusCode::CONFLICT, "files_unavailable"));
    }
    if headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return Err(ApiProblem::bad_request("upload_content_type"));
    }
    let file_session_token = secret_header(&headers, FILE_SESSION_HEADER)?;
    let upload_plan_token = secret_header(&headers, FILE_UPLOAD_PLAN_HEADER)?;
    let lease = state
        .files
        .acquire(
            file_session_token.as_str(),
            jw_session_token.as_str(),
            state.channel,
            &origin,
        )
        .map_err(map_file_session_error)?;
    let upload = state
        .files
        .begin_upload(lease, upload_plan_token.as_str(), now)
        .map_err(map_file_session_error)?;
    let expected_size = upload.expected_content_bytes();
    if let Some(length) = headers.get(CONTENT_LENGTH) {
        let Some(length) = length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return Err(map_file_session_error(
                upload.reject("upload_length_invalid"),
            ));
        };
        if length != expected_size {
            return Err(map_file_session_error(
                upload.reject("upload_length_mismatch"),
            ));
        }
    }
    let limit = usize::try_from(FILE_MAX_UPLOAD_BYTES)
        .map_err(|_| ApiProblem::internal())?
        .saturating_add(1);
    let bytes = match to_bytes(body, limit).await {
        Ok(bytes) => bytes,
        Err(_) => return Err(map_file_session_error(upload.reject("upload_too_large"))),
    };
    let applied = upload
        .apply(bytes.to_vec())
        .await
        .map_err(map_file_session_error)?;
    Ok(Json(FileUploadResultView {
        path: applied.path,
        target_state: applied.target_state,
        digest: applied.digest,
        content_bytes: applied.content_bytes,
        verification: String::from("size_and_sha256_read_back"),
        assurance: file_upload_assurance(None),
    }))
}

fn acquire_file_lease(
    state: &AppState,
    headers: &HeaderMap,
    input: &FilePathRequest,
) -> Result<crate::FileLease, ApiProblem> {
    let now = unix_milliseconds()?;
    let (jw_session_token, session) = current_session(state, headers, now)?;
    require_csrf(headers, jw_session_token.as_str())?;
    let origin = require_exact_origin(state, headers)?;
    if file_gate_reason(state, &session).is_some() {
        return Err(ApiProblem::new(StatusCode::CONFLICT, "files_unavailable"));
    }
    state
        .files
        .acquire(
            input.session_token.expose(),
            jw_session_token.as_str(),
            state.channel,
            &origin,
        )
        .map_err(map_file_session_error)
}

fn secret_header(headers: &HeaderMap, name: &str) -> Result<Zeroizing<String>, ApiProblem> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| ApiProblem::unauthorized("file_upload_token_required"))?;
    if values.next().is_some() {
        return Err(ApiProblem::bad_request("file_upload_token_invalid"));
    }
    Ok(Zeroizing::new(value.to_owned()))
}

fn file_gate_reason(state: &AppState, session: &SessionView) -> Option<String> {
    if session.subject.uid == 0 || session.subject.role == Role::Viewer {
        return Some(String::from("현재 계정은 파일 세션을 열 수 없습니다."));
    }
    if session.additional_auth_policy != AdditionalAuthPolicy::Disabled {
        return Some(String::from(
            "설정된 추가 인증 provider가 아직 없어 파일 세션이 차단되었습니다.",
        ));
    }
    terminal_runtime_available(&state.config)
        .err()
        .map(str::to_owned)
}

fn file_assurance(reason: Option<String>) -> AssuranceView {
    AssuranceView {
        level: AssuranceLevel::G0ObserveOnly,
        rollback_support: RollbackSupport::NotApplicable,
        operation_available: reason.is_none(),
        scope: vec![String::from(
            "현재 로그인한 non-root Linux 계정의 홈 디렉터리 읽기",
        )],
        excluded_effects: vec![
            String::from("업로드·생성·편집·삭제·이동·권한 변경"),
            String::from("홈 밖 경로와 system-owned 설정 접근"),
        ],
        apply_verifier: vec![
            String::from("PAM 재인증과 canonical UID/username 일치"),
            String::from("OpenSSH REALPATH 기반 홈 경계 검증"),
        ],
        rollback_verifier: vec![String::from("읽기 전용이므로 원복 대상 없음")],
        reason,
    }
}

fn file_upload_assurance(reason: Option<String>) -> AssuranceView {
    AssuranceView {
        level: AssuranceLevel::G1VerifiedAction,
        rollback_support: RollbackSupport::NotGuaranteed,
        operation_available: reason.is_none(),
        scope: vec![String::from(
            "현재 로그인한 non-root Linux 계정 홈의 일반 파일 생성 또는 명시적 교체",
        )],
        excluded_effects: vec![
            String::from("자동 백업·자동 원복과 system-owned 설정 변경"),
            String::from("삭제·이동·chmod·chown·symlink 생성·재귀 전송"),
        ],
        apply_verifier: vec![
            String::from("PAM 재인증, 기존 SHA-256 충돌 검사와 home 경계 재확인"),
            String::from("same-directory 임시파일 fsync·원자 rename·size/SHA-256 read-back"),
        ],
        rollback_verifier: vec![String::from(
            "자동 원복 없음; 결과 불명확 시 manual recovery required",
        )],
        reason,
    }
}

fn map_file_session_error(error: FileSessionError) -> ApiProblem {
    match error {
        FileSessionError::Busy => ApiProblem::new(StatusCode::CONFLICT, "file_session_busy"),
        FileSessionError::Expired => ApiProblem::unauthorized("file_session_expired"),
        FileSessionError::Invalid => ApiProblem::unauthorized("file_session_rejected"),
        FileSessionError::Storage => ApiProblem::unavailable("file_audit_unavailable"),
        FileSessionError::Connection(reason) => match reason.as_str() {
            "openssh_authentication_failed" => ApiProblem::unauthorized(reason),
            "openssh_authentication_timeout" => {
                ApiProblem::new(StatusCode::GATEWAY_TIMEOUT, reason)
            }
            _ => ApiProblem::unavailable(reason),
        },
        FileSessionError::Operation(reason) => match reason.as_str() {
            "path_invalid"
            | "not_directory"
            | "not_regular_file"
            | "binary_text"
            | "sftp_unsafe_name"
            | "upload_path_invalid"
            | "upload_plan_invalid"
            | "upload_digest_invalid"
            | "upload_length_invalid"
            | "upload_length_mismatch"
            | "upload_digest_mismatch"
            | "upload_content_type" => ApiProblem::bad_request(reason),
            "path_outside_home" | "permission_denied" | "target_symlink_denied" => {
                ApiProblem::forbidden(reason)
            }
            "not_found" => ApiProblem::new(StatusCode::NOT_FOUND, reason),
            "text_too_large"
            | "download_too_large"
            | "sftp_list_limit_exceeded"
            | "upload_too_large"
            | "upload_target_too_large" => ApiProblem::new(StatusCode::PAYLOAD_TOO_LARGE, reason),
            "sftp_timeout" => ApiProblem::new(StatusCode::GATEWAY_TIMEOUT, reason),
            "overwrite_confirmation_required"
            | "target_changed"
            | "target_type_unsupported"
            | "target_metadata_incomplete"
            | "sftp_write_extension_unavailable"
            | "temporary_cleanup_failed"
            | "manual_recovery_required" => ApiProblem::new(StatusCode::CONFLICT, reason),
            _ => ApiProblem::new(StatusCode::BAD_GATEWAY, reason),
        },
    }
}

#[utoipa::path(get, path = "/api/v1/host", responses(
    (status = 200, description = "Host observation", body = jw_contracts::HostObservation),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
async fn host(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<jw_contracts::HostObservation>, ApiProblem> {
    let _session = current_session(&state, &headers, unix_milliseconds()?)?;
    Ok(Json(observe_host(
        &ObservationProfile::default(),
        now_rfc3339()?,
    )))
}

#[utoipa::path(get, path = "/api/v1/capabilities", responses(
    (status = 200, description = "Read-only capability view", body = CapabilityView),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
async fn capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CapabilityView>, ApiProblem> {
    let _session = current_session(&state, &headers, unix_milliseconds()?)?;
    let view = match state.ops.capabilities().await {
        Ok(response) => CapabilityView {
            opsd: CapabilityStatus::Available,
            read_only: response.read_only,
            supported_operations: response.supported_operations,
            forensic_lockdown: response.forensic_lockdown,
        },
        Err(_) => CapabilityView {
            opsd: CapabilityStatus::Unavailable,
            read_only: true,
            supported_operations: Vec::new(),
            forensic_lockdown: false,
        },
    };
    Ok(Json(view))
}

#[utoipa::path(get, path = "/api/v1/services", responses(
    (status = 200, description = "Observed services", body = ServicesView),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
async fn services(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ServicesView>, ApiProblem> {
    let _session = current_session(&state, &headers, unix_milliseconds()?)?;
    let observed_at = now_rfc3339()?;
    tokio::task::spawn_blocking(move || {
        observe_services(&ServiceObservationProfile::default(), observed_at)
    })
    .await
    .map(Json)
    .map_err(|_| ApiProblem::internal())
}

#[utoipa::path(get, path = "/api/v1/services/nginx/sites", responses(
    (status = 200, description = "Nginx site inventory", body = NginxSitesView),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
async fn nginx_sites(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<NginxSitesView>, ApiProblem> {
    let (_, session) = current_session(&state, &headers, unix_milliseconds()?)?;
    let mutation_reason =
        nginx_mutation_gate_reason(&state, &session.subject, session.additional_auth_policy).await;
    Ok(Json(observe_nginx_with_mutation_gate(
        &ObservationProfile::default(),
        now_rfc3339()?,
        mutation_reason.as_deref(),
    )))
}

#[utoipa::path(get, path = "/api/v1/certificates", responses(
    (status = 200, description = "Sanitized Certbot certificate inventory", body = CertificateInventoryView),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 409, description = "Certificate inventory unavailable", body = ProblemDetails)
))]
async fn certificates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CertificateInventoryView>, ApiProblem> {
    let (_, session) = current_session(&state, &headers, unix_milliseconds()?)?;
    let mut inventory = state
        .ops
        .certificate_inventory(session.subject.clone())
        .await
        .map_err(map_ops_error)?;
    if let Some(reason) =
        certbot_mutation_gate_reason(&state, &session.subject, session.additional_auth_policy).await
    {
        inventory.renew_test_operation_type = None;
        inventory.issue_operation_type = None;
        inventory.attach_operation_type = None;
        inventory.assurance.reason = Some(reason);
    } else if let Some(reason) = certbot_issue_gate_reason(&state).await {
        inventory.issue_operation_type = None;
        inventory.assurance.reason = Some(reason);
    }
    if inventory.attach_operation_type.is_some()
        && let Some(reason) = certbot_attach_gate_reason(&state).await
    {
        inventory.attach_operation_type = None;
        inventory.assurance.reason = Some(reason);
    }
    Ok(Json(inventory))
}

async fn certbot_issue_gate_reason(state: &AppState) -> Option<String> {
    if state.config.public_host.is_none() || state.config.public_addresses.is_empty() {
        return Some(String::from(
            "신규 발급에는 JW_AGENT_PUBLIC_HOST와 JW_AGENT_PUBLIC_ADDRESSES 설정이 필요합니다.",
        ));
    }
    match state.ops.capabilities().await {
        Ok(capability)
            if !capability.read_only
                && capability
                    .supported_operations
                    .iter()
                    .any(|operation| operation == CERTBOT_ISSUE_OPERATION) =>
        {
            None
        }
        Ok(_) => Some(String::from(
            "이 빌드에서는 Certbot 신규 발급 fault gate가 아직 닫히지 않았습니다.",
        )),
        Err(_) => Some(String::from(
            "권한 분리 서비스 상태를 확인할 수 없어 신규 발급이 차단되었습니다.",
        )),
    }
}

async fn certbot_attach_gate_reason(state: &AppState) -> Option<String> {
    if state.config.public_host.is_none() {
        return Some(String::from(
            "인증서 연결에는 JW_AGENT_PUBLIC_HOST 설정이 필요합니다.",
        ));
    }
    match state.ops.capabilities().await {
        Ok(capability)
            if !capability.read_only
                && capability
                    .supported_operations
                    .iter()
                    .any(|operation| operation == CERTBOT_ATTACH_OPERATION) =>
        {
            None
        }
        Ok(_) => Some(String::from(
            "이 빌드에서는 Certbot Nginx 연결 fault gate가 아직 닫히지 않았습니다.",
        )),
        Err(_) => Some(String::from(
            "권한 분리 서비스 상태를 확인할 수 없어 인증서 연결이 차단되었습니다.",
        )),
    }
}

#[utoipa::path(post, path = "/api/v1/operations/certbot/issue/plans", request_body = CertbotIssuePlanRequest, responses(
    (status = 200, description = "Immutable Certbot issuance plan", body = CertbotIssuePlanView),
    (status = 400, description = "Invalid typed request", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Role or CSRF rejected", body = ProblemDetails),
    (status = 409, description = "DNS, listener, staging, stale, busy, or idempotency conflict", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails)
))]
async fn plan_certbot_issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CertbotIssuePlanRequest>,
) -> Result<Json<CertbotIssuePlanView>, ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    if certbot_issue_gate_reason(&state).await.is_some() {
        return Err(ApiProblem::new(
            StatusCode::CONFLICT,
            "issuance_unavailable",
        ));
    }
    if state.config.public_host.as_deref() != Some(input.primary_domain.as_str()) {
        return Err(ApiProblem::new(StatusCode::CONFLICT, "invalid_domain"));
    }
    let preflight = observe_certbot_issue_preflight(&state, &input.domains(), now).await?;
    let plan = state
        .ops
        .plan_certbot_issue(
            session.subject,
            CertbotIssuePlanInput {
                request: input,
                preflight,
            },
        )
        .await
        .map_err(map_ops_error)?;
    Ok(Json(plan))
}

#[utoipa::path(post, path = "/api/v1/operations/certbot/issue/approvals", request_body = CertbotIssueApprovalRequest, responses(
    (status = 202, description = "Certbot issuance accepted", body = OperationAcceptedView),
    (status = 400, description = "Invalid approval shape", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Claim, role, or CSRF rejected", body = ProblemDetails),
    (status = 409, description = "Expired, stale, busy, or conflicting operation", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails),
    (status = 428, description = "Additional authentication is configured but unavailable", body = ProblemDetails)
))]
async fn approve_certbot_issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CertbotIssueApprovalRequest>,
) -> Result<(StatusCode, Json<OperationAcceptedView>), ApiProblem> {
    input.validate_shape().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    if session.additional_auth_policy != AdditionalAuthPolicy::Disabled {
        return Err(ApiProblem::new(
            StatusCode::PRECONDITION_REQUIRED,
            "additional_authentication_unavailable",
        ));
    }
    if input.additional_auth_claim.is_some() {
        return Err(ApiProblem::bad_request(
            "additional_authentication_claim_unexpected",
        ));
    }
    state
        .store
        .consume_operation_claim(
            token.as_str(),
            &session.subject,
            &input.plan_hash,
            &input.reauth_token,
            now,
        )
        .map_err(map_operation_claim_error)?;
    let actor = session.subject;
    let receipt = state
        .ops
        .approve_certbot_issue(
            actor.clone(),
            input.plan_id,
            input.plan_hash,
            input.idempotency_key,
            input.external_effect_confirmed,
            input.local_attach_deferred_confirmed,
        )
        .await
        .map_err(map_ops_error)?;
    if receipt.operation_type != CERTBOT_ISSUE_OPERATION {
        return Err(ApiProblem::internal());
    }
    let operation_id = receipt.operation_id.clone();
    let accepted = OperationAcceptedView {
        schema_version: receipt.schema_version,
        operation_type: receipt.operation_type,
        operation_id: operation_id.clone(),
        plan_id: receipt.plan_id,
        plan_hash: receipt.plan_hash,
        actor: receipt.actor,
        current_stage: receipt.terminal_state,
        event_stream: format!("/api/v1/operations/{operation_id}/events"),
    };
    let ops = Arc::clone(&state.ops);
    let _execution_task = tokio::spawn(async move {
        let _execution_result = ops.execute_operation(actor, operation_id).await;
    });
    Ok((StatusCode::ACCEPTED, Json(accepted)))
}

#[utoipa::path(post, path = "/api/v1/operations/certbot/attach/plans", request_body = CertbotAttachPlanRequest, responses(
    (status = 200, description = "Immutable Certbot Nginx TLS attach plan", body = CertbotAttachPlanView),
    (status = 400, description = "Invalid typed request", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Role or CSRF rejected", body = ProblemDetails),
    (status = 409, description = "Stale site, certificate, timer, or unsupported config", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails)
))]
async fn plan_certbot_attach(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CertbotAttachPlanRequest>,
) -> Result<Json<CertbotAttachPlanView>, ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    if certbot_attach_gate_reason(&state).await.is_some() {
        return Err(ApiProblem::new(StatusCode::CONFLICT, "attach_unavailable"));
    }
    if state.config.public_host.as_deref() != Some(input.primary_domain.as_str()) {
        return Err(ApiProblem::new(StatusCode::CONFLICT, "invalid_domain"));
    }
    state
        .ops
        .plan_certbot_attach(session.subject, input)
        .await
        .map(Json)
        .map_err(map_ops_error)
}

#[utoipa::path(post, path = "/api/v1/operations/certbot/attach/approvals", request_body = CertbotAttachApprovalRequest, responses(
    (status = 202, description = "Certbot Nginx TLS attach accepted", body = OperationAcceptedView),
    (status = 400, description = "Invalid approval shape", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Claim, role, or CSRF rejected", body = ProblemDetails),
    (status = 409, description = "Expired, stale, busy, or conflicting operation", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails),
    (status = 428, description = "Additional authentication is configured but unavailable", body = ProblemDetails)
))]
async fn approve_certbot_attach(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CertbotAttachApprovalRequest>,
) -> Result<(StatusCode, Json<OperationAcceptedView>), ApiProblem> {
    input.validate_shape().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    if session.additional_auth_policy != AdditionalAuthPolicy::Disabled {
        return Err(ApiProblem::new(
            StatusCode::PRECONDITION_REQUIRED,
            "additional_authentication_unavailable",
        ));
    }
    if input.additional_auth_claim.is_some() {
        return Err(ApiProblem::bad_request(
            "additional_authentication_claim_unexpected",
        ));
    }
    state
        .store
        .consume_operation_claim(
            token.as_str(),
            &session.subject,
            &input.plan_hash,
            &input.reauth_token,
            now,
        )
        .map_err(map_operation_claim_error)?;
    let actor = session.subject;
    let receipt = state
        .ops
        .approve_certbot_attach(
            actor.clone(),
            input.plan_id,
            input.plan_hash,
            input.idempotency_key,
            input.config_replace_confirmed,
            input.service_reload_confirmed,
        )
        .await
        .map_err(map_ops_error)?;
    if receipt.operation_type != CERTBOT_ATTACH_OPERATION {
        return Err(ApiProblem::internal());
    }
    let operation_id = receipt.operation_id.clone();
    let accepted = OperationAcceptedView {
        schema_version: receipt.schema_version,
        operation_type: receipt.operation_type,
        operation_id: operation_id.clone(),
        plan_id: receipt.plan_id,
        plan_hash: receipt.plan_hash,
        actor: receipt.actor,
        current_stage: receipt.terminal_state,
        event_stream: format!("/api/v1/operations/{operation_id}/events"),
    };
    let ops = Arc::clone(&state.ops);
    let _execution_task = tokio::spawn(async move {
        let _execution_result = ops.execute_operation(actor, operation_id).await;
    });
    Ok((StatusCode::ACCEPTED, Json(accepted)))
}

async fn observe_certbot_issue_preflight(
    state: &AppState,
    domains: &[String],
    now_ms: i64,
) -> Result<CertbotIssuePreflightEvidence, ApiProblem> {
    let mut expected = state.config.public_addresses.clone();
    expected.sort();
    expected.dedup();
    if expected.is_empty() {
        return Err(ApiProblem::new(
            StatusCode::CONFLICT,
            "public_address_unconfigured",
        ));
    }
    for domain in domains {
        let lookup = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host((domain.as_str(), 80)),
        )
        .await
        .map_err(|_| ApiProblem::new(StatusCode::CONFLICT, "dns_resolution_failed"))?
        .map_err(|_| ApiProblem::new(StatusCode::CONFLICT, "dns_resolution_failed"))?;
        let mut resolved: Vec<_> = lookup.map(|address| address.ip()).collect();
        resolved.sort();
        resolved.dedup();
        if resolved != expected {
            return Err(ApiProblem::new(StatusCode::CONFLICT, "dns_mismatch"));
        }
    }
    let local_port_80_reachable = local_tcp_reachable(80).await;
    if !local_port_80_reachable {
        return Err(ApiProblem::new(
            StatusCode::CONFLICT,
            "challenge_unreachable",
        ));
    }
    Ok(CertbotIssuePreflightEvidence {
        observed_at_unix_ms: now_ms,
        resolved_addresses: expected.iter().map(ToString::to_string).collect(),
        expected_addresses: expected.iter().map(ToString::to_string).collect(),
        local_port_80_reachable,
        local_port_443_reachable: local_tcp_reachable(443).await,
    })
}

async fn local_tcp_reachable(port: u16) -> bool {
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}

async fn certbot_mutation_gate_reason(
    state: &AppState,
    subject: &Subject,
    additional_auth_policy: AdditionalAuthPolicy,
) -> Option<String> {
    if !matches!(subject.role, Role::Admin | Role::Operator) {
        return Some(String::from("현재 계정은 인증서 작업 권한이 없습니다."));
    }
    if additional_auth_policy != AdditionalAuthPolicy::Disabled {
        return Some(String::from(
            "설정된 추가 인증 수단이 아직 준비되지 않아 인증서 작업이 차단되었습니다.",
        ));
    }
    match state.ops.capabilities().await {
        Ok(capability) if capability.forensic_lockdown => Some(String::from(
            "감사 원장 무결성 잠금 상태여서 모든 변경이 차단되었습니다.",
        )),
        Ok(capability)
            if !capability.read_only
                && capability
                    .supported_operations
                    .iter()
                    .any(|operation| operation == CERTBOT_RENEW_TEST_OPERATION) =>
        {
            None
        }
        Ok(_) => Some(String::from(
            "이 서버에서는 Certbot 갱신 사전 검증을 사용할 수 없습니다.",
        )),
        Err(_) => Some(String::from(
            "권한 분리 서비스 상태를 확인할 수 없어 인증서 작업이 차단되었습니다.",
        )),
    }
}

#[utoipa::path(post, path = "/api/v1/operations/certbot/renew-test/plans", request_body = CertbotRenewTestPlanRequest, responses(
    (status = 200, description = "Immutable Certbot renewal dry-run plan", body = CertbotRenewTestPlanView),
    (status = 400, description = "Invalid typed request", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Role or CSRF rejected", body = ProblemDetails),
    (status = 409, description = "Stale, busy, or idempotency conflict", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails)
))]
async fn plan_certbot_renew_test(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CertbotRenewTestPlanRequest>,
) -> Result<Json<CertbotRenewTestPlanView>, ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    let plan = state
        .ops
        .plan_certbot_renew_test(session.subject, input)
        .await
        .map_err(map_ops_error)?;
    Ok(Json(plan))
}

#[utoipa::path(post, path = "/api/v1/operations/certbot/renew-test/approvals", request_body = CertbotRenewTestApprovalRequest, responses(
    (status = 202, description = "Certbot renewal test accepted", body = OperationAcceptedView),
    (status = 400, description = "Invalid approval shape", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Claim, role, or CSRF rejected", body = ProblemDetails),
    (status = 409, description = "Expired, stale, busy, or conflicting operation", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails),
    (status = 428, description = "Additional authentication is configured but unavailable", body = ProblemDetails)
))]
async fn approve_certbot_renew_test(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CertbotRenewTestApprovalRequest>,
) -> Result<(StatusCode, Json<OperationAcceptedView>), ApiProblem> {
    input.validate_shape().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    if session.additional_auth_policy != AdditionalAuthPolicy::Disabled {
        return Err(ApiProblem::new(
            StatusCode::PRECONDITION_REQUIRED,
            "additional_authentication_unavailable",
        ));
    }
    if input.additional_auth_claim.is_some() {
        return Err(ApiProblem::bad_request(
            "additional_authentication_claim_unexpected",
        ));
    }
    state
        .store
        .consume_operation_claim(
            token.as_str(),
            &session.subject,
            &input.plan_hash,
            &input.reauth_token,
            now,
        )
        .map_err(map_operation_claim_error)?;
    let actor = session.subject;
    let receipt = state
        .ops
        .approve_certbot_renew_test(
            actor.clone(),
            input.plan_id,
            input.plan_hash,
            input.idempotency_key,
            input.external_effect_confirmed,
        )
        .await
        .map_err(map_ops_error)?;
    if receipt.operation_type != CERTBOT_RENEW_TEST_OPERATION {
        return Err(ApiProblem::internal());
    }
    let operation_id = receipt.operation_id.clone();
    let accepted = OperationAcceptedView {
        schema_version: receipt.schema_version,
        operation_type: receipt.operation_type,
        operation_id: operation_id.clone(),
        plan_id: receipt.plan_id,
        plan_hash: receipt.plan_hash,
        actor: receipt.actor,
        current_stage: receipt.terminal_state,
        event_stream: format!("/api/v1/operations/{operation_id}/events"),
    };
    let ops = Arc::clone(&state.ops);
    let _execution_task = tokio::spawn(async move {
        let _execution_result = ops.execute_operation(actor, operation_id).await;
    });
    Ok((StatusCode::ACCEPTED, Json(accepted)))
}

async fn nginx_mutation_gate_reason(
    state: &AppState,
    subject: &Subject,
    additional_auth_policy: AdditionalAuthPolicy,
) -> Option<String> {
    if !matches!(subject.role, Role::Admin | Role::Operator) {
        return Some(String::from("현재 계정은 Nginx 변경 권한이 없습니다."));
    }
    if additional_auth_policy != AdditionalAuthPolicy::Disabled {
        return Some(String::from(
            "설정된 추가 인증 수단이 아직 준비되지 않아 변경이 차단되었습니다.",
        ));
    }
    match state.ops.capabilities().await {
        Ok(capability) if capability.forensic_lockdown => Some(String::from(
            "감사 원장 무결성 잠금 상태여서 모든 변경이 차단되었습니다.",
        )),
        Ok(capability)
            if !capability.read_only
                && capability
                    .supported_operations
                    .iter()
                    .any(|operation| operation == NGINX_SITE_STATE_OPERATION) =>
        {
            None
        }
        Ok(_) => Some(String::from(
            "이 서버에서는 Nginx 자동 원복 작업을 사용할 수 없습니다.",
        )),
        Err(_) => Some(String::from(
            "권한 분리 서비스 상태를 확인할 수 없어 변경이 차단되었습니다.",
        )),
    }
}

#[utoipa::path(post, path = "/api/v1/operations/nginx/site-state/plans", request_body = NginxSiteStatePlanRequest, responses(
    (status = 200, description = "Immutable Nginx site-state plan", body = NginxSiteStatePlanView),
    (status = 400, description = "Invalid typed request", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Role or CSRF rejected", body = ProblemDetails),
    (status = 409, description = "Stale, busy, or idempotency conflict", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails)
))]
async fn plan_nginx_site_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<NginxSiteStatePlanRequest>,
) -> Result<Json<NginxSiteStatePlanView>, ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    let plan = state
        .ops
        .plan_nginx_site_state(session.subject, input)
        .await
        .map_err(map_ops_error)?;
    Ok(Json(plan))
}

#[utoipa::path(post, path = "/api/v1/operations/nginx/site-state/approvals", request_body = OperationApprovalRequest, responses(
    (status = 202, description = "Operation accepted for durable background execution", body = OperationAcceptedView),
    (status = 400, description = "Invalid approval shape", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Claim, role, or CSRF rejected", body = ProblemDetails),
    (status = 409, description = "Expired, stale, busy, or conflicting operation", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails),
    (status = 428, description = "Additional authentication is configured but unavailable", body = ProblemDetails)
))]
async fn approve_nginx_site_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<OperationApprovalRequest>,
) -> Result<(StatusCode, Json<OperationAcceptedView>), ApiProblem> {
    input.validate_shape().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    if session.additional_auth_policy != AdditionalAuthPolicy::Disabled {
        return Err(ApiProblem::new(
            StatusCode::PRECONDITION_REQUIRED,
            "additional_authentication_unavailable",
        ));
    }
    if input.additional_auth_claim.is_some() {
        return Err(ApiProblem::bad_request(
            "additional_authentication_claim_unexpected",
        ));
    }
    state
        .store
        .consume_operation_claim(
            token.as_str(),
            &session.subject,
            &input.plan_hash,
            &input.reauth_token,
            now,
        )
        .map_err(map_operation_claim_error)?;
    let actor = session.subject;
    let receipt = state
        .ops
        .approve_nginx_site_state(
            actor.clone(),
            input.plan_id,
            input.plan_hash,
            input.idempotency_key,
        )
        .await
        .map_err(map_ops_error)?;
    let operation_id = receipt.operation_id.clone();
    let accepted = OperationAcceptedView {
        schema_version: receipt.schema_version,
        operation_type: receipt.operation_type,
        operation_id: operation_id.clone(),
        plan_id: receipt.plan_id,
        plan_hash: receipt.plan_hash,
        actor: receipt.actor,
        current_stage: receipt.terminal_state,
        event_stream: format!("/api/v1/operations/{operation_id}/events"),
    };
    let ops = Arc::clone(&state.ops);
    let _execution_task = tokio::spawn(async move {
        let _execution_result = ops.execute_operation(actor, operation_id).await;
    });
    Ok((StatusCode::ACCEPTED, Json(accepted)))
}

#[utoipa::path(get, path = "/api/v1/config-resources/{resource_id}", params(
    ("resource_id" = String, Path, description = "Opaque allowlisted configuration resource identifier")
), responses(
    (status = 200, description = "Managed configuration resource", body = ManagedConfigResourceView),
    (status = 400, description = "Invalid resource identifier", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Protected resource", body = ProblemDetails),
    (status = 404, description = "Resource not found", body = ProblemDetails)
))]
async fn managed_config_resource(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(resource_id): Path<String>,
) -> Result<Json<ManagedConfigResourceView>, ApiProblem> {
    validate_managed_config_resource_id(&resource_id)?;
    let (_, session) = current_session(&state, &headers, unix_milliseconds()?)?;
    let resource = state
        .ops
        .read_managed_config(session.subject, resource_id)
        .await
        .map_err(map_ops_error)?;
    Ok(Json(resource))
}

#[utoipa::path(post, path = "/api/v1/operations/service/config-file/plans", request_body = ManagedConfigPlanRequest, responses(
    (status = 200, description = "Immutable managed configuration plan", body = ManagedConfigPlanView),
    (status = 400, description = "Invalid typed request", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Role, protected resource, or CSRF rejected", body = ProblemDetails),
    (status = 409, description = "Stale, busy, or idempotency conflict", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails)
))]
async fn plan_managed_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ManagedConfigPlanRequest>,
) -> Result<Json<ManagedConfigPlanView>, ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    let plan = state
        .ops
        .plan_managed_config(session.subject, input)
        .await
        .map_err(map_ops_error)?;
    Ok(Json(plan))
}

#[utoipa::path(post, path = "/api/v1/operations/service/config-file/approvals", request_body = ManagedConfigApprovalRequest, responses(
    (status = 202, description = "Managed configuration operation accepted", body = OperationAcceptedView),
    (status = 400, description = "Invalid approval shape", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Claim, role, or CSRF rejected", body = ProblemDetails),
    (status = 409, description = "Expired, stale, busy, or conflicting operation", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails),
    (status = 428, description = "Additional authentication is configured but unavailable", body = ProblemDetails)
))]
async fn approve_managed_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ManagedConfigApprovalRequest>,
) -> Result<(StatusCode, Json<OperationAcceptedView>), ApiProblem> {
    input.validate_shape().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    if session.additional_auth_policy != AdditionalAuthPolicy::Disabled {
        return Err(ApiProblem::new(
            StatusCode::PRECONDITION_REQUIRED,
            "additional_authentication_unavailable",
        ));
    }
    if input.additional_auth_claim.is_some() {
        return Err(ApiProblem::bad_request(
            "additional_authentication_claim_unexpected",
        ));
    }
    state
        .store
        .consume_operation_claim(
            token.as_str(),
            &session.subject,
            &input.plan_hash,
            &input.reauth_token,
            now,
        )
        .map_err(map_operation_claim_error)?;
    let actor = session.subject;
    let receipt = state
        .ops
        .approve_managed_config(
            actor.clone(),
            input.plan_id,
            input.plan_hash,
            input.idempotency_key,
            input.approval_intent,
        )
        .await
        .map_err(map_ops_error)?;
    if receipt.operation_type != MANAGED_CONFIG_OPERATION {
        return Err(ApiProblem::internal());
    }
    let operation_id = receipt.operation_id.clone();
    let accepted = OperationAcceptedView {
        schema_version: receipt.schema_version,
        operation_type: receipt.operation_type,
        operation_id: operation_id.clone(),
        plan_id: receipt.plan_id,
        plan_hash: receipt.plan_hash,
        actor: receipt.actor,
        current_stage: receipt.terminal_state,
        event_stream: format!("/api/v1/operations/{operation_id}/events"),
    };
    let ops = Arc::clone(&state.ops);
    let _execution_task = tokio::spawn(async move {
        let _execution_result = ops.execute_operation(actor, operation_id).await;
    });
    Ok((StatusCode::ACCEPTED, Json(accepted)))
}

#[utoipa::path(get, path = "/api/v1/operations/{operation_id}/events", params(
    ("operation_id" = String, Path, description = "Opaque operation identifier")
), responses(
    (status = 200, description = "Resumable operation stage event stream", content_type = "text/event-stream"),
    (status = 400, description = "Invalid operation or event identifier", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
async fn operation_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(operation_id): Path<String>,
) -> Result<Response, ApiProblem> {
    validate_operation_id(&operation_id)?;
    let (_, session) = current_session(&state, &headers, unix_milliseconds()?)?;
    let last_sequence = last_event_sequence(&headers)?;
    let stream = OperationEventStream::new(
        Arc::clone(&state.ops),
        session.subject,
        operation_id,
        last_sequence,
    );
    let mut response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(10))
                .text("keepalive"),
        )
        .into_response();
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(response)
}

#[utoipa::path(get, path = "/api/v1/operations/{operation_id}", params(
    ("operation_id" = String, Path, description = "Opaque operation identifier")
), responses(
    (status = 200, description = "Operation receipt or current stage", body = OperationReceiptView),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Operation belongs to another actor", body = ProblemDetails),
    (status = 404, description = "Operation not found", body = ProblemDetails)
))]
async fn operation_receipt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(operation_id): Path<String>,
) -> Result<Json<OperationReceiptView>, ApiProblem> {
    validate_operation_id(&operation_id)?;
    let (_, session) = current_session(&state, &headers, unix_milliseconds()?)?;
    let receipt = state
        .ops
        .operation_receipt(session.subject, operation_id)
        .await
        .map_err(map_ops_error)?;
    Ok(Json(receipt))
}

type ReceiptFuture =
    Pin<Box<dyn Future<Output = Result<OperationReceiptView, OpsBrokerError>> + Send + 'static>>;

struct OperationEventStream {
    ops: Arc<dyn OpsBroker>,
    actor: Subject,
    operation_id: String,
    last_sequence: u64,
    queue: VecDeque<Event>,
    delay: Pin<Box<tokio::time::Sleep>>,
    pending: Option<ReceiptFuture>,
    deadline: Instant,
    close_after_queue: bool,
}

impl OperationEventStream {
    fn new(
        ops: Arc<dyn OpsBroker>,
        actor: Subject,
        operation_id: String,
        last_sequence: u64,
    ) -> Self {
        Self {
            ops,
            actor,
            operation_id,
            last_sequence,
            queue: VecDeque::new(),
            delay: Box::pin(tokio::time::sleep(Duration::ZERO)),
            pending: None,
            deadline: Instant::now() + Duration::from_secs(15 * 60),
            close_after_queue: false,
        }
    }

    fn record_receipt(&mut self, receipt: OperationReceiptView) {
        for stage in receipt.stages {
            if stage.sequence <= self.last_sequence {
                continue;
            }
            self.last_sequence = self.last_sequence.max(stage.sequence);
            self.push_stage(stage);
        }
        if receipt.terminal_state.is_terminal() {
            self.close_after_queue = true;
        } else {
            self.delay = Box::pin(tokio::time::sleep(Duration::from_millis(300)));
        }
    }

    fn push_stage(&mut self, stage: OperationStageEvidenceView) {
        match serde_json::to_string(&stage) {
            Ok(data) => self.queue.push_back(
                Event::default()
                    .event("operation-stage")
                    .id(stage.sequence.to_string())
                    .data(data),
            ),
            Err(_) => self.push_error("event_serialization_failed"),
        }
    }

    fn push_error(&mut self, code: &str) {
        let data = format!("{{\"code\":\"{code}\"}}");
        self.queue
            .push_back(Event::default().event("operation-error").data(data));
        self.close_after_queue = true;
    }
}

impl Stream for OperationEventStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.get_mut();
        loop {
            if let Some(event) = stream.queue.pop_front() {
                return Poll::Ready(Some(Ok(event)));
            }
            if stream.close_after_queue {
                return Poll::Ready(None);
            }
            if Instant::now() >= stream.deadline {
                stream.push_error("event_stream_window_elapsed");
                continue;
            }
            if let Some(mut pending) = stream.pending.take() {
                match pending.as_mut().poll(context) {
                    Poll::Pending => {
                        stream.pending = Some(pending);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(receipt)) => stream.record_receipt(receipt),
                    Poll::Ready(Err(_)) => stream.push_error("operation_receipt_unavailable"),
                }
                continue;
            }
            match stream.delay.as_mut().poll(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {
                    let ops = Arc::clone(&stream.ops);
                    let actor = stream.actor.clone();
                    let operation_id = stream.operation_id.clone();
                    stream.pending = Some(Box::pin(async move {
                        ops.operation_receipt(actor, operation_id).await
                    }));
                }
            }
        }
    }
}

fn validate_operation_id(operation_id: &str) -> Result<(), ApiProblem> {
    if operation_id.is_empty()
        || operation_id.len() > 64
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Err(ApiProblem::bad_request("operation_id"))
    } else {
        Ok(())
    }
}

fn validate_managed_config_resource_id(resource_id: &str) -> Result<(), ApiProblem> {
    if resource_id.len() < 12
        || resource_id.len() > 64
        || !resource_id.starts_with("ngc_")
        || !resource_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Err(ApiProblem::bad_request("resource_id"))
    } else {
        Ok(())
    }
}

fn last_event_sequence(headers: &HeaderMap) -> Result<u64, ApiProblem> {
    let Some(value) = headers.get("last-event-id") else {
        return Ok(0);
    };
    let text = value
        .to_str()
        .map_err(|_| ApiProblem::bad_request("last_event_id"))?;
    text.parse::<u64>()
        .map_err(|_| ApiProblem::bad_request("last_event_id"))
}

#[utoipa::path(get, path = "/api/v1/integrations", responses(
    (status = 200, description = "Curated integration catalog", body = IntegrationCatalogView),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
async fn integrations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<IntegrationCatalogView>, ApiProblem> {
    let _session = current_session(&state, &headers, unix_milliseconds()?)?;
    Ok(Json(observe_integrations(
        &IntegrationObservationProfile::default(),
        now_rfc3339()?,
    )))
}

#[utoipa::path(get, path = "/api/v1/settings/access", responses(
    (status = 200, description = "Access settings", body = AccessSettingsView),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
async fn access_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AccessSettingsView>, ApiProblem> {
    let _session = current_session(&state, &headers, unix_milliseconds()?)?;
    Ok(Json(access_view(&state)?))
}

#[utoipa::path(put, path = "/api/v1/settings/access/additional-auth", request_body = UpdateAdditionalAuthRequest, responses(
    (status = 200, description = "Updated access settings", body = AccessSettingsView),
    (status = 403, description = "Role, CSRF, or claim rejected", body = ProblemDetails),
    (status = 428, description = "Recent PAM reauthentication required", body = ProblemDetails)
))]
async fn update_additional_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<UpdateAdditionalAuthRequest>,
) -> Result<Json<AccessSettingsView>, ApiProblem> {
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    state
        .store
        .update_additional_auth_policy(
            token.as_str(),
            &session.subject,
            input.policy,
            input.reauth_token.as_deref(),
            now,
        )
        .map_err(map_policy_error)?;
    Ok(Json(access_view(&state)?))
}

async fn request_guard(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if let Err(problem) = validate_request_boundary(&state, &request) {
        return problem.into_response();
    }
    let mut response = next.run(request).await;
    apply_security_headers(&state, &mut response);
    response
}

fn validate_request_boundary(state: &AppState, request: &Request<Body>) -> Result<(), ApiProblem> {
    let expected_host = state.config.expected_host(state.channel);
    let actual_host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiProblem::bad_request("host_required"))?;
    if expected_host.is_empty() || actual_host != expected_host {
        return Err(ApiProblem::bad_request("host_rejected"));
    }

    if is_mutation(request.method()) {
        let expected_origin = state.config.expected_origin(state.channel);
        let actual_origin = request
            .headers()
            .get(ORIGIN)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ApiProblem::forbidden("origin_required"))?;
        if expected_origin.is_empty() || actual_origin != expected_origin {
            return Err(ApiProblem::forbidden("origin_rejected"));
        }
    }
    Ok(())
}

fn is_mutation(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn apply_security_headers(state: &AppState, response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if state.channel == IngressChannel::Public {
        headers.insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
}

fn current_session(
    state: &AppState,
    headers: &HeaderMap,
    now_unix_ms: i64,
) -> Result<(Zeroizing<String>, SessionView), ApiProblem> {
    let token = session_cookie(state, headers)?
        .ok_or_else(|| ApiProblem::unauthorized("authentication_required"))?;
    let view = state
        .store
        .authenticate_session(token.as_str(), state.channel, now_unix_ms)
        .map_err(|_| ApiProblem::internal())?
        .ok_or_else(|| ApiProblem::unauthorized("authentication_required"))?;
    Ok((token, view))
}

fn session_cookie(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<Zeroizing<String>>, ApiProblem> {
    let cookie_header = match headers.get(COOKIE) {
        Some(value) => value
            .to_str()
            .map_err(|_| ApiProblem::bad_request("cookie_rejected"))?,
        None => return Ok(None),
    };
    let own_name = state.channel.cookie_name();
    let forbidden_name = state.channel.forbidden_cookie_name();
    let mut own_value: Option<Zeroizing<String>> = None;
    for item in cookie_header.split(';') {
        let Some((name, value)) = item.trim().split_once('=') else {
            continue;
        };
        if name == forbidden_name {
            return Err(ApiProblem::unauthorized("ingress_session_mismatch"));
        }
        if name == own_name {
            if own_value.is_some() {
                return Err(ApiProblem::bad_request("duplicate_session_cookie"));
            }
            own_value = Some(Zeroizing::new(value.to_owned()));
        }
    }
    Ok(own_value)
}

fn require_csrf(headers: &HeaderMap, session_token: &str) -> Result<(), ApiProblem> {
    let provided = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiProblem::forbidden("csrf_required"))?;
    if crate::session::csrf_matches(session_token, provided) {
        Ok(())
    } else {
        Err(ApiProblem::forbidden("csrf_rejected"))
    }
}

fn set_session_cookie(
    state: &AppState,
    token: &str,
    response: &mut Response,
) -> Result<(), ApiProblem> {
    let secure = if state.channel == IngressChannel::Public {
        "; Secure"
    } else {
        ""
    };
    let value = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict{}",
        state.channel.cookie_name(),
        token,
        secure
    );
    let header = HeaderValue::from_str(&value).map_err(|_| ApiProblem::internal())?;
    response.headers_mut().append(SET_COOKIE, header);
    Ok(())
}

fn clear_session_cookie(state: &AppState, response: &mut Response) -> Result<(), ApiProblem> {
    let secure = if state.channel == IngressChannel::Public {
        "; Secure"
    } else {
        ""
    };
    let value = format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        state.channel.cookie_name(),
        secure
    );
    let header = HeaderValue::from_str(&value).map_err(|_| ApiProblem::internal())?;
    response.headers_mut().append(SET_COOKIE, header);
    response.headers_mut().insert(
        "clear-site-data",
        HeaderValue::from_static("\"cache\", \"storage\""),
    );
    Ok(())
}

fn request_source(state: &AppState, headers: &HeaderMap) -> Result<String, ApiProblem> {
    if state.channel == IngressChannel::Recovery {
        return Ok(String::from("loopback"));
    }
    let source = headers
        .get(CLIENT_ADDRESS_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiProblem::bad_request("trusted_client_address_required"))?;
    if source.len() > 64 || source.parse::<std::net::IpAddr>().is_err() {
        return Err(ApiProblem::bad_request("trusted_client_address_rejected"));
    }
    Ok(source.to_owned())
}

fn access_view(state: &AppState) -> Result<AccessSettingsView, ApiProblem> {
    let policy = state
        .store
        .additional_auth_policy()
        .map_err(|_| ApiProblem::internal())?;
    Ok(AccessSettingsView {
        ingress: state.channel,
        public_host: state.config.public_host.clone(),
        recovery_origin: state.config.recovery_origin.clone(),
        additional_auth_policy: policy,
        additional_auth_provider: AdditionalAuthProviderStatus::NotImplemented,
        mutation_approval_available: policy == AdditionalAuthPolicy::Disabled,
        assurance: AssuranceView {
            level: AssuranceLevel::G2ReversibleConfig,
            rollback_support: RollbackSupport::AutomaticBounded,
            operation_available: true,
            scope: vec![String::from("JW Agent 추가 인증 정책 값")],
            excluded_effects: vec![String::from(
                "외부 추가 인증 provider의 등록·복구·credential",
            )],
            apply_verifier: vec![String::from(
                "SQLite transaction commit 후 canonical read-back",
            )],
            rollback_verifier: vec![String::from(
                "저장 실패 시 transaction abort로 이전 정책 유지",
            )],
            reason: None,
        },
    })
}

fn reauth_context(purpose: &ReauthPurpose) -> String {
    match purpose {
        ReauthPurpose::Operation { plan_hash } => plan_hash.clone(),
        ReauthPurpose::SecurityPolicyChange { target_policy } => {
            target_policy.as_storage_value().to_owned()
        }
    }
}

fn validate_auth_response(
    response: &jw_contracts::AuthResponse,
    request_id: &str,
) -> Result<(), ApiProblem> {
    if response.protocol_version != IPC_PROTOCOL_VERSION || response.request_id != request_id {
        Err(ApiProblem::unavailable("authentication_invalid_response"))
    } else {
        Ok(())
    }
}

fn auth_failure(class: AuthFailureClass) -> ApiProblem {
    match class {
        AuthFailureClass::Denied | AuthFailureClass::InvalidRequest => {
            ApiProblem::unauthorized("invalid_credentials")
        }
        AuthFailureClass::Unsupported | AuthFailureClass::Unavailable => {
            ApiProblem::unavailable("authentication_unavailable")
        }
    }
}

fn map_policy_error(error: PolicyUpdateError) -> ApiProblem {
    match error {
        PolicyUpdateError::Denied => ApiProblem::forbidden("role_denied"),
        PolicyUpdateError::ReauthRequired => ApiProblem::new(
            StatusCode::PRECONDITION_REQUIRED,
            "reauthentication_required",
        ),
        PolicyUpdateError::InvalidReauth => ApiProblem::forbidden("reauthentication_rejected"),
        PolicyUpdateError::Storage(_) => ApiProblem::internal(),
    }
}

fn map_operation_claim_error(error: OperationClaimError) -> ApiProblem {
    match error {
        OperationClaimError::Invalid => ApiProblem::forbidden("reauthentication_rejected"),
        OperationClaimError::Storage(_) => ApiProblem::internal(),
    }
}

fn map_ops_error(error: OpsBrokerError) -> ApiProblem {
    match error {
        OpsBrokerError::Unavailable | OpsBrokerError::Timeout | OpsBrokerError::InvalidResponse => {
            ApiProblem::unavailable("operation_service_unavailable")
        }
        OpsBrokerError::Rejected(code) => match code.as_str() {
            "role_denied"
            | "protected_resource"
            | "protected_content"
            | "operation_access_denied" => ApiProblem::forbidden(code),
            "forensic_lockdown" => ApiProblem::new(StatusCode::LOCKED, code),
            "site_missing" | "resource_missing" | "plan_missing" | "operation_missing" => {
                ApiProblem::new(StatusCode::NOT_FOUND, code)
            }
            "schema_version"
            | "operation_type"
            | "site_id"
            | "digest"
            | "idempotency_key"
            | "plan_id"
            | "plan_hash"
            | "operation_id"
            | "resource_id"
            | "size_limit"
            | "invalid_encoding"
            | "unsupported_service_action"
            | "approval_intent"
            | "external_effect_confirmation" => ApiProblem::bad_request(code),
            _ => ApiProblem::new(StatusCode::CONFLICT, code),
        },
    }
}

fn random_identifier() -> Result<String, ApiProblem> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ApiProblem::internal())?;
    let mut output = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").map_err(|_| ApiProblem::internal())?;
    }
    Ok(output)
}

fn deadline(now_unix_ms: i64, timeout: Duration) -> i64 {
    let timeout_ms = i64::try_from(timeout.as_millis()).map_or(i64::MAX, std::convert::identity);
    now_unix_ms.saturating_add(timeout_ms)
}

fn unix_milliseconds() -> Result<i64, ApiProblem> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiProblem::internal())?;
    i64::try_from(duration.as_millis()).map_err(|_| ApiProblem::internal())
}

fn now_rfc3339() -> Result<String, ApiProblem> {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| ApiProblem::internal())
}

fn format_unix_ms(unix_ms: i64) -> Result<String, ApiProblem> {
    let nanos = i128::from(unix_ms).saturating_mul(1_000_000);
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| ApiProblem::internal())?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| ApiProblem::internal())
}

#[derive(Clone, Default)]
struct AuthLimiter {
    state: Arc<Mutex<AuthLimiterState>>,
}

#[derive(Default)]
struct AuthLimiterState {
    global: Option<Counter>,
    sources: HashMap<String, Counter>,
    subjects: HashMap<[u8; 32], Counter>,
}

struct Counter {
    started: Instant,
    attempts: u32,
}

impl AuthLimiter {
    fn consume(&self, source: &str, username: &str) -> Result<(), ApiProblem> {
        let now = Instant::now();
        let subject: [u8; 32] = Sha256::digest(username.as_bytes()).into();
        let mut state = self
            .state
            .lock()
            .map_err(|_| ApiProblem::rate_limited(AUTH_WINDOW))?;
        cleanup_limiter(&mut state, now);
        if state.sources.len() >= AUTH_KEY_LIMIT && !state.sources.contains_key(source) {
            return Err(ApiProblem::rate_limited(AUTH_WINDOW));
        }
        if state.subjects.len() >= AUTH_KEY_LIMIT && !state.subjects.contains_key(&subject) {
            return Err(ApiProblem::rate_limited(AUTH_WINDOW));
        }
        consume_counter(&mut state.global, AUTH_GLOBAL_LIMIT, now)?;
        consume_map_counter(
            &mut state.sources,
            source.to_owned(),
            AUTH_SOURCE_LIMIT,
            now,
        )?;
        consume_map_counter(&mut state.subjects, subject, AUTH_SUBJECT_LIMIT, now)
    }
}

fn cleanup_limiter(state: &mut AuthLimiterState, now: Instant) {
    state
        .sources
        .retain(|_, counter| now.duration_since(counter.started) < AUTH_WINDOW);
    state
        .subjects
        .retain(|_, counter| now.duration_since(counter.started) < AUTH_WINDOW);
    if state
        .global
        .as_ref()
        .is_some_and(|counter| now.duration_since(counter.started) >= AUTH_WINDOW)
    {
        state.global = None;
    }
}

fn consume_counter(slot: &mut Option<Counter>, limit: u32, now: Instant) -> Result<(), ApiProblem> {
    let counter = slot.get_or_insert(Counter {
        started: now,
        attempts: 0,
    });
    if counter.attempts >= limit {
        return Err(ApiProblem::rate_limited(remaining(counter, now)));
    }
    counter.attempts = counter.attempts.saturating_add(1);
    Ok(())
}

fn consume_map_counter<K: std::hash::Hash + Eq>(
    map: &mut HashMap<K, Counter>,
    key: K,
    limit: u32,
    now: Instant,
) -> Result<(), ApiProblem> {
    let counter = map.entry(key).or_insert(Counter {
        started: now,
        attempts: 0,
    });
    if counter.attempts >= limit {
        return Err(ApiProblem::rate_limited(remaining(counter, now)));
    }
    counter.attempts = counter.attempts.saturating_add(1);
    Ok(())
}

fn remaining(counter: &Counter, now: Instant) -> Duration {
    AUTH_WINDOW.saturating_sub(now.duration_since(counter.started))
}

#[derive(Debug)]
struct ApiProblem {
    status: StatusCode,
    code: String,
    retry_after: Option<Duration>,
}

impl ApiProblem {
    fn new(status: StatusCode, code: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            retry_after: None,
        }
    }

    fn bad_request(code: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code)
    }

    fn unauthorized(code: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code)
    }

    fn forbidden(code: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code)
    }

    fn unavailable(code: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, code)
    }

    fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
    }

    fn rate_limited(retry_after: Duration) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: String::from("authentication_rate_limited"),
            retry_after: Some(retry_after),
        }
    }
}

impl IntoResponse for ApiProblem {
    fn into_response(self) -> Response {
        let title = match self.status {
            StatusCode::BAD_REQUEST => "Request rejected",
            StatusCode::UNAUTHORIZED => "Authentication required",
            StatusCode::FORBIDDEN => "Request forbidden",
            StatusCode::NOT_FOUND => "Resource not found",
            StatusCode::CONFLICT => "Operation conflict",
            StatusCode::LOCKED => "Operations locked",
            StatusCode::TOO_MANY_REQUESTS => "Too many requests",
            StatusCode::PRECONDITION_REQUIRED => "Precondition required",
            StatusCode::SERVICE_UNAVAILABLE => "Service unavailable",
            _ => "Internal server error",
        };
        let problem = ProblemDetails {
            type_uri: String::from("about:blank"),
            title: title.to_owned(),
            status: self.status.as_u16(),
            code: self.code.to_owned(),
        };
        let mut response = (self.status, Json(problem)).into_response();
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Some(retry_after) = self.retry_after {
            let seconds = retry_after.as_secs().max(1).to_string();
            if let Ok(value) = HeaderValue::from_str(&seconds) {
                response.headers_mut().insert("retry-after", value);
            }
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::header::{COOKIE, HOST, ORIGIN, SET_COOKIE};
    use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
    use jw_contracts::{
        AuthRequest, AuthResponse, AuthResult, IPC_PROTOCOL_VERSION, IngressChannel, LoginRequest,
        Role, SecretString, Subject,
    };

    use crate::auth_client::AuthFuture;
    use crate::ops_client::{OpsBrokerError, OpsFuture};
    use crate::{AgentConfig, AuthBroker, OpsBroker, SessionStore};

    use super::{
        AppState, AuthLimiter, login, session_cookie, validate_request_boundary, websocket_ticket,
    };

    struct StaticAuth;
    struct StaticOps;

    impl AuthBroker for StaticAuth {
        fn authenticate<'a>(&'a self, request: AuthRequest) -> AuthFuture<'a> {
            Box::pin(async move {
                Ok(AuthResponse {
                    protocol_version: IPC_PROTOCOL_VERSION,
                    request_id: request.request_id,
                    result: AuthResult::Authenticated {
                        subject: Subject {
                            uid: 1_000,
                            username: request.username,
                            role: Role::Admin,
                        },
                        account_validated_at: String::from("2026-07-21T00:00:00Z"),
                    },
                })
            })
        }

        fn platform_supported(&self) -> bool {
            true
        }
    }

    impl OpsBroker for StaticOps {
        fn capabilities<'a>(&'a self) -> OpsFuture<'a, jw_contracts::OpsCapabilityResponse> {
            Box::pin(async move {
                Ok(jw_contracts::OpsCapabilityResponse {
                    read_only: true,
                    supported_operations: Vec::new(),
                    forensic_lockdown: false,
                })
            })
        }

        fn certificate_inventory<'a>(
            &'a self,
            _actor: Subject,
        ) -> OpsFuture<'a, jw_contracts::CertificateInventoryView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }

        fn plan_certbot_issue<'a>(
            &'a self,
            _actor: Subject,
            _plan: jw_contracts::CertbotIssuePlanInput,
        ) -> OpsFuture<'a, jw_contracts::CertbotIssuePlanView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }

        fn approve_certbot_issue<'a>(
            &'a self,
            _actor: Subject,
            _plan_id: String,
            _plan_hash: String,
            _idempotency_key: String,
            _external_effect_confirmed: bool,
            _local_attach_deferred_confirmed: bool,
        ) -> OpsFuture<'a, jw_contracts::OperationReceiptView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }

        fn plan_certbot_renew_test<'a>(
            &'a self,
            _actor: Subject,
            _plan: jw_contracts::CertbotRenewTestPlanRequest,
        ) -> OpsFuture<'a, jw_contracts::CertbotRenewTestPlanView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }

        fn approve_certbot_renew_test<'a>(
            &'a self,
            _actor: Subject,
            _plan_id: String,
            _plan_hash: String,
            _idempotency_key: String,
            _external_effect_confirmed: bool,
        ) -> OpsFuture<'a, jw_contracts::OperationReceiptView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }

        fn plan_certbot_attach<'a>(
            &'a self,
            _actor: Subject,
            _plan: jw_contracts::CertbotAttachPlanRequest,
        ) -> OpsFuture<'a, jw_contracts::CertbotAttachPlanView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }

        fn approve_certbot_attach<'a>(
            &'a self,
            _actor: Subject,
            _plan_id: String,
            _plan_hash: String,
            _idempotency_key: String,
            _config_replace_confirmed: bool,
            _service_reload_confirmed: bool,
        ) -> OpsFuture<'a, jw_contracts::OperationReceiptView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }

        fn read_managed_config<'a>(
            &'a self,
            _actor: Subject,
            _resource_id: String,
        ) -> OpsFuture<'a, jw_contracts::ManagedConfigResourceView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }

        fn plan_nginx_site_state<'a>(
            &'a self,
            _actor: Subject,
            _plan: jw_contracts::NginxSiteStatePlanRequest,
        ) -> OpsFuture<'a, jw_contracts::NginxSiteStatePlanView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }

        fn approve_nginx_site_state<'a>(
            &'a self,
            _actor: Subject,
            _plan_id: String,
            _plan_hash: String,
            _idempotency_key: String,
        ) -> OpsFuture<'a, jw_contracts::OperationReceiptView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }

        fn plan_managed_config<'a>(
            &'a self,
            _actor: Subject,
            _plan: jw_contracts::ManagedConfigPlanRequest,
        ) -> OpsFuture<'a, jw_contracts::ManagedConfigPlanView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }

        fn approve_managed_config<'a>(
            &'a self,
            _actor: Subject,
            _plan_id: String,
            _plan_hash: String,
            _idempotency_key: String,
            _approval_intent: jw_contracts::ManagedConfigApprovalIntent,
        ) -> OpsFuture<'a, jw_contracts::OperationReceiptView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }

        fn operation_receipt<'a>(
            &'a self,
            _actor: Subject,
            _operation_id: String,
        ) -> OpsFuture<'a, jw_contracts::OperationReceiptView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }

        fn execute_operation<'a>(
            &'a self,
            _actor: Subject,
            _operation_id: String,
        ) -> OpsFuture<'a, jw_contracts::OperationReceiptView> {
            Box::pin(async move { Err(OpsBrokerError::Unavailable) })
        }
    }

    fn test_state(channel: IngressChannel) -> Result<(AppState, PathBuf), String> {
        let path = test_path()?;
        let store = SessionStore::open(path.clone(), 1_000)?;
        let recovery_address = "127.0.0.1:8787"
            .parse()
            .map_err(|_| String::from("test recovery address is invalid"))?;
        let config = AgentConfig {
            recovery_address,
            recovery_origin: String::from("http://127.0.0.1:8787"),
            public_host: Some(String::from("server.example.com")),
            public_addresses: vec![
                "192.0.2.10"
                    .parse()
                    .map_err(|_| String::from("test public address is invalid"))?,
            ],
            proxy_socket: PathBuf::from("/run/jw-agent-proxy/agentd.sock"),
            auth_socket: PathBuf::from("/run/jw-agent/authd.sock"),
            ops_socket: PathBuf::from("/run/jw-agent/opsd.sock"),
            database: path.clone(),
            web_root: std::env::temp_dir(),
            ssh_executable: PathBuf::from("/usr/bin/ssh"),
            ssh_known_hosts: PathBuf::from("/etc/jw-agent/ssh_known_hosts"),
            askpass_executable: PathBuf::from("/usr/lib/jw-agent/jw-agentd"),
            askpass_directory: PathBuf::from("/run/jw-agent/askpass"),
            stty_executable: PathBuf::from("/usr/bin/stty"),
            setsid_executable: PathBuf::from("/usr/bin/setsid"),
            auth_timeout: Duration::from_secs(8),
            operation_timeout: Duration::from_secs(125),
        };
        Ok((
            AppState::new(
                config,
                channel,
                store,
                Arc::new(StaticAuth),
                Arc::new(StaticOps),
            ),
            path,
        ))
    }

    fn test_path() -> Result<PathBuf, String> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|_| String::from("random unavailable"))?;
        Ok(std::env::temp_dir().join(format!("jw-agent-api-{:02x?}.sqlite3", random)))
    }

    fn cleanup_database(path: &Path) -> Result<(), String> {
        for candidate in [
            path.to_path_buf(),
            path.with_extension("sqlite3-wal"),
            path.with_extension("sqlite3-shm"),
        ] {
            if candidate.exists() {
                fs::remove_file(&candidate).map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    fn login_input() -> LoginRequest {
        LoginRequest {
            username: String::from("admin"),
            password: SecretString::new(String::from("test-only-password")),
        }
    }

    fn cookie_token(response: &axum::response::Response) -> Result<String, String> {
        let value = response
            .headers()
            .get(SET_COOKIE)
            .ok_or_else(|| String::from("session cookie missing"))?
            .to_str()
            .map_err(|_| String::from("session cookie invalid"))?;
        let (_, token_and_attributes) = value
            .split_once('=')
            .ok_or_else(|| String::from("session cookie missing value"))?;
        let token = token_and_attributes
            .split(';')
            .next()
            .ok_or_else(|| String::from("session cookie missing token"))?;
        Ok(token.to_owned())
    }

    #[tokio::test]
    async fn repeated_login_rotates_and_revokes_prior_session() -> Result<(), String> {
        let (state, path) = test_state(IngressChannel::Recovery)?;
        let first = login(
            axum::extract::State(state.clone()),
            HeaderMap::new(),
            axum::Json(login_input()),
        )
        .await
        .map_err(|_| String::from("first login failed"))?;
        let first_token = cookie_token(&first)?;
        assert!(
            state
                .store
                .authenticate_session(&first_token, IngressChannel::Recovery, 2_000)?
                .is_some()
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("jw_recovery_session={first_token}"))
                .map_err(|_| String::from("test cookie invalid"))?,
        );
        let second = login(
            axum::extract::State(state.clone()),
            headers,
            axum::Json(login_input()),
        )
        .await
        .map_err(|_| String::from("second login failed"))?;
        let second_token = cookie_token(&second)?;
        assert_ne!(first_token, second_token);
        assert!(
            state
                .store
                .authenticate_session(&first_token, IngressChannel::Recovery, i64::MAX)?
                .is_none()
        );
        drop(second);
        drop(first);
        drop(state);
        cleanup_database(&path)
    }

    #[test]
    fn ingress_boundary_requires_exact_host_and_origin() -> Result<(), String> {
        let (state, path) = test_state(IngressChannel::Public)?;
        let valid = Request::builder()
            .method(Method::POST)
            .header(HOST, "server.example.com")
            .header(ORIGIN, "https://server.example.com")
            .body(Body::empty())
            .map_err(|error| error.to_string())?;
        assert!(validate_request_boundary(&state, &valid).is_ok());

        let wrong_origin = Request::builder()
            .method(Method::POST)
            .header(HOST, "server.example.com")
            .header(ORIGIN, "https://attacker.example")
            .body(Body::empty())
            .map_err(|error| error.to_string())?;
        let problem = validate_request_boundary(&state, &wrong_origin)
            .err()
            .ok_or_else(|| String::from("wrong origin was accepted"))?;
        assert_eq!(problem.status, StatusCode::FORBIDDEN);
        drop(state);
        cleanup_database(&path)
    }

    #[test]
    fn cross_channel_cookie_and_subject_abuse_are_rejected() -> Result<(), String> {
        let (state, path) = test_state(IngressChannel::Recovery)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static("__Host-jw_session=not-a-valid-session"),
        );
        let problem = session_cookie(&state, &headers)
            .err()
            .ok_or_else(|| String::from("cross-channel cookie was accepted"))?;
        assert_eq!(problem.status, StatusCode::UNAUTHORIZED);

        let limiter = AuthLimiter::default();
        for _attempt in 0..6 {
            assert!(limiter.consume("loopback", "admin").is_ok());
        }
        let rate_problem = limiter
            .consume("loopback", "admin")
            .err()
            .ok_or_else(|| String::from("subject limit was not enforced"))?;
        assert_eq!(rate_problem.status, StatusCode::TOO_MANY_REQUESTS);
        drop(state);
        cleanup_database(&path)
    }

    #[test]
    fn terminal_websocket_ticket_is_header_only_and_single_value() -> Result<(), String> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "sec-websocket-protocol",
            HeaderValue::from_static(
                "jw-terminal-v1, ticket.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        );
        let ticket = websocket_ticket(&headers)
            .map_err(|_| String::from("valid terminal protocol rejected"))?;
        assert_eq!(ticket.len(), 43);

        headers.insert(
            "sec-websocket-protocol",
            HeaderValue::from_static(
                "jw-terminal-v1, ticket.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, ticket.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            ),
        );
        assert!(websocket_ticket(&headers).is_err());
        Ok(())
    }
}
