use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, HOST, ORIGIN, REFERRER_POLICY,
    SET_COOKIE, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
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
    AssuranceView, AuthFailureClass, AuthPurpose, AuthRequest, AuthResult, CapabilityStatus,
    CapabilityView, HealthStatus, HealthView, IPC_PROTOCOL_VERSION, IngressChannel,
    IntegrationCatalogView, LoginRequest, MANAGED_CONFIG_OPERATION, ManagedConfigApprovalRequest,
    ManagedConfigPlanRequest, ManagedConfigPlanView, ManagedConfigResourceView,
    NGINX_SITE_STATE_OPERATION, NginxSiteStatePlanRequest, NginxSiteStatePlanView, NginxSitesView,
    ObservationStatus, OperationAcceptedView, OperationApprovalRequest, OperationReceiptView,
    OperationStageEvidenceView, ProblemDetails, ReauthPurpose, ReauthRequest, ReauthView, Role,
    RollbackSupport, ServiceAction, ServiceSummary, ServicesView, SessionView, Subject,
    UpdateAdditionalAuthRequest,
};
use sha2::{Digest, Sha256};
use tower_http::services::{ServeDir, ServeFile};
use utoipa::OpenApi;
use zeroize::Zeroizing;

use crate::integration_catalog::{IntegrationObservationProfile, observe_integrations};
use crate::observation::{ObservationProfile, observe_host, observe_nginx_with_mutation_gate};
use crate::ops_client::OpsBrokerError;
use crate::session::{OperationClaimError, PolicyUpdateError};
use crate::{AgentConfig, AuthBroker, OpsBroker, SessionStore};

const API_BODY_MAX_BYTES: usize = 64 * 1_024;
const CLIENT_ADDRESS_HEADER: &str = "x-jw-client-address";
const CSRF_HEADER: &str = "x-csrf-token";
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
            auth_limiter: AuthLimiter::default(),
        }
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
        ServicesView,
        SessionView,
        jw_contracts::Subject,
        UpdateAdditionalAuthRequest,
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
        .route("/api/v1/host", get(host))
        .route("/api/v1/capabilities", get(capabilities))
        .route("/api/v1/services", get(services))
        .route("/api/v1/services/nginx/sites", get(nginx_sites))
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
        && state.store.revoke_session(prior.as_str(), now).is_err()
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
    let (_, session) = current_session(&state, &headers, unix_milliseconds()?)?;
    let observed_at = now_rfc3339()?;
    let mutation_reason =
        nginx_mutation_gate_reason(&state, &session.subject, session.additional_auth_policy).await;
    let nginx = observe_nginx_with_mutation_gate(
        &ObservationProfile::default(),
        observed_at.clone(),
        mutation_reason.as_deref(),
    );
    Ok(Json(ServicesView {
        observed_at,
        services: vec![ServiceSummary {
            service: "nginx".to_owned(),
            status: nginx.status,
            read_only: mutation_reason.is_some(),
        }],
    }))
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
            deadline: Instant::now() + Duration::from_secs(180),
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
            | "approval_intent" => ApiProblem::bad_request(code),
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

    use super::{AppState, AuthLimiter, login, session_cookie, validate_request_boundary};

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
            proxy_socket: PathBuf::from("/run/jw-agent-proxy/agentd.sock"),
            auth_socket: PathBuf::from("/run/jw-agent/authd.sock"),
            ops_socket: PathBuf::from("/run/jw-agent/opsd.sock"),
            database: path.clone(),
            web_root: std::env::temp_dir(),
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
}
