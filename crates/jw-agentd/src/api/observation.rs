use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use jw_contracts::{
    AdditionalAuthPolicy, AdditionalAuthProviderStatus, CapabilityStatus, CapabilityView,
    ManagedServiceConfigInventoryView, NGINX_SITE_STATE_OPERATION, NginxSitesView, ProblemDetails,
    Role, ServicesView, Subject,
};

use crate::observation::{ObservationProfile, observe_host, observe_nginx_with_mutation_gate};
use crate::service_config_inventory::{ServiceConfigObservationProfile, observe_service_configs};
use crate::service_inventory::{ServiceObservationProfile, observe_services};

use super::{ApiProblem, AppState, current_session, now_rfc3339, unix_milliseconds};

async fn nginx_mutation_gate_reason(
    state: &AppState,
    subject: &Subject,
    additional_auth_policy: AdditionalAuthPolicy,
) -> Option<String> {
    if !matches!(subject.role, Role::Admin | Role::Operator) {
        return Some(String::from("현재 계정은 Nginx 변경 권한이 없습니다."));
    }
    if additional_auth_policy != AdditionalAuthPolicy::Disabled
        && state.store.totp().provider_status(subject.uid).ok()
            != Some(AdditionalAuthProviderStatus::Ready)
    {
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

#[utoipa::path(get, path = "/api/v1/host", responses(
    (status = 200, description = "Host observation", body = jw_contracts::HostObservation),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
pub(super) async fn host(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<jw_contracts::HostObservation>, ApiProblem> {
    let _session = current_session(&state, &headers, unix_milliseconds()?)?;
    Ok(Json(
        observe_host(&ObservationProfile::default(), now_rfc3339()?).await,
    ))
}

#[utoipa::path(get, path = "/api/v1/capabilities", responses(
    (status = 200, description = "Read-only capability view", body = CapabilityView),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
pub(super) async fn capabilities(
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
pub(super) async fn services(
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

#[utoipa::path(get, path = "/api/v1/services/{service_key}/configurations", params(
    ("service_key" = String, Path, description = "Supported service key: nginx or apache")
), responses(
    (status = 200, description = "Managed service configuration inventory", body = ManagedServiceConfigInventoryView),
    (status = 400, description = "Unsupported service key", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
pub(super) async fn service_configurations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(service_key): Path<String>,
) -> Result<Json<ManagedServiceConfigInventoryView>, ApiProblem> {
    let _session = current_session(&state, &headers, unix_milliseconds()?)?;
    if !matches!(service_key.as_str(), "nginx" | "apache") {
        return Err(ApiProblem::bad_request("unsupported_service_key"));
    }
    let observed_at = now_rfc3339()?;
    tokio::task::spawn_blocking(move || {
        let services = observe_services(&ServiceObservationProfile::default(), observed_at.clone());
        observe_service_configs(
            &ServiceConfigObservationProfile::default(),
            &services,
            &service_key,
            observed_at,
        )
    })
    .await
    .map(Json)
    .map_err(|_| ApiProblem::internal())
}

#[utoipa::path(get, path = "/api/v1/services/nginx/sites", responses(
    (status = 200, description = "Nginx site inventory", body = NginxSitesView),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
pub(super) async fn nginx_sites(
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
