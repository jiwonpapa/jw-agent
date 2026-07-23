use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use jw_contracts::{
    CapabilityStatus, CapabilityView, NginxSitesView, ProblemDetails, ServicesView,
};

use crate::observation::{ObservationProfile, observe_host, observe_nginx_with_mutation_gate};
use crate::service_inventory::{ServiceObservationProfile, observe_services};

use super::{
    ApiProblem, AppState, current_session, nginx_mutation_gate_reason, now_rfc3339,
    unix_milliseconds,
};

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
