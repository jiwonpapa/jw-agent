use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use jw_contracts::{
    AdditionalAuthPolicy, AdditionalAuthProviderStatus, MANAGED_CONFIG_OPERATION, PhpFpmView,
    ProblemDetails, Role, Subject,
};

use crate::php_fpm::{PhpFpmObservationProfile, observe_php_fpm};
use crate::service_inventory::{ServiceObservationProfile, observe_services};

use super::{ApiProblem, AppState, current_session, now_rfc3339, unix_milliseconds};

#[utoipa::path(get, path = "/api/v1/services/php-fpm", responses(
    (status = 200, description = "Sanitized PHP-FPM runtime and managed config capability", body = PhpFpmView),
    (status = 401, description = "Authentication required", body = ProblemDetails)
))]
pub(super) async fn php_fpm(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PhpFpmView>, ApiProblem> {
    let (_, session) = current_session(&state, &headers, unix_milliseconds()?)?;
    let observed_at = now_rfc3339()?;
    let observation_time = observed_at.clone();
    let mut view = tokio::task::spawn_blocking(move || {
        let services = observe_services(&ServiceObservationProfile::default(), observation_time);
        observe_php_fpm(&PhpFpmObservationProfile::default(), &services, observed_at)
    })
    .await
    .map_err(|_| ApiProblem::internal())?;
    if let Some(reason) = managed_config_mutation_gate_reason(
        &state,
        &session.subject,
        session.additional_auth_policy,
    )
    .await
    {
        for runtime in &mut view.runtimes {
            runtime.managed_config_resource_id = None;
            runtime.managed_config_operation_type = None;
            runtime.managed_config_schema_version = None;
            runtime.blocked_reason = Some(reason.clone());
            runtime.assurance.operation_available = false;
            runtime.assurance.reason = Some(reason.clone());
        }
    }
    Ok(Json(view))
}

async fn managed_config_mutation_gate_reason(
    state: &AppState,
    subject: &Subject,
    additional_auth_policy: AdditionalAuthPolicy,
) -> Option<String> {
    if !matches!(subject.role, Role::Admin | Role::Operator) {
        return Some(String::from(
            "현재 계정은 서비스 설정 변경 권한이 없습니다.",
        ));
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
                    .any(|operation| operation == MANAGED_CONFIG_OPERATION) =>
        {
            None
        }
        Ok(_) => Some(String::from(
            "이 서버에서는 설정 자동 원복 작업을 사용할 수 없습니다.",
        )),
        Err(_) => Some(String::from(
            "권한 분리 서비스 상태를 확인할 수 없어 변경이 차단되었습니다.",
        )),
    }
}
