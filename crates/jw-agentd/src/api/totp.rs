use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use jw_contracts::{
    ProblemDetails, TotpEnrollmentConfirmRequest, TotpEnrollmentConfirmView,
    TotpEnrollmentStartRequest, TotpEnrollmentStartView, TotpRecoveryResetRequest,
    TotpVerificationRequest, TotpVerificationView, validate_enrollment_id, validate_totp_code,
};

use crate::totp::TotpError;

use super::{
    ApiProblem, AppState, clear_session_cookie, current_session, request_source, require_csrf,
    unix_milliseconds,
};

#[utoipa::path(post, path = "/api/v1/settings/access/totp/enrollment", request_body = TotpEnrollmentStartRequest, responses(
    (status = 201, description = "One-time TOTP enrollment material", body = TotpEnrollmentStartView),
    (status = 403, description = "Recovery ingress, admin role, CSRF, or PAM claim rejected", body = ProblemDetails),
    (status = 409, description = "Provider already configured", body = ProblemDetails),
    (status = 503, description = "Wrapping key unavailable", body = ProblemDetails)
))]
pub(super) async fn begin_totp_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<TotpEnrollmentStartRequest>,
) -> Result<(StatusCode, Json<TotpEnrollmentStartView>), ApiProblem> {
    let now = unix_milliseconds()?;
    let (session_token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, session_token.as_str())?;
    let source = request_source(&state, &headers)?;
    state
        .totp_limiter
        .consume(&source, &session.subject.username)?;
    let label = state
        .config
        .public_host
        .as_deref()
        .map_or("local-server", |value| value);
    let issue = state
        .store
        .totp()
        .begin_enrollment(
            session_token.as_str(),
            &session.subject,
            state.channel,
            input.reauth_token.expose(),
            label,
            now,
        )
        .map_err(map_totp_error)?;
    Ok((StatusCode::CREATED, Json(issue.view)))
}

#[utoipa::path(post, path = "/api/v1/settings/access/totp/enrollment/confirm", request_body = TotpEnrollmentConfirmRequest, responses(
    (status = 200, description = "Enrollment confirmation progress", body = TotpEnrollmentConfirmView),
    (status = 403, description = "Generic confirmation rejection", body = ProblemDetails),
    (status = 429, description = "TOTP rate limited", body = ProblemDetails)
))]
pub(super) async fn confirm_totp_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<TotpEnrollmentConfirmRequest>,
) -> Result<Json<TotpEnrollmentConfirmView>, ApiProblem> {
    validate_enrollment_id(&input.enrollment_id).map_err(ApiProblem::bad_request)?;
    validate_totp_code(input.code.expose()).map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (session_token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, session_token.as_str())?;
    let source = request_source(&state, &headers)?;
    state
        .totp_limiter
        .consume(&source, &session.subject.username)?;
    let view = state
        .store
        .totp()
        .confirm_enrollment(
            &session.subject,
            state.channel,
            &input.enrollment_id,
            input.code.expose(),
            now,
        )
        .map_err(map_totp_error)?;
    Ok(Json(view))
}

#[utoipa::path(post, path = "/api/v1/auth/totp/verify", request_body = TotpVerificationRequest, responses(
    (status = 200, description = "Plan-bound single-use additional-auth claim", body = TotpVerificationView),
    (status = 403, description = "Generic TOTP or claim rejection", body = ProblemDetails),
    (status = 429, description = "TOTP rate limited", body = ProblemDetails),
    (status = 503, description = "TOTP provider unavailable", body = ProblemDetails)
))]
pub(super) async fn verify_totp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<TotpVerificationRequest>,
) -> Result<Json<TotpVerificationView>, ApiProblem> {
    validate_totp_code(input.code.expose()).map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (session_token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, session_token.as_str())?;
    let source = request_source(&state, &headers)?;
    state
        .totp_limiter
        .consume(&source, &session.subject.username)?;
    let view = state
        .store
        .totp()
        .issue_operation_claim(
            session_token.as_str(),
            &session.subject,
            input.reauth_token.expose(),
            &input.plan_hash,
            input.code.expose(),
            now,
        )
        .map_err(map_totp_error)?;
    Ok(Json(view))
}

#[utoipa::path(post, path = "/api/v1/settings/access/totp/reset", request_body = TotpRecoveryResetRequest, responses(
    (status = 204, description = "TOTP enrollment removed and subject sessions revoked"),
    (status = 403, description = "Recovery ingress, PAM claim, or recovery code rejected", body = ProblemDetails),
    (status = 429, description = "TOTP rate limited", body = ProblemDetails)
))]
pub(super) async fn reset_totp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<TotpRecoveryResetRequest>,
) -> Result<Response, ApiProblem> {
    let now = unix_milliseconds()?;
    let (session_token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, session_token.as_str())?;
    let source = request_source(&state, &headers)?;
    state
        .totp_limiter
        .consume(&source, &session.subject.username)?;
    state
        .store
        .totp()
        .recovery_reset(
            session_token.as_str(),
            &session.subject,
            state.channel,
            input.reauth_token.expose(),
            input.recovery_code.expose(),
            now,
        )
        .map_err(map_totp_error)?;
    state.terminal.revoke_session(session_token.as_str());
    state.files.revoke_session(session_token.as_str());
    let mut response = StatusCode::NO_CONTENT.into_response();
    clear_session_cookie(&state, &mut response)?;
    Ok(response)
}

pub(super) fn map_totp_error(error: TotpError) -> ApiProblem {
    match error {
        TotpError::Denied => ApiProblem::forbidden("additional_authentication_denied"),
        TotpError::AlreadyConfigured => ApiProblem::new(
            StatusCode::CONFLICT,
            "additional_authentication_already_configured",
        ),
        TotpError::NotConfigured
        | TotpError::InvalidClaim
        | TotpError::InvalidCode
        | TotpError::Replay
        | TotpError::ClockRollback
        | TotpError::EnrollmentExpired => {
            ApiProblem::forbidden("additional_authentication_rejected")
        }
        TotpError::KeyUnavailable => {
            ApiProblem::unavailable("additional_authentication_unavailable")
        }
        TotpError::Storage => ApiProblem::internal(),
    }
}
