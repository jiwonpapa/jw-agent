use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use jw_contracts::{
    AdditionalAuthPolicy, AdministrativeAccessRequest, AdministrativeAccessState, AuthPurpose,
    AuthRequest, AuthResult, IPC_PROTOCOL_VERSION, ProblemDetails, Role, SessionView,
};

use super::{
    ApiProblem, AppState, auth_failure, current_session, deadline, random_identifier,
    request_source, require_csrf, set_session_cookie, unix_milliseconds, validate_auth_response,
};

const ADMINISTRATIVE_CONTEXT: &str = "administrative-access/v1";

#[utoipa::path(post, path = "/api/v1/auth/administrative-access", request_body = AdministrativeAccessRequest, responses(
    (status = 200, description = "Rotated non-root admin session with bounded administrative access", body = SessionView),
    (status = 401, description = "Generic PAM authentication failure", body = ProblemDetails),
    (status = 403, description = "Role, CSRF, subject, or TOTP rejected", body = ProblemDetails),
    (status = 429, description = "Authentication rate limited", body = ProblemDetails),
    (status = 503, description = "Authentication provider unavailable", body = ProblemDetails)
))]
pub(super) async fn enter_administrative_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<AdministrativeAccessRequest>,
) -> Result<Response, ApiProblem> {
    let now = unix_milliseconds()?;
    let (old_token, current) = current_session(&state, &headers, now)?;
    require_csrf(&headers, old_token.as_str())?;
    if current.subject.role != Role::Admin || current.subject.uid == 0 {
        state
            .store
            .record_administrative_denial(&current.subject, state.channel, "role_denied", now)
            .map_err(|_| ApiProblem::internal())?;
        return Err(ApiProblem::forbidden("administrative_access_denied"));
    }

    let source = request_source(&state, &headers)?;
    state
        .administrative_limiter
        .consume(&source, &current.subject.username)?;
    let request_id = random_identifier()?;
    let auth_request = AuthRequest {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: request_id.clone(),
        deadline_unix_ms: deadline(now, state.config.auth_timeout),
        username: current.subject.username.clone(),
        password: input.password,
        remote_address: Some(source),
        purpose: AuthPurpose::StepUp {
            context_digest: String::from(ADMINISTRATIVE_CONTEXT),
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
        AuthResult::Failed { class } => {
            state
                .store
                .record_administrative_denial(&current.subject, state.channel, "pam_rejected", now)
                .map_err(|_| ApiProblem::internal())?;
            return Err(auth_failure(class));
        }
    };
    if authenticated.uid != current.subject.uid
        || authenticated.username != current.subject.username
        || authenticated.role != Role::Admin
    {
        state
            .store
            .record_administrative_denial(&current.subject, state.channel, "subject_mismatch", now)
            .map_err(|_| ApiProblem::internal())?;
        return Err(ApiProblem::forbidden("administrative_access_denied"));
    }

    if current.additional_auth_policy != AdditionalAuthPolicy::Disabled {
        let Some(code) = input.additional_auth_code.as_ref() else {
            state
                .store
                .record_administrative_denial(
                    &current.subject,
                    state.channel,
                    "additional_auth_required",
                    now,
                )
                .map_err(|_| ApiProblem::internal())?;
            return Err(ApiProblem::new(
                StatusCode::PRECONDITION_REQUIRED,
                "additional_authentication_required",
            ));
        };
        if let Err(error) = state.store.totp().verify_direct_context(
            &authenticated,
            ADMINISTRATIVE_CONTEXT,
            code.expose(),
            now,
        ) {
            state
                .store
                .record_administrative_denial(
                    &current.subject,
                    state.channel,
                    "additional_auth_rejected",
                    now,
                )
                .map_err(|_| ApiProblem::internal())?;
            return Err(super::totp_api::map_totp_error(error));
        }
    }

    let issued = state
        .store
        .issue_administrative_session(&authenticated, state.channel, now)
        .map_err(|_| ApiProblem::internal())?;
    state.terminal.revoke_session(old_token.as_str());
    state.files.revoke_session(old_token.as_str());
    if state.store.revoke_session(old_token.as_str(), now).is_err() {
        let _cleanup = state.store.revoke_session(issued.token(), now);
        return Err(ApiProblem::internal());
    }
    let mut api_response = Json(issued.view.clone()).into_response();
    set_session_cookie(&state, issued.token(), &mut api_response)?;
    Ok(api_response)
}

#[utoipa::path(delete, path = "/api/v1/auth/administrative-access", responses(
    (status = 200, description = "Current session returned to standard access", body = SessionView),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "CSRF rejected", body = ProblemDetails)
))]
pub(super) async fn leave_administrative_access(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionView>, ApiProblem> {
    let now = unix_milliseconds()?;
    let (token, current) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    state
        .store
        .revoke_administrative_access(token.as_str(), state.channel, &current.subject, now)
        .map_err(|_| ApiProblem::internal())?;
    let view = state
        .store
        .authenticate_session(token.as_str(), state.channel, now)
        .map_err(|_| ApiProblem::internal())?
        .ok_or_else(|| ApiProblem::unauthorized("authentication_required"))?;
    Ok(Json(view))
}

pub(super) fn require_administrative_access(session: &SessionView) -> Result<(), ApiProblem> {
    if session.subject.role == Role::Admin
        && session.administrative_access == AdministrativeAccessState::Administrative
    {
        Ok(())
    } else {
        Err(ApiProblem::forbidden("administrative_access_required"))
    }
}

#[cfg(test)]
mod tests {
    use jw_contracts::{
        AdditionalAuthPolicy, AdministrativeAccessState, IngressChannel, Role, SessionView, Subject,
    };

    use super::require_administrative_access;

    fn session(role: Role, access: AdministrativeAccessState) -> SessionView {
        SessionView {
            subject: Subject {
                uid: 1_000,
                username: String::from("tester"),
                role,
            },
            ingress: IngressChannel::Public,
            authenticated_at: String::from("1970-01-01T00:00:01Z"),
            idle_expires_at: String::from("1970-01-01T00:15:01Z"),
            absolute_expires_at: String::from("1970-01-01T08:00:01Z"),
            csrf_token: String::from("csrf"),
            additional_auth_policy: AdditionalAuthPolicy::Disabled,
            administrative_access: access,
            administrative_expires_at: None,
        }
    }

    #[test]
    fn root_typed_operation_gate_requires_elevated_admin() {
        assert!(
            require_administrative_access(&session(
                Role::Admin,
                AdministrativeAccessState::Administrative,
            ))
            .is_ok()
        );
        assert!(
            require_administrative_access(&session(
                Role::Admin,
                AdministrativeAccessState::Standard,
            ))
            .is_err()
        );
        assert!(
            require_administrative_access(&session(
                Role::Operator,
                AdministrativeAccessState::Administrative,
            ))
            .is_err()
        );
    }
}
