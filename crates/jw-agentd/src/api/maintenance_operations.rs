use super::*;

#[utoipa::path(post, path = "/api/v1/operations/service/config-file/plans", request_body = ManagedConfigPlanRequest, responses(
    (status = 200, description = "Immutable managed configuration plan", body = ManagedConfigPlanView),
    (status = 400, description = "Invalid typed request", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Role, protected resource, or CSRF rejected", body = ProblemDetails),
    (status = 409, description = "Stale, busy, or idempotency conflict", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails)
))]
pub(super) async fn plan_managed_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ManagedConfigPlanRequest>,
) -> Result<Json<ManagedConfigPlanView>, ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    require_administrative_access(&session)?;
    let plan = state
        .ops
        .plan_managed_config(session.subject, input)
        .await
        .map_err(map_ops_error)?;
    Ok(Json(plan))
}

#[utoipa::path(post, path = "/api/v1/operations/service/config-file/restore/plans", request_body = ManagedConfigRestorePlanRequest, responses(
    (status = 200, description = "Immutable managed configuration restore plan", body = ManagedConfigPlanView),
    (status = 400, description = "Invalid typed request", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Administrative access required", body = ProblemDetails),
    (status = 409, description = "Source unavailable, stale, or busy", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails)
))]
pub(super) async fn plan_managed_config_restore(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ManagedConfigRestorePlanRequest>,
) -> Result<Json<ManagedConfigPlanView>, ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    require_administrative_access(&session)?;
    let plan = state
        .ops
        .plan_managed_config_restore(session.subject, input)
        .await
        .map_err(map_ops_error)?;
    Ok(Json(plan))
}

#[utoipa::path(post, path = "/api/v1/operations/service/lifecycle/plans", request_body = ServiceControlPlanRequest, responses(
    (status = 200, description = "Immutable service lifecycle plan", body = ServiceControlPlanView),
    (status = 400, description = "Invalid typed request", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Administrative access required", body = ProblemDetails),
    (status = 409, description = "Stale or busy service", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails)
))]
pub(super) async fn plan_service_control(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ServiceControlPlanRequest>,
) -> Result<Json<ServiceControlPlanView>, ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    require_administrative_access(&session)?;
    let plan = state
        .ops
        .plan_service_control(session.subject, input)
        .await
        .map_err(map_ops_error)?;
    Ok(Json(plan))
}

#[utoipa::path(post, path = "/api/v1/operations/service/lifecycle/approvals", request_body = ServiceControlApprovalRequest, responses(
    (status = 202, description = "Service lifecycle operation accepted", body = OperationAcceptedView),
    (status = 400, description = "Invalid approval", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Administrative access required", body = ProblemDetails),
    (status = 409, description = "Expired, stale, or busy service", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails)
))]
pub(super) async fn approve_service_control(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ServiceControlApprovalRequest>,
) -> Result<(StatusCode, Json<OperationAcceptedView>), ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    require_administrative_access(&session)?;
    let receipt = state
        .ops
        .approve_service_control(
            session.subject,
            input.plan_id,
            input.plan_hash,
            input.idempotency_key,
        )
        .await
        .map_err(map_ops_error)?;
    if receipt.operation_type != SERVICE_CONTROL_OPERATION {
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
    let actor = accepted.actor.clone();
    let ops = Arc::clone(&state.ops);
    let _execution_task = tokio::spawn(async move {
        let _execution_result = ops.execute_operation(actor, operation_id).await;
    });
    Ok((StatusCode::ACCEPTED, Json(accepted)))
}
