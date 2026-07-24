use super::*;

#[utoipa::path(get, path = "/api/v1/firewall/ufw", responses(
    (status = 200, description = "UFW status and bounded rule inventory", body = UfwView),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 503, description = "Root observation unavailable", body = ProblemDetails)
))]
pub(super) async fn ufw(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UfwView>, ApiProblem> {
    let (_, session) = current_session(&state, &headers, unix_milliseconds()?)?;
    state
        .ops
        .ufw_inventory(session.subject)
        .await
        .map(Json)
        .map_err(map_ops_error)
}

#[utoipa::path(post, path = "/api/v1/operations/ufw/rules/plans", request_body = UfwRulePlanRequest, responses(
    (status = 200, description = "Immutable typed UFW rule plan", body = UfwRulePlanView),
    (status = 400, description = "Invalid typed rule", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Administrative access or protected rule rejected", body = ProblemDetails),
    (status = 409, description = "Stale or conflicting rule", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails)
))]
pub(super) async fn plan_ufw_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<UfwRulePlanRequest>,
) -> Result<Json<UfwRulePlanView>, ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    require_administrative_access(&session)?;
    state
        .ops
        .plan_ufw_rule(session.subject, input)
        .await
        .map(Json)
        .map_err(map_ops_error)
}

#[utoipa::path(post, path = "/api/v1/operations/ufw/rules/approvals", request_body = UfwRuleApprovalRequest, responses(
    (status = 202, description = "UFW rule operation accepted", body = OperationAcceptedView),
    (status = 400, description = "Invalid approval", body = ProblemDetails),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 403, description = "Administrative access required", body = ProblemDetails),
    (status = 409, description = "Expired, stale, or busy rule set", body = ProblemDetails),
    (status = 423, description = "Forensic lockdown", body = ProblemDetails)
))]
pub(super) async fn approve_ufw_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<UfwRuleApprovalRequest>,
) -> Result<(StatusCode, Json<OperationAcceptedView>), ApiProblem> {
    input.validate().map_err(ApiProblem::bad_request)?;
    let now = unix_milliseconds()?;
    let (token, session) = current_session(&state, &headers, now)?;
    require_csrf(&headers, token.as_str())?;
    require_administrative_access(&session)?;
    let receipt = state
        .ops
        .approve_ufw_rule(
            session.subject,
            input.plan_id,
            input.plan_hash,
            input.idempotency_key,
        )
        .await
        .map_err(map_ops_error)?;
    if receipt.operation_type != UFW_RULE_OPERATION {
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
