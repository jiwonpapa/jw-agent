use axum::{Json, extract::State, http::HeaderMap};
use jw_contracts::{OperationListView, ProblemDetails};

use super::{ApiProblem, AppState, current_session, map_ops_error, unix_milliseconds};

#[utoipa::path(get, path = "/api/v1/activity", responses(
    (status = 200, description = "Recent typed-operation receipts for the current Linux subject", body = OperationListView),
    (status = 401, description = "Authentication required", body = ProblemDetails),
    (status = 503, description = "Operation ledger unavailable", body = ProblemDetails)
))]
pub(super) async fn recent_operations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<OperationListView>, ApiProblem> {
    let (_, session) = current_session(&state, &headers, unix_milliseconds()?)?;
    let operations = state
        .ops
        .recent_operations(session.subject)
        .await
        .map_err(map_ops_error)?;
    Ok(Json(operations))
}
