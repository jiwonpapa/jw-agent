use jw_contracts::{
    AccessSettingsView, AdditionalAuthPolicy, AdditionalAuthProviderStatus, AssuranceLevel,
    AssuranceView, RollbackSupport, SessionView, Subject,
};

use crate::session::OperationAuthorization;

use super::{ApiProblem, AppState, map_operation_claim_error};

pub(super) fn access_view(
    state: &AppState,
    subject: &Subject,
) -> Result<AccessSettingsView, ApiProblem> {
    let policy = state
        .store
        .additional_auth_policy()
        .map_err(|_| ApiProblem::internal())?;
    let provider = state
        .store
        .totp()
        .provider_status(subject.uid)
        .map_err(|_| ApiProblem::internal())?;
    Ok(AccessSettingsView {
        ingress: state.channel,
        public_host: state.config.public_host.clone(),
        recovery_origin: state.config.recovery_origin.clone(),
        additional_auth_policy: policy,
        additional_auth_provider: provider,
        mutation_approval_available: policy == AdditionalAuthPolicy::Disabled
            || provider == AdditionalAuthProviderStatus::Ready,
        assurance: AssuranceView {
            level: AssuranceLevel::G2ReversibleConfig,
            rollback_support: RollbackSupport::AutomaticBounded,
            operation_available: true,
            scope: vec![String::from("JW Agent 추가 인증 정책 값")],
            excluded_effects: vec![String::from(
                "Linux PAM·SSH MFA 설정과 운영체제 console recovery",
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

pub(super) fn consume_operation_authorization(
    state: &AppState,
    session_token: &str,
    session: &SessionView,
    plan_hash: &str,
    reauth_token: &str,
    additional_auth_claim: Option<&str>,
    now_unix_ms: i64,
) -> Result<(), ApiProblem> {
    state
        .store
        .consume_operation_claims(OperationAuthorization {
            session_token,
            subject: &session.subject,
            plan_hash,
            reauth_token,
            additional_auth_claim,
            additional_auth_required: session.additional_auth_policy
                != AdditionalAuthPolicy::Disabled,
            now_unix_ms,
        })
        .map_err(map_operation_claim_error)
}
