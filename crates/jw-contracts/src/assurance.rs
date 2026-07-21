use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceLevel {
    G0ObserveOnly,
    G1VerifiedAction,
    G2ReversibleConfig,
    G3RestoreValidatedData,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RollbackSupport {
    NotApplicable,
    NotGuaranteed,
    AutomaticBounded,
    RestoreValidated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AssuranceView {
    pub level: AssuranceLevel,
    pub rollback_support: RollbackSupport,
    pub operation_available: bool,
    pub scope: Vec<String>,
    pub excluded_effects: Vec<String>,
    pub apply_verifier: Vec<String>,
    pub rollback_verifier: Vec<String>,
    pub reason: Option<String>,
}
