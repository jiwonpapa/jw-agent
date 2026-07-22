use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{AssuranceView, IngressChannel};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdditionalAuthPolicy {
    Disabled,
    RiskyOperations,
    AllMutations,
}

impl AdditionalAuthPolicy {
    #[must_use]
    pub const fn is_downgrade_from(self, current: Self) -> bool {
        (self as u8) < (current as u8)
    }

    #[must_use]
    pub const fn as_storage_value(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::RiskyOperations => "risky_operations",
            Self::AllMutations => "all_mutations",
        }
    }

    pub fn from_storage_value(value: &str) -> Result<Self, &'static str> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "risky_operations" => Ok(Self::RiskyOperations),
            "all_mutations" => Ok(Self::AllMutations),
            _ => Err("unknown additional authentication policy"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdditionalAuthProviderStatus {
    NotImplemented,
    NotConfigured,
    Ready,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccessSettingsView {
    pub ingress: IngressChannel,
    pub public_host: Option<String>,
    pub recovery_origin: String,
    pub additional_auth_policy: AdditionalAuthPolicy,
    pub additional_auth_provider: AdditionalAuthProviderStatus,
    pub mutation_approval_available: bool,
    pub assurance: AssuranceView,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateAdditionalAuthRequest {
    pub policy: AdditionalAuthPolicy,
    #[schema(format = Password)]
    pub reauth_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::AdditionalAuthPolicy;

    #[test]
    fn downgrade_order_is_explicit() {
        assert!(
            AdditionalAuthPolicy::Disabled.is_downgrade_from(AdditionalAuthPolicy::RiskyOperations)
        );
        assert!(
            !AdditionalAuthPolicy::AllMutations
                .is_downgrade_from(AdditionalAuthPolicy::RiskyOperations)
        );
    }
}
