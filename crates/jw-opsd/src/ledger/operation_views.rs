use super::*;

impl Ledger {
    pub(crate) fn service_control_plan_view(
        &self,
        plan: &StoredPlan,
    ) -> Result<ServiceControlPlanView, OpsError> {
        if plan.operation_type != SERVICE_CONTROL_OPERATION {
            return Err(OpsError::Rejected("operation_type"));
        }
        let service = registered_service(&plan.site_id)?;
        Ok(ServiceControlPlanView {
            schema_version: OPERATION_SCHEMA_VERSION,
            operation_type: plan.operation_type.clone(),
            plan_id: plan.plan_id.clone(),
            plan_hash: plan.plan_hash.clone(),
            created_at: format_time(plan.created_at_ms)?,
            expires_at: format_time(plan.expires_at_ms)?,
            actor: plan.actor.clone(),
            service_id: plan.site_id.clone(),
            unit_name: String::from(service.unit_name()),
            display_name: plan.display_name.clone(),
            current_active: plan.current_state == NginxSiteState::Enabled,
            action: service_action_from_digest(&plan.available_digest)?,
            expected_state_digest: plan.enabled_state_digest.clone(),
            impact: SERVICE_CONTROL_IMPACT
                .iter()
                .map(ToString::to_string)
                .collect(),
            recovery_path: SERVICE_CONTROL_RECOVERY_PATH
                .iter()
                .map(ToString::to_string)
                .collect(),
            assurance: plan.assurance.clone(),
        })
    }
}

pub(super) fn recovery_path_for(plan: &StoredPlan) -> Vec<String> {
    let values: &[&str] = if plan.operation_type == MANAGED_CONFIG_OPERATION
        || plan.operation_type == MANAGED_CONFIG_RESTORE_OPERATION
    {
        managed_config_adapter(&plan.site_id)
            .map_or(&[] as &[&str], |adapter| adapter.recovery_path())
    } else if plan.operation_type == SERVICE_CONTROL_OPERATION {
        &SERVICE_CONTROL_RECOVERY_PATH
    } else if plan.operation_type == CERTBOT_ISSUE_OPERATION {
        &CERTBOT_ISSUE_RECOVERY_PATH
    } else if plan.operation_type == jw_contracts::CERTBOT_RENEW_TEST_OPERATION {
        &CERTBOT_RENEW_RECOVERY_PATH
    } else if plan.operation_type == CERTBOT_ATTACH_OPERATION {
        &CERTBOT_ATTACH_RECOVERY_PATH
    } else {
        &NGINX_RECOVERY_PATH
    };
    values.iter().map(ToString::to_string).collect()
}
