use jw_contracts::{
    ManagedServiceAction, NginxSiteState, OperationReceiptView, OperationStage,
    SERVICE_CONTROL_OPERATION, ServiceControlPlanRequest, ServiceControlPlanView, Subject,
    service_state_digest,
};
use serde::Serialize;

use super::{
    Ledger, OpsError, OpsService, PlanHashMaterial, StoredOperation, StoredPlan, Transition,
    canonical_digest, command_digest, random_id,
};
use crate::service_control::{
    SERVICE_CONTROL_IMPACT, SERVICE_CONTROL_RECOVERY_PATH, expected_active, registered_service,
    service_action_digest, service_action_from_digest, service_control_assurance,
};
use crate::snapshot::{
    ServiceStateSnapshot, read_service_state_snapshot, write_service_state_snapshot,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceControlPlanRequestDigest<'a> {
    operation_type: &'a str,
    actor: &'a Subject,
    request: &'a ServiceControlPlanRequest,
}

impl OpsService {
    pub(super) fn plan_service_control(
        &self,
        actor: &Subject,
        request: &ServiceControlPlanRequest,
        now_ms: i64,
    ) -> Result<ServiceControlPlanView, OpsError> {
        request.validate().map_err(OpsError::Rejected)?;
        let service = registered_service(&request.service_id)?;
        let active_evidence = self.runner.run(service.active_command())?;
        let active = active_evidence.success;
        let current_digest = service_state_digest(service.unit_name(), active);
        if current_digest != request.expected_state_digest {
            return Err(OpsError::Rejected("precondition_changed"));
        }
        match request.action {
            ManagedServiceAction::Start if active => {
                return Err(OpsError::Rejected("service_already_active"));
            }
            ManagedServiceAction::Stop
            | ManagedServiceAction::Restart
            | ManagedServiceAction::Reload
                if !active =>
            {
                return Err(OpsError::Rejected("service_inactive"));
            }
            _ => {}
        }
        let ttl_ms = i64::try_from(self.policy.plan_ttl.as_millis())
            .map_err(|_| OpsError::Storage(String::from("plan ttl overflow")))?;
        let plan_id = random_id("plan")?;
        let request_digest = canonical_digest(
            b"jw-agent/operation-request/v1",
            &ServiceControlPlanRequestDigest {
                operation_type: SERVICE_CONTROL_OPERATION,
                actor,
                request,
            },
        )?;
        let mut plan = StoredPlan {
            operation_type: String::from(SERVICE_CONTROL_OPERATION),
            plan_id,
            plan_hash: String::new(),
            actor: actor.clone(),
            site_id: request.service_id.clone(),
            display_name: String::from(service.display_name()),
            current_state: if active {
                NginxSiteState::Enabled
            } else {
                NginxSiteState::Disabled
            },
            target_state: if expected_active(request.action) {
                NginxSiteState::Enabled
            } else {
                NginxSiteState::Disabled
            },
            available_digest: service_action_digest(request.action),
            enabled_state_digest: current_digest,
            created_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
            idempotency_key: request.idempotency_key.clone(),
            request_digest,
            resource_key: format!("service/{}", service.unit_name()),
            assurance: service_control_assurance(service),
            managed_config: None,
            certbot_renew: None,
            certbot_issue: None,
            certbot_attach: None,
        };
        plan.plan_hash = service_control_plan_hash(&plan)?;
        let mut ledger = self.open_ledger()?;
        let stored = ledger.create_or_reuse_plan(&plan)?;
        ledger.service_control_plan_view(&stored)
    }

    pub(super) fn approve_service_control(
        &self,
        actor: &Subject,
        plan_id: &str,
        plan_hash: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let mut ledger = self.open_ledger()?;
        let plan = ledger.load_plan(plan_id)?;
        if plan.operation_type != SERVICE_CONTROL_OPERATION {
            return Err(OpsError::Rejected("approval_mismatch"));
        }
        let operation_id = random_id("op")?;
        let operation = ledger.begin_operation(
            &operation_id,
            plan_id,
            plan_hash,
            idempotency_key,
            actor,
            now_ms,
        )?;
        ledger.receipt(&operation.operation_id)
    }

    pub(super) fn execute_service_control(
        &self,
        ledger: &mut Ledger,
        operation: StoredOperation,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let service = registered_service(&operation.plan.site_id)?;
        let action = service_action_from_digest(&operation.plan.available_digest)?;
        let before_active = self.runner.run(service.active_command())?.success;
        let before_digest = service_state_digest(service.unit_name(), before_active);
        if before_digest != operation.plan.enabled_state_digest
            || before_active != (operation.plan.current_state == NginxSiteState::Enabled)
        {
            let cancelled = ledger.transition(
                &operation.operation_id,
                Transition {
                    expected: &[OperationStage::Approved],
                    next: OperationStage::CancelledBeforeApply,
                    result_code: "precondition_changed",
                    evidence_digest: &before_digest,
                    after_digest: None,
                    rollback_result: None,
                    now_ms,
                },
            )?;
            return ledger.receipt(&cancelled.operation_id);
        }
        let snapshot = ServiceStateSnapshot {
            schema_version: 1,
            service_id: operation.plan.site_id.clone(),
            unit_name: String::from(service.unit_name()),
            active: before_active,
            state_digest: before_digest.clone(),
        };
        let record = match write_service_state_snapshot(
            &self.paths,
            &self.policy,
            &operation.operation_id,
            &snapshot,
        ) {
            Ok(record) => record,
            Err(error) => {
                let cancelled = ledger.transition(
                    &operation.operation_id,
                    Transition {
                        expected: &[OperationStage::Approved],
                        next: OperationStage::CancelledBeforeApply,
                        result_code: error.code(),
                        evidence_digest: &jw_contracts::sha256_digest(error.code().as_bytes()),
                        after_digest: None,
                        rollback_result: None,
                        now_ms,
                    },
                )?;
                return ledger.receipt(&cancelled.operation_id);
            }
        };
        let snapshotted = ledger.attach_snapshot(&operation.operation_id, &record, now_ms)?;
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Snapshotted],
                next: OperationStage::Applying,
                result_code: "service_action_started",
                evidence_digest: &service_action_digest(action),
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let action_evidence = match self.runner.run(service.action_command(action)) {
            Ok(evidence) => evidence,
            Err(error) => {
                return self.rollback_service_control(
                    ledger,
                    &snapshotted.operation_id,
                    error.code(),
                    &jw_contracts::sha256_digest(error.code().as_bytes()),
                    now_ms,
                );
            }
        };
        let action_digest = command_digest(&action_evidence)?;
        if !action_evidence.success {
            return self.rollback_service_control(
                ledger,
                &snapshotted.operation_id,
                "service_action_failed",
                &action_digest,
                now_ms,
            );
        }
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Applying],
                next: OperationStage::Verifying,
                result_code: "service_action_completed",
                evidence_digest: &action_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let active_evidence = self.runner.run(service.active_command())?;
        let after_active = active_evidence.success;
        let after_digest = service_state_digest(service.unit_name(), after_active);
        if after_active != expected_active(action) {
            return self.rollback_service_control(
                ledger,
                &snapshotted.operation_id,
                "service_state_verification_failed",
                &command_digest(&active_evidence)?,
                now_ms,
            );
        }
        let succeeded = ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Verifying],
                next: OperationStage::Succeeded,
                result_code: "service_state_verified",
                evidence_digest: &command_digest(&active_evidence)?,
                after_digest: Some(&after_digest),
                rollback_result: None,
                now_ms,
            },
        )?;
        ledger.receipt(&succeeded.operation_id)
    }

    pub(super) fn rollback_service_control(
        &self,
        ledger: &mut Ledger,
        operation_id: &str,
        failure_code: &str,
        failure_digest: &str,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let current = ledger.load_operation(operation_id)?;
        let rolling = if current.stage == OperationStage::RollingBack {
            current
        } else {
            ledger.transition(
                operation_id,
                Transition {
                    expected: &[OperationStage::Applying, OperationStage::Verifying],
                    next: OperationStage::RollingBack,
                    result_code: failure_code,
                    evidence_digest: failure_digest,
                    after_digest: None,
                    rollback_result: None,
                    now_ms,
                },
            )?
        };
        let record = rolling
            .snapshot
            .as_ref()
            .ok_or(OpsError::ForensicLockdown)?;
        let snapshot = read_service_state_snapshot(&self.paths, record)?;
        let service = registered_service(&snapshot.service_id)?;
        if snapshot.unit_name != service.unit_name()
            || snapshot.state_digest != service_state_digest(service.unit_name(), snapshot.active)
        {
            return Err(OpsError::ForensicLockdown);
        }
        let restore = self.runner.run(service.restore_command(snapshot.active));
        let verified = restore.is_ok_and(|evidence| evidence.success)
            && self
                .runner
                .run(service.active_command())
                .is_ok_and(|evidence| evidence.success == snapshot.active);
        let after_digest = service_state_digest(service.unit_name(), snapshot.active);
        let terminal = ledger.transition(
            operation_id,
            Transition {
                expected: &[OperationStage::RollingBack],
                next: if verified {
                    OperationStage::RolledBack
                } else {
                    OperationStage::RecoveryRequired
                },
                result_code: if verified {
                    "service_state_restored"
                } else {
                    "service_restore_failed"
                },
                evidence_digest: &after_digest,
                after_digest: Some(&after_digest),
                rollback_result: Some(if verified {
                    "restored"
                } else {
                    "manual_recovery_required"
                }),
                now_ms,
            },
        )?;
        ledger.receipt(&terminal.operation_id)
    }
}

fn service_control_plan_hash(plan: &StoredPlan) -> Result<String, OpsError> {
    canonical_digest(
        b"jw-agent/operation-plan/v1",
        &PlanHashMaterial {
            schema_version: 1,
            operation_type: SERVICE_CONTROL_OPERATION,
            plan_id: &plan.plan_id,
            created_at_ms: plan.created_at_ms,
            expires_at_ms: plan.expires_at_ms,
            actor: &plan.actor,
            site_id: &plan.site_id,
            display_name: &plan.display_name,
            current_state: plan.current_state,
            target_state: plan.target_state,
            available_digest: &plan.available_digest,
            enabled_state_digest: &plan.enabled_state_digest,
            resource_key: &plan.resource_key,
            impact: &SERVICE_CONTROL_IMPACT,
            recovery_path: &SERVICE_CONTROL_RECOVERY_PATH,
            assurance: &plan.assurance,
        },
    )
}
