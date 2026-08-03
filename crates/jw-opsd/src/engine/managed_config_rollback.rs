use jw_contracts::{
    ManagedConfigDiagnosticView, OperationReceiptView, OperationStage, ServiceAction,
};

use super::{OpsService, command_digest};
use crate::error::OpsError;
use crate::ledger::{Ledger, Transition};
use crate::managed_config::{
    ProposalRecord, managed_config_test_succeeded, remove_proposal, restore_managed_config,
};
use crate::snapshot::read_managed_config_snapshot;

impl OpsService {
    pub(super) fn rollback_managed_config_with_diagnostics(
        &self,
        ledger: &mut Ledger,
        operation_id: &str,
        cause: &str,
        cause_evidence_digest: &str,
        diagnostics: &[ManagedConfigDiagnosticView],
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let operation = ledger.load_operation(operation_id)?;
        let expected = [
            OperationStage::Applying,
            OperationStage::Validating,
            OperationStage::Reloading,
            OperationStage::Verifying,
            OperationStage::RollingBack,
        ];
        let rolling = if operation.stage == OperationStage::RollingBack {
            operation
        } else {
            let change = Transition {
                expected: &expected,
                next: OperationStage::RollingBack,
                result_code: cause,
                evidence_digest: cause_evidence_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            };
            if diagnostics.is_empty() {
                ledger.transition(operation_id, change)?
            } else {
                ledger.transition_with_diagnostics(operation_id, change, diagnostics)?
            }
        };
        let Some(record) = &rolling.snapshot else {
            return self.recovery_required(ledger, operation_id, "snapshot_missing", now_ms);
        };
        let snapshot = match read_managed_config_snapshot(&self.paths, record) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return self.recovery_required(ledger, operation_id, error.code(), now_ms);
            }
        };
        let restored = match restore_managed_config(
            &self.paths,
            &snapshot.resource_id,
            &snapshot.basename,
            &snapshot.content,
            snapshot.mode,
            snapshot.uid,
            snapshot.gid,
        ) {
            Ok(resource) => resource,
            Err(_) => {
                return self.recovery_required(
                    ledger,
                    operation_id,
                    "rollback_replace_failed",
                    now_ms,
                );
            }
        };
        let config = match self.runner.run(restored.adapter.config_test()) {
            Ok(evidence) if managed_config_test_succeeded(restored.adapter, &evidence) => evidence,
            _ => {
                return self.recovery_required(
                    ledger,
                    operation_id,
                    "rollback_syntax_failed",
                    now_ms,
                );
            }
        };
        let validate_only = rolling
            .plan
            .managed_config
            .as_ref()
            .is_some_and(|payload| payload.service_action == ServiceAction::ValidateOnly);
        let runtime_evidence = if validate_only {
            None
        } else {
            let reload = match self.runner.run(restored.adapter.reload()) {
                Ok(evidence) if evidence.success => evidence,
                _ => {
                    return self.recovery_required(
                        ledger,
                        operation_id,
                        "rollback_reload_failed",
                        now_ms,
                    );
                }
            };
            let active = match self.runner.run(restored.adapter.active()) {
                Ok(evidence) if evidence.success => evidence,
                _ => {
                    return self.recovery_required(
                        ledger,
                        operation_id,
                        "rollback_active_failed",
                        now_ms,
                    );
                }
            };
            if !reload.success {
                return self.recovery_required(
                    ledger,
                    operation_id,
                    "rollback_reload_failed",
                    now_ms,
                );
            }
            Some(active)
        };
        if restored.content_digest != snapshot.content_digest
            || restored.metadata_digest != snapshot.metadata_digest
            || !config.success
        {
            return self.recovery_required(ledger, operation_id, "rollback_verify_failed", now_ms);
        }
        let rollback_evidence = match runtime_evidence {
            Some(active) => command_digest(&active)?,
            None => command_digest(&config)?,
        };
        let terminal = ledger.transition(
            operation_id,
            Transition {
                expected: &[OperationStage::RollingBack],
                next: OperationStage::RolledBack,
                result_code: "rollback_verified",
                evidence_digest: &rollback_evidence,
                after_digest: Some(&snapshot.content_digest),
                rollback_result: Some("verified"),
                now_ms,
            },
        )?;
        let receipt = ledger.receipt(&terminal.operation_id)?;
        if let Some(payload) = terminal.plan.managed_config {
            let _cleanup = remove_proposal(
                &self.paths,
                &ProposalRecord {
                    relative_path: payload.proposal_relative_path,
                    digest: payload.proposal_digest,
                },
            );
        }
        Ok(receipt)
    }
}
