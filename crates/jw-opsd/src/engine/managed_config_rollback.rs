use jw_contracts::{
    ManagedConfigDiagnosticView, OperationCommandEvidenceView, OperationReceiptView,
    OperationStage, ServiceAction,
};

use super::{OpsService, command_digest, command_evidence_view};
use crate::error::OpsError;
use crate::ledger::{Ledger, Transition};
use crate::managed_config::{
    ProposalRecord, managed_config_test_succeeded, remove_proposal, restore_managed_config,
};
use crate::snapshot::read_managed_config_snapshot;

pub(super) struct ManagedConfigRollbackEvidence<'a> {
    pub(super) cause: &'a str,
    pub(super) digest: &'a str,
    pub(super) diagnostics: &'a [ManagedConfigDiagnosticView],
    pub(super) command: Option<&'a OperationCommandEvidenceView>,
}

impl<'a> ManagedConfigRollbackEvidence<'a> {
    pub(super) fn plain(cause: &'a str, digest: &'a str) -> Self {
        Self {
            cause,
            digest,
            diagnostics: &[],
            command: None,
        }
    }

    pub(super) fn command(
        cause: &'a str,
        digest: &'a str,
        command: &'a OperationCommandEvidenceView,
    ) -> Self {
        Self {
            cause,
            digest,
            diagnostics: &[],
            command: Some(command),
        }
    }

    pub(super) fn diagnostics_and_command(
        cause: &'a str,
        digest: &'a str,
        diagnostics: &'a [ManagedConfigDiagnosticView],
        command: &'a OperationCommandEvidenceView,
    ) -> Self {
        Self {
            cause,
            digest,
            diagnostics,
            command: Some(command),
        }
    }
}

impl OpsService {
    pub(super) fn rollback_managed_config_with_evidence(
        &self,
        ledger: &mut Ledger,
        operation_id: &str,
        evidence: ManagedConfigRollbackEvidence<'_>,
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
                result_code: evidence.cause,
                evidence_digest: evidence.digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            };
            match (evidence.diagnostics.is_empty(), evidence.command) {
                (true, None) => ledger.transition(operation_id, change)?,
                (true, Some(command)) => {
                    ledger.transition_with_command_evidence(operation_id, change, command)?
                }
                (false, None) => ledger.transition_with_diagnostics(
                    operation_id,
                    change,
                    evidence.diagnostics,
                )?,
                (false, Some(command)) => ledger.transition_with_diagnostics_and_command(
                    operation_id,
                    change,
                    evidence.diagnostics,
                    command,
                )?,
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
        let rollback_command = match runtime_evidence.as_ref() {
            Some(value) => value,
            None => &config,
        };
        let rollback_evidence = command_digest(rollback_command)?;
        let terminal = ledger.transition_with_command_evidence(
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
            &command_evidence_view(rollback_command),
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
