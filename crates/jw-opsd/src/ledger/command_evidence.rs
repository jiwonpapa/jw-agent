use jw_contracts::{ManagedConfigDiagnosticView, OperationCommandEvidenceView};

use crate::digest::canonical_digest;
use crate::error::OpsError;

use super::diagnostics::prepare_diagnostics;
use super::{Ledger, StoredOperation, Transition};

pub(super) struct StoredCommandEvidence {
    pub(super) json: String,
}

pub(super) fn prepare_command_evidence(
    command: &OperationCommandEvidenceView,
    expected_digest: &str,
) -> Result<StoredCommandEvidence, OpsError> {
    if command.validate_shape().is_err() || command_evidence_digest(command)? != expected_digest {
        return Err(OpsError::Rejected("invalid_command_evidence"));
    }
    let json =
        serde_json::to_string(command).map_err(|error| OpsError::Storage(error.to_string()))?;
    Ok(StoredCommandEvidence { json })
}

pub(super) fn load_command_evidence(
    command_json: Option<String>,
    event_evidence_digest: &str,
    validator_evidence_digest: Option<&str>,
) -> Result<Option<OperationCommandEvidenceView>, OpsError> {
    let Some(json) = command_json else {
        return Ok(None);
    };
    let command: OperationCommandEvidenceView =
        serde_json::from_str(&json).map_err(|_| OpsError::ForensicLockdown)?;
    if command.validate_shape().is_err() {
        return Err(OpsError::ForensicLockdown);
    }
    let digest = command_evidence_digest(&command)?;
    let expected = match validator_evidence_digest {
        Some(value) => value,
        None => event_evidence_digest,
    };
    if digest != expected {
        return Err(OpsError::ForensicLockdown);
    }
    Ok(Some(command))
}

pub(crate) fn command_evidence_digest(
    command: &OperationCommandEvidenceView,
) -> Result<String, OpsError> {
    canonical_digest(b"jw-agent/command-evidence/v1", command)
}

impl Ledger {
    pub fn transition_with_command_evidence(
        &mut self,
        operation_id: &str,
        change: Transition<'_>,
        command: &OperationCommandEvidenceView,
    ) -> Result<StoredOperation, OpsError> {
        let stored = prepare_command_evidence(command, change.evidence_digest)?;
        self.transition_internal(operation_id, change, None, Some(&stored))
    }

    pub fn transition_with_diagnostics_and_command(
        &mut self,
        operation_id: &str,
        change: Transition<'_>,
        diagnostics: &[ManagedConfigDiagnosticView],
        command: &OperationCommandEvidenceView,
    ) -> Result<StoredOperation, OpsError> {
        if diagnostics.is_empty() {
            return self.transition_with_command_evidence(operation_id, change, command);
        }
        let stored_command = prepare_command_evidence(command, change.evidence_digest)?;
        let (stored_diagnostics, combined) =
            prepare_diagnostics(change.evidence_digest, diagnostics)?;
        self.transition_internal(
            operation_id,
            Transition {
                expected: change.expected,
                next: change.next,
                result_code: change.result_code,
                evidence_digest: &combined,
                after_digest: change.after_digest,
                rollback_result: change.rollback_result,
                now_ms: change.now_ms,
            },
            Some(&stored_diagnostics),
            Some(&stored_command),
        )
    }
}
