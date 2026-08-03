use jw_contracts::{
    MANAGED_CONFIG_DIAGNOSTIC_MAX_ENTRIES, ManagedConfigDiagnosticView, sha256_digest,
    validate_digest,
};
use serde::Serialize;

use crate::digest::canonical_digest;
use crate::error::OpsError;

use super::{Ledger, StoredOperation, Transition};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticEvidence<'a> {
    schema_version: u16,
    validator_evidence_digest: &'a str,
    diagnostics_digest: &'a str,
}

pub(super) struct StoredDiagnostics {
    pub(super) json: String,
    pub(super) digest: String,
    pub(super) validator_evidence_digest: String,
}

pub(super) fn prepare_diagnostics(
    validator_evidence_digest: &str,
    diagnostics: &[ManagedConfigDiagnosticView],
) -> Result<(StoredDiagnostics, String), OpsError> {
    if diagnostics.is_empty()
        || diagnostics.len() > MANAGED_CONFIG_DIAGNOSTIC_MAX_ENTRIES
        || diagnostics
            .iter()
            .any(|diagnostic| diagnostic.validate_shape().is_err())
        || validate_digest(validator_evidence_digest).is_err()
    {
        return Err(OpsError::Rejected("invalid_diagnostic"));
    }
    let json =
        serde_json::to_string(diagnostics).map_err(|error| OpsError::Storage(error.to_string()))?;
    let digest = sha256_digest(json.as_bytes());
    let combined = diagnostic_evidence_digest(validator_evidence_digest, &digest)?;
    Ok((
        StoredDiagnostics {
            json,
            digest,
            validator_evidence_digest: String::from(validator_evidence_digest),
        },
        combined,
    ))
}

pub(super) fn load_diagnostics(
    diagnostics_json: Option<String>,
    diagnostics_digest: Option<String>,
    validator_evidence_digest: Option<String>,
    event_evidence_digest: &str,
) -> Result<Vec<ManagedConfigDiagnosticView>, OpsError> {
    let (json, digest, validator_digest) = match (
        diagnostics_json,
        diagnostics_digest,
        validator_evidence_digest,
    ) {
        (None, None, None) => return Ok(Vec::new()),
        (Some(json), Some(digest), Some(validator_digest)) => (json, digest, validator_digest),
        _ => return Err(OpsError::ForensicLockdown),
    };
    if validate_digest(&digest).is_err()
        || validate_digest(&validator_digest).is_err()
        || sha256_digest(json.as_bytes()) != digest
    {
        return Err(OpsError::ForensicLockdown);
    }
    let diagnostics: Vec<ManagedConfigDiagnosticView> =
        serde_json::from_str(&json).map_err(|_| OpsError::ForensicLockdown)?;
    if diagnostics.is_empty()
        || diagnostics.len() > MANAGED_CONFIG_DIAGNOSTIC_MAX_ENTRIES
        || diagnostics
            .iter()
            .any(|diagnostic| diagnostic.validate_shape().is_err())
        || diagnostic_evidence_digest(&validator_digest, &digest)? != event_evidence_digest
    {
        return Err(OpsError::ForensicLockdown);
    }
    Ok(diagnostics)
}

fn diagnostic_evidence_digest(
    validator_evidence_digest: &str,
    diagnostics_digest: &str,
) -> Result<String, OpsError> {
    canonical_digest(
        b"jw-agent/managed-config-diagnostic-evidence/v1",
        &DiagnosticEvidence {
            schema_version: 1,
            validator_evidence_digest,
            diagnostics_digest,
        },
    )
}

impl Ledger {
    pub fn transition_with_diagnostics(
        &mut self,
        operation_id: &str,
        change: Transition<'_>,
        diagnostics: &[ManagedConfigDiagnosticView],
    ) -> Result<StoredOperation, OpsError> {
        if diagnostics.is_empty() {
            return self.transition(operation_id, change);
        }
        let (stored, combined) = prepare_diagnostics(change.evidence_digest, diagnostics)?;
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
            Some(&stored),
            None,
        )
    }
}
