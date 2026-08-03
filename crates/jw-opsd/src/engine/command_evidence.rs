use jw_contracts::{OperationCommandEvidenceView, sha256_digest};

use crate::error::OpsError;
use crate::ledger::command_evidence_digest;
use crate::runner::{CommandClass, CommandEvidence, StreamEvidence};

pub(super) fn command_digest(evidence: &CommandEvidence) -> Result<String, OpsError> {
    command_evidence_digest(&command_evidence_view(evidence))
}

pub(super) fn command_evidence_view(evidence: &CommandEvidence) -> OperationCommandEvidenceView {
    OperationCommandEvidenceView {
        class: String::from(evidence.class.as_str()),
        success: evidence.success,
        exit_code: evidence.exit_code,
        timed_out: evidence.timed_out,
        stdout_digest: evidence.stdout.digest.clone(),
        stdout_truncated: evidence.stdout.truncated,
        stderr_digest: evidence.stderr.digest.clone(),
        stderr_truncated: evidence.stderr.truncated,
    }
}

pub(super) fn failed_evidence(class: CommandClass) -> CommandEvidence {
    let empty = sha256_digest(b"");
    CommandEvidence {
        class,
        success: false,
        exit_code: None,
        timed_out: false,
        stdout: StreamEvidence {
            digest: empty.clone(),
            captured: Vec::new(),
            truncated: false,
        },
        stderr: StreamEvidence {
            digest: empty,
            captured: Vec::new(),
            truncated: false,
        },
    }
}
