use jw_contracts::{
    NginxSiteState, OperationReceiptView, OperationStage, Subject, UFW_RULE_OPERATION,
    UfwRuleMutation, UfwRulePlanRequest, UfwRulePlanView, UfwStatus, UfwView, sha256_digest,
};
use serde::Serialize;

use super::{
    Ledger, OpsError, OpsService, StoredOperation, StoredPlan, Transition, canonical_digest,
    command_digest, random_id,
};
use crate::ledger::format_time;
use crate::snapshot::{UfwSnapshot, read_ufw_snapshot, write_ufw_snapshot};
use crate::ufw::{
    UfwCommand, UfwPlanPayload, UfwRuleSpec, matching_owned_rule, normalized_source, observe_ufw,
    rule_matches_spec, ufw_assurance,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UfwPlanRequestDigest<'a> {
    operation_type: &'a str,
    actor: &'a Subject,
    request: &'a UfwRulePlanRequest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UfwPlanHashMaterial<'a> {
    schema_version: u16,
    operation_type: &'a str,
    plan_id: &'a str,
    created_at_ms: i64,
    expires_at_ms: i64,
    actor: &'a Subject,
    expected_state_digest: &'a str,
    resource_key: &'a str,
    payload: &'a UfwPlanPayload,
    assurance: &'a jw_contracts::AssuranceView,
}

impl OpsService {
    pub(super) fn ufw_inventory(&self, now_ms: i64) -> Result<UfwView, OpsError> {
        let observed_at = format_time(now_ms)?;
        if self.paths.enforce_root_ownership && !self.paths.ufw_executable.is_file() {
            let reason = String::from("ufw_not_installed");
            return Ok(UfwView {
                observed_at,
                status: UfwStatus::NotInstalled,
                default_incoming: None,
                default_outgoing: None,
                rules: Vec::new(),
                state_digest: sha256_digest(b"jw-agent/ufw/not-installed/v1"),
                truncated: false,
                mutation_available: false,
                blocked_reason: Some(reason.clone()),
                assurance: ufw_assurance(false, Some(reason)),
            });
        }
        observe_ufw(self.runner.as_ref(), observed_at)
    }

    pub(super) fn plan_ufw_rule(
        &self,
        actor: &Subject,
        request: &UfwRulePlanRequest,
        now_ms: i64,
    ) -> Result<UfwRulePlanView, OpsError> {
        request.validate().map_err(OpsError::Rejected)?;
        let inventory = self.ufw_inventory(now_ms)?;
        if inventory.status != UfwStatus::Active || !inventory.mutation_available {
            return Err(OpsError::Rejected("ufw_inactive"));
        }
        if inventory.state_digest != request.expected_state_digest {
            return Err(OpsError::Rejected("precondition_changed"));
        }
        let (rule, delete_sequences) = resolve_rule(request, &inventory)?;
        let payload = UfwPlanPayload {
            requested_mutation: request.mutation,
            rule,
            delete_sequences,
        };
        let ttl_ms = i64::try_from(self.policy.plan_ttl.as_millis())
            .map_err(|_| OpsError::Storage(String::from("plan ttl overflow")))?;
        let plan_id = random_id("plan")?;
        let request_digest = canonical_digest(
            b"jw-agent/operation-request/v1",
            &UfwPlanRequestDigest {
                operation_type: UFW_RULE_OPERATION,
                actor,
                request,
            },
        )?;
        let mut plan = StoredPlan {
            operation_type: String::from(UFW_RULE_OPERATION),
            plan_id,
            plan_hash: String::new(),
            actor: actor.clone(),
            site_id: payload.rule.rule_id.clone(),
            display_name: format!(
                "UFW {} {}/{}",
                request.mutation.as_str(),
                payload.rule.port,
                payload.rule.protocol.as_str()
            ),
            current_state: NginxSiteState::Enabled,
            target_state: NginxSiteState::Enabled,
            available_digest: inventory.state_digest.clone(),
            enabled_state_digest: inventory.state_digest,
            created_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
            idempotency_key: request.idempotency_key.clone(),
            request_digest,
            resource_key: String::from("ufw/rules"),
            assurance: ufw_assurance(true, None),
            managed_config: None,
            certbot_renew: None,
            certbot_issue: None,
            certbot_attach: None,
            ufw_rule: Some(payload),
        };
        plan.plan_hash = ufw_plan_hash(&plan)?;
        let mut ledger = self.open_ledger()?;
        let stored = ledger.create_or_reuse_plan(&plan)?;
        ledger.ufw_rule_plan_view(&stored)
    }

    pub(super) fn approve_ufw_rule(
        &self,
        actor: &Subject,
        plan_id: &str,
        plan_hash: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let mut ledger = self.open_ledger()?;
        let plan = ledger.load_plan(plan_id)?;
        if plan.operation_type != UFW_RULE_OPERATION || plan.ufw_rule.is_none() {
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

    pub(super) fn execute_ufw_rule(
        &self,
        ledger: &mut Ledger,
        operation: StoredOperation,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let payload = operation
            .plan
            .ufw_rule
            .as_ref()
            .ok_or(OpsError::ForensicLockdown)?;
        let before = self.ufw_inventory(now_ms)?;
        if before.status != UfwStatus::Active
            || before.state_digest != operation.plan.enabled_state_digest
        {
            let cancelled = ledger.transition(
                &operation.operation_id,
                Transition {
                    expected: &[OperationStage::Approved],
                    next: OperationStage::CancelledBeforeApply,
                    result_code: "precondition_changed",
                    evidence_digest: &before.state_digest,
                    after_digest: None,
                    rollback_result: None,
                    now_ms,
                },
            )?;
            return ledger.receipt(&cancelled.operation_id);
        }
        validate_resolved_rule(payload, &before)?;
        let snapshot = UfwSnapshot {
            schema_version: 1,
            state_digest: before.state_digest.clone(),
            rules: before.rules,
        };
        let record = match write_ufw_snapshot(
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
                        evidence_digest: &sha256_digest(error.code().as_bytes()),
                        after_digest: None,
                        rollback_result: None,
                        now_ms,
                    },
                )?;
                return ledger.receipt(&cancelled.operation_id);
            }
        };
        ledger.attach_snapshot(&operation.operation_id, &record, now_ms)?;
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Snapshotted],
                next: OperationStage::Applying,
                result_code: "ufw_rule_apply_started",
                evidence_digest: &record.digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let apply_digest = match apply_payload(self.runner.as_ref(), payload) {
            Ok(digest) => digest,
            Err(error) => {
                return self.rollback_ufw_rule(
                    ledger,
                    &operation.operation_id,
                    error.code(),
                    &sha256_digest(error.code().as_bytes()),
                    now_ms,
                );
            }
        };
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Applying],
                next: OperationStage::Verifying,
                result_code: "ufw_rule_applied",
                evidence_digest: &apply_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let after = self.ufw_inventory(now_ms)?;
        if !effect_verified(payload, &after) {
            return self.rollback_ufw_rule(
                ledger,
                &operation.operation_id,
                "rule_verify_failed",
                &after.state_digest,
                now_ms,
            );
        }
        let succeeded = ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Verifying],
                next: OperationStage::Succeeded,
                result_code: "ufw_rule_verified",
                evidence_digest: &after.state_digest,
                after_digest: Some(&after.state_digest),
                rollback_result: None,
                now_ms,
            },
        )?;
        ledger.receipt(&succeeded.operation_id)
    }

    pub(super) fn rollback_ufw_rule(
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
                    expected: &[
                        OperationStage::Applying,
                        OperationStage::Verifying,
                        OperationStage::Validating,
                        OperationStage::Reloading,
                    ],
                    next: OperationStage::RollingBack,
                    result_code: failure_code,
                    evidence_digest: failure_digest,
                    after_digest: None,
                    rollback_result: None,
                    now_ms,
                },
            )?
        };
        let payload = rolling
            .plan
            .ufw_rule
            .as_ref()
            .ok_or(OpsError::ForensicLockdown)?;
        let record = rolling
            .snapshot
            .as_ref()
            .ok_or(OpsError::ForensicLockdown)?;
        let snapshot = read_ufw_snapshot(&self.paths, record)?;
        let original = snapshot
            .rules
            .iter()
            .filter(|rule| rule.rule_id.as_deref() == Some(payload.rule.rule_id.as_str()))
            .collect::<Vec<_>>();
        let restored = restore_product_effect(self.runner.as_ref(), payload, &original)
            .and_then(|()| self.ufw_inventory(now_ms))
            .is_ok_and(|view| rollback_verified(payload, &view, &original));
        let after = self.ufw_inventory(now_ms).map_or_else(
            |_| sha256_digest(b"ufw_read_back_failed"),
            |view| view.state_digest,
        );
        let terminal = ledger.transition(
            operation_id,
            Transition {
                expected: &[OperationStage::RollingBack],
                next: if restored {
                    OperationStage::RolledBack
                } else {
                    OperationStage::RecoveryRequired
                },
                result_code: if restored {
                    "ufw_rule_restored"
                } else {
                    "rule_rollback_failed"
                },
                evidence_digest: &after,
                after_digest: Some(&after),
                rollback_result: Some(if restored {
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

fn resolve_rule(
    request: &UfwRulePlanRequest,
    inventory: &UfwView,
) -> Result<(UfwRuleSpec, Vec<u16>), OpsError> {
    match request.mutation {
        UfwRuleMutation::Allow | UfwRuleMutation::Deny => {
            let rule_id = request
                .generated_rule_id()
                .ok_or(OpsError::Rejected("rule_id"))?;
            if matching_owned_rule(inventory, &rule_id).is_some() {
                return Err(OpsError::Rejected("rule_exists"));
            }
            Ok((
                UfwRuleSpec {
                    mutation: request.mutation,
                    protocol: request.protocol.ok_or(OpsError::Rejected("protocol"))?,
                    port: request.port.ok_or(OpsError::Rejected("port"))?,
                    source: request
                        .source
                        .as_deref()
                        .map_or_else(|| String::from("any"), str::to_owned),
                    rule_id,
                },
                Vec::new(),
            ))
        }
        UfwRuleMutation::Delete => {
            let rule_id = request
                .rule_id
                .as_deref()
                .ok_or(OpsError::Rejected("rule_id"))?;
            let matches = inventory
                .rules
                .iter()
                .filter(|rule| rule.rule_id.as_deref() == Some(rule_id))
                .collect::<Vec<_>>();
            let first = matches.first().ok_or(OpsError::Rejected("rule_missing"))?;
            if matches.iter().any(|rule| !rule.owned) {
                return Err(OpsError::Rejected("rule_not_owned"));
            }
            if matches.iter().any(|rule| rule.protected) {
                return Err(OpsError::Rejected("protected_management_rule"));
            }
            let mutation = match first.action.as_str() {
                "allow" => UfwRuleMutation::Allow,
                "deny" => UfwRuleMutation::Deny,
                _ => return Err(OpsError::Rejected("unsupported_rule")),
            };
            let protocol = first
                .protocol
                .ok_or(OpsError::Rejected("unsupported_rule"))?;
            let port = first.port.ok_or(OpsError::Rejected("unsupported_rule"))?;
            let source = String::from(normalized_source(&first.source));
            if matches.iter().any(|rule| {
                rule.action != first.action
                    || rule.protocol != Some(protocol)
                    || rule.port != Some(port)
                    || normalized_source(&rule.source) != source
            }) {
                return Err(OpsError::Rejected("rule_identity_conflict"));
            }
            let mut sequences = matches.iter().map(|rule| rule.sequence).collect::<Vec<_>>();
            sequences.sort_unstable_by(|left, right| right.cmp(left));
            Ok((
                UfwRuleSpec {
                    mutation,
                    protocol,
                    port,
                    source,
                    rule_id: String::from(rule_id),
                },
                sequences,
            ))
        }
    }
}

fn validate_resolved_rule(payload: &UfwPlanPayload, inventory: &UfwView) -> Result<(), OpsError> {
    match payload.requested_mutation {
        UfwRuleMutation::Allow | UfwRuleMutation::Deny => {
            if matching_owned_rule(inventory, &payload.rule.rule_id).is_some() {
                Err(OpsError::Rejected("rule_exists"))
            } else {
                Ok(())
            }
        }
        UfwRuleMutation::Delete => {
            let current = inventory
                .rules
                .iter()
                .filter(|rule| rule.rule_id.as_deref() == Some(payload.rule.rule_id.as_str()))
                .collect::<Vec<_>>();
            if current.len() != payload.delete_sequences.len()
                || current
                    .iter()
                    .any(|rule| !rule_matches_spec(rule, &payload.rule) || rule.protected)
            {
                Err(OpsError::Rejected("precondition_changed"))
            } else {
                Ok(())
            }
        }
    }
}

fn apply_payload(
    runner: &dyn crate::runner::OperationRunner,
    payload: &UfwPlanPayload,
) -> Result<String, OpsError> {
    match payload.requested_mutation {
        UfwRuleMutation::Allow | UfwRuleMutation::Deny => {
            let evidence = runner.run_ufw(&UfwCommand::Add(payload.rule.clone()))?;
            if !evidence.success {
                return Err(OpsError::Rejected("rule_apply_failed"));
            }
            command_digest(&evidence)
        }
        UfwRuleMutation::Delete => delete_sequences(runner, &payload.delete_sequences),
    }
}

fn delete_sequences(
    runner: &dyn crate::runner::OperationRunner,
    sequences: &[u16],
) -> Result<String, OpsError> {
    let mut digests = Vec::with_capacity(sequences.len());
    for sequence in sequences {
        let evidence = runner.run_ufw(&UfwCommand::Delete {
            sequence: *sequence,
        })?;
        if !evidence.success {
            return Err(OpsError::Rejected("rule_apply_failed"));
        }
        digests.push(command_digest(&evidence)?);
    }
    canonical_digest(b"jw-agent/ufw-command-evidence/v1", &digests)
}

fn effect_verified(payload: &UfwPlanPayload, inventory: &UfwView) -> bool {
    let matches = inventory
        .rules
        .iter()
        .filter(|rule| rule.rule_id.as_deref() == Some(payload.rule.rule_id.as_str()))
        .collect::<Vec<_>>();
    match payload.requested_mutation {
        UfwRuleMutation::Allow | UfwRuleMutation::Deny => {
            !matches.is_empty()
                && matches
                    .iter()
                    .all(|rule| rule_matches_spec(rule, &payload.rule))
        }
        UfwRuleMutation::Delete => matches.is_empty(),
    }
}

fn restore_product_effect(
    runner: &dyn crate::runner::OperationRunner,
    payload: &UfwPlanPayload,
    original: &[&jw_contracts::UfwRuleView],
) -> Result<(), OpsError> {
    let current_evidence = runner.run_ufw(&UfwCommand::Status)?;
    let current = crate::ufw::parse_ufw_status(&current_evidence, String::new());
    let mut sequences = current
        .rules
        .iter()
        .filter(|rule| rule.rule_id.as_deref() == Some(payload.rule.rule_id.as_str()))
        .map(|rule| rule.sequence)
        .collect::<Vec<_>>();
    sequences.sort_unstable_by(|left, right| right.cmp(left));
    if !sequences.is_empty() {
        delete_sequences(runner, &sequences)?;
    }
    if !original.is_empty() {
        let evidence = runner.run_ufw(&UfwCommand::Add(payload.rule.clone()))?;
        if !evidence.success {
            return Err(OpsError::Rejected("rule_rollback_failed"));
        }
    }
    Ok(())
}

fn rollback_verified(
    payload: &UfwPlanPayload,
    inventory: &UfwView,
    original: &[&jw_contracts::UfwRuleView],
) -> bool {
    let current = inventory
        .rules
        .iter()
        .filter(|rule| rule.rule_id.as_deref() == Some(payload.rule.rule_id.as_str()))
        .collect::<Vec<_>>();
    if original.is_empty() {
        current.is_empty()
    } else {
        current.len() == original.len()
            && current
                .iter()
                .all(|rule| rule_matches_spec(rule, &payload.rule))
    }
}

fn ufw_plan_hash(plan: &StoredPlan) -> Result<String, OpsError> {
    let payload = plan.ufw_rule.as_ref().ok_or(OpsError::ForensicLockdown)?;
    canonical_digest(
        b"jw-agent/operation-plan/v1",
        &UfwPlanHashMaterial {
            schema_version: 1,
            operation_type: UFW_RULE_OPERATION,
            plan_id: &plan.plan_id,
            created_at_ms: plan.created_at_ms,
            expires_at_ms: plan.expires_at_ms,
            actor: &plan.actor,
            expected_state_digest: &plan.enabled_state_digest,
            resource_key: &plan.resource_key,
            payload,
            assurance: &plan.assurance,
        },
    )
}
