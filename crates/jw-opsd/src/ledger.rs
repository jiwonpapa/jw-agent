use std::fs::{File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use jw_contracts::{
    AssuranceView, MANAGED_CONFIG_OPERATION, ManagedConfigPlanView, NGINX_SITE_STATE_OPERATION,
    NginxSiteState, NginxSiteStatePlanView, OPERATION_SCHEMA_VERSION, OperationReceiptView,
    OperationStage, OperationStageEvidenceView, Role, Subject,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::config::OpsPaths;
use crate::digest::ledger_event_digest;
use crate::error::OpsError;
use crate::managed_config::{
    MANAGED_CONFIG_IMPACT, MANAGED_CONFIG_RECOVERY_PATH, ManagedConfigPlanPayload,
};
use crate::nginx::{NGINX_IMPACT, NGINX_RECOVERY_PATH};
use crate::snapshot::SnapshotRecord;

const GENESIS_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const CHECKPOINT_PENDING_KEY: &str = "checkpoint_required_sequence";

#[derive(Clone, Debug)]
pub struct StoredPlan {
    pub operation_type: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub actor: Subject,
    pub site_id: String,
    pub display_name: String,
    pub current_state: NginxSiteState,
    pub target_state: NginxSiteState,
    pub available_digest: String,
    pub enabled_state_digest: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub idempotency_key: String,
    pub request_digest: String,
    pub resource_key: String,
    pub assurance: AssuranceView,
    pub managed_config: Option<ManagedConfigPlanPayload>,
}

impl StoredPlan {
    #[must_use]
    pub fn before_digest(&self) -> &str {
        if self.operation_type == MANAGED_CONFIG_OPERATION {
            &self.available_digest
        } else {
            &self.enabled_state_digest
        }
    }
}

#[derive(Clone, Debug)]
pub struct StoredOperation {
    pub operation_id: String,
    pub plan: StoredPlan,
    pub stage: OperationStage,
    pub before_digest: String,
    pub after_digest: String,
    pub rollback_result: Option<String>,
    pub snapshot: Option<SnapshotRecord>,
}

pub struct Transition<'a> {
    pub expected: &'a [OperationStage],
    pub next: OperationStage,
    pub result_code: &'a str,
    pub evidence_digest: &'a str,
    pub after_digest: Option<&'a str>,
    pub rollback_result: Option<&'a str>,
    pub now_ms: i64,
}

#[derive(Debug)]
pub struct Ledger {
    connection: Connection,
    paths: OpsPaths,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalEvent<'a> {
    schema_version: u16,
    sequence: i64,
    previous_digest: &'a str,
    operation_id: &'a str,
    plan_id: &'a str,
    stage: &'a str,
    result_code: &'a str,
    recorded_at_ms: i64,
    evidence_digest: &'a str,
}

struct EventInput<'a> {
    operation_id: &'a str,
    plan_id: &'a str,
    stage: OperationStage,
    result_code: &'a str,
    recorded_at_ms: i64,
    evidence_digest: &'a str,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Checkpoint {
    schema_version: u16,
    sequence: i64,
    event_digest: String,
}

impl Ledger {
    pub fn open(paths: &OpsPaths) -> Result<Self, OpsError> {
        prepare_state(paths)?;
        let connection = Connection::open(&paths.database)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.busy_timeout(std::time::Duration::from_secs(2))?;
        migrate(&connection)?;
        secure_database_files(paths)?;
        let mut ledger = Self {
            connection,
            paths: paths.clone(),
        };
        ledger.validate_continuity()?;
        ledger.complete_pending_checkpoint()?;
        Ok(ledger)
    }

    pub fn create_or_reuse_plan(&mut self, plan: &StoredPlan) -> Result<StoredPlan, OpsError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String)> = transaction
            .query_row(
                "SELECT request_digest, plan_id FROM idempotency WHERE idempotency_key = ?1",
                [&plan.idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((request_digest, plan_id)) = existing {
            if request_digest != plan.request_digest {
                return Err(OpsError::Rejected("idempotency_conflict"));
            }
            return load_plan_from(&transaction, &plan_id);
        }
        let role = serde_json::to_string(&plan.actor.role)
            .map_err(|error| OpsError::Storage(error.to_string()))?;
        let current_state = serde_json::to_string(&plan.current_state)
            .map_err(|error| OpsError::Storage(error.to_string()))?;
        let target_state = serde_json::to_string(&plan.target_state)
            .map_err(|error| OpsError::Storage(error.to_string()))?;
        let assurance = serde_json::to_string(&plan.assurance)
            .map_err(|error| OpsError::Storage(error.to_string()))?;
        let payload = serde_json::to_string(&plan.managed_config)
            .map_err(|error| OpsError::Storage(error.to_string()))?;
        transaction.execute(
            "INSERT INTO plans (
                plan_id, operation_type, plan_hash, actor_uid, actor_username, actor_role,
                site_id, display_name, current_state, target_state, available_digest,
                enabled_state_digest, created_at_ms, expires_at_ms, idempotency_key,
                request_digest, resource_key, assurance_json, payload_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                plan.plan_id,
                plan.operation_type,
                plan.plan_hash,
                i64::from(plan.actor.uid),
                plan.actor.username,
                role,
                plan.site_id,
                plan.display_name,
                current_state,
                target_state,
                plan.available_digest,
                plan.enabled_state_digest,
                plan.created_at_ms,
                plan.expires_at_ms,
                plan.idempotency_key,
                plan.request_digest,
                plan.resource_key,
                assurance,
                payload,
            ],
        )?;
        transaction.execute(
            "INSERT INTO idempotency (idempotency_key, request_digest, plan_id)
             VALUES (?1, ?2, ?3)",
            params![plan.idempotency_key, plan.request_digest, plan.plan_id],
        )?;
        let sequence = append_event(
            &transaction,
            &EventInput {
                operation_id: "",
                plan_id: &plan.plan_id,
                stage: OperationStage::Planned,
                result_code: "planned",
                recorded_at_ms: plan.created_at_ms,
                evidence_digest: &plan.plan_hash,
            },
        )?;
        mark_checkpoint_if_needed(&transaction, sequence, false)?;
        transaction.commit()?;
        self.complete_pending_checkpoint()?;
        Ok(plan.clone())
    }

    pub fn begin_operation(
        &mut self,
        operation_id: &str,
        plan_id: &str,
        plan_hash: &str,
        idempotency_key: &str,
        actor: &Subject,
        now_ms: i64,
    ) -> Result<StoredOperation, OpsError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let plan = load_plan_from(&transaction, plan_id)?;
        if plan.plan_hash != plan_hash
            || plan.idempotency_key != idempotency_key
            || plan.actor != *actor
        {
            return Err(OpsError::Rejected("approval_mismatch"));
        }
        if plan.expires_at_ms <= now_ms {
            return Err(OpsError::Rejected("plan_expired"));
        }
        let existing: Option<String> = transaction
            .query_row(
                "SELECT operation_id FROM operations WHERE plan_id = ?1",
                [plan_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing_id) = existing {
            return load_operation_from(&transaction, &existing_id);
        }
        transaction.execute(
            "INSERT INTO operations (
                operation_id, plan_id, stage, before_digest, after_digest,
                created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?5)",
            params![
                operation_id,
                plan_id,
                OperationStage::Approved.as_storage_value(),
                plan.before_digest(),
                now_ms,
            ],
        )?;
        transaction
            .execute(
                "INSERT INTO resource_locks (resource_key, operation_id, acquired_at_ms)
                 VALUES (?1, ?2, ?3)",
                params![plan.resource_key, operation_id, now_ms],
            )
            .map_err(|_| OpsError::Rejected("resource_busy"))?;
        transaction
            .execute(
                "INSERT INTO resource_locks (resource_key, operation_id, acquired_at_ms)
                 VALUES (?1, ?2, ?3)",
                params!["nginx/reload", operation_id, now_ms],
            )
            .map_err(|_| OpsError::Rejected("resource_busy"))?;
        transaction.execute(
            "UPDATE idempotency SET operation_id = ?1 WHERE idempotency_key = ?2",
            params![operation_id, idempotency_key],
        )?;
        let sequence = append_event(
            &transaction,
            &EventInput {
                operation_id,
                plan_id,
                stage: OperationStage::Approved,
                result_code: "approved",
                recorded_at_ms: now_ms,
                evidence_digest: plan_hash,
            },
        )?;
        mark_checkpoint_if_needed(&transaction, sequence, false)?;
        transaction.commit()?;
        self.complete_pending_checkpoint()?;
        self.load_operation(operation_id)
    }

    pub fn attach_snapshot(
        &mut self,
        operation_id: &str,
        snapshot: &SnapshotRecord,
        now_ms: i64,
    ) -> Result<StoredOperation, OpsError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction
            .execute(
                "UPDATE operations
             SET stage = ?1, snapshot_relative_path = ?2, snapshot_digest = ?3, updated_at_ms = ?4
             WHERE operation_id = ?5 AND stage = ?6",
                params![
                    OperationStage::Snapshotted.as_storage_value(),
                    snapshot.relative_path,
                    snapshot.digest,
                    now_ms,
                    operation_id,
                    OperationStage::Approved.as_storage_value(),
                ],
            )
            .and_then(require_one_row)?;
        let operation = load_operation_from(&transaction, operation_id)?;
        let sequence = append_event(
            &transaction,
            &EventInput {
                operation_id,
                plan_id: &operation.plan.plan_id,
                stage: OperationStage::Snapshotted,
                result_code: "snapshot_durable",
                recorded_at_ms: now_ms,
                evidence_digest: &snapshot.digest,
            },
        )?;
        mark_checkpoint_if_needed(&transaction, sequence, false)?;
        transaction.commit()?;
        self.complete_pending_checkpoint()?;
        self.load_operation(operation_id)
    }

    pub fn transition(
        &mut self,
        operation_id: &str,
        change: Transition<'_>,
    ) -> Result<StoredOperation, OpsError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_operation_from(&transaction, operation_id)?;
        if !change.expected.contains(&current.stage) {
            return Err(OpsError::Rejected("stage_conflict"));
        }
        let after = match change.after_digest {
            Some(value) => value,
            None => &current.after_digest,
        };
        let rollback = change
            .rollback_result
            .or(current.rollback_result.as_deref());
        transaction.execute(
            "UPDATE operations SET stage = ?1, after_digest = ?2, rollback_result = ?3, updated_at_ms = ?4
             WHERE operation_id = ?5",
            params![
                change.next.as_storage_value(),
                after,
                rollback,
                change.now_ms,
                operation_id
            ],
        )?;
        let sequence = append_event(
            &transaction,
            &EventInput {
                operation_id,
                plan_id: &current.plan.plan_id,
                stage: change.next,
                result_code: change.result_code,
                recorded_at_ms: change.now_ms,
                evidence_digest: change.evidence_digest,
            },
        )?;
        if change.next.is_terminal() {
            transaction.execute(
                "DELETE FROM resource_locks WHERE operation_id = ?1",
                [operation_id],
            )?;
        }
        mark_checkpoint_if_needed(&transaction, sequence, change.next.is_terminal())?;
        transaction.commit()?;
        self.complete_pending_checkpoint()?;
        self.load_operation(operation_id)
    }

    pub fn load_operation(&self, operation_id: &str) -> Result<StoredOperation, OpsError> {
        load_operation_from(&self.connection, operation_id)
    }

    pub fn load_plan(&self, plan_id: &str) -> Result<StoredPlan, OpsError> {
        load_plan_from(&self.connection, plan_id)
    }

    pub fn incomplete_operations(&self) -> Result<Vec<StoredOperation>, OpsError> {
        let mut statement = self.connection.prepare(
            "SELECT operation_id FROM operations
             WHERE stage NOT IN ('SUCCEEDED','ROLLED_BACK','RECOVERY_REQUIRED','REJECTED','EXPIRED','CANCELLED_BEFORE_APPLY')
             ORDER BY created_at_ms, operation_id",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut operations = Vec::new();
        for row in rows {
            operations.push(self.load_operation(&row?)?);
        }
        Ok(operations)
    }

    pub fn expired_unexecuted_managed_plans(
        &self,
        now_ms: i64,
    ) -> Result<Vec<StoredPlan>, OpsError> {
        let mut statement = self.connection.prepare(
            "SELECT plans.plan_id FROM plans
             LEFT JOIN operations ON operations.plan_id = plans.plan_id
             WHERE plans.operation_type = ?1
               AND plans.expires_at_ms <= ?2
               AND operations.operation_id IS NULL
             ORDER BY plans.expires_at_ms, plans.plan_id",
        )?;
        let rows = statement.query_map(params![MANAGED_CONFIG_OPERATION, now_ms], |row| {
            row.get::<_, String>(0)
        })?;
        let mut plans = Vec::new();
        for row in rows {
            plans.push(self.load_plan(&row?)?);
        }
        Ok(plans)
    }

    pub fn receipt(&self, operation_id: &str) -> Result<OperationReceiptView, OpsError> {
        let operation = self.load_operation(operation_id)?;
        let mut statement = self.connection.prepare(
            "SELECT sequence, stage, recorded_at_ms, result_code, evidence_digest
             FROM ledger_events WHERE operation_id = ?1 ORDER BY sequence",
        )?;
        let rows = statement.query_map([operation_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut stages = Vec::new();
        for row in rows {
            let (sequence, stage, recorded_at_ms, result_code, evidence_digest) = row?;
            stages.push(OperationStageEvidenceView {
                sequence: u64::try_from(sequence).map_err(|_| OpsError::ForensicLockdown)?,
                stage: parse_stage(&stage)?,
                recorded_at: format_time(recorded_at_ms)?,
                result_code,
                evidence_digest,
            });
        }
        Ok(OperationReceiptView {
            schema_version: OPERATION_SCHEMA_VERSION,
            operation_type: operation.plan.operation_type.clone(),
            operation_id: operation.operation_id,
            plan_id: operation.plan.plan_id,
            plan_hash: operation.plan.plan_hash,
            actor: operation.plan.actor,
            terminal_state: operation.stage,
            before_digest: operation.before_digest,
            after_digest: operation.after_digest,
            stages,
            assurance: operation.plan.assurance,
            rollback_result: operation.rollback_result,
            recovery_path: if operation.stage == OperationStage::RecoveryRequired {
                recovery_path_for(&operation.plan.operation_type)
            } else {
                Vec::new()
            },
        })
    }

    pub fn plan_view(&self, plan: &StoredPlan) -> Result<NginxSiteStatePlanView, OpsError> {
        if plan.operation_type != NGINX_SITE_STATE_OPERATION {
            return Err(OpsError::Rejected("operation_type"));
        }
        Ok(NginxSiteStatePlanView {
            schema_version: OPERATION_SCHEMA_VERSION,
            operation_type: String::from(NGINX_SITE_STATE_OPERATION),
            plan_id: plan.plan_id.clone(),
            plan_hash: plan.plan_hash.clone(),
            created_at: format_time(plan.created_at_ms)?,
            expires_at: format_time(plan.expires_at_ms)?,
            actor: plan.actor.clone(),
            site_id: plan.site_id.clone(),
            display_name: plan.display_name.clone(),
            current_state: plan.current_state,
            target_state: plan.target_state,
            available_digest: plan.available_digest.clone(),
            enabled_state_digest: plan.enabled_state_digest.clone(),
            impact: NGINX_IMPACT.iter().map(ToString::to_string).collect(),
            recovery_path: NGINX_RECOVERY_PATH
                .iter()
                .map(ToString::to_string)
                .collect(),
            assurance: plan.assurance.clone(),
        })
    }

    pub fn managed_config_plan_view(
        &self,
        plan: &StoredPlan,
    ) -> Result<ManagedConfigPlanView, OpsError> {
        if plan.operation_type != MANAGED_CONFIG_OPERATION {
            return Err(OpsError::Rejected("operation_type"));
        }
        let payload = plan
            .managed_config
            .as_ref()
            .ok_or(OpsError::ForensicLockdown)?;
        Ok(ManagedConfigPlanView {
            schema_version: OPERATION_SCHEMA_VERSION,
            operation_type: plan.operation_type.clone(),
            plan_id: plan.plan_id.clone(),
            plan_hash: plan.plan_hash.clone(),
            created_at: format_time(plan.created_at_ms)?,
            expires_at: format_time(plan.expires_at_ms)?,
            actor: plan.actor.clone(),
            adapter_id: String::from(jw_contracts::NGINX_CONFIG_ADAPTER_ID),
            resource_id: plan.site_id.clone(),
            display_name: plan.display_name.clone(),
            masked_path: format!("…/sites-available/{}", plan.display_name),
            current_content_digest: plan.available_digest.clone(),
            proposed_content_digest: payload.proposed_content_digest.clone(),
            metadata_digest: plan.enabled_state_digest.clone(),
            current_bytes: payload.current_bytes,
            proposed_bytes: payload.proposed_bytes,
            added_lines: payload.added_lines,
            removed_lines: payload.removed_lines,
            diff_summary: payload.diff_summary.clone(),
            service_action: payload.service_action,
            impact: MANAGED_CONFIG_IMPACT
                .iter()
                .map(ToString::to_string)
                .collect(),
            recovery_path: MANAGED_CONFIG_RECOVERY_PATH
                .iter()
                .map(ToString::to_string)
                .collect(),
            assurance: plan.assurance.clone(),
        })
    }

    fn validate_continuity(&self) -> Result<(), OpsError> {
        let integrity: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(OpsError::ForensicLockdown);
        }
        let mut statement = self.connection.prepare(
            "SELECT sequence, operation_id, plan_id, stage, result_code, recorded_at_ms,
                    evidence_digest, previous_digest, event_digest
             FROM ledger_events ORDER BY sequence",
        )?;
        let mut rows = statement.query([])?;
        let mut expected_sequence = 1_i64;
        let mut previous = String::from(GENESIS_DIGEST);
        while let Some(row) = rows.next()? {
            let sequence: i64 = row.get(0)?;
            let operation_id: String = row.get(1)?;
            let plan_id: String = row.get(2)?;
            let stage: String = row.get(3)?;
            let result_code: String = row.get(4)?;
            let recorded_at_ms: i64 = row.get(5)?;
            let evidence_digest: String = row.get(6)?;
            let stored_previous: String = row.get(7)?;
            let stored_digest: String = row.get(8)?;
            if sequence != expected_sequence || stored_previous != previous {
                return Err(OpsError::ForensicLockdown);
            }
            let canonical_event = CanonicalEvent {
                schema_version: 1,
                sequence,
                previous_digest: &previous,
                operation_id: &operation_id,
                plan_id: &plan_id,
                stage: &stage,
                result_code: &result_code,
                recorded_at_ms,
                evidence_digest: &evidence_digest,
            };
            let canonical = canonical_event_bytes(&canonical_event)?;
            let expected_digest = ledger_event_digest(&previous, &canonical)?;
            if stored_digest != expected_digest {
                return Err(OpsError::ForensicLockdown);
            }
            previous = stored_digest;
            expected_sequence = expected_sequence.saturating_add(1);
        }
        self.validate_checkpoint(expected_sequence.saturating_sub(1))
    }

    fn validate_checkpoint(&self, latest_sequence: i64) -> Result<(), OpsError> {
        validate_private_file(
            &self.paths.checkpoint,
            self.paths.enforce_root_ownership,
            true,
        )?;
        let terminal_sequence: Option<i64> = self.connection.query_row(
            "SELECT MAX(sequence) FROM ledger_events
             WHERE stage IN ('SUCCEEDED','ROLLED_BACK','RECOVERY_REQUIRED','REJECTED','EXPIRED','CANCELLED_BEFORE_APPLY')",
            [],
            |row| row.get(0),
        )?;
        let periodic_sequence = latest_sequence.saturating_sub(latest_sequence.rem_euclid(128));
        let required_sequence = terminal_sequence
            .map_or(0, std::convert::identity)
            .max(periodic_sequence);
        let pending_sequence: Option<i64> = self
            .connection
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM metadata WHERE key = ?1",
                [CHECKPOINT_PENDING_KEY],
                |row| row.get(0),
            )
            .optional()?;
        if pending_sequence.is_some_and(|sequence| sequence <= 0 || sequence > latest_sequence) {
            return Err(OpsError::ForensicLockdown);
        }
        let bytes = match std::fs::read(&self.paths.checkpoint) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return if required_sequence == 0
                    || pending_sequence.is_some_and(|sequence| sequence >= required_sequence)
                {
                    Ok(())
                } else {
                    Err(OpsError::ForensicLockdown)
                };
            }
            Err(_) => return Err(OpsError::ForensicLockdown),
        };
        let checkpoint: Checkpoint =
            serde_json::from_slice(&bytes).map_err(|_| OpsError::ForensicLockdown)?;
        if checkpoint.schema_version != 1
            || checkpoint.sequence > latest_sequence
            || (checkpoint.sequence < required_sequence
                && pending_sequence.is_none_or(|sequence| sequence < required_sequence))
        {
            return Err(OpsError::ForensicLockdown);
        }
        let stored: Option<String> = self
            .connection
            .query_row(
                "SELECT event_digest FROM ledger_events WHERE sequence = ?1",
                [checkpoint.sequence],
                |row| row.get(0),
            )
            .optional()?;
        if stored.as_deref() == Some(checkpoint.event_digest.as_str()) {
            Ok(())
        } else {
            Err(OpsError::ForensicLockdown)
        }
    }

    fn complete_pending_checkpoint(&mut self) -> Result<(), OpsError> {
        let pending: Option<i64> = self
            .connection
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM metadata WHERE key = ?1",
                [CHECKPOINT_PENDING_KEY],
                |row| row.get(0),
            )
            .optional()?;
        let Some(required_sequence) = pending else {
            return Ok(());
        };
        let (sequence, event_digest): (i64, String) = self.connection.query_row(
            "SELECT sequence, event_digest FROM ledger_events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if sequence < required_sequence {
            return Err(OpsError::ForensicLockdown);
        }
        write_checkpoint(
            &self.paths.checkpoint,
            &Checkpoint {
                schema_version: 1,
                sequence,
                event_digest,
            },
        )?;
        self.connection.execute(
            "DELETE FROM metadata WHERE key = ?1",
            [CHECKPOINT_PENDING_KEY],
        )?;
        Ok(())
    }
}

fn append_event(transaction: &Transaction<'_>, event: &EventInput<'_>) -> Result<i64, OpsError> {
    let previous: Option<(i64, String)> = transaction
        .query_row(
            "SELECT sequence, event_digest FROM ledger_events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (last_sequence, previous_digest) = match previous {
        Some(value) => value,
        None => (0, String::from(GENESIS_DIGEST)),
    };
    let sequence = last_sequence.saturating_add(1);
    let stage_value = event.stage.as_storage_value();
    let canonical_event = CanonicalEvent {
        schema_version: 1,
        sequence,
        previous_digest: &previous_digest,
        operation_id: event.operation_id,
        plan_id: event.plan_id,
        stage: stage_value,
        result_code: event.result_code,
        recorded_at_ms: event.recorded_at_ms,
        evidence_digest: event.evidence_digest,
    };
    let canonical = canonical_event_bytes(&canonical_event)?;
    let digest = ledger_event_digest(&previous_digest, &canonical)?;
    transaction.execute(
        "INSERT INTO ledger_events (
            sequence, operation_id, plan_id, stage, result_code, recorded_at_ms,
            evidence_digest, previous_digest, event_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            sequence,
            event.operation_id,
            event.plan_id,
            stage_value,
            event.result_code,
            event.recorded_at_ms,
            event.evidence_digest,
            previous_digest,
            digest,
        ],
    )?;
    Ok(sequence)
}

fn canonical_event_bytes(event: &CanonicalEvent<'_>) -> Result<Vec<u8>, OpsError> {
    serde_json::to_vec(event).map_err(|error| OpsError::Storage(error.to_string()))
}

fn mark_checkpoint_if_needed(
    transaction: &Transaction<'_>,
    sequence: i64,
    terminal: bool,
) -> Result<(), OpsError> {
    if terminal || sequence % 128 == 0 {
        transaction.execute(
            "INSERT INTO metadata (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![CHECKPOINT_PENDING_KEY, sequence.to_string()],
        )?;
    }
    Ok(())
}

fn load_plan_from(connection: &Connection, plan_id: &str) -> Result<StoredPlan, OpsError> {
    connection
        .query_row(
            "SELECT operation_type, plan_id, plan_hash, actor_uid, actor_username, actor_role, site_id,
                    display_name, current_state, target_state, available_digest,
                    enabled_state_digest, created_at_ms, expires_at_ms, idempotency_key,
                    request_digest, resource_key, assurance_json, payload_json
             FROM plans WHERE plan_id = ?1",
            [plan_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, String>(18)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => OpsError::Rejected("plan_missing"),
            other => OpsError::from(other),
        })
        .and_then(|row| {
            let uid = u32::try_from(row.3).map_err(|_| OpsError::ForensicLockdown)?;
            let role: Role =
                serde_json::from_str(&row.5).map_err(|_| OpsError::ForensicLockdown)?;
            let current_state: NginxSiteState =
                serde_json::from_str(&row.8).map_err(|_| OpsError::ForensicLockdown)?;
            let target_state: NginxSiteState =
                serde_json::from_str(&row.9).map_err(|_| OpsError::ForensicLockdown)?;
            let assurance: AssuranceView =
                serde_json::from_str(&row.17).map_err(|_| OpsError::ForensicLockdown)?;
            let managed_config: Option<ManagedConfigPlanPayload> =
                serde_json::from_str(&row.18).map_err(|_| OpsError::ForensicLockdown)?;
            Ok(StoredPlan {
                operation_type: row.0,
                plan_id: row.1,
                plan_hash: row.2,
                actor: Subject {
                    uid,
                    username: row.4,
                    role,
                },
                site_id: row.6,
                display_name: row.7,
                current_state,
                target_state,
                available_digest: row.10,
                enabled_state_digest: row.11,
                created_at_ms: row.12,
                expires_at_ms: row.13,
                idempotency_key: row.14,
                request_digest: row.15,
                resource_key: row.16,
                assurance,
                managed_config,
            })
        })
}

fn migrate(connection: &Connection) -> Result<(), OpsError> {
    connection.execute_batch(include_str!("../migrations/0001_initial.sql"))?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    match version {
        0 => {
            connection.pragma_update(None, "user_version", 1)?;
            connection.execute_batch(include_str!("../migrations/0002_managed_config.sql"))?;
            connection.pragma_update(None, "user_version", 2)?;
        }
        1 => {
            connection.execute_batch(include_str!("../migrations/0002_managed_config.sql"))?;
            connection.pragma_update(None, "user_version", 2)?;
        }
        2 => {}
        _ => return Err(OpsError::ForensicLockdown),
    }
    Ok(())
}

fn recovery_path_for(operation_type: &str) -> Vec<String> {
    let values: &[&str] = if operation_type == MANAGED_CONFIG_OPERATION {
        &MANAGED_CONFIG_RECOVERY_PATH
    } else {
        &NGINX_RECOVERY_PATH
    };
    values.iter().map(ToString::to_string).collect()
}

fn load_operation_from(
    connection: &Connection,
    operation_id: &str,
) -> Result<StoredOperation, OpsError> {
    let row = connection
        .query_row(
            "SELECT plan_id, stage, before_digest, after_digest, rollback_result,
                snapshot_relative_path, snapshot_digest
         FROM operations WHERE operation_id = ?1",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => OpsError::Rejected("operation_missing"),
            other => OpsError::from(other),
        })?;
    let snapshot = match (row.5, row.6) {
        (Some(relative_path), Some(digest)) => Some(SnapshotRecord {
            relative_path,
            digest,
        }),
        (None, None) => None,
        _ => return Err(OpsError::ForensicLockdown),
    };
    Ok(StoredOperation {
        operation_id: operation_id.to_owned(),
        plan: load_plan_from(connection, &row.0)?,
        stage: parse_stage(&row.1)?,
        before_digest: row.2,
        after_digest: row.3,
        rollback_result: row.4,
        snapshot,
    })
}

fn parse_stage(value: &str) -> Result<OperationStage, OpsError> {
    match value {
        "PLANNED" => Ok(OperationStage::Planned),
        "APPROVED" => Ok(OperationStage::Approved),
        "SNAPSHOTTED" => Ok(OperationStage::Snapshotted),
        "APPLYING" => Ok(OperationStage::Applying),
        "VALIDATING" => Ok(OperationStage::Validating),
        "RELOADING" => Ok(OperationStage::Reloading),
        "VERIFYING" => Ok(OperationStage::Verifying),
        "ROLLING_BACK" => Ok(OperationStage::RollingBack),
        "SUCCEEDED" => Ok(OperationStage::Succeeded),
        "ROLLED_BACK" => Ok(OperationStage::RolledBack),
        "RECOVERY_REQUIRED" => Ok(OperationStage::RecoveryRequired),
        "REJECTED" => Ok(OperationStage::Rejected),
        "EXPIRED" => Ok(OperationStage::Expired),
        "CANCELLED_BEFORE_APPLY" => Ok(OperationStage::CancelledBeforeApply),
        _ => Err(OpsError::ForensicLockdown),
    }
}

fn require_one_row(count: usize) -> rusqlite::Result<usize> {
    if count == 1 {
        Ok(count)
    } else {
        Err(rusqlite::Error::QueryReturnedNoRows)
    }
}

fn prepare_state(paths: &OpsPaths) -> Result<(), OpsError> {
    let Some(parent) = paths.database.parent() else {
        return Err(OpsError::Storage(String::from("database has no parent")));
    };
    std::fs::create_dir_all(parent).map_err(|error| OpsError::Storage(error.to_string()))?;
    let metadata = std::fs::symlink_metadata(parent).map_err(|_| OpsError::ForensicLockdown)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(OpsError::ForensicLockdown);
    }
    #[cfg(unix)]
    if paths.enforce_root_ownership && metadata.uid() != 0 {
        return Err(OpsError::ForensicLockdown);
    }
    #[cfg(unix)]
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| OpsError::Storage(error.to_string()))?;
    validate_private_file(&paths.database, paths.enforce_root_ownership, true)?;
    for sidecar in database_sidecars(&paths.database) {
        validate_private_file(&sidecar, paths.enforce_root_ownership, true)?;
    }
    validate_private_file(&paths.checkpoint, paths.enforce_root_ownership, true)?;
    Ok(())
}

fn secure_database_files(paths: &OpsPaths) -> Result<(), OpsError> {
    set_private_file_mode(&paths.database)?;
    validate_private_file(&paths.database, paths.enforce_root_ownership, false)?;
    for sidecar in database_sidecars(&paths.database) {
        if sidecar.exists() {
            set_private_file_mode(&sidecar)?;
            validate_private_file(&sidecar, paths.enforce_root_ownership, false)?;
        }
    }
    Ok(())
}

fn database_sidecars(database: &Path) -> [std::path::PathBuf; 2] {
    let mut wal = database.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shared = database.as_os_str().to_os_string();
    shared.push("-shm");
    [wal.into(), shared.into()]
}

fn validate_private_file(
    path: &Path,
    enforce_root_ownership: bool,
    missing_allowed: bool,
) -> Result<(), OpsError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if missing_allowed && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(_) => return Err(OpsError::ForensicLockdown),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(OpsError::ForensicLockdown);
    }
    #[cfg(unix)]
    {
        if metadata.nlink() != 1 || (enforce_root_ownership && metadata.uid() != 0) {
            return Err(OpsError::ForensicLockdown);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_file_mode(path: &Path) -> Result<(), OpsError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| OpsError::Storage(error.to_string()))
}

#[cfg(not(unix))]
fn set_private_file_mode(_path: &Path) -> Result<(), OpsError> {
    Ok(())
}

fn write_checkpoint(path: &Path, checkpoint: &Checkpoint) -> Result<(), OpsError> {
    let Some(parent) = path.parent() else {
        return Err(OpsError::Storage(String::from("checkpoint has no parent")));
    };
    let bytes =
        serde_json::to_vec(checkpoint).map_err(|error| OpsError::Storage(error.to_string()))?;
    validate_private_file(path, false, true)?;
    let random = random_suffix()?;
    let temporary = parent.join(format!(".ledger.checkpoint.{random}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| OpsError::Storage(error.to_string()))?;
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| OpsError::Storage(error.to_string()))?;
    file.write_all(&bytes)
        .map_err(|error| OpsError::Storage(error.to_string()))?;
    file.sync_all()
        .map_err(|error| OpsError::Storage(error.to_string()))?;
    std::fs::rename(&temporary, path).map_err(|error| OpsError::Storage(error.to_string()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| OpsError::Storage(error.to_string()))
}

fn random_suffix() -> Result<String, OpsError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|error| OpsError::Storage(error.to_string()))?;
    Ok(format!("{:016x}", u64::from_le_bytes(bytes)))
}

fn format_time(milliseconds: i64) -> Result<String, OpsError> {
    let value = time::OffsetDateTime::from_unix_timestamp_nanos(
        i128::from(milliseconds).saturating_mul(1_000_000),
    )
    .map_err(|error| OpsError::Storage(error.to_string()))?;
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| OpsError::Storage(error.to_string()))
}

#[cfg(test)]
mod tests {
    use jw_contracts::{
        AssuranceLevel, AssuranceView, NGINX_SITE_STATE_OPERATION, NginxSiteState, OperationStage,
        Role, RollbackSupport, Subject, sha256_digest,
    };

    use crate::config::OpsPaths;

    use super::{Ledger, StoredPlan, Transition};

    #[test]
    fn idempotency_reuses_same_plan_and_rejects_different_meaning() -> Result<(), String> {
        let root = test_root("idempotency")?;
        let paths = OpsPaths::for_test(&root);
        let mut ledger = Ledger::open(&paths).map_err(|error| error.to_string())?;
        let plan = fixture_plan();
        let first = ledger
            .create_or_reuse_plan(&plan)
            .map_err(|error| error.to_string())?;
        let second = ledger
            .create_or_reuse_plan(&plan)
            .map_err(|error| error.to_string())?;
        assert_eq!(first.plan_id, second.plan_id);
        let mut conflict = plan;
        conflict.plan_id = String::from("plan-other");
        conflict.request_digest = sha256_digest(b"different");
        assert!(matches!(
            ledger.create_or_reuse_plan(&conflict),
            Err(crate::error::OpsError::Rejected("idempotency_conflict"))
        ));
        std::fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn tampered_event_enters_forensic_lockdown() -> Result<(), String> {
        let root = test_root("tamper")?;
        let paths = OpsPaths::for_test(&root);
        let mut ledger = Ledger::open(&paths).map_err(|error| error.to_string())?;
        ledger
            .create_or_reuse_plan(&fixture_plan())
            .map_err(|error| error.to_string())?;
        drop(ledger);
        let connection =
            rusqlite::Connection::open(&paths.database).map_err(|error| error.to_string())?;
        connection
            .execute(
                "UPDATE ledger_events SET result_code = 'forged' WHERE sequence = 1",
                [],
            )
            .map_err(|error| error.to_string())?;
        drop(connection);
        assert!(matches!(
            Ledger::open(&paths),
            Err(crate::error::OpsError::ForensicLockdown)
        ));
        std::fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn deleting_required_checkpoint_enters_forensic_lockdown() -> Result<(), String> {
        let root = test_root("checkpoint-delete")?;
        let paths = OpsPaths::for_test(&root);
        let mut ledger = Ledger::open(&paths).map_err(|error| error.to_string())?;
        let plan = ledger
            .create_or_reuse_plan(&fixture_plan())
            .map_err(|error| error.to_string())?;
        let operation = ledger
            .begin_operation(
                "op-1",
                &plan.plan_id,
                &plan.plan_hash,
                &plan.idempotency_key,
                &plan.actor,
                1_500,
            )
            .map_err(|error| error.to_string())?;
        ledger
            .transition(
                &operation.operation_id,
                Transition {
                    expected: &[OperationStage::Approved],
                    next: OperationStage::CancelledBeforeApply,
                    result_code: "test_cancel",
                    evidence_digest: &sha256_digest(b"test_cancel"),
                    after_digest: None,
                    rollback_result: None,
                    now_ms: 1_501,
                },
            )
            .map_err(|error| error.to_string())?;
        drop(ledger);
        std::fs::remove_file(&paths.checkpoint).map_err(|error| error.to_string())?;
        assert!(matches!(
            Ledger::open(&paths),
            Err(crate::error::OpsError::ForensicLockdown)
        ));
        std::fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn missing_operation_has_a_typed_error() -> Result<(), String> {
        let root = test_root("missing-operation")?;
        let paths = OpsPaths::for_test(&root);
        let ledger = Ledger::open(&paths).map_err(|error| error.to_string())?;
        assert!(matches!(
            ledger.load_operation("missing"),
            Err(crate::error::OpsError::Rejected("operation_missing"))
        ));
        std::fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    fn fixture_plan() -> StoredPlan {
        StoredPlan {
            operation_type: String::from(NGINX_SITE_STATE_OPERATION),
            plan_id: String::from("plan-1"),
            plan_hash: sha256_digest(b"plan"),
            actor: Subject {
                uid: 1_000,
                username: String::from("operator"),
                role: Role::Admin,
            },
            site_id: String::from("ngs_tQ9Xog5xTe1fh8OsTIdiw6xr"),
            display_name: String::from("example.com"),
            current_state: NginxSiteState::Disabled,
            target_state: NginxSiteState::Enabled,
            available_digest: sha256_digest(b"server {}\n"),
            enabled_state_digest: sha256_digest(b"disabled"),
            created_at_ms: 1_000,
            expires_at_ms: 2_000,
            idempotency_key: String::from("0123456789abcdef"),
            request_digest: sha256_digest(b"request"),
            resource_key: String::from("nginx/site/example"),
            assurance: AssuranceView {
                level: AssuranceLevel::G2ReversibleConfig,
                rollback_support: RollbackSupport::AutomaticBounded,
                operation_available: true,
                scope: vec![String::from("enabled link")],
                excluded_effects: vec![String::from("connections")],
                apply_verifier: vec![String::from("read back")],
                rollback_verifier: vec![String::from("restore")],
                reason: None,
            },
            managed_config: None,
        }
    }

    fn test_root(label: &str) -> Result<std::path::PathBuf, String> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|error| error.to_string())?;
        Ok(std::env::temp_dir().join(format!(
            "jw-opsd-ledger-{label}-{}-{}",
            std::process::id(),
            u64::from_le_bytes(random)
        )))
    }
}
