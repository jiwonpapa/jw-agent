use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use jw_contracts::{
    AssuranceLevel, AssuranceView, NGINX_SITE_STATE_OPERATION, NginxSiteState,
    NginxSiteStatePlanRequest, OperationReceiptView, OperationStage, OpsCapabilityResponse,
    OpsRejectedResponse, OpsRequest, OpsRequestBody, OpsResponse, OpsResponseBody, Role,
    RollbackSupport, Subject, nginx_enabled_state_digest as enabled_state_digest, sha256_digest,
};
use serde::Serialize;

use crate::config::{OpsPaths, OpsPolicy};
use crate::digest::canonical_digest;
use crate::error::OpsError;
use crate::ledger::{Ledger, StoredOperation, StoredPlan, Transition};
use crate::nginx::{NGINX_IMPACT, NGINX_RECOVERY_PATH, NginxSite, discover_site, set_enabled};
use crate::runner::{CommandClass, CommandEvidence, OperationRunner};
use crate::snapshot::{NginxLinkSnapshot, read_nginx_snapshot, write_nginx_snapshot};

#[derive(Clone)]
pub struct OpsService {
    paths: OpsPaths,
    policy: OpsPolicy,
    runner: Arc<dyn OperationRunner>,
    forensic_lockdown: Arc<AtomicBool>,
    execution_lock: Arc<Mutex<()>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanRequestDigest<'a> {
    operation_type: &'a str,
    actor: &'a Subject,
    request: &'a NginxSiteStatePlanRequest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanHashMaterial<'a> {
    schema_version: u16,
    operation_type: &'a str,
    plan_id: &'a str,
    created_at_ms: i64,
    expires_at_ms: i64,
    actor: &'a Subject,
    site_id: &'a str,
    display_name: &'a str,
    current_state: NginxSiteState,
    target_state: NginxSiteState,
    available_digest: &'a str,
    enabled_state_digest: &'a str,
    resource_key: &'a str,
    impact: &'a [&'a str],
    recovery_path: &'a [&'a str],
    assurance: &'a AssuranceView,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandDigest<'a> {
    class: &'a str,
    success: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    stdout_digest: &'a str,
    stdout_truncated: bool,
    stderr_digest: &'a str,
    stderr_truncated: bool,
}

impl OpsService {
    #[must_use]
    pub fn new(paths: OpsPaths, policy: OpsPolicy, runner: Arc<dyn OperationRunner>) -> Self {
        Self {
            paths,
            policy,
            runner,
            forensic_lockdown: Arc::new(AtomicBool::new(false)),
            execution_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn initialize(&self, now_ms: i64) -> Result<(), OpsError> {
        let mut ledger = match Ledger::open(&self.paths) {
            Ok(ledger) => ledger,
            Err(OpsError::ForensicLockdown) => {
                self.forensic_lockdown.store(true, Ordering::SeqCst);
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        for operation in ledger.incomplete_operations()? {
            self.recover_operation(&mut ledger, operation, now_ms)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn response_for(&self, request: &OpsRequest, now_ms: i64) -> OpsResponse {
        let body = match request.validate(now_ms) {
            Ok(()) => match self.handle_body(&request.body, now_ms) {
                Ok(body) => body,
                Err(error) => OpsResponseBody::Rejected(OpsRejectedResponse {
                    code: error.code().to_owned(),
                }),
            },
            Err(code) => OpsResponseBody::Rejected(OpsRejectedResponse {
                code: code.to_owned(),
            }),
        };
        OpsResponse {
            protocol_version: jw_contracts::IPC_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            body,
        }
    }

    fn handle_body(&self, body: &OpsRequestBody, now_ms: i64) -> Result<OpsResponseBody, OpsError> {
        match body {
            OpsRequestBody::Capabilities => Ok(OpsResponseBody::Capabilities(self.capabilities())),
            OpsRequestBody::PlanNginxSiteState { actor, plan } => {
                self.require_write_available()?;
                require_operator(actor)?;
                self.plan_nginx(actor, plan, now_ms)
                    .map(OpsResponseBody::NginxSiteStatePlan)
            }
            OpsRequestBody::ApproveNginxSiteState {
                actor,
                plan_id,
                plan_hash,
                idempotency_key,
            } => {
                self.require_write_available()?;
                require_operator(actor)?;
                self.approve_nginx(actor, plan_id, plan_hash, idempotency_key, now_ms)
                    .map(OpsResponseBody::OperationReceipt)
            }
            OpsRequestBody::ExecuteOperation {
                actor,
                operation_id,
            } => {
                self.require_write_available()?;
                require_operator(actor)?;
                self.execute_operation(actor, operation_id, now_ms)
                    .map(OpsResponseBody::OperationReceipt)
            }
            OpsRequestBody::OperationReceipt {
                actor,
                operation_id,
            } => self
                .operation_receipt(actor, operation_id)
                .map(OpsResponseBody::OperationReceipt),
        }
    }

    fn capabilities(&self) -> OpsCapabilityResponse {
        let locked = self.forensic_lockdown.load(Ordering::SeqCst);
        if locked {
            return OpsCapabilityResponse {
                read_only: true,
                supported_operations: Vec::new(),
                forensic_lockdown: true,
            };
        }
        match Ledger::open(&self.paths) {
            Ok(_) if nginx_runtime_present(&self.paths) => OpsCapabilityResponse {
                read_only: false,
                supported_operations: vec![String::from(NGINX_SITE_STATE_OPERATION)],
                forensic_lockdown: false,
            },
            Ok(_) => OpsCapabilityResponse {
                read_only: true,
                supported_operations: Vec::new(),
                forensic_lockdown: false,
            },
            Err(OpsError::ForensicLockdown) => {
                self.forensic_lockdown.store(true, Ordering::SeqCst);
                OpsCapabilityResponse {
                    read_only: true,
                    supported_operations: Vec::new(),
                    forensic_lockdown: true,
                }
            }
            Err(_) => OpsCapabilityResponse {
                read_only: true,
                supported_operations: Vec::new(),
                forensic_lockdown: true,
            },
        }
    }

    fn require_write_available(&self) -> Result<(), OpsError> {
        if self.forensic_lockdown.load(Ordering::SeqCst) {
            Err(OpsError::ForensicLockdown)
        } else {
            Ok(())
        }
    }

    fn plan_nginx(
        &self,
        actor: &Subject,
        request: &NginxSiteStatePlanRequest,
        now_ms: i64,
    ) -> Result<jw_contracts::NginxSiteStatePlanView, OpsError> {
        request.validate().map_err(OpsError::Rejected)?;
        let site = discover_site(&self.paths, &request.site_id)?;
        if site.protected {
            return Err(OpsError::Rejected("protected_resource"));
        }
        if site.available_digest != request.expected_available_digest
            || site.enabled_state_digest != request.expected_enabled_state_digest
        {
            return Err(OpsError::Rejected("precondition_changed"));
        }
        let plan_id = random_id("plan")?;
        let ttl_ms = i64::try_from(self.policy.plan_ttl.as_millis())
            .map_err(|_| OpsError::Storage(String::from("plan ttl overflow")))?;
        let expires_at_ms = now_ms.saturating_add(ttl_ms);
        let assurance = nginx_assurance();
        let resource_key = format!("nginx/site/{}", site.site_id);
        let request_digest = canonical_digest(
            b"jw-agent/operation-request/v1",
            &PlanRequestDigest {
                operation_type: NGINX_SITE_STATE_OPERATION,
                actor,
                request,
            },
        )?;
        let mut plan = StoredPlan {
            plan_id,
            plan_hash: String::new(),
            actor: actor.clone(),
            site_id: site.site_id,
            display_name: site.basename,
            current_state: site.state,
            target_state: request.target_state,
            available_digest: site.available_digest,
            enabled_state_digest: site.enabled_state_digest,
            created_at_ms: now_ms,
            expires_at_ms,
            idempotency_key: request.idempotency_key.clone(),
            request_digest,
            resource_key,
            assurance,
        };
        plan.plan_hash = plan_hash(&plan)?;
        let mut ledger = self.open_ledger()?;
        let stored = ledger.create_or_reuse_plan(&plan)?;
        ledger.plan_view(&stored)
    }

    fn approve_nginx(
        &self,
        actor: &Subject,
        plan_id: &str,
        plan_hash: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let mut ledger = self.open_ledger()?;
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

    fn execute_operation(
        &self,
        actor: &Subject,
        operation_id: &str,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let _execution_guard = self
            .execution_lock
            .lock()
            .map_err(|_| OpsError::ForensicLockdown)?;
        let mut ledger = self.open_ledger()?;
        let operation = ledger.load_operation(operation_id)?;
        if operation.plan.actor != *actor {
            return Err(OpsError::Rejected("operation_access_denied"));
        }
        if operation.stage.is_terminal() || operation.stage != OperationStage::Approved {
            return ledger.receipt(&operation.operation_id);
        }
        let preflight = match self.validate_precondition(&operation) {
            Ok(site) => site,
            Err(error) => {
                let terminal = ledger.transition(
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
                return ledger.receipt(&terminal.operation_id);
            }
        };
        let snapshot = NginxLinkSnapshot {
            schema_version: 1,
            site_id: preflight.site_id.clone(),
            basename: preflight.basename.clone(),
            enabled: preflight.state == NginxSiteState::Enabled,
            available_digest: preflight.available_digest.clone(),
            enabled_state_digest: preflight.enabled_state_digest.clone(),
        };
        let record = match write_nginx_snapshot(
            &self.paths,
            &self.policy,
            &operation.operation_id,
            &snapshot,
        ) {
            Ok(record) => record,
            Err(error) => {
                let evidence = sha256_digest(error.code().as_bytes());
                let cancelled = ledger.transition(
                    &operation.operation_id,
                    Transition {
                        expected: &[OperationStage::Approved],
                        next: OperationStage::CancelledBeforeApply,
                        result_code: error.code(),
                        evidence_digest: &evidence,
                        after_digest: None,
                        rollback_result: None,
                        now_ms,
                    },
                )?;
                return ledger.receipt(&cancelled.operation_id);
            }
        };
        let snapshotted = ledger.attach_snapshot(&operation.operation_id, &record, now_ms)?;
        if snapshotted.plan.current_state == snapshotted.plan.target_state {
            return self.finish_noop(&mut ledger, &snapshotted, now_ms);
        }
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Snapshotted],
                next: OperationStage::Applying,
                result_code: "apply_started",
                evidence_digest: &preflight.enabled_state_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        if let Err(error) = set_enabled(
            &self.paths,
            &preflight,
            snapshotted.plan.target_state == NginxSiteState::Enabled,
        ) {
            let evidence = sha256_digest(error.code().as_bytes());
            return self.rollback(
                &mut ledger,
                &snapshotted.operation_id,
                error.code(),
                &evidence,
                now_ms,
            );
        }
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Applying],
                next: OperationStage::Validating,
                result_code: "link_applied",
                evidence_digest: &enabled_state_digest(
                    snapshotted.plan.target_state == NginxSiteState::Enabled,
                ),
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let config_test = match self.runner.run(CommandClass::NginxConfigTest) {
            Ok(evidence) => evidence,
            Err(error) => {
                let evidence = sha256_digest(error.code().as_bytes());
                return self.rollback(
                    &mut ledger,
                    &snapshotted.operation_id,
                    "nginx_config_test_unavailable",
                    &evidence,
                    now_ms,
                );
            }
        };
        let config_digest = command_digest(&config_test)?;
        if !config_test.success {
            return self.rollback(
                &mut ledger,
                &snapshotted.operation_id,
                "nginx_config_test_failed",
                &config_digest,
                now_ms,
            );
        }
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Validating],
                next: OperationStage::Reloading,
                result_code: "nginx_config_valid",
                evidence_digest: &config_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let reload = match self.runner.run(CommandClass::NginxReload) {
            Ok(evidence) => evidence,
            Err(error) => {
                let evidence = sha256_digest(error.code().as_bytes());
                return self.rollback(
                    &mut ledger,
                    &snapshotted.operation_id,
                    "nginx_reload_unavailable",
                    &evidence,
                    now_ms,
                );
            }
        };
        let reload_digest = command_digest(&reload)?;
        if !reload.success {
            return self.rollback(
                &mut ledger,
                &snapshotted.operation_id,
                "nginx_reload_failed",
                &reload_digest,
                now_ms,
            );
        }
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Reloading],
                next: OperationStage::Verifying,
                result_code: "nginx_reloaded",
                evidence_digest: &reload_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let after = match discover_site(&self.paths, &snapshotted.plan.site_id) {
            Ok(site) => site,
            Err(error) => {
                let evidence = sha256_digest(error.code().as_bytes());
                return self.rollback(
                    &mut ledger,
                    &snapshotted.operation_id,
                    "read_back_unavailable",
                    &evidence,
                    now_ms,
                );
            }
        };
        let active = match self.runner.run(CommandClass::NginxActive) {
            Ok(evidence) => evidence,
            Err(error) => {
                let evidence = sha256_digest(error.code().as_bytes());
                return self.rollback(
                    &mut ledger,
                    &snapshotted.operation_id,
                    "nginx_active_unavailable",
                    &evidence,
                    now_ms,
                );
            }
        };
        let active_digest = command_digest(&active)?;
        if after.state != snapshotted.plan.target_state
            || after.available_digest != snapshotted.plan.available_digest
            || !active.success
        {
            return self.rollback(
                &mut ledger,
                &snapshotted.operation_id,
                "read_back_failed",
                &active_digest,
                now_ms,
            );
        }
        let succeeded = ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Verifying],
                next: OperationStage::Succeeded,
                result_code: "verified",
                evidence_digest: &active_digest,
                after_digest: Some(&after.enabled_state_digest),
                rollback_result: None,
                now_ms,
            },
        )?;
        ledger.receipt(&succeeded.operation_id)
    }

    fn finish_noop(
        &self,
        ledger: &mut Ledger,
        operation: &StoredOperation,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Snapshotted],
                next: OperationStage::Verifying,
                result_code: "no_change_required",
                evidence_digest: &operation.plan.enabled_state_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let config = match self.runner.run(CommandClass::NginxConfigTest) {
            Ok(evidence) => evidence,
            Err(error) => {
                return self.cancel_noop(
                    ledger,
                    operation,
                    error.code(),
                    &sha256_digest(error.code().as_bytes()),
                    now_ms,
                );
            }
        };
        let active = match self.runner.run(CommandClass::NginxActive) {
            Ok(evidence) => evidence,
            Err(error) => {
                return self.cancel_noop(
                    ledger,
                    operation,
                    error.code(),
                    &sha256_digest(error.code().as_bytes()),
                    now_ms,
                );
            }
        };
        if !config.success || !active.success {
            return self.cancel_noop(
                ledger,
                operation,
                "preexisting_validation_failed",
                &command_digest(&active)?,
                now_ms,
            );
        }
        let succeeded = ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Verifying],
                next: OperationStage::Succeeded,
                result_code: "verified_noop",
                evidence_digest: &command_digest(&active)?,
                after_digest: Some(&operation.plan.enabled_state_digest),
                rollback_result: None,
                now_ms,
            },
        )?;
        ledger.receipt(&succeeded.operation_id)
    }

    fn cancel_noop(
        &self,
        ledger: &mut Ledger,
        operation: &StoredOperation,
        result_code: &str,
        evidence_digest: &str,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let cancelled = ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Verifying],
                next: OperationStage::CancelledBeforeApply,
                result_code,
                evidence_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        ledger.receipt(&cancelled.operation_id)
    }

    fn rollback(
        &self,
        ledger: &mut Ledger,
        operation_id: &str,
        cause: &str,
        cause_evidence_digest: &str,
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
            ledger.transition(
                operation_id,
                Transition {
                    expected: &expected,
                    next: OperationStage::RollingBack,
                    result_code: cause,
                    evidence_digest: cause_evidence_digest,
                    after_digest: None,
                    rollback_result: None,
                    now_ms,
                },
            )?
        };
        let Some(record) = &rolling.snapshot else {
            return self.recovery_required(ledger, operation_id, "snapshot_missing", now_ms);
        };
        let snapshot = match read_nginx_snapshot(&self.paths, record) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return self.recovery_required(ledger, operation_id, error.code(), now_ms);
            }
        };
        let current = match discover_site(&self.paths, &snapshot.site_id) {
            Ok(site) => site,
            Err(error) => {
                return self.recovery_required(ledger, operation_id, error.code(), now_ms);
            }
        };
        if set_enabled(&self.paths, &current, snapshot.enabled).is_err() {
            return self.recovery_required(ledger, operation_id, "rollback_link_failed", now_ms);
        }
        let config = match self.runner.run(CommandClass::NginxConfigTest) {
            Ok(evidence) => evidence,
            Err(error) => {
                return self.recovery_required(ledger, operation_id, error.code(), now_ms);
            }
        };
        let reload = if config.success {
            match self.runner.run(CommandClass::NginxReload) {
                Ok(evidence) => evidence,
                Err(error) => {
                    return self.recovery_required(ledger, operation_id, error.code(), now_ms);
                }
            }
        } else {
            failed_evidence(CommandClass::NginxReload)
        };
        let active = if reload.success {
            match self.runner.run(CommandClass::NginxActive) {
                Ok(evidence) => evidence,
                Err(error) => {
                    return self.recovery_required(ledger, operation_id, error.code(), now_ms);
                }
            }
        } else {
            failed_evidence(CommandClass::NginxActive)
        };
        let restored = discover_site(&self.paths, &snapshot.site_id);
        let verified = restored.as_ref().is_ok_and(|site| {
            site.available_digest == snapshot.available_digest
                && site.enabled_state_digest == snapshot.enabled_state_digest
        }) && config.success
            && reload.success
            && active.success;
        if !verified {
            return self.recovery_required(ledger, operation_id, "rollback_verify_failed", now_ms);
        }
        let terminal = ledger.transition(
            operation_id,
            Transition {
                expected: &[OperationStage::RollingBack],
                next: OperationStage::RolledBack,
                result_code: "rollback_verified",
                evidence_digest: &command_digest(&active)?,
                after_digest: Some(&snapshot.enabled_state_digest),
                rollback_result: Some("verified"),
                now_ms,
            },
        )?;
        ledger.receipt(&terminal.operation_id)
    }

    fn recovery_required(
        &self,
        ledger: &mut Ledger,
        operation_id: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let terminal = ledger.transition(
            operation_id,
            Transition {
                expected: &[OperationStage::RollingBack],
                next: OperationStage::RecoveryRequired,
                result_code: reason,
                evidence_digest: &sha256_digest(reason.as_bytes()),
                after_digest: None,
                rollback_result: Some("failed"),
                now_ms,
            },
        )?;
        ledger.receipt(&terminal.operation_id)
    }

    fn recover_operation(
        &self,
        ledger: &mut Ledger,
        operation: StoredOperation,
        now_ms: i64,
    ) -> Result<(), OpsError> {
        match operation.stage {
            OperationStage::Approved | OperationStage::Snapshotted => {
                let terminal = ledger.transition(
                    &operation.operation_id,
                    Transition {
                        expected: &[operation.stage],
                        next: OperationStage::CancelledBeforeApply,
                        result_code: "recovered_before_apply",
                        evidence_digest: &sha256_digest(b"recovered_before_apply"),
                        after_digest: None,
                        rollback_result: None,
                        now_ms,
                    },
                )?;
                if !terminal.stage.is_terminal() {
                    return Err(OpsError::ForensicLockdown);
                }
                Ok(())
            }
            OperationStage::Applying
            | OperationStage::Validating
            | OperationStage::Reloading
            | OperationStage::Verifying
            | OperationStage::RollingBack => self
                .rollback(
                    ledger,
                    &operation.operation_id,
                    "restart_recovery",
                    &sha256_digest(b"restart_recovery"),
                    now_ms,
                )
                .map(|_| ()),
            OperationStage::Planned => Err(OpsError::ForensicLockdown),
            OperationStage::Succeeded
            | OperationStage::RolledBack
            | OperationStage::RecoveryRequired
            | OperationStage::Rejected
            | OperationStage::Expired
            | OperationStage::CancelledBeforeApply => Ok(()),
        }
    }

    fn validate_precondition(&self, operation: &StoredOperation) -> Result<NginxSite, OpsError> {
        let site = discover_site(&self.paths, &operation.plan.site_id)?;
        if site.protected {
            return Err(OpsError::Rejected("protected_resource"));
        }
        if site.available_digest != operation.plan.available_digest
            || site.enabled_state_digest != operation.plan.enabled_state_digest
            || site.state != operation.plan.current_state
        {
            return Err(OpsError::Rejected("precondition_changed"));
        }
        Ok(site)
    }

    fn operation_receipt(
        &self,
        actor: &Subject,
        operation_id: &str,
    ) -> Result<OperationReceiptView, OpsError> {
        let ledger = self.open_ledger()?;
        let operation = ledger.load_operation(operation_id)?;
        if operation.plan.actor.uid != actor.uid {
            return Err(OpsError::Rejected("operation_access_denied"));
        }
        ledger.receipt(operation_id)
    }

    fn open_ledger(&self) -> Result<Ledger, OpsError> {
        match Ledger::open(&self.paths) {
            Ok(ledger) => Ok(ledger),
            Err(OpsError::ForensicLockdown) => {
                self.forensic_lockdown.store(true, Ordering::SeqCst);
                Err(OpsError::ForensicLockdown)
            }
            Err(error) => Err(error),
        }
    }
}

fn plan_hash(plan: &StoredPlan) -> Result<String, OpsError> {
    canonical_digest(
        b"jw-agent/operation-plan/v1",
        &PlanHashMaterial {
            schema_version: 1,
            operation_type: NGINX_SITE_STATE_OPERATION,
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
            impact: &NGINX_IMPACT,
            recovery_path: &NGINX_RECOVERY_PATH,
            assurance: &plan.assurance,
        },
    )
}

fn nginx_assurance() -> AssuranceView {
    AssuranceView {
        level: AssuranceLevel::G2ReversibleConfig,
        rollback_support: RollbackSupport::AutomaticBounded,
        operation_available: true,
        scope: vec![String::from("선택한 Nginx site의 enabled link 존재 상태")],
        excluded_effects: vec![
            String::from("sites-available 설정 내용"),
            String::from("기존 연결과 process history"),
            String::from("제품 밖 root 사용자의 동시 변경"),
        ],
        apply_verifier: vec![
            String::from("enabled link read-back"),
            String::from("nginx -t"),
            String::from("nginx.service active"),
        ],
        rollback_verifier: vec![
            String::from("이전 link 상태 복원"),
            String::from("nginx -t와 reload 후 active 확인"),
        ],
        reason: None,
    }
}

fn require_operator(actor: &Subject) -> Result<(), OpsError> {
    if matches!(actor.role, Role::Admin | Role::Operator) {
        Ok(())
    } else {
        Err(OpsError::Rejected("role_denied"))
    }
}

fn nginx_runtime_present(paths: &OpsPaths) -> bool {
    paths.nginx_available.is_dir()
        && paths.nginx_enabled.is_dir()
        && Path::new("/usr/sbin/nginx").is_file()
        && Path::new("/usr/bin/systemctl").is_file()
}

fn command_digest(evidence: &CommandEvidence) -> Result<String, OpsError> {
    canonical_digest(
        b"jw-agent/command-evidence/v1",
        &CommandDigest {
            class: evidence.class.as_str(),
            success: evidence.success,
            exit_code: evidence.exit_code,
            timed_out: evidence.timed_out,
            stdout_digest: &evidence.stdout.digest,
            stdout_truncated: evidence.stdout.truncated,
            stderr_digest: &evidence.stderr.digest,
            stderr_truncated: evidence.stderr.truncated,
        },
    )
}

fn failed_evidence(class: CommandClass) -> CommandEvidence {
    let empty = sha256_digest(b"");
    CommandEvidence {
        class,
        success: false,
        exit_code: None,
        timed_out: false,
        stdout: crate::runner::StreamEvidence {
            digest: empty.clone(),
            captured: Vec::new(),
            truncated: false,
        },
        stderr: crate::runner::StreamEvidence {
            digest: empty,
            captured: Vec::new(),
            truncated: false,
        },
    }
}

fn random_id(prefix: &str) -> Result<String, OpsError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| OpsError::Storage(error.to_string()))?;
    let mut value = String::with_capacity(prefix.len().saturating_add(33));
    value.push_str(prefix);
    value.push('_');
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::{Arc, Mutex};

    use jw_contracts::{
        IPC_PROTOCOL_VERSION, NGINX_LAYOUT_ID, NGINX_MANAGEMENT_MARKER, NGINX_SITE_STATE_OPERATION,
        NginxSiteState, NginxSiteStatePlanRequest, OpsRequest, OpsRequestBody, OpsResponseBody,
        Role, Subject, nginx_enabled_state_digest as enabled_state_digest,
        nginx_site_id as site_id, sha256_digest,
    };

    use crate::config::{OpsPaths, OpsPolicy};
    use crate::error::OpsError;
    use crate::runner::{CommandClass, CommandEvidence, OperationRunner, StreamEvidence};

    use super::OpsService;

    #[derive(Debug)]
    struct FakeRunner {
        results: Mutex<VecDeque<(CommandClass, bool)>>,
    }

    impl FakeRunner {
        fn all_success() -> Self {
            Self {
                results: Mutex::new(VecDeque::from([
                    (CommandClass::NginxConfigTest, true),
                    (CommandClass::NginxReload, true),
                    (CommandClass::NginxActive, true),
                ])),
            }
        }

        fn syntax_failure_then_rollback() -> Self {
            Self {
                results: Mutex::new(VecDeque::from([
                    (CommandClass::NginxConfigTest, false),
                    (CommandClass::NginxConfigTest, true),
                    (CommandClass::NginxReload, true),
                    (CommandClass::NginxActive, true),
                ])),
            }
        }

        fn reload_failure_then_rollback() -> Self {
            Self {
                results: Mutex::new(VecDeque::from([
                    (CommandClass::NginxConfigTest, true),
                    (CommandClass::NginxReload, false),
                    (CommandClass::NginxConfigTest, true),
                    (CommandClass::NginxReload, true),
                    (CommandClass::NginxActive, true),
                ])),
            }
        }

        fn syntax_and_rollback_validation_fail() -> Self {
            Self {
                results: Mutex::new(VecDeque::from([
                    (CommandClass::NginxConfigTest, false),
                    (CommandClass::NginxConfigTest, false),
                ])),
            }
        }

        fn noop_success() -> Self {
            Self {
                results: Mutex::new(VecDeque::from([
                    (CommandClass::NginxConfigTest, true),
                    (CommandClass::NginxActive, true),
                ])),
            }
        }
    }

    impl OperationRunner for FakeRunner {
        fn run(&self, class: CommandClass) -> Result<CommandEvidence, OpsError> {
            let mut results = self
                .results
                .lock()
                .map_err(|_| OpsError::Command(String::from("fake runner poisoned")))?;
            let Some((expected, success)) = results.pop_front() else {
                return Err(OpsError::Command(String::from("unexpected command")));
            };
            if expected != class {
                return Err(OpsError::Command(String::from("command order mismatch")));
            }
            let empty = sha256_digest(b"");
            Ok(CommandEvidence {
                class,
                success,
                exit_code: Some(if success { 0 } else { 1 }),
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
            })
        }
    }

    #[test]
    fn successful_enable_reaches_verified_terminal_receipt() -> Result<(), String> {
        let root = test_root("success")?;
        let service = fixture_service(&root, Arc::new(FakeRunner::all_success()))?;
        let plan = plan(&service, 1_000)?;
        let receipt = approve(&service, &plan, 1_001)?;
        assert_eq!(
            receipt.terminal_state,
            jw_contracts::OperationStage::Succeeded
        );
        assert_eq!(receipt.after_digest, enabled_state_digest(true));
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn syntax_failure_restores_previous_link_and_reports_rolled_back() -> Result<(), String> {
        let root = test_root("rollback")?;
        let service = fixture_service(&root, Arc::new(FakeRunner::syntax_failure_then_rollback()))?;
        let plan = plan(&service, 1_000)?;
        let receipt = approve(&service, &plan, 1_001)?;
        assert_eq!(
            receipt.terminal_state,
            jw_contracts::OperationStage::RolledBack
        );
        assert_eq!(receipt.after_digest, enabled_state_digest(false));
        let link = OpsPaths::for_test(&root).nginx_enabled.join("example.com");
        assert!(!link.exists());
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn reload_failure_restores_previous_link_and_reports_rolled_back() -> Result<(), String> {
        let root = test_root("reload-rollback")?;
        let service = fixture_service(&root, Arc::new(FakeRunner::reload_failure_then_rollback()))?;
        let plan = plan(&service, 1_000)?;
        let receipt = approve(&service, &plan, 1_001)?;
        assert_eq!(
            receipt.terminal_state,
            jw_contracts::OperationStage::RolledBack
        );
        assert_eq!(receipt.after_digest, enabled_state_digest(false));
        assert!(
            receipt
                .stages
                .iter()
                .any(|stage| stage.result_code == "nginx_reload_failed")
        );
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn rollback_validation_failure_requires_manual_recovery() -> Result<(), String> {
        let root = test_root("recovery-required")?;
        let service = fixture_service(
            &root,
            Arc::new(FakeRunner::syntax_and_rollback_validation_fail()),
        )?;
        let plan = plan(&service, 1_000)?;
        let receipt = approve(&service, &plan, 1_001)?;
        assert_eq!(
            receipt.terminal_state,
            jw_contracts::OperationStage::RecoveryRequired
        );
        assert_eq!(receipt.rollback_result.as_deref(), Some("failed"));
        assert!(!receipt.recovery_path.is_empty());
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn already_target_is_verified_without_reload() -> Result<(), String> {
        let root = test_root("noop")?;
        let service = fixture_service(&root, Arc::new(FakeRunner::noop_success()))?;
        let plan = plan_target(
            &service,
            1_000,
            NginxSiteState::Disabled,
            "noop-key-01234567",
        )?;
        let receipt = approve_with_key(&service, &plan, 1_001, "noop-key-01234567")?;
        assert_eq!(
            receipt.terminal_state,
            jw_contracts::OperationStage::Succeeded
        );
        assert!(
            receipt
                .stages
                .iter()
                .any(|stage| stage.result_code == "verified_noop")
        );
        assert!(
            !receipt
                .stages
                .iter()
                .any(|stage| stage.stage == jw_contracts::OperationStage::Reloading)
        );
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn duplicate_approval_reuses_terminal_operation() -> Result<(), String> {
        let root = test_root("duplicate-approval")?;
        let service = fixture_service(&root, Arc::new(FakeRunner::all_success()))?;
        let plan = plan(&service, 1_000)?;
        let first = approve(&service, &plan, 1_001)?;
        let second = approve(&service, &plan, 1_002)?;
        assert_eq!(first.operation_id, second.operation_id);
        assert_eq!(first.stages, second.stages);
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn snapshot_failure_cancels_before_apply_and_releases_locks() -> Result<(), String> {
        let root = test_root("snapshot-failure")?;
        let service = fixture_service(&root, Arc::new(FakeRunner::all_success()))?;
        let paths = OpsPaths::for_test(&root);
        fs::write(&paths.snapshots, b"not-a-directory").map_err(|error| error.to_string())?;
        let first_plan = plan(&service, 1_000)?;
        let first = approve(&service, &first_plan, 1_001)?;
        assert_eq!(
            first.terminal_state,
            jw_contracts::OperationStage::CancelledBeforeApply
        );
        let second_plan = plan_target(
            &service,
            1_002,
            NginxSiteState::Enabled,
            "second-key-012345",
        )?;
        let second = approve_with_key(&service, &second_plan, 1_003, "second-key-012345")?;
        assert_eq!(
            second.terminal_state,
            jw_contracts::OperationStage::CancelledBeforeApply
        );
        assert_ne!(first.operation_id, second.operation_id);
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn management_marker_blocks_plan_under_custom_basename() -> Result<(), String> {
        let root = test_root("protected-management")?;
        let service = fixture_service(&root, Arc::new(FakeRunner::all_success()))?;
        let paths = OpsPaths::for_test(&root);
        let mut content = Vec::from(b"# " as &[u8]);
        content.extend_from_slice(NGINX_MANAGEMENT_MARKER);
        content.extend_from_slice(b"\nserver {}\n");
        fs::write(paths.nginx_available.join("example.com"), &content)
            .map_err(|error| error.to_string())?;
        let request = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-protected-plan"),
            deadline_unix_ms: 2_000,
            body: OpsRequestBody::PlanNginxSiteState {
                actor: actor(),
                plan: NginxSiteStatePlanRequest {
                    schema_version: 1,
                    operation_type: String::from(NGINX_SITE_STATE_OPERATION),
                    site_id: site_id(NGINX_LAYOUT_ID, "example.com"),
                    target_state: NginxSiteState::Enabled,
                    expected_available_digest: sha256_digest(&content),
                    expected_enabled_state_digest: enabled_state_digest(false),
                    idempotency_key: String::from("protected-key-01"),
                },
            },
        };
        let response = service.response_for(&request, 1_000);
        let OpsResponseBody::Rejected(rejected) = response.body else {
            return Err(String::from("protected management plan was accepted"));
        };
        assert_eq!(rejected.code, "protected_resource");
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    fn fixture_service(
        root: &std::path::Path,
        runner: Arc<dyn OperationRunner>,
    ) -> Result<OpsService, String> {
        let paths = OpsPaths::for_test(root);
        fs::create_dir_all(&paths.nginx_available).map_err(|error| error.to_string())?;
        fs::create_dir_all(&paths.nginx_enabled).map_err(|error| error.to_string())?;
        fs::write(paths.nginx_available.join("example.com"), b"server {}\n")
            .map_err(|error| error.to_string())?;
        let service = OpsService::new(paths, OpsPolicy::default(), runner);
        service.initialize(900).map_err(|error| error.to_string())?;
        Ok(service)
    }

    fn plan(
        service: &OpsService,
        now_ms: i64,
    ) -> Result<jw_contracts::NginxSiteStatePlanView, String> {
        plan_target(service, now_ms, NginxSiteState::Enabled, "0123456789abcdef")
    }

    fn plan_target(
        service: &OpsService,
        now_ms: i64,
        target_state: NginxSiteState,
        idempotency_key: &str,
    ) -> Result<jw_contracts::NginxSiteStatePlanView, String> {
        let actor = actor();
        let request = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-plan"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::PlanNginxSiteState {
                actor,
                plan: NginxSiteStatePlanRequest {
                    schema_version: 1,
                    operation_type: String::from(NGINX_SITE_STATE_OPERATION),
                    site_id: site_id(NGINX_LAYOUT_ID, "example.com"),
                    target_state,
                    expected_available_digest: sha256_digest(b"server {}\n"),
                    expected_enabled_state_digest: enabled_state_digest(false),
                    idempotency_key: idempotency_key.to_owned(),
                },
            },
        };
        let response = service.response_for(&request, now_ms);
        let OpsResponseBody::NginxSiteStatePlan(plan) = response.body else {
            return Err(String::from("plan response rejected"));
        };
        Ok(plan)
    }

    fn approve(
        service: &OpsService,
        plan: &jw_contracts::NginxSiteStatePlanView,
        now_ms: i64,
    ) -> Result<jw_contracts::OperationReceiptView, String> {
        approve_with_key(service, plan, now_ms, "0123456789abcdef")
    }

    fn approve_with_key(
        service: &OpsService,
        plan: &jw_contracts::NginxSiteStatePlanView,
        now_ms: i64,
        idempotency_key: &str,
    ) -> Result<jw_contracts::OperationReceiptView, String> {
        let request = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-approve"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::ApproveNginxSiteState {
                actor: actor(),
                plan_id: plan.plan_id.clone(),
                plan_hash: plan.plan_hash.clone(),
                idempotency_key: idempotency_key.to_owned(),
            },
        };
        let response = service.response_for(&request, now_ms);
        let OpsResponseBody::OperationReceipt(accepted) = response.body else {
            return Err(String::from("approval response rejected"));
        };
        let execute = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-execute"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::ExecuteOperation {
                actor: actor(),
                operation_id: accepted.operation_id,
            },
        };
        let response = service.response_for(&execute, now_ms);
        let OpsResponseBody::OperationReceipt(receipt) = response.body else {
            return Err(String::from("execution response rejected"));
        };
        Ok(receipt)
    }

    fn actor() -> Subject {
        Subject {
            uid: 1_000,
            username: String::from("operator"),
            role: Role::Admin,
        }
    }

    fn test_root(label: &str) -> Result<std::path::PathBuf, String> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|error| error.to_string())?;
        Ok(std::env::temp_dir().join(format!(
            "jw-opsd-engine-{label}-{}-{}",
            std::process::id(),
            u64::from_le_bytes(random)
        )))
    }
}
