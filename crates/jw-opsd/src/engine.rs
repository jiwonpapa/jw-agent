use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use jw_contracts::{
    AssuranceLevel, AssuranceView, CERTBOT_ATTACH_OPERATION, CERTBOT_ISSUE_OPERATION,
    CERTBOT_RENEW_TEST_OPERATION, CertbotAttachPlanRequest, CertbotAttachPlanView, CertbotCommand,
    CertbotCommandEvidence, CertbotIssuePlanInput, CertbotIssuePlanView,
    CertbotRenewTestPlanRequest, CertbotRenewTestPlanView, CertificateEnvironment,
    CertificateInventoryView, MANAGED_CONFIG_OPERATION, MANAGED_CONFIG_RESTORE_OPERATION,
    ManagedConfigApprovalIntent, ManagedConfigPlanRequest, ManagedConfigPlanView,
    ManagedConfigResourceView, ManagedConfigRestorePlanRequest, NGINX_SITE_STATE_OPERATION,
    NginxSiteState, NginxSiteStatePlanRequest, OperationReceiptView, OperationStage,
    OpsCapabilityResponse, OpsRejectedResponse, OpsRequest, OpsRequestBody, OpsResponse,
    OpsResponseBody, Role, RollbackSupport, SERVICE_CONTROL_OPERATION, Subject,
    nginx_enabled_state_digest as enabled_state_digest, sha256_digest,
};
use serde::Serialize;

use crate::certbot_runner::{CertbotRunner, UdsCertbotRunner};
use crate::certificate::{
    CertbotAttachPlanPayload, CertbotIssuePlanPayload, CertbotRenewPlanPayload, attach_assurance,
    certificate_inventory, issue_assurance, mask_account_email, prepare_tls_attachment,
    renew_test_assurance, validate_issue_preconditions, validate_issue_site,
};
use crate::config::{OpsPaths, OpsPolicy};
use crate::digest::canonical_digest;
use crate::error::OpsError;
use crate::ledger::{Ledger, StoredOperation, StoredPlan, Transition};
use crate::managed_config::{
    ManagedConfigAdapter, ManagedConfigPlanPayload, ProposalRecord, cleanup_internal_temporaries,
    diff_stats, discover_managed_config, discover_protected_config, managed_config_adapter,
    managed_config_assurance, managed_config_failure_code, managed_config_test_succeeded,
    read_proposal, remove_proposal, replace_managed_config, replace_protected_config,
    restore_managed_config, restore_protected_config, validate_managed_config_candidate,
    write_proposal,
};
use crate::nginx::{NGINX_IMPACT, NGINX_RECOVERY_PATH, NginxSite, discover_site, set_enabled};
use crate::runner::{CommandClass, CommandEvidence, OperationRunner};
use crate::snapshot::{
    CertificateInventorySnapshot, ManagedConfigSnapshot, NginxLinkSnapshot,
    read_certificate_inventory_snapshot, read_managed_config_snapshot, read_nginx_snapshot,
    write_certificate_inventory_snapshot, write_managed_config_snapshot, write_nginx_snapshot,
};

mod managed_config_plan;
mod service_operation;

const CERTBOT_STAGING_EVIDENCE_TTL_MS: i64 = 24 * 60 * 60 * 1_000;

#[derive(Clone)]
pub struct OpsService {
    paths: OpsPaths,
    policy: OpsPolicy,
    runner: Arc<dyn OperationRunner>,
    certbot_runner: Arc<dyn CertbotRunner>,
    forensic_lockdown: Arc<AtomicBool>,
    request_lock: Arc<Mutex<()>>,
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
struct ManagedPlanRequestDigest<'a> {
    operation_type: &'a str,
    actor: &'a Subject,
    request: &'a ManagedConfigPlanRequest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedRestorePlanRequestDigest<'a> {
    operation_type: &'a str,
    actor: &'a Subject,
    request: &'a ManagedConfigRestorePlanRequest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertbotRenewPlanRequestDigest<'a> {
    operation_type: &'a str,
    actor: &'a Subject,
    request: &'a CertbotRenewTestPlanRequest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertbotIssuePlanRequestDigest<'a> {
    operation_type: &'a str,
    actor: &'a Subject,
    request: &'a CertbotIssuePlanInput,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertbotAttachPlanRequestDigest<'a> {
    operation_type: &'a str,
    actor: &'a Subject,
    request: &'a CertbotAttachPlanRequest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertbotStagingEvidenceMaterial<'a> {
    domains: &'a [String],
    site_digest: &'a str,
    resolved_addresses: &'a [String],
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
struct ManagedPlanHashMaterial<'a> {
    schema_version: u16,
    operation_type: &'a str,
    plan_id: &'a str,
    created_at_ms: i64,
    expires_at_ms: i64,
    actor: &'a Subject,
    resource_id: &'a str,
    display_name: &'a str,
    current_content_digest: &'a str,
    metadata_digest: &'a str,
    proposed_content_digest: &'a str,
    service_action: &'a str,
    current_bytes: u32,
    proposed_bytes: u32,
    added_lines: u32,
    removed_lines: u32,
    diff_summary: &'a [String],
    resource_key: &'a str,
    impact: &'a [&'a str],
    recovery_path: &'a [&'a str],
    assurance: &'a AssuranceView,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertbotRenewPlanHashMaterial<'a> {
    schema_version: u16,
    operation_type: &'a str,
    plan_id: &'a str,
    created_at_ms: i64,
    expires_at_ms: i64,
    actor: &'a Subject,
    inventory_digest: &'a str,
    timer_enabled: bool,
    timer_active: bool,
    certificate_count: u32,
    resource_key: &'a str,
    assurance: &'a AssuranceView,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertbotIssuePlanHashMaterial<'a> {
    schema_version: u16,
    operation_type: &'a str,
    plan_id: &'a str,
    created_at_ms: i64,
    expires_at_ms: i64,
    actor: &'a Subject,
    primary_domain: &'a str,
    domains: &'a [String],
    account_email_digest: &'a str,
    masked_account_email: &'a str,
    environment: CertificateEnvironment,
    site_id: &'a str,
    site_digest: &'a str,
    inventory_digest: &'a str,
    preflight_observed_at_ms: i64,
    resolved_addresses: &'a [String],
    local_port_80_reachable: bool,
    local_port_443_reachable: bool,
    staging_evidence_valid: bool,
    staging_evidence_key: &'a str,
    resource_key: &'a str,
    assurance: &'a AssuranceView,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertbotAttachPlanHashMaterial<'a> {
    schema_version: u16,
    operation_type: &'a str,
    plan_id: &'a str,
    created_at_ms: i64,
    expires_at_ms: i64,
    actor: &'a Subject,
    primary_domain: &'a str,
    site_id: &'a str,
    site_digest: &'a str,
    metadata_digest: &'a str,
    inventory_digest: &'a str,
    certificate_fingerprint: &'a str,
    sans: &'a [String],
    not_after: &'a str,
    current_certificate_path: &'a str,
    target_certificate_path: &'a str,
    proposed_content_digest: &'a str,
    timer_enabled: bool,
    timer_active: bool,
    resource_key: &'a str,
    assurance: &'a AssuranceView,
}

struct CertbotIssueApprovalInput<'a> {
    plan_id: &'a str,
    plan_hash: &'a str,
    idempotency_key: &'a str,
    external_effect_confirmed: bool,
    local_attach_deferred_confirmed: bool,
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
        Self::new_with_certbot_runner(paths, policy, runner, Arc::new(UdsCertbotRunner::default()))
    }

    #[must_use]
    pub fn new_with_certbot_runner(
        paths: OpsPaths,
        policy: OpsPolicy,
        runner: Arc<dyn OperationRunner>,
        certbot_runner: Arc<dyn CertbotRunner>,
    ) -> Self {
        Self {
            paths,
            policy,
            runner,
            certbot_runner,
            forensic_lockdown: Arc::new(AtomicBool::new(false)),
            request_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn initialize(&self, now_ms: i64) -> Result<(), OpsError> {
        cleanup_internal_temporaries(&self.paths)?;
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
        self.remove_expired_proposals(&ledger, now_ms)?;
        Ok(())
    }

    #[must_use]
    pub fn response_for(&self, request: &OpsRequest, now_ms: i64) -> OpsResponse {
        let body = match self.request_lock.lock() {
            Ok(_guard) => match request.validate(now_ms) {
                Ok(()) => match self.handle_body(&request.body, now_ms) {
                    Ok(body) => body,
                    Err(error) => OpsResponseBody::Rejected(OpsRejectedResponse {
                        code: error.code().to_owned(),
                    }),
                },
                Err(code) => OpsResponseBody::Rejected(OpsRejectedResponse {
                    code: code.to_owned(),
                }),
            },
            Err(_) => OpsResponseBody::Rejected(OpsRejectedResponse {
                code: String::from("forensic_lockdown"),
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
            OpsRequestBody::CertificateInventory { .. } => self
                .certificate_inventory(now_ms)
                .map(OpsResponseBody::CertificateInventory),
            OpsRequestBody::PlanCertbotIssue { actor, plan } => {
                self.require_write_available()?;
                require_operator(actor)?;
                self.plan_certbot_issue(actor, plan, now_ms)
                    .map(OpsResponseBody::CertbotIssuePlan)
            }
            OpsRequestBody::ApproveCertbotIssue {
                actor,
                plan_id,
                plan_hash,
                idempotency_key,
                external_effect_confirmed,
                local_attach_deferred_confirmed,
            } => {
                self.require_write_available()?;
                require_operator(actor)?;
                self.approve_certbot_issue(
                    actor,
                    CertbotIssueApprovalInput {
                        plan_id,
                        plan_hash,
                        idempotency_key,
                        external_effect_confirmed: *external_effect_confirmed,
                        local_attach_deferred_confirmed: *local_attach_deferred_confirmed,
                    },
                    now_ms,
                )
                .map(OpsResponseBody::OperationReceipt)
            }
            OpsRequestBody::PlanCertbotRenewTest { actor, plan } => {
                self.require_write_available()?;
                require_operator(actor)?;
                self.plan_certbot_renew_test(actor, plan, now_ms)
                    .map(OpsResponseBody::CertbotRenewTestPlan)
            }
            OpsRequestBody::ApproveCertbotRenewTest {
                actor,
                plan_id,
                plan_hash,
                idempotency_key,
                external_effect_confirmed,
            } => {
                self.require_write_available()?;
                require_operator(actor)?;
                self.approve_certbot_renew_test(
                    actor,
                    plan_id,
                    plan_hash,
                    idempotency_key,
                    *external_effect_confirmed,
                    now_ms,
                )
                .map(OpsResponseBody::OperationReceipt)
            }
            OpsRequestBody::PlanCertbotAttach { actor, plan } => {
                self.require_write_available()?;
                require_operator(actor)?;
                self.plan_certbot_attach(actor, plan, now_ms)
                    .map(OpsResponseBody::CertbotAttachPlan)
            }
            OpsRequestBody::ApproveCertbotAttach {
                actor,
                plan_id,
                plan_hash,
                idempotency_key,
                config_replace_confirmed,
                service_reload_confirmed,
            } => {
                self.require_write_available()?;
                require_operator(actor)?;
                self.approve_certbot_attach(
                    actor,
                    plan_id,
                    plan_hash,
                    idempotency_key,
                    *config_replace_confirmed,
                    *service_reload_confirmed,
                    now_ms,
                )
                .map(OpsResponseBody::OperationReceipt)
            }
            OpsRequestBody::ReadManagedConfig { actor, resource_id } => {
                require_operator(actor)?;
                self.read_managed_config(resource_id)
                    .map(OpsResponseBody::ManagedConfigResource)
            }
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
            OpsRequestBody::PlanManagedConfig { actor, plan } => {
                self.require_write_available()?;
                require_operator(actor)?;
                self.plan_managed_config(actor, plan, now_ms)
                    .map(OpsResponseBody::ManagedConfigPlan)
            }
            OpsRequestBody::PlanManagedConfigRestore { actor, plan } => {
                self.require_write_available()?;
                require_operator(actor)?;
                self.plan_managed_config_restore(actor, plan, now_ms)
                    .map(OpsResponseBody::ManagedConfigPlan)
            }
            OpsRequestBody::ApproveManagedConfig {
                actor,
                plan_id,
                plan_hash,
                idempotency_key,
                approval_intent,
            } => {
                self.require_write_available()?;
                require_operator(actor)?;
                self.approve_managed_config(
                    actor,
                    plan_id,
                    plan_hash,
                    idempotency_key,
                    approval_intent,
                    now_ms,
                )
                .map(OpsResponseBody::OperationReceipt)
            }
            OpsRequestBody::PlanServiceControl { actor, plan } => {
                self.require_write_available()?;
                require_operator(actor)?;
                self.plan_service_control(actor, plan, now_ms)
                    .map(OpsResponseBody::ServiceControlPlan)
            }
            OpsRequestBody::ApproveServiceControl {
                actor,
                plan_id,
                plan_hash,
                idempotency_key,
                impact_confirmed,
            } => {
                self.require_write_available()?;
                require_operator(actor)?;
                if !impact_confirmed {
                    return Err(OpsError::Rejected("impact_confirmation"));
                }
                self.approve_service_control(actor, plan_id, plan_hash, idempotency_key, now_ms)
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
            OpsRequestBody::RecentOperations { actor } => self
                .open_ledger()?
                .recent_receipts(actor.uid, 8)
                .map(OpsResponseBody::RecentOperations),
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
                supported_operations: vec![
                    String::from(NGINX_SITE_STATE_OPERATION),
                    String::from(MANAGED_CONFIG_OPERATION),
                    String::from(CERTBOT_ISSUE_OPERATION),
                    String::from(CERTBOT_RENEW_TEST_OPERATION),
                    String::from(CERTBOT_ATTACH_OPERATION),
                    String::from(SERVICE_CONTROL_OPERATION),
                ],
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

    fn read_managed_config(
        &self,
        resource_id: &str,
    ) -> Result<ManagedConfigResourceView, OpsError> {
        let resource = discover_managed_config(&self.paths, resource_id)?;
        let assurance = managed_config_assurance(resource.adapter);
        resource.view(assurance)
    }

    fn certificate_inventory(&self, now_ms: i64) -> Result<CertificateInventoryView, OpsError> {
        let mut inventory = certificate_inventory(&self.paths, self.runner.as_ref(), now_ms)?;
        if inventory.certbot_installed
            && !self.forensic_lockdown.load(Ordering::SeqCst)
            && Ledger::open(&self.paths).is_ok()
        {
            inventory.issue_operation_type = Some(String::from(CERTBOT_ISSUE_OPERATION));
            inventory.renew_test_operation_type = Some(String::from(CERTBOT_RENEW_TEST_OPERATION));
            inventory.attach_operation_type = Some(String::from(CERTBOT_ATTACH_OPERATION));
            inventory.assurance.reason = Some(String::from(
                "목록은 G0 조회 전용이며 발급·갱신 G1과 Nginx 연결 G2는 각각 별도 계획·재인증을 요구합니다.",
            ));
        }
        Ok(inventory)
    }

    fn plan_certbot_issue(
        &self,
        actor: &Subject,
        input: &CertbotIssuePlanInput,
        now_ms: i64,
    ) -> Result<CertbotIssuePlanView, OpsError> {
        let ledger = self.open_ledger()?;
        self.remove_expired_proposals(&ledger, now_ms)?;
        drop(ledger);
        let site = validate_issue_preconditions(&self.paths, input, now_ms)?;
        let inventory = self.certificate_inventory(now_ms)?;
        if !inventory.certbot_installed {
            return Err(OpsError::Rejected("unsupported_environment"));
        }
        if inventory.inventory_digest != input.request.expected_inventory_digest {
            return Err(OpsError::Rejected("stale_inventory"));
        }
        let nginx_test = self.runner.run(CommandClass::NginxConfigTest)?;
        let nginx_active = self.runner.run(CommandClass::NginxActive)?;
        if !nginx_test.success || !nginx_active.success {
            return Err(OpsError::Rejected("unsupported_environment"));
        }
        let domains = input.request.domains();
        let staging_evidence_key = canonical_digest(
            b"jw-agent/certbot-staging-evidence/v1",
            &CertbotStagingEvidenceMaterial {
                domains: &domains,
                site_digest: &site.available_digest,
                resolved_addresses: &input.preflight.resolved_addresses,
            },
        )?;
        let staging_evidence_valid = self.open_ledger()?.has_recent_staging_evidence(
            &staging_evidence_key,
            now_ms.saturating_sub(CERTBOT_STAGING_EVIDENCE_TTL_MS),
        )?;
        if input.request.environment == CertificateEnvironment::Production
            && !staging_evidence_valid
        {
            return Err(OpsError::Rejected("staging_required"));
        }
        let ttl_ms = i64::try_from(self.policy.plan_ttl.as_millis())
            .map_err(|_| OpsError::Storage(String::from("plan ttl overflow")))?;
        let plan_id = random_id("plan")?;
        let created_plan_id = plan_id.clone();
        let account_email_proposal = write_proposal(
            &self.paths,
            &self.policy,
            &plan_id,
            &input.request.account_email,
        )?;
        let request_digest = canonical_digest(
            b"jw-agent/operation-request/v1",
            &CertbotIssuePlanRequestDigest {
                operation_type: CERTBOT_ISSUE_OPERATION,
                actor,
                request: input,
            },
        )?;
        let payload = CertbotIssuePlanPayload {
            primary_domain: input.request.primary_domain.clone(),
            domains,
            account_email_proposal_relative_path: account_email_proposal.relative_path.clone(),
            account_email_proposal_digest: account_email_proposal.digest.clone(),
            masked_account_email: mask_account_email(&input.request.account_email),
            environment: input.request.environment,
            site_id: site.site_id.clone(),
            site_digest: site.available_digest.clone(),
            inventory_digest: inventory.inventory_digest.clone(),
            preflight_observed_at_ms: input.preflight.observed_at_unix_ms,
            resolved_addresses: input.preflight.resolved_addresses.clone(),
            local_port_80_reachable: input.preflight.local_port_80_reachable,
            local_port_443_reachable: input.preflight.local_port_443_reachable,
            staging_evidence_valid,
            staging_evidence_key,
        };
        let mut plan = StoredPlan {
            operation_type: String::from(CERTBOT_ISSUE_OPERATION),
            plan_id,
            plan_hash: String::new(),
            actor: actor.clone(),
            site_id: site.site_id,
            display_name: input.request.primary_domain.clone(),
            current_state: NginxSiteState::Disabled,
            target_state: NginxSiteState::Disabled,
            available_digest: inventory.inventory_digest.clone(),
            enabled_state_digest: inventory.inventory_digest,
            created_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
            idempotency_key: input.request.idempotency_key.clone(),
            request_digest,
            resource_key: String::from("certbot/global"),
            assurance: issue_assurance(),
            managed_config: None,
            certbot_renew: None,
            certbot_issue: Some(payload),
            certbot_attach: None,
        };
        plan.plan_hash = certbot_issue_plan_hash(&plan)?;
        let result = (|| {
            let mut ledger = self.open_ledger()?;
            let stored = ledger.create_or_reuse_plan(&plan)?;
            let view = ledger.certbot_issue_plan_view(&stored)?;
            Ok((stored.plan_id, view))
        })();
        match result {
            Ok((stored_plan_id, view)) => {
                if stored_plan_id != created_plan_id {
                    let _cleanup = remove_proposal(&self.paths, &account_email_proposal);
                }
                Ok(view)
            }
            Err(error) => {
                let _cleanup = remove_proposal(&self.paths, &account_email_proposal);
                Err(error)
            }
        }
    }

    fn approve_certbot_issue(
        &self,
        actor: &Subject,
        approval: CertbotIssueApprovalInput<'_>,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        if !approval.external_effect_confirmed {
            return Err(OpsError::Rejected("external_effect_confirmation"));
        }
        if !approval.local_attach_deferred_confirmed {
            return Err(OpsError::Rejected("local_attach_deferred_confirmation"));
        }
        let mut ledger = self.open_ledger()?;
        let plan = ledger.load_plan(approval.plan_id)?;
        if plan.operation_type != CERTBOT_ISSUE_OPERATION {
            return Err(OpsError::Rejected("approval_mismatch"));
        }
        let payload = plan
            .certbot_issue
            .as_ref()
            .ok_or(OpsError::ForensicLockdown)?;
        if now_ms.saturating_sub(payload.preflight_observed_at_ms) > 60_000 {
            return Err(OpsError::Rejected("preflight_stale"));
        }
        let operation_id = random_id("op")?;
        let operation = ledger.begin_operation(
            &operation_id,
            approval.plan_id,
            approval.plan_hash,
            approval.idempotency_key,
            actor,
            now_ms,
        )?;
        ledger.receipt(&operation.operation_id)
    }

    fn plan_certbot_renew_test(
        &self,
        actor: &Subject,
        request: &CertbotRenewTestPlanRequest,
        now_ms: i64,
    ) -> Result<CertbotRenewTestPlanView, OpsError> {
        request.validate().map_err(OpsError::Rejected)?;
        let inventory = self.certificate_inventory(now_ms)?;
        if !inventory.certbot_installed {
            return Err(OpsError::Rejected("unsupported_environment"));
        }
        if inventory.inventory_digest != request.expected_inventory_digest {
            return Err(OpsError::Rejected("stale_inventory"));
        }
        let certificate_count = u32::try_from(inventory.certificates.len())
            .map_err(|_| OpsError::Rejected("certificate_inventory_too_large"))?;
        let ttl_ms = i64::try_from(self.policy.plan_ttl.as_millis())
            .map_err(|_| OpsError::Storage(String::from("plan ttl overflow")))?;
        let plan_id = random_id("plan")?;
        let request_digest = canonical_digest(
            b"jw-agent/operation-request/v1",
            &CertbotRenewPlanRequestDigest {
                operation_type: CERTBOT_RENEW_TEST_OPERATION,
                actor,
                request,
            },
        )?;
        let payload = CertbotRenewPlanPayload {
            inventory_digest: inventory.inventory_digest.clone(),
            timer_enabled: inventory.timer_enabled,
            timer_active: inventory.timer_active,
            certificate_count,
        };
        let mut plan = StoredPlan {
            operation_type: String::from(CERTBOT_RENEW_TEST_OPERATION),
            plan_id,
            plan_hash: String::new(),
            actor: actor.clone(),
            site_id: String::from("certbot-renewal"),
            display_name: String::from("Certbot 갱신 사전 검증"),
            current_state: NginxSiteState::Disabled,
            target_state: NginxSiteState::Disabled,
            available_digest: inventory.inventory_digest.clone(),
            enabled_state_digest: inventory.inventory_digest,
            created_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
            idempotency_key: request.idempotency_key.clone(),
            request_digest,
            resource_key: String::from("certbot/global"),
            assurance: renew_test_assurance(),
            managed_config: None,
            certbot_renew: Some(payload),
            certbot_issue: None,
            certbot_attach: None,
        };
        plan.plan_hash = certbot_renew_plan_hash(&plan)?;
        let mut ledger = self.open_ledger()?;
        let stored = ledger.create_or_reuse_plan(&plan)?;
        ledger.certbot_renew_plan_view(&stored)
    }

    fn approve_certbot_renew_test(
        &self,
        actor: &Subject,
        plan_id: &str,
        plan_hash: &str,
        idempotency_key: &str,
        external_effect_confirmed: bool,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        if !external_effect_confirmed {
            return Err(OpsError::Rejected("external_effect_confirmation"));
        }
        let mut ledger = self.open_ledger()?;
        let plan = ledger.load_plan(plan_id)?;
        if plan.operation_type != CERTBOT_RENEW_TEST_OPERATION {
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

    fn plan_certbot_attach(
        &self,
        actor: &Subject,
        request: &CertbotAttachPlanRequest,
        now_ms: i64,
    ) -> Result<CertbotAttachPlanView, OpsError> {
        request.validate().map_err(OpsError::Rejected)?;
        let inventory = self.certificate_inventory(now_ms)?;
        if inventory.inventory_digest != request.expected_inventory_digest {
            return Err(OpsError::Rejected("stale_inventory"));
        }
        if !inventory.certbot_installed || !inventory.timer_enabled || !inventory.timer_active {
            return Err(OpsError::Rejected("unsupported_environment"));
        }
        let certificate = inventory
            .certificates
            .iter()
            .find(|certificate| certificate.primary_domain == request.primary_domain)
            .ok_or(OpsError::Rejected("certificate_invalid"))?;
        if certificate.fingerprint_sha256 != request.expected_certificate_fingerprint
            || !certificate.private_key_present
            || !certificate.renewal_config_present
            || !certificate.webroot_managed
            || !certificate
                .sans
                .iter()
                .any(|domain| domain == &request.primary_domain)
        {
            return Err(OpsError::Rejected("certificate_invalid"));
        }
        let attachment = prepare_tls_attachment(
            &self.paths,
            &request.primary_domain,
            &request.site_id,
            &request.expected_site_digest,
        )?;
        let nginx_test = self.runner.run(CommandClass::NginxConfigTest)?;
        let nginx_active = self.runner.run(CommandClass::NginxActive)?;
        if !nginx_test.success || !nginx_active.success {
            return Err(OpsError::Rejected("unsupported_environment"));
        }
        let ttl_ms = i64::try_from(self.policy.plan_ttl.as_millis())
            .map_err(|_| OpsError::Storage(String::from("plan ttl overflow")))?;
        let plan_id = random_id("plan")?;
        let request_digest = canonical_digest(
            b"jw-agent/operation-request/v1",
            &CertbotAttachPlanRequestDigest {
                operation_type: CERTBOT_ATTACH_OPERATION,
                actor,
                request,
            },
        )?;
        let payload = CertbotAttachPlanPayload {
            primary_domain: request.primary_domain.clone(),
            site_id: request.site_id.clone(),
            site_digest: attachment.config.content_digest.clone(),
            metadata_digest: attachment.config.metadata_digest.clone(),
            inventory_digest: inventory.inventory_digest.clone(),
            certificate_fingerprint: certificate.fingerprint_sha256.clone(),
            sans: certificate.sans.clone(),
            not_after: certificate.not_after.clone(),
            current_certificate_path: attachment.current_certificate_path,
            target_certificate_path: attachment.target_certificate_path,
            proposed_content_digest: attachment.proposed_content_digest,
            timer_enabled: inventory.timer_enabled,
            timer_active: inventory.timer_active,
        };
        let mut plan = StoredPlan {
            operation_type: String::from(CERTBOT_ATTACH_OPERATION),
            plan_id,
            plan_hash: String::new(),
            actor: actor.clone(),
            site_id: request.site_id.clone(),
            display_name: request.primary_domain.clone(),
            current_state: NginxSiteState::Enabled,
            target_state: NginxSiteState::Enabled,
            available_digest: attachment.config.content_digest,
            enabled_state_digest: attachment.config.metadata_digest,
            created_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
            idempotency_key: request.idempotency_key.clone(),
            request_digest,
            resource_key: String::from("certbot/global"),
            assurance: attach_assurance(),
            managed_config: None,
            certbot_renew: None,
            certbot_issue: None,
            certbot_attach: Some(payload),
        };
        plan.plan_hash = certbot_attach_plan_hash(&plan)?;
        let mut ledger = self.open_ledger()?;
        let stored = ledger.create_or_reuse_plan(&plan)?;
        ledger.certbot_attach_plan_view(&stored)
    }

    #[allow(clippy::too_many_arguments)]
    fn approve_certbot_attach(
        &self,
        actor: &Subject,
        plan_id: &str,
        plan_hash: &str,
        idempotency_key: &str,
        config_replace_confirmed: bool,
        service_reload_confirmed: bool,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        if !config_replace_confirmed {
            return Err(OpsError::Rejected("config_replace_confirmation"));
        }
        if !service_reload_confirmed {
            return Err(OpsError::Rejected("service_reload_confirmation"));
        }
        let mut ledger = self.open_ledger()?;
        let plan = ledger.load_plan(plan_id)?;
        if plan.operation_type != CERTBOT_ATTACH_OPERATION {
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
            operation_type: String::from(NGINX_SITE_STATE_OPERATION),
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
            managed_config: None,
            certbot_renew: None,
            certbot_issue: None,
            certbot_attach: None,
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
        let plan = ledger.load_plan(plan_id)?;
        if plan.operation_type != NGINX_SITE_STATE_OPERATION {
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

    fn execute_operation(
        &self,
        actor: &Subject,
        operation_id: &str,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let mut ledger = self.open_ledger()?;
        let operation = ledger.load_operation(operation_id)?;
        if operation.plan.actor != *actor {
            return Err(OpsError::Rejected("operation_access_denied"));
        }
        if operation.stage.is_terminal() || operation.stage != OperationStage::Approved {
            return ledger.receipt(&operation.operation_id);
        }
        if operation.plan.operation_type == CERTBOT_ISSUE_OPERATION {
            return self.execute_certbot_issue(&mut ledger, operation, now_ms);
        }
        if operation.plan.operation_type == CERTBOT_RENEW_TEST_OPERATION {
            return self.execute_certbot_renew_test(&mut ledger, operation, now_ms);
        }
        if operation.plan.operation_type == CERTBOT_ATTACH_OPERATION {
            return self.execute_certbot_attach(&mut ledger, operation, now_ms);
        }
        if operation.plan.operation_type == MANAGED_CONFIG_OPERATION
            || operation.plan.operation_type == MANAGED_CONFIG_RESTORE_OPERATION
        {
            return self.execute_managed_config(&mut ledger, operation, now_ms);
        }
        if operation.plan.operation_type == SERVICE_CONTROL_OPERATION {
            return self.execute_service_control(&mut ledger, operation, now_ms);
        }
        if operation.plan.operation_type != NGINX_SITE_STATE_OPERATION {
            return Err(OpsError::ForensicLockdown);
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

    fn execute_certbot_issue(
        &self,
        ledger: &mut Ledger,
        operation: StoredOperation,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let payload = operation
            .plan
            .certbot_issue
            .as_ref()
            .ok_or(OpsError::ForensicLockdown)?
            .clone();
        let account_email_proposal = ProposalRecord {
            relative_path: payload.account_email_proposal_relative_path.clone(),
            digest: payload.account_email_proposal_digest.clone(),
        };
        let account_email = match read_proposal(&self.paths, &account_email_proposal) {
            Ok(value) => value,
            Err(error) => {
                return self.cancel_certbot_before_apply(ledger, &operation, error.code(), now_ms);
            }
        };
        if payload.environment == CertificateEnvironment::Production
            && !ledger.has_recent_staging_evidence(
                &payload.staging_evidence_key,
                now_ms.saturating_sub(CERTBOT_STAGING_EVIDENCE_TTL_MS),
            )?
        {
            return self.cancel_certbot_before_apply(
                ledger,
                &operation,
                "staging_required",
                now_ms,
            );
        }
        if validate_issue_site(
            &self.paths,
            &payload.site_id,
            &payload.site_digest,
            &payload.domains,
        )
        .is_err()
        {
            return self.cancel_certbot_before_apply(
                ledger,
                &operation,
                "precondition_changed",
                now_ms,
            );
        }
        let inventory = match self.certificate_inventory(now_ms) {
            Ok(inventory) => inventory,
            Err(error) => {
                return self.cancel_certbot_before_apply(ledger, &operation, error.code(), now_ms);
            }
        };
        if !inventory.certbot_installed || inventory.inventory_digest != payload.inventory_digest {
            return self.cancel_certbot_before_apply(
                ledger,
                &operation,
                "precondition_changed",
                now_ms,
            );
        }
        let snapshot = CertificateInventorySnapshot {
            schema_version: 1,
            inventory_digest: inventory.inventory_digest.clone(),
            timer_enabled: inventory.timer_enabled,
            timer_active: inventory.timer_active,
            certificate_count: u32::try_from(inventory.certificates.len())
                .map_err(|_| OpsError::Rejected("certificate_inventory_too_large"))?,
        };
        let record = match write_certificate_inventory_snapshot(
            &self.paths,
            &self.policy,
            &operation.operation_id,
            &snapshot,
        ) {
            Ok(record) => record,
            Err(error) => {
                return self.cancel_certbot_before_apply(ledger, &operation, error.code(), now_ms);
            }
        };
        let snapshotted = ledger.attach_snapshot(&operation.operation_id, &record, now_ms)?;
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Snapshotted],
                next: OperationStage::Applying,
                result_code: match payload.environment {
                    CertificateEnvironment::Staging => "certbot_staging_dry_run_started",
                    CertificateEnvironment::Production => "certbot_production_issue_started",
                },
                evidence_digest: &record.digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let evidence = match self.certbot_runner.run(
            CertbotCommand::Issue {
                primary_domain: payload.primary_domain.clone(),
                domains: payload.domains.clone(),
                account_email,
                environment: payload.environment,
                tos_agreed: true,
            },
            now_ms,
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                return self.reject_certbot_execution(
                    ledger,
                    &snapshotted.operation_id,
                    OperationStage::Applying,
                    "issuance_unavailable",
                    &sha256_digest(error.code().as_bytes()),
                    now_ms,
                );
            }
        };
        let evidence_digest = certbot_command_digest(&evidence)?;
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Applying],
                next: OperationStage::Validating,
                result_code: if evidence.success {
                    "certbot_issue_command_completed"
                } else {
                    "certbot_issue_command_failed"
                },
                evidence_digest: &evidence_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        if !evidence.success {
            return self.reject_certbot_execution(
                ledger,
                &operation.operation_id,
                OperationStage::Validating,
                "issuance_failed",
                &evidence_digest,
                now_ms,
            );
        }
        let read_back = match self.certificate_inventory(now_ms) {
            Ok(inventory) => inventory,
            Err(error) => {
                return self.reject_certbot_execution(
                    ledger,
                    &operation.operation_id,
                    OperationStage::Validating,
                    "certificate_invalid",
                    &sha256_digest(error.code().as_bytes()),
                    now_ms,
                );
            }
        };
        let verified = match payload.environment {
            CertificateEnvironment::Staging => {
                read_back.inventory_digest == payload.inventory_digest
            }
            CertificateEnvironment::Production => {
                read_back
                    .certificates
                    .iter()
                    .find(|certificate| certificate.primary_domain == payload.primary_domain)
                    .is_some_and(|certificate| {
                        certificate.sans == payload.domains && certificate.webroot_managed
                    })
                    && read_back.timer_enabled
                    && read_back.timer_active
            }
        };
        if !verified {
            return self.reject_certbot_execution(
                ledger,
                &operation.operation_id,
                OperationStage::Validating,
                "certificate_invalid",
                &read_back.inventory_digest,
                now_ms,
            );
        }
        let terminal = ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Validating],
                next: OperationStage::Succeeded,
                result_code: match payload.environment {
                    CertificateEnvironment::Staging => "staging_challenge_verified",
                    CertificateEnvironment::Production => "production_certificate_verified",
                },
                evidence_digest: &read_back.inventory_digest,
                after_digest: Some(&read_back.inventory_digest),
                rollback_result: None,
                now_ms,
            },
        )?;
        let receipt = ledger.receipt(&terminal.operation_id)?;
        self.remove_operation_proposal(&terminal);
        Ok(receipt)
    }

    fn execute_certbot_attach(
        &self,
        ledger: &mut Ledger,
        operation: StoredOperation,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let payload = operation
            .plan
            .certbot_attach
            .as_ref()
            .ok_or(OpsError::ForensicLockdown)?
            .clone();
        let inventory = match self.certificate_inventory(now_ms) {
            Ok(inventory) => inventory,
            Err(error) => {
                return self.cancel_certbot_before_apply(ledger, &operation, error.code(), now_ms);
            }
        };
        let certificate_valid = inventory.inventory_digest == payload.inventory_digest
            && inventory.timer_enabled
            && inventory.timer_active
            && inventory
                .certificates
                .iter()
                .find(|certificate| certificate.primary_domain == payload.primary_domain)
                .is_some_and(|certificate| {
                    certificate.fingerprint_sha256 == payload.certificate_fingerprint
                        && certificate.sans == payload.sans
                        && certificate.not_after == payload.not_after
                        && certificate.private_key_present
                        && certificate.renewal_config_present
                        && certificate.webroot_managed
                });
        if !certificate_valid {
            return self.cancel_certbot_before_apply(
                ledger,
                &operation,
                "precondition_changed",
                now_ms,
            );
        }
        let attachment = match prepare_tls_attachment(
            &self.paths,
            &payload.primary_domain,
            &payload.site_id,
            &payload.site_digest,
        ) {
            Ok(attachment)
                if attachment.config.metadata_digest == payload.metadata_digest
                    && attachment.proposed_content_digest == payload.proposed_content_digest =>
            {
                attachment
            }
            Ok(_) => {
                return self.cancel_certbot_before_apply(
                    ledger,
                    &operation,
                    "precondition_changed",
                    now_ms,
                );
            }
            Err(error) => {
                return self.cancel_certbot_before_apply(ledger, &operation, error.code(), now_ms);
            }
        };
        let snapshot = ManagedConfigSnapshot {
            schema_version: 1,
            resource_id: attachment.config.resource_id.clone(),
            basename: attachment.config.basename.clone(),
            content: attachment.config.content.clone(),
            content_digest: attachment.config.content_digest.clone(),
            metadata_digest: attachment.config.metadata_digest.clone(),
            mode: attachment.config.mode,
            uid: attachment.config.uid,
            gid: attachment.config.gid,
        };
        let record = match write_managed_config_snapshot(
            &self.paths,
            &self.policy,
            &operation.operation_id,
            &snapshot,
        ) {
            Ok(record) => record,
            Err(error) => {
                return self.cancel_certbot_before_apply(ledger, &operation, error.code(), now_ms);
            }
        };
        let snapshotted = ledger.attach_snapshot(&operation.operation_id, &record, now_ms)?;
        if attachment.config.content_digest == attachment.proposed_content_digest {
            ledger.transition(
                &operation.operation_id,
                Transition {
                    expected: &[OperationStage::Snapshotted],
                    next: OperationStage::Verifying,
                    result_code: "certificate_already_attached",
                    evidence_digest: &attachment.proposed_content_digest,
                    after_digest: None,
                    rollback_result: None,
                    now_ms,
                },
            )?;
            return self.verify_certbot_attach(ledger, &snapshotted, &payload, now_ms);
        }
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Snapshotted],
                next: OperationStage::Applying,
                result_code: "tls_directives_replace_started",
                evidence_digest: &record.digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let applied = match replace_protected_config(
            &self.paths,
            &attachment.config,
            &attachment.proposed_content,
        ) {
            Ok(applied) if applied.content_digest == payload.proposed_content_digest => applied,
            Ok(_) => {
                return self.rollback_certbot_attach(
                    ledger,
                    &snapshotted.operation_id,
                    "config_read_back_failed",
                    &sha256_digest(b"config_read_back_failed"),
                    now_ms,
                );
            }
            Err(error) => {
                return self.rollback_certbot_attach(
                    ledger,
                    &snapshotted.operation_id,
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
                next: OperationStage::Validating,
                result_code: "tls_directives_replaced",
                evidence_digest: &applied.content_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let config_test = match self.runner.run(CommandClass::NginxConfigTest) {
            Ok(evidence) => evidence,
            Err(error) => {
                return self.rollback_certbot_attach(
                    ledger,
                    &snapshotted.operation_id,
                    "nginx_config_test_unavailable",
                    &sha256_digest(error.code().as_bytes()),
                    now_ms,
                );
            }
        };
        let config_digest = command_digest(&config_test)?;
        if !config_test.success {
            return self.rollback_certbot_attach(
                ledger,
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
                return self.rollback_certbot_attach(
                    ledger,
                    &snapshotted.operation_id,
                    "nginx_reload_unavailable",
                    &sha256_digest(error.code().as_bytes()),
                    now_ms,
                );
            }
        };
        let reload_digest = command_digest(&reload)?;
        if !reload.success {
            return self.rollback_certbot_attach(
                ledger,
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
        self.verify_certbot_attach(ledger, &snapshotted, &payload, now_ms)
    }

    fn verify_certbot_attach(
        &self,
        ledger: &mut Ledger,
        operation: &StoredOperation,
        payload: &CertbotAttachPlanPayload,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let config = discover_protected_config(&self.paths, &payload.site_id);
        let active = self.runner.run(CommandClass::NginxActive);
        let inventory = self.certificate_inventory(now_ms);
        let tls = self.certbot_runner.run(
            CertbotCommand::VerifyLocalTls {
                server_name: payload.primary_domain.clone(),
                expected_fingerprint: payload.certificate_fingerprint.clone(),
            },
            now_ms,
        );
        let inventory_verified = inventory.as_ref().is_ok_and(|inventory| {
            inventory.inventory_digest == payload.inventory_digest
                && inventory.timer_enabled
                && inventory.timer_active
                && inventory.certificates.iter().any(|certificate| {
                    certificate.primary_domain == payload.primary_domain
                        && certificate.fingerprint_sha256 == payload.certificate_fingerprint
                        && certificate.webroot_managed
                })
        });
        let verified = config.as_ref().is_ok_and(|config| {
            config.content_digest == payload.proposed_content_digest
                && config.metadata_digest == payload.metadata_digest
        }) && active.as_ref().is_ok_and(|evidence| evidence.success)
            && inventory_verified
            && tls.as_ref().is_ok_and(|evidence| evidence.success);
        if !verified {
            let evidence = match tls.as_ref() {
                Ok(value) => certbot_command_digest(value)?,
                Err(_) => sha256_digest(b"tls_probe_unavailable"),
            };
            return self.rollback_certbot_attach(
                ledger,
                &operation.operation_id,
                "tls_read_back_failed",
                &evidence,
                now_ms,
            );
        }
        let tls = tls?;
        let terminal = ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Verifying],
                next: OperationStage::Succeeded,
                result_code: "tls_attachment_verified",
                evidence_digest: &certbot_command_digest(&tls)?,
                after_digest: Some(&payload.proposed_content_digest),
                rollback_result: None,
                now_ms,
            },
        )?;
        ledger.receipt(&terminal.operation_id)
    }

    fn rollback_certbot_attach(
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
        let snapshot = match read_managed_config_snapshot(&self.paths, record) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return self.recovery_required(ledger, operation_id, error.code(), now_ms);
            }
        };
        let restored = match restore_protected_config(
            &self.paths,
            &snapshot.resource_id,
            &snapshot.basename,
            &snapshot.content,
            snapshot.mode,
            snapshot.uid,
            snapshot.gid,
        ) {
            Ok(restored) => restored,
            Err(_) => {
                return self.recovery_required(
                    ledger,
                    operation_id,
                    "rollback_replace_failed",
                    now_ms,
                );
            }
        };
        let config = self.runner.run(CommandClass::NginxConfigTest);
        let reload = self.runner.run(CommandClass::NginxReload);
        let active = self.runner.run(CommandClass::NginxActive);
        let verified = restored.content_digest == snapshot.content_digest
            && restored.metadata_digest == snapshot.metadata_digest
            && config.as_ref().is_ok_and(|evidence| evidence.success)
            && reload.as_ref().is_ok_and(|evidence| evidence.success)
            && active.as_ref().is_ok_and(|evidence| evidence.success);
        if !verified {
            return self.recovery_required(ledger, operation_id, "rollback_verify_failed", now_ms);
        }
        let active = active?;
        let terminal = ledger.transition(
            operation_id,
            Transition {
                expected: &[OperationStage::RollingBack],
                next: OperationStage::RolledBack,
                result_code: "rollback_verified",
                evidence_digest: &command_digest(&active)?,
                after_digest: Some(&snapshot.content_digest),
                rollback_result: Some("verified"),
                now_ms,
            },
        )?;
        ledger.receipt(&terminal.operation_id)
    }

    fn execute_certbot_renew_test(
        &self,
        ledger: &mut Ledger,
        operation: StoredOperation,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let payload = operation
            .plan
            .certbot_renew
            .as_ref()
            .ok_or(OpsError::ForensicLockdown)?
            .clone();
        let inventory = match self.certificate_inventory(now_ms) {
            Ok(inventory) => inventory,
            Err(error) => {
                return self.cancel_certbot_before_apply(ledger, &operation, error.code(), now_ms);
            }
        };
        if !inventory.certbot_installed || inventory.inventory_digest != payload.inventory_digest {
            return self.cancel_certbot_before_apply(
                ledger,
                &operation,
                "precondition_changed",
                now_ms,
            );
        }
        let snapshot = CertificateInventorySnapshot {
            schema_version: 1,
            inventory_digest: inventory.inventory_digest.clone(),
            timer_enabled: inventory.timer_enabled,
            timer_active: inventory.timer_active,
            certificate_count: u32::try_from(inventory.certificates.len())
                .map_err(|_| OpsError::Rejected("certificate_inventory_too_large"))?,
        };
        let record = match write_certificate_inventory_snapshot(
            &self.paths,
            &self.policy,
            &operation.operation_id,
            &snapshot,
        ) {
            Ok(record) => record,
            Err(error) => {
                return self.cancel_certbot_before_apply(ledger, &operation, error.code(), now_ms);
            }
        };
        let snapshotted = ledger.attach_snapshot(&operation.operation_id, &record, now_ms)?;
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Snapshotted],
                next: OperationStage::Applying,
                result_code: "certbot_renew_dry_run_started",
                evidence_digest: &record.digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let evidence = match self.certbot_runner.run(CertbotCommand::RenewDryRun, now_ms) {
            Ok(evidence) => evidence,
            Err(error) => {
                return self.reject_certbot_execution(
                    ledger,
                    &snapshotted.operation_id,
                    OperationStage::Applying,
                    "renewal_test_unavailable",
                    &sha256_digest(error.code().as_bytes()),
                    now_ms,
                );
            }
        };
        let evidence_digest = certbot_command_digest(&evidence)?;
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Applying],
                next: OperationStage::Validating,
                result_code: if evidence.success {
                    "certbot_renew_dry_run_completed"
                } else {
                    "certbot_renew_dry_run_failed"
                },
                evidence_digest: &evidence_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        if !evidence.success {
            return self.reject_certbot_execution(
                ledger,
                &operation.operation_id,
                OperationStage::Validating,
                "renewal_test_failed",
                &evidence_digest,
                now_ms,
            );
        }
        let read_back = match self.certificate_inventory(now_ms) {
            Ok(inventory) => inventory,
            Err(error) => {
                return self.reject_certbot_execution(
                    ledger,
                    &operation.operation_id,
                    OperationStage::Validating,
                    "renewal_read_back_failed",
                    &sha256_digest(error.code().as_bytes()),
                    now_ms,
                );
            }
        };
        if !read_back.certbot_installed || !read_back.timer_enabled || !read_back.timer_active {
            return self.reject_certbot_execution(
                ledger,
                &operation.operation_id,
                OperationStage::Validating,
                "renewal_timer_unhealthy",
                &read_back.inventory_digest,
                now_ms,
            );
        }
        let terminal = ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Validating],
                next: OperationStage::Succeeded,
                result_code: "renewal_test_verified",
                evidence_digest: &read_back.inventory_digest,
                after_digest: Some(&read_back.inventory_digest),
                rollback_result: None,
                now_ms,
            },
        )?;
        let receipt = ledger.receipt(&terminal.operation_id)?;
        self.remove_operation_proposal(&terminal);
        Ok(receipt)
    }

    fn cancel_certbot_before_apply(
        &self,
        ledger: &mut Ledger,
        operation: &StoredOperation,
        reason: &str,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let terminal = ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Approved],
                next: OperationStage::CancelledBeforeApply,
                result_code: reason,
                evidence_digest: &sha256_digest(reason.as_bytes()),
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let receipt = ledger.receipt(&terminal.operation_id)?;
        self.remove_operation_proposal(&terminal);
        Ok(receipt)
    }

    fn reject_certbot_execution(
        &self,
        ledger: &mut Ledger,
        operation_id: &str,
        expected: OperationStage,
        reason: &str,
        evidence_digest: &str,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let terminal = ledger.transition(
            operation_id,
            Transition {
                expected: &[expected],
                next: OperationStage::Rejected,
                result_code: reason,
                evidence_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let receipt = ledger.receipt(&terminal.operation_id)?;
        self.remove_operation_proposal(&terminal);
        Ok(receipt)
    }

    fn execute_managed_config(
        &self,
        ledger: &mut Ledger,
        operation: StoredOperation,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let payload = operation
            .plan
            .managed_config
            .clone()
            .ok_or(OpsError::ForensicLockdown)?;
        let preflight = match discover_managed_config(&self.paths, &operation.plan.site_id) {
            Ok(resource)
                if resource.content_digest == operation.plan.available_digest
                    && resource.metadata_digest == operation.plan.enabled_state_digest =>
            {
                resource
            }
            Ok(_) => {
                return self.cancel_managed_before_apply(
                    ledger,
                    &operation,
                    "stale_resource",
                    now_ms,
                );
            }
            Err(error) => {
                return self.cancel_managed_before_apply(ledger, &operation, error.code(), now_ms);
            }
        };
        let proposal = ProposalRecord {
            relative_path: payload.proposal_relative_path.clone(),
            digest: payload.proposal_digest.clone(),
        };
        let proposed = match read_proposal(&self.paths, &proposal) {
            Ok(content) if sha256_digest(content.as_bytes()) == payload.proposed_content_digest => {
                content
            }
            Ok(_) => {
                return self.cancel_managed_before_apply(
                    ledger,
                    &operation,
                    "proposal_digest_mismatch",
                    now_ms,
                );
            }
            Err(error) => {
                return self.cancel_managed_before_apply(ledger, &operation, error.code(), now_ms);
            }
        };
        if let Err(error) =
            validate_managed_config_candidate(preflight.adapter, &preflight.content, &proposed)
        {
            return self.cancel_managed_before_apply(ledger, &operation, error.code(), now_ms);
        }
        let snapshot = ManagedConfigSnapshot {
            schema_version: 1,
            resource_id: preflight.resource_id.clone(),
            basename: preflight.basename.clone(),
            content: preflight.content.clone(),
            content_digest: preflight.content_digest.clone(),
            metadata_digest: preflight.metadata_digest.clone(),
            mode: preflight.mode,
            uid: preflight.uid,
            gid: preflight.gid,
        };
        let record = match write_managed_config_snapshot(
            &self.paths,
            &self.policy,
            &operation.operation_id,
            &snapshot,
        ) {
            Ok(record) => record,
            Err(error) => {
                return self.cancel_managed_before_apply(ledger, &operation, error.code(), now_ms);
            }
        };
        let snapshotted = ledger.attach_snapshot(&operation.operation_id, &record, now_ms)?;
        if preflight.content_digest == payload.proposed_content_digest {
            return self.finish_managed_noop(
                ledger,
                &snapshotted,
                &proposal,
                preflight.adapter,
                now_ms,
            );
        }
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Snapshotted],
                next: OperationStage::Applying,
                result_code: "config_apply_started",
                evidence_digest: &preflight.content_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let applied = match replace_managed_config(&self.paths, &preflight, &proposed) {
            Ok(resource) => resource,
            Err(error) => {
                return self.rollback_managed_config(
                    ledger,
                    &snapshotted.operation_id,
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
                next: OperationStage::Validating,
                result_code: "config_replaced",
                evidence_digest: &applied.content_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let config_test = match self.runner.run(preflight.adapter.config_test()) {
            Ok(evidence) => evidence,
            Err(error) => {
                let code = format!("{}_unavailable", preflight.adapter.config_test().as_str());
                return self.rollback_managed_config(
                    ledger,
                    &snapshotted.operation_id,
                    &code,
                    &sha256_digest(error.code().as_bytes()),
                    now_ms,
                );
            }
        };
        let config_digest = command_digest(&config_test)?;
        if !managed_config_test_succeeded(preflight.adapter, &config_test) {
            let failure_code =
                managed_config_failure_code(preflight.adapter, &config_test, &preflight.basename);
            return self.rollback_managed_config(
                ledger,
                &snapshotted.operation_id,
                &failure_code,
                &config_digest,
                now_ms,
            );
        }
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Validating],
                next: OperationStage::Reloading,
                result_code: preflight.adapter.config_valid_code(),
                evidence_digest: &config_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let reload = match self.runner.run(preflight.adapter.reload()) {
            Ok(evidence) => evidence,
            Err(error) => {
                let code = format!("{}_unavailable", preflight.adapter.reload().as_str());
                return self.rollback_managed_config(
                    ledger,
                    &snapshotted.operation_id,
                    &code,
                    &sha256_digest(error.code().as_bytes()),
                    now_ms,
                );
            }
        };
        let reload_digest = command_digest(&reload)?;
        if !reload.success {
            let code = format!("{}_failed", preflight.adapter.reload().as_str());
            return self.rollback_managed_config(
                ledger,
                &snapshotted.operation_id,
                &code,
                &reload_digest,
                now_ms,
            );
        }
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Reloading],
                next: OperationStage::Verifying,
                result_code: preflight.adapter.reloaded_code(),
                evidence_digest: &reload_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let read_back = discover_managed_config(&self.paths, &snapshotted.plan.site_id);
        let active = self.runner.run(preflight.adapter.active());
        let verified = read_back.as_ref().is_ok_and(|resource| {
            resource.content_digest == payload.proposed_content_digest
                && resource.metadata_digest == snapshotted.plan.enabled_state_digest
        }) && active.as_ref().is_ok_and(|evidence| evidence.success);
        if !verified {
            let evidence = match active.as_ref() {
                Ok(value) => command_digest(value)?,
                Err(_) => sha256_digest(preflight.adapter.active().as_str().as_bytes()),
            };
            return self.rollback_managed_config(
                ledger,
                &snapshotted.operation_id,
                "read_back_failed",
                &evidence,
                now_ms,
            );
        }
        let active = active?;
        let succeeded = ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Verifying],
                next: OperationStage::Succeeded,
                result_code: "config_verified",
                evidence_digest: &command_digest(&active)?,
                after_digest: Some(&payload.proposed_content_digest),
                rollback_result: None,
                now_ms,
            },
        )?;
        let receipt = ledger.receipt(&succeeded.operation_id)?;
        let _cleanup = remove_proposal(&self.paths, &proposal);
        Ok(receipt)
    }

    fn cancel_managed_before_apply(
        &self,
        ledger: &mut Ledger,
        operation: &StoredOperation,
        result_code: &str,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        let terminal = ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Approved],
                next: OperationStage::CancelledBeforeApply,
                result_code,
                evidence_digest: &sha256_digest(result_code.as_bytes()),
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let receipt = ledger.receipt(&terminal.operation_id)?;
        self.remove_operation_proposal(operation);
        Ok(receipt)
    }

    fn finish_managed_noop(
        &self,
        ledger: &mut Ledger,
        operation: &StoredOperation,
        proposal: &ProposalRecord,
        adapter: ManagedConfigAdapter,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Snapshotted],
                next: OperationStage::Verifying,
                result_code: "no_change_required",
                evidence_digest: &operation.plan.available_digest,
                after_digest: None,
                rollback_result: None,
                now_ms,
            },
        )?;
        let config = self.runner.run(adapter.config_test());
        let active = self.runner.run(adapter.active());
        let valid = config
            .as_ref()
            .is_ok_and(|evidence| managed_config_test_succeeded(adapter, evidence))
            && active.as_ref().is_ok_and(|evidence| evidence.success);
        if !valid {
            let cancelled = ledger.transition(
                &operation.operation_id,
                Transition {
                    expected: &[OperationStage::Verifying],
                    next: OperationStage::CancelledBeforeApply,
                    result_code: "preexisting_validation_failed",
                    evidence_digest: &sha256_digest(b"preexisting_validation_failed"),
                    after_digest: None,
                    rollback_result: None,
                    now_ms,
                },
            )?;
            let receipt = ledger.receipt(&cancelled.operation_id)?;
            self.remove_operation_proposal(operation);
            return Ok(receipt);
        }
        let active = active?;
        let succeeded = ledger.transition(
            &operation.operation_id,
            Transition {
                expected: &[OperationStage::Verifying],
                next: OperationStage::Succeeded,
                result_code: "verified_noop",
                evidence_digest: &command_digest(&active)?,
                after_digest: Some(&operation.plan.available_digest),
                rollback_result: None,
                now_ms,
            },
        )?;
        let receipt = ledger.receipt(&succeeded.operation_id)?;
        let _cleanup = remove_proposal(&self.paths, proposal);
        Ok(receipt)
    }

    fn rollback_managed_config(
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
        if restored.content_digest != snapshot.content_digest
            || restored.metadata_digest != snapshot.metadata_digest
            || !config.success
            || !reload.success
        {
            return self.recovery_required(ledger, operation_id, "rollback_verify_failed", now_ms);
        }
        let terminal = ledger.transition(
            operation_id,
            Transition {
                expected: &[OperationStage::RollingBack],
                next: OperationStage::RolledBack,
                result_code: "rollback_verified",
                evidence_digest: &command_digest(&active)?,
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
        let receipt = ledger.receipt(&terminal.operation_id)?;
        self.remove_operation_proposal(&terminal);
        Ok(receipt)
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
        let receipt = ledger.receipt(&terminal.operation_id)?;
        self.remove_operation_proposal(&terminal);
        Ok(receipt)
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
                self.remove_operation_proposal(&terminal);
                Ok(())
            }
            OperationStage::Applying
            | OperationStage::Validating
            | OperationStage::Reloading
            | OperationStage::Verifying
            | OperationStage::RollingBack => {
                if operation.plan.operation_type == CERTBOT_RENEW_TEST_OPERATION
                    || operation.plan.operation_type == CERTBOT_ISSUE_OPERATION
                {
                    let record = operation
                        .snapshot
                        .as_ref()
                        .ok_or(OpsError::ForensicLockdown)?;
                    let _snapshot = read_certificate_inventory_snapshot(&self.paths, record)?;
                    let terminal = ledger.transition(
                        &operation.operation_id,
                        Transition {
                            expected: &[operation.stage],
                            next: OperationStage::RecoveryRequired,
                            result_code: if operation.plan.operation_type == CERTBOT_ISSUE_OPERATION
                            {
                                "certificate_issue_interrupted"
                            } else {
                                "renewal_test_interrupted"
                            },
                            evidence_digest: &record.digest,
                            after_digest: None,
                            rollback_result: Some("not_applicable_external_status_unknown"),
                            now_ms,
                        },
                    )?;
                    self.remove_operation_proposal(&terminal);
                    Ok(())
                } else if operation.plan.operation_type == CERTBOT_ATTACH_OPERATION {
                    self.rollback_certbot_attach(
                        ledger,
                        &operation.operation_id,
                        "restart_recovery",
                        &sha256_digest(b"restart_recovery"),
                        now_ms,
                    )
                    .map(|_| ())
                } else if operation.plan.operation_type == MANAGED_CONFIG_OPERATION
                    || operation.plan.operation_type == MANAGED_CONFIG_RESTORE_OPERATION
                {
                    self.rollback_managed_config(
                        ledger,
                        &operation.operation_id,
                        "restart_recovery",
                        &sha256_digest(b"restart_recovery"),
                        now_ms,
                    )
                    .map(|_| ())
                } else if operation.plan.operation_type == SERVICE_CONTROL_OPERATION {
                    self.rollback_service_control(
                        ledger,
                        &operation.operation_id,
                        "restart_recovery",
                        &sha256_digest(b"restart_recovery"),
                        now_ms,
                    )
                    .map(|_| ())
                } else {
                    self.rollback(
                        ledger,
                        &operation.operation_id,
                        "restart_recovery",
                        &sha256_digest(b"restart_recovery"),
                        now_ms,
                    )
                    .map(|_| ())
                }
            }
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

    fn remove_operation_proposal(&self, operation: &StoredOperation) {
        self.remove_plan_proposal(&operation.plan);
    }

    fn remove_plan_proposal(&self, plan: &StoredPlan) {
        if let Some(payload) = &plan.managed_config {
            let _cleanup = remove_proposal(
                &self.paths,
                &ProposalRecord {
                    relative_path: payload.proposal_relative_path.clone(),
                    digest: payload.proposal_digest.clone(),
                },
            );
        }
        if let Some(payload) = &plan.certbot_issue {
            let _cleanup = remove_proposal(
                &self.paths,
                &ProposalRecord {
                    relative_path: payload.account_email_proposal_relative_path.clone(),
                    digest: payload.account_email_proposal_digest.clone(),
                },
            );
        }
    }

    fn remove_expired_proposals(&self, ledger: &Ledger, now_ms: i64) -> Result<(), OpsError> {
        for plan in ledger.expired_unexecuted_proposal_plans(now_ms)? {
            self.remove_plan_proposal(&plan);
        }
        Ok(())
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

fn managed_config_plan_hash(plan: &StoredPlan) -> Result<String, OpsError> {
    let payload = plan
        .managed_config
        .as_ref()
        .ok_or(OpsError::ForensicLockdown)?;
    let adapter = managed_config_adapter(&plan.site_id)?;
    canonical_digest(
        b"jw-agent/operation-plan/v1",
        &ManagedPlanHashMaterial {
            schema_version: 1,
            operation_type: &plan.operation_type,
            plan_id: &plan.plan_id,
            created_at_ms: plan.created_at_ms,
            expires_at_ms: plan.expires_at_ms,
            actor: &plan.actor,
            resource_id: &plan.site_id,
            display_name: &plan.display_name,
            current_content_digest: &plan.available_digest,
            metadata_digest: &plan.enabled_state_digest,
            proposed_content_digest: &payload.proposed_content_digest,
            service_action: payload.service_action.as_storage_value(),
            current_bytes: payload.current_bytes,
            proposed_bytes: payload.proposed_bytes,
            added_lines: payload.added_lines,
            removed_lines: payload.removed_lines,
            diff_summary: &payload.diff_summary,
            resource_key: &plan.resource_key,
            impact: adapter.impact(),
            recovery_path: adapter.recovery_path(),
            assurance: &plan.assurance,
        },
    )
}

fn certbot_renew_plan_hash(plan: &StoredPlan) -> Result<String, OpsError> {
    let payload = plan
        .certbot_renew
        .as_ref()
        .ok_or(OpsError::ForensicLockdown)?;
    canonical_digest(
        b"jw-agent/operation-plan/v1",
        &CertbotRenewPlanHashMaterial {
            schema_version: 1,
            operation_type: CERTBOT_RENEW_TEST_OPERATION,
            plan_id: &plan.plan_id,
            created_at_ms: plan.created_at_ms,
            expires_at_ms: plan.expires_at_ms,
            actor: &plan.actor,
            inventory_digest: &payload.inventory_digest,
            timer_enabled: payload.timer_enabled,
            timer_active: payload.timer_active,
            certificate_count: payload.certificate_count,
            resource_key: &plan.resource_key,
            assurance: &plan.assurance,
        },
    )
}

fn certbot_issue_plan_hash(plan: &StoredPlan) -> Result<String, OpsError> {
    let payload = plan
        .certbot_issue
        .as_ref()
        .ok_or(OpsError::ForensicLockdown)?;
    canonical_digest(
        b"jw-agent/operation-plan/v1",
        &CertbotIssuePlanHashMaterial {
            schema_version: 1,
            operation_type: CERTBOT_ISSUE_OPERATION,
            plan_id: &plan.plan_id,
            created_at_ms: plan.created_at_ms,
            expires_at_ms: plan.expires_at_ms,
            actor: &plan.actor,
            primary_domain: &payload.primary_domain,
            domains: &payload.domains,
            account_email_digest: &payload.account_email_proposal_digest,
            masked_account_email: &payload.masked_account_email,
            environment: payload.environment,
            site_id: &payload.site_id,
            site_digest: &payload.site_digest,
            inventory_digest: &payload.inventory_digest,
            preflight_observed_at_ms: payload.preflight_observed_at_ms,
            resolved_addresses: &payload.resolved_addresses,
            local_port_80_reachable: payload.local_port_80_reachable,
            local_port_443_reachable: payload.local_port_443_reachable,
            staging_evidence_valid: payload.staging_evidence_valid,
            staging_evidence_key: &payload.staging_evidence_key,
            resource_key: &plan.resource_key,
            assurance: &plan.assurance,
        },
    )
}

fn certbot_attach_plan_hash(plan: &StoredPlan) -> Result<String, OpsError> {
    let payload = plan
        .certbot_attach
        .as_ref()
        .ok_or(OpsError::ForensicLockdown)?;
    canonical_digest(
        b"jw-agent/operation-plan/v1",
        &CertbotAttachPlanHashMaterial {
            schema_version: 1,
            operation_type: CERTBOT_ATTACH_OPERATION,
            plan_id: &plan.plan_id,
            created_at_ms: plan.created_at_ms,
            expires_at_ms: plan.expires_at_ms,
            actor: &plan.actor,
            primary_domain: &payload.primary_domain,
            site_id: &payload.site_id,
            site_digest: &payload.site_digest,
            metadata_digest: &payload.metadata_digest,
            inventory_digest: &payload.inventory_digest,
            certificate_fingerprint: &payload.certificate_fingerprint,
            sans: &payload.sans,
            not_after: &payload.not_after,
            current_certificate_path: &payload.current_certificate_path,
            target_certificate_path: &payload.target_certificate_path,
            proposed_content_digest: &payload.proposed_content_digest,
            timer_enabled: payload.timer_enabled,
            timer_active: payload.timer_active,
            resource_key: &plan.resource_key,
            assurance: &plan.assurance,
        },
    )
}

fn certbot_command_digest(evidence: &CertbotCommandEvidence) -> Result<String, OpsError> {
    canonical_digest(b"jw-agent/certbot-command-evidence/v1", evidence)
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
#[path = "engine_test_fakes.rs"]
mod test_fakes;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;
    use std::sync::Arc;

    use jw_contracts::{
        AssuranceLevel, CERTBOT_ATTACH_OPERATION, CERTBOT_ISSUE_OPERATION,
        CERTBOT_RENEW_TEST_OPERATION, CertbotAttachPlanRequest, CertbotIssuePlanInput,
        CertbotIssuePlanRequest, CertbotIssuePreflightEvidence, CertbotRenewTestPlanRequest,
        CertificateEnvironment, IPC_PROTOCOL_VERSION, MANAGED_CONFIG_OPERATION,
        ManagedConfigApprovalIntent, ManagedConfigPlanRequest, NGINX_CONFIG_ADAPTER_ID,
        NGINX_LAYOUT_ID, NGINX_MANAGEMENT_MARKER, NGINX_SITE_STATE_OPERATION, NginxSiteState,
        NginxSiteStatePlanRequest, OperationStage, OpsRequest, OpsRequestBody, OpsResponseBody,
        PHP_FPM_CONFIG_ADAPTER_ID, Role, ServiceAction, Subject, nginx_config_resource_id,
        nginx_enabled_state_digest as enabled_state_digest, nginx_site_id as site_id,
        php_fpm_config_resource_id, sha256_digest,
    };

    use crate::certbot_runner::CertbotRunner;
    use crate::config::{OpsPaths, OpsPolicy};
    use crate::ledger::{Ledger, Transition};
    use crate::runner::OperationRunner;
    use crate::snapshot::{NginxLinkSnapshot, write_nginx_snapshot};

    use super::OpsService;
    use super::test_fakes::{FakeCertbotRunner, FakeRunner};

    mod operation_smoke_tests;
    mod php_fpm_tests;

    #[test]
    fn certbot_staging_issue_is_non_persistent_and_unlocks_production_plan() -> Result<(), String> {
        let root = test_root("certbot-issue-staging")?;
        let certbot = Arc::new(FakeCertbotRunner::new(true));
        let service = fixture_issue_service(
            &root,
            Arc::new(FakeRunner::certbot_issue_staging_and_production_plan()),
            certbot.clone(),
        )?;
        let staging = certbot_issue_plan(
            &service,
            1_000,
            "certbot-issue-stage1",
            CertificateEnvironment::Staging,
        )?;
        assert!(!staging.staging_evidence_valid);
        assert_eq!(staging.masked_account_email, "o***@example.com");
        let paths = OpsPaths::for_test(&root);
        for persisted in [
            paths.database.clone(),
            paths.database.with_file_name("opsd.sqlite3-wal"),
        ] {
            if persisted.exists() {
                let bytes = fs::read(persisted).map_err(|error| error.to_string())?;
                assert!(
                    !bytes
                        .windows(b"owner@example.com".len())
                        .any(|window| window == b"owner@example.com")
                );
            }
        }
        assert_eq!(
            fs::read_dir(&paths.proposals)
                .map_err(|error| error.to_string())?
                .count(),
            1
        );
        let receipt = approve_certbot_issue(&service, &staging, 1_001, "certbot-issue-stage1")?;
        assert_eq!(
            receipt.terminal_state,
            jw_contracts::OperationStage::Succeeded
        );
        assert_eq!(receipt.before_digest, receipt.after_digest);
        assert!(
            receipt
                .stages
                .iter()
                .any(|stage| stage.result_code == "staging_challenge_verified")
        );
        assert_eq!(
            fs::read_dir(&paths.proposals)
                .map_err(|error| error.to_string())?
                .count(),
            0
        );
        let production = certbot_issue_plan(
            &service,
            1_100,
            "certbot-issue-prod01",
            CertificateEnvironment::Production,
        )?;
        assert!(production.staging_evidence_valid);
        let calls = certbot
            .calls
            .lock()
            .map_err(|_| String::from("fake certbot runner poisoned"))?;
        assert_eq!(*calls, 1);
        drop(calls);
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn certbot_renew_dry_run_is_planned_snapshotted_and_verified() -> Result<(), String> {
        let root = test_root("certbot-renew-success")?;
        let certbot = Arc::new(FakeCertbotRunner::new(true));
        let service = fixture_service_with_certbot(
            &root,
            Arc::new(FakeRunner::certbot_timer_success(4)),
            certbot.clone(),
        )?;
        let plan = certbot_renew_plan(&service, 1_000, "certbot-renew-key1")?;
        let receipt = approve_certbot_renew(&service, &plan, 1_001, "certbot-renew-key1")?;
        assert_eq!(
            receipt.terminal_state,
            jw_contracts::OperationStage::Succeeded
        );
        assert!(receipt.stages.iter().any(|stage| {
            stage.result_code == "certbot_renew_dry_run_started"
                && stage.stage == jw_contracts::OperationStage::Applying
        }));
        assert!(
            receipt
                .stages
                .iter()
                .any(|stage| stage.result_code == "renewal_test_verified")
        );
        let calls = certbot
            .calls
            .lock()
            .map_err(|_| String::from("fake certbot runner poisoned"))?;
        assert_eq!(*calls, 1);
        drop(calls);
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn certbot_renew_failure_is_terminal_without_false_rollback() -> Result<(), String> {
        let root = test_root("certbot-renew-failure")?;
        let service = fixture_service_with_certbot(
            &root,
            Arc::new(FakeRunner::certbot_timer_success(3)),
            Arc::new(FakeCertbotRunner::new(false)),
        )?;
        let plan = certbot_renew_plan(&service, 1_000, "certbot-renew-key2")?;
        let receipt = approve_certbot_renew(&service, &plan, 1_001, "certbot-renew-key2")?;
        assert_eq!(
            receipt.terminal_state,
            jw_contracts::OperationStage::Rejected
        );
        assert_eq!(receipt.rollback_result, None);
        assert!(
            receipt
                .stages
                .iter()
                .any(|stage| stage.result_code == "renewal_test_failed")
        );
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn certbot_attach_replaces_only_tls_directives_and_verifies_g2() -> Result<(), String> {
        let root = test_root("certbot-attach-success")?;
        let service = fixture_attach_service(
            &root,
            Arc::new(FakeRunner::certbot_attach_success()),
            Arc::new(FakeCertbotRunner::new(true)),
        )?;
        let plan = certbot_attach_plan(&service, 1_000, "certbot-attach-key1")?;
        assert_eq!(plan.assurance.level, AssuranceLevel::G2ReversibleConfig);
        let receipt = approve_certbot_attach(&service, &plan, 1_001, "certbot-attach-key1")?;
        assert_eq!(
            receipt.terminal_state,
            jw_contracts::OperationStage::Succeeded
        );
        assert!(
            receipt
                .stages
                .iter()
                .any(|stage| stage.result_code == "tls_attachment_verified")
        );
        let content = fs::read_to_string(
            OpsPaths::for_test(&root)
                .nginx_available
                .join("example.com"),
        )
        .map_err(|error| error.to_string())?;
        let expected_fullchain = OpsPaths::for_test(&root)
            .letsencrypt_live
            .join("example.com/fullchain.pem");
        assert!(content.contains(&expected_fullchain.to_string_lossy().to_string()));
        assert!(!content.contains("/legacy/server.crt"));
        assert!(content.contains("proxy_pass http://unix:/run/jw-agent/agentd.sock"));
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn certbot_attach_tls_failure_restores_exact_protected_config() -> Result<(), String> {
        let root = test_root("certbot-attach-rollback")?;
        let service = fixture_attach_service(
            &root,
            Arc::new(FakeRunner::certbot_attach_tls_failure_then_rollback()),
            Arc::new(FakeCertbotRunner::new(false)),
        )?;
        let original = fs::read(
            OpsPaths::for_test(&root)
                .nginx_available
                .join("example.com"),
        )
        .map_err(|error| error.to_string())?;
        let plan = certbot_attach_plan(&service, 1_000, "certbot-attach-key2")?;
        let receipt = approve_certbot_attach(&service, &plan, 1_001, "certbot-attach-key2")?;
        assert_eq!(
            receipt.terminal_state,
            jw_contracts::OperationStage::RolledBack
        );
        assert_eq!(receipt.rollback_result.as_deref(), Some("verified"));
        let restored = fs::read(
            OpsPaths::for_test(&root)
                .nginx_available
                .join("example.com"),
        )
        .map_err(|error| error.to_string())?;
        assert_eq!(restored, original);
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

    #[test]
    fn managed_config_save_reloads_and_verifies_content() -> Result<(), String> {
        let root = test_root("managed-success")?;
        let service = fixture_service(&root, Arc::new(FakeRunner::all_success()))?;
        let plan = managed_plan(
            &service,
            1_000,
            "server { listen 8080; }\n",
            "managed-key-0001",
        )?;
        let receipt = approve_managed(&service, &plan, 1_001, "managed-key-0001", true)?;
        assert_eq!(
            receipt.terminal_state,
            jw_contracts::OperationStage::Succeeded
        );
        assert_eq!(
            receipt.after_digest,
            sha256_digest(b"server { listen 8080; }\n")
        );
        let content = fs::read_to_string(
            OpsPaths::for_test(&root)
                .nginx_available
                .join("example.com"),
        )
        .map_err(|error| error.to_string())?;
        assert_eq!(content, "server { listen 8080; }\n");
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn managed_config_syntax_failure_restores_exact_content() -> Result<(), String> {
        let root = test_root("managed-rollback")?;
        let service = fixture_service(&root, Arc::new(FakeRunner::syntax_failure_then_rollback()))?;
        let plan = managed_plan(&service, 1_000, "server { invalid; }\n", "managed-key-0002")?;
        let receipt = approve_managed(&service, &plan, 1_001, "managed-key-0002", true)?;
        assert_eq!(
            receipt.terminal_state,
            jw_contracts::OperationStage::RolledBack
        );
        assert_eq!(receipt.after_digest, sha256_digest(b"server {}\n"));
        let content = fs::read_to_string(
            OpsPaths::for_test(&root)
                .nginx_available
                .join("example.com"),
        )
        .map_err(|error| error.to_string())?;
        assert_eq!(content, "server {}\n");
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn managed_config_external_edit_cancels_without_overwrite() -> Result<(), String> {
        let root = test_root("managed-stale")?;
        let service = fixture_service(&root, Arc::new(FakeRunner::all_success()))?;
        let plan = managed_plan(
            &service,
            1_000,
            "server { listen 8080; }\n",
            "managed-key-0003",
        )?;
        fs::write(
            OpsPaths::for_test(&root)
                .nginx_available
                .join("example.com"),
            "server { listen 9090; }\n",
        )
        .map_err(|error| error.to_string())?;
        let receipt = approve_managed(&service, &plan, 1_001, "managed-key-0003", true)?;
        assert_eq!(
            receipt.terminal_state,
            jw_contracts::OperationStage::CancelledBeforeApply
        );
        let content = fs::read_to_string(
            OpsPaths::for_test(&root)
                .nginx_available
                .join("example.com"),
        )
        .map_err(|error| error.to_string())?;
        assert_eq!(content, "server { listen 9090; }\n");
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn managed_config_requires_both_approval_intents() -> Result<(), String> {
        let root = test_root("managed-intent")?;
        let service = fixture_service(&root, Arc::new(FakeRunner::all_success()))?;
        let plan = managed_plan(
            &service,
            1_000,
            "server { listen 8080; }\n",
            "managed-key-0004",
        )?;
        let result = approve_managed(&service, &plan, 1_001, "managed-key-0004", false);
        assert!(result.is_err());
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn expired_unapproved_managed_plan_removes_private_proposal() -> Result<(), String> {
        let root = test_root("managed-expired-proposal")?;
        let service = fixture_service(&root, Arc::new(FakeRunner::all_success()))?;
        let _plan = managed_plan(
            &service,
            1_000,
            "server { listen 8080; }\n",
            "managed-expired-01",
        )?;
        let paths = OpsPaths::for_test(&root);
        let before = fs::read_dir(&paths.proposals)
            .map_err(|error| error.to_string())?
            .count();
        assert_eq!(before, 1);
        service
            .initialize(700_001)
            .map_err(|error| error.to_string())?;
        let after = fs::read_dir(&paths.proposals)
            .map_err(|error| error.to_string())?
            .count();
        assert_eq!(after, 0);
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    #[test]
    fn restart_recovery_covers_every_durable_nginx_stage() -> Result<(), String> {
        for stage in [
            OperationStage::Approved,
            OperationStage::Snapshotted,
            OperationStage::Applying,
            OperationStage::Validating,
            OperationStage::Reloading,
            OperationStage::Verifying,
            OperationStage::RollingBack,
        ] {
            assert_restart_recovery(stage)?;
        }
        Ok(())
    }

    fn assert_restart_recovery(interrupted_stage: OperationStage) -> Result<(), String> {
        let root = test_root(interrupted_stage.as_storage_value())?;
        let service = fixture_service(&root, Arc::new(FakeRunner::all_success()))?;
        let plan = plan(&service, 1_000)?;
        let accepted = approve_only(&service, &plan, 1_001, "0123456789abcdef")?;
        assert_eq!(accepted.terminal_state, OperationStage::Approved);

        let paths = OpsPaths::for_test(&root);
        let policy = OpsPolicy::default();
        if interrupted_stage != OperationStage::Approved {
            let snapshot = NginxLinkSnapshot {
                schema_version: 1,
                site_id: plan.site_id.clone(),
                basename: String::from("example.com"),
                enabled: false,
                available_digest: plan.available_digest.clone(),
                enabled_state_digest: plan.enabled_state_digest.clone(),
            };
            let record = write_nginx_snapshot(&paths, &policy, &accepted.operation_id, &snapshot)
                .map_err(|error| error.to_string())?;
            let mut ledger = Ledger::open(&paths).map_err(|error| error.to_string())?;
            ledger
                .attach_snapshot(&accepted.operation_id, &record, 1_002)
                .map_err(|error| error.to_string())?;
            let mut current = OperationStage::Snapshotted;
            for next in [
                OperationStage::Applying,
                OperationStage::Validating,
                OperationStage::Reloading,
                OperationStage::Verifying,
                OperationStage::RollingBack,
            ] {
                if current == interrupted_stage {
                    break;
                }
                ledger
                    .transition(
                        &accepted.operation_id,
                        Transition {
                            expected: &[current],
                            next,
                            result_code: "restart_fixture_stage",
                            evidence_digest: &sha256_digest(next.as_storage_value().as_bytes()),
                            after_digest: None,
                            rollback_result: None,
                            now_ms: 1_003,
                        },
                    )
                    .map_err(|error| error.to_string())?;
                current = next;
            }
            assert_eq!(current, interrupted_stage);
        }
        drop(service);

        let restarted = OpsService::new(paths.clone(), policy, Arc::new(FakeRunner::all_success()));
        restarted
            .initialize(2_000)
            .map_err(|error| error.to_string())?;
        let ledger = Ledger::open(&paths).map_err(|error| error.to_string())?;
        let receipt = ledger
            .receipt(&accepted.operation_id)
            .map_err(|error| error.to_string())?;
        let expected = if matches!(
            interrupted_stage,
            OperationStage::Approved | OperationStage::Snapshotted
        ) {
            OperationStage::CancelledBeforeApply
        } else {
            OperationStage::RolledBack
        };
        assert_eq!(receipt.terminal_state, expected);
        assert!(!paths.nginx_enabled.join("example.com").exists());
        fs::remove_dir_all(root).map_err(|error| error.to_string())
    }

    fn fixture_service(
        root: &std::path::Path,
        runner: Arc<dyn OperationRunner>,
    ) -> Result<OpsService, String> {
        fixture_service_with_certbot(root, runner, Arc::new(FakeCertbotRunner::new(false)))
    }

    fn fixture_service_with_certbot(
        root: &std::path::Path,
        runner: Arc<dyn OperationRunner>,
        certbot_runner: Arc<dyn CertbotRunner>,
    ) -> Result<OpsService, String> {
        let paths = OpsPaths::for_test(root);
        fs::create_dir_all(&paths.nginx_available).map_err(|error| error.to_string())?;
        fs::create_dir_all(&paths.nginx_enabled).map_err(|error| error.to_string())?;
        fs::write(paths.nginx_available.join("example.com"), b"server {}\n")
            .map_err(|error| error.to_string())?;
        if let Some(parent) = paths.certbot_executable.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        fs::write(&paths.certbot_executable, b"test fixture").map_err(|error| error.to_string())?;
        let service = OpsService::new_with_certbot_runner(
            paths,
            OpsPolicy::default(),
            runner,
            certbot_runner,
        );
        service.initialize(900).map_err(|error| error.to_string())?;
        Ok(service)
    }

    fn fixture_issue_service(
        root: &std::path::Path,
        runner: Arc<dyn OperationRunner>,
        certbot_runner: Arc<dyn CertbotRunner>,
    ) -> Result<OpsService, String> {
        let service = fixture_service_with_certbot(root, runner, certbot_runner)?;
        let paths = OpsPaths::for_test(root);
        let content = issue_site_content();
        fs::write(paths.nginx_available.join("example.com"), content)
            .map_err(|error| error.to_string())?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            "../sites-available/example.com",
            paths.nginx_enabled.join("example.com"),
        )
        .map_err(|error| error.to_string())?;
        fs::create_dir_all(&paths.acme_webroot).map_err(|error| error.to_string())?;
        Ok(service)
    }

    fn fixture_attach_service(
        root: &std::path::Path,
        runner: Arc<dyn OperationRunner>,
        certbot_runner: Arc<dyn CertbotRunner>,
    ) -> Result<OpsService, String> {
        let service = fixture_service_with_certbot(root, runner, certbot_runner)?;
        let paths = OpsPaths::for_test(root);
        let content = b"# jw-agent:protected-management-v1\nserver {\n    listen 443 ssl;\n    server_name example.com;\n    ssl_certificate /legacy/server.crt;\n    ssl_certificate_key /legacy/server.key;\n    location / { proxy_pass http://unix:/run/jw-agent/agentd.sock; }\n}\n";
        fs::write(paths.nginx_available.join("example.com"), content)
            .map_err(|error| error.to_string())?;
        std::os::unix::fs::symlink(
            "../sites-available/example.com",
            paths.nginx_enabled.join("example.com"),
        )
        .map_err(|error| error.to_string())?;
        create_test_lineage(&paths, "example.com")?;
        Ok(service)
    }

    fn create_test_lineage(paths: &OpsPaths, domain: &str) -> Result<(), String> {
        let archive = paths.letsencrypt_archive.join(domain);
        let live = paths.letsencrypt_live.join(domain);
        fs::create_dir_all(&archive).map_err(|error| error.to_string())?;
        fs::create_dir_all(&live).map_err(|error| error.to_string())?;
        fs::create_dir_all(&paths.letsencrypt_renewal).map_err(|error| error.to_string())?;
        let fullchain = archive.join("fullchain1.pem");
        let private_key = archive.join("privkey1.pem");
        let status = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes"])
            .arg("-keyout")
            .arg(&private_key)
            .arg("-out")
            .arg(&fullchain)
            .args([
                "-days",
                "2",
                "-subj",
                "/CN=example.com",
                "-addext",
                "subjectAltName=DNS:example.com",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|error| error.to_string())?;
        if !status.success() {
            return Err(String::from("test certificate generation failed"));
        }
        std::os::unix::fs::symlink(
            "../../archive/example.com/fullchain1.pem",
            live.join("fullchain.pem"),
        )
        .map_err(|error| error.to_string())?;
        std::os::unix::fs::symlink(
            "../../archive/example.com/privkey1.pem",
            live.join("privkey.pem"),
        )
        .map_err(|error| error.to_string())?;
        fs::write(
            paths.letsencrypt_renewal.join(format!("{domain}.conf")),
            "[renewalparams]\nauthenticator = webroot\nwebroot_path = /var/lib/jw-agent/acme-webroot\n",
        )
        .map_err(|error| error.to_string())
    }

    fn issue_site_content() -> &'static [u8] {
        b"# jw-agent:protected-management-v1\nserver {\n    listen 80;\n    server_name example.com;\n    include /usr/share/jw-agent/nginx/acme-challenge.conf;\n}\n"
    }

    fn certbot_issue_plan(
        service: &OpsService,
        now_ms: i64,
        idempotency_key: &str,
        environment: CertificateEnvironment,
    ) -> Result<jw_contracts::CertbotIssuePlanView, String> {
        let inventory_request = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-certbot-issue-inventory"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::CertificateInventory { actor: actor() },
        };
        let inventory_response = service.response_for(&inventory_request, now_ms);
        let OpsResponseBody::CertificateInventory(inventory) = inventory_response.body else {
            return Err(String::from("certificate inventory rejected"));
        };
        let request = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-certbot-issue-plan"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::PlanCertbotIssue {
                actor: actor(),
                plan: CertbotIssuePlanInput {
                    request: CertbotIssuePlanRequest {
                        schema_version: 1,
                        operation_type: String::from(CERTBOT_ISSUE_OPERATION),
                        primary_domain: String::from("example.com"),
                        alternative_domains: Vec::new(),
                        account_email: String::from("owner@example.com"),
                        environment,
                        site_id: site_id(NGINX_LAYOUT_ID, "example.com"),
                        expected_site_digest: sha256_digest(issue_site_content()),
                        expected_inventory_digest: inventory.inventory_digest,
                        tos_agreed: true,
                        idempotency_key: idempotency_key.to_owned(),
                    },
                    preflight: CertbotIssuePreflightEvidence {
                        observed_at_unix_ms: now_ms,
                        resolved_addresses: vec![String::from("192.0.2.10")],
                        expected_addresses: vec![String::from("192.0.2.10")],
                        local_port_80_reachable: true,
                        local_port_443_reachable: true,
                    },
                },
            },
        };
        let response = service.response_for(&request, now_ms);
        let OpsResponseBody::CertbotIssuePlan(plan) = response.body else {
            return Err(String::from("certbot issue plan rejected"));
        };
        Ok(plan)
    }

    fn approve_certbot_issue(
        service: &OpsService,
        plan: &jw_contracts::CertbotIssuePlanView,
        now_ms: i64,
        idempotency_key: &str,
    ) -> Result<jw_contracts::OperationReceiptView, String> {
        let approval = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-certbot-issue-approve"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::ApproveCertbotIssue {
                actor: actor(),
                plan_id: plan.plan_id.clone(),
                plan_hash: plan.plan_hash.clone(),
                idempotency_key: idempotency_key.to_owned(),
                external_effect_confirmed: true,
                local_attach_deferred_confirmed: true,
            },
        };
        let approval_response = service.response_for(&approval, now_ms);
        let OpsResponseBody::OperationReceipt(accepted) = approval_response.body else {
            return Err(String::from("certbot issue approval rejected"));
        };
        let execute = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-certbot-issue-execute"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::ExecuteOperation {
                actor: actor(),
                operation_id: accepted.operation_id,
            },
        };
        let response = service.response_for(&execute, now_ms);
        let OpsResponseBody::OperationReceipt(receipt) = response.body else {
            return Err(String::from("certbot issue execution rejected"));
        };
        Ok(receipt)
    }

    fn certbot_attach_plan(
        service: &OpsService,
        now_ms: i64,
        idempotency_key: &str,
    ) -> Result<jw_contracts::CertbotAttachPlanView, String> {
        let inventory_request = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-certbot-attach-inventory"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::CertificateInventory { actor: actor() },
        };
        let inventory_response = service.response_for(&inventory_request, now_ms);
        let OpsResponseBody::CertificateInventory(inventory) = inventory_response.body else {
            return Err(String::from("certificate inventory rejected"));
        };
        let certificate = inventory
            .certificates
            .first()
            .ok_or_else(|| String::from("certificate fixture missing"))?;
        let request = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-certbot-attach-plan"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::PlanCertbotAttach {
                actor: actor(),
                plan: CertbotAttachPlanRequest {
                    schema_version: 1,
                    operation_type: String::from(CERTBOT_ATTACH_OPERATION),
                    primary_domain: String::from("example.com"),
                    site_id: site_id(NGINX_LAYOUT_ID, "example.com"),
                    expected_site_digest: sha256_digest(
                        b"# jw-agent:protected-management-v1\nserver {\n    listen 443 ssl;\n    server_name example.com;\n    ssl_certificate /legacy/server.crt;\n    ssl_certificate_key /legacy/server.key;\n    location / { proxy_pass http://unix:/run/jw-agent/agentd.sock; }\n}\n",
                    ),
                    expected_inventory_digest: inventory.inventory_digest,
                    expected_certificate_fingerprint: certificate.fingerprint_sha256.clone(),
                    idempotency_key: idempotency_key.to_owned(),
                },
            },
        };
        let response = service.response_for(&request, now_ms);
        match response.body {
            OpsResponseBody::CertbotAttachPlan(plan) => Ok(plan),
            OpsResponseBody::Rejected(rejected) => {
                Err(format!("certbot attach plan rejected: {}", rejected.code))
            }
            _ => Err(String::from("certbot attach plan response mismatch")),
        }
    }

    fn approve_certbot_attach(
        service: &OpsService,
        plan: &jw_contracts::CertbotAttachPlanView,
        now_ms: i64,
        idempotency_key: &str,
    ) -> Result<jw_contracts::OperationReceiptView, String> {
        let approval = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-certbot-attach-approve"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::ApproveCertbotAttach {
                actor: actor(),
                plan_id: plan.plan_id.clone(),
                plan_hash: plan.plan_hash.clone(),
                idempotency_key: idempotency_key.to_owned(),
                config_replace_confirmed: true,
                service_reload_confirmed: true,
            },
        };
        let approval_response = service.response_for(&approval, now_ms);
        let OpsResponseBody::OperationReceipt(accepted) = approval_response.body else {
            return Err(String::from("certbot attach approval rejected"));
        };
        let execute = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-certbot-attach-execute"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::ExecuteOperation {
                actor: actor(),
                operation_id: accepted.operation_id,
            },
        };
        let response = service.response_for(&execute, now_ms);
        let OpsResponseBody::OperationReceipt(receipt) = response.body else {
            return Err(String::from("certbot attach execution rejected"));
        };
        Ok(receipt)
    }

    fn certbot_renew_plan(
        service: &OpsService,
        now_ms: i64,
        idempotency_key: &str,
    ) -> Result<jw_contracts::CertbotRenewTestPlanView, String> {
        let inventory_request = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-certbot-inventory"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::CertificateInventory { actor: actor() },
        };
        let inventory_response = service.response_for(&inventory_request, now_ms);
        let OpsResponseBody::CertificateInventory(inventory) = inventory_response.body else {
            return Err(String::from("certificate inventory rejected"));
        };
        let request = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-certbot-renew-plan"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::PlanCertbotRenewTest {
                actor: actor(),
                plan: CertbotRenewTestPlanRequest {
                    schema_version: 1,
                    operation_type: String::from(CERTBOT_RENEW_TEST_OPERATION),
                    expected_inventory_digest: inventory.inventory_digest,
                    idempotency_key: idempotency_key.to_owned(),
                },
            },
        };
        let response = service.response_for(&request, now_ms);
        let OpsResponseBody::CertbotRenewTestPlan(plan) = response.body else {
            return Err(String::from("certbot renew plan rejected"));
        };
        Ok(plan)
    }

    fn approve_certbot_renew(
        service: &OpsService,
        plan: &jw_contracts::CertbotRenewTestPlanView,
        now_ms: i64,
        idempotency_key: &str,
    ) -> Result<jw_contracts::OperationReceiptView, String> {
        let approval = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-certbot-renew-approve"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::ApproveCertbotRenewTest {
                actor: actor(),
                plan_id: plan.plan_id.clone(),
                plan_hash: plan.plan_hash.clone(),
                idempotency_key: idempotency_key.to_owned(),
                external_effect_confirmed: true,
            },
        };
        let approval_response = service.response_for(&approval, now_ms);
        let OpsResponseBody::OperationReceipt(accepted) = approval_response.body else {
            return Err(String::from("certbot renew approval rejected"));
        };
        let execute = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-certbot-renew-execute"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::ExecuteOperation {
                actor: actor(),
                operation_id: accepted.operation_id,
            },
        };
        let response = service.response_for(&execute, now_ms);
        let OpsResponseBody::OperationReceipt(receipt) = response.body else {
            return Err(String::from("certbot renew execution rejected"));
        };
        Ok(receipt)
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
        let accepted = approve_only(service, plan, now_ms, idempotency_key)?;
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

    fn approve_only(
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
        Ok(accepted)
    }

    fn managed_plan(
        service: &OpsService,
        now_ms: i64,
        proposed_content: &str,
        idempotency_key: &str,
    ) -> Result<jw_contracts::ManagedConfigPlanView, String> {
        let paths = service.paths.clone();
        let enabled = paths.nginx_enabled.join("example.com");
        if !enabled.exists() {
            std::os::unix::fs::symlink("../sites-available/example.com", &enabled)
                .map_err(|error| error.to_string())?;
        }
        let resource_id = nginx_config_resource_id(NGINX_CONFIG_ADAPTER_ID, "example.com");
        let resource = crate::managed_config::discover_managed_config(&paths, &resource_id)
            .map_err(|error| error.to_string())?;
        let request = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-managed-plan"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::PlanManagedConfig {
                actor: actor(),
                plan: ManagedConfigPlanRequest {
                    schema_version: 1,
                    operation_type: String::from(MANAGED_CONFIG_OPERATION),
                    resource_id,
                    expected_content_digest: resource.content_digest,
                    expected_metadata_digest: resource.metadata_digest,
                    proposed_content: proposed_content.to_owned(),
                    service_action: ServiceAction::Reload,
                    idempotency_key: idempotency_key.to_owned(),
                },
            },
        };
        let response = service.response_for(&request, now_ms);
        let OpsResponseBody::ManagedConfigPlan(plan) = response.body else {
            return Err(String::from("managed plan response rejected"));
        };
        Ok(plan)
    }

    fn approve_managed(
        service: &OpsService,
        plan: &jw_contracts::ManagedConfigPlanView,
        now_ms: i64,
        idempotency_key: &str,
        confirmed: bool,
    ) -> Result<jw_contracts::OperationReceiptView, String> {
        let request = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-managed-approve"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::ApproveManagedConfig {
                actor: actor(),
                plan_id: plan.plan_id.clone(),
                plan_hash: plan.plan_hash.clone(),
                idempotency_key: idempotency_key.to_owned(),
                approval_intent: ManagedConfigApprovalIntent {
                    validation_confirmed: confirmed,
                    service_action_confirmed: confirmed,
                },
            },
        };
        let response = service.response_for(&request, now_ms);
        let OpsResponseBody::OperationReceipt(accepted) = response.body else {
            return Err(String::from("managed approval response rejected"));
        };
        let execute = OpsRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: String::from("request-managed-execute"),
            deadline_unix_ms: now_ms.saturating_add(1_000),
            body: OpsRequestBody::ExecuteOperation {
                actor: actor(),
                operation_id: accepted.operation_id,
            },
        };
        let response = service.response_for(&execute, now_ms);
        let OpsResponseBody::OperationReceipt(receipt) = response.body else {
            return Err(String::from("managed execution response rejected"));
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
