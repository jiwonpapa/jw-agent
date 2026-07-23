use super::*;

struct ManagedPlanStorage {
    plan_id: String,
    proposal: ProposalRecord,
    operation_type: &'static str,
    request_digest: String,
}

impl OpsService {
    pub(super) fn plan_managed_config(
        &self,
        actor: &Subject,
        request: &ManagedConfigPlanRequest,
        now_ms: i64,
    ) -> Result<ManagedConfigPlanView, OpsError> {
        request.validate().map_err(OpsError::Rejected)?;
        let ledger = self.open_ledger()?;
        self.remove_expired_proposals(&ledger, now_ms)?;
        drop(ledger);
        let resource = discover_managed_config(&self.paths, &request.resource_id)?;
        if request.proposed_content.len() > resource.adapter.maximum_bytes() {
            return Err(OpsError::Rejected("size_limit"));
        }
        if resource.content_digest != request.expected_content_digest
            || resource.metadata_digest != request.expected_metadata_digest
        {
            return Err(OpsError::Rejected("stale_resource"));
        }
        validate_managed_config_candidate(
            resource.adapter,
            &resource.content,
            &request.proposed_content,
        )?;
        let plan_id = random_id("plan")?;
        let created_plan_id = plan_id.clone();
        let proposal = write_proposal(
            &self.paths,
            &self.policy,
            &plan_id,
            &request.proposed_content,
        )?;
        let request_digest = canonical_digest(
            b"jw-agent/operation-request/v1",
            &ManagedPlanRequestDigest {
                operation_type: MANAGED_CONFIG_OPERATION,
                actor,
                request,
            },
        )?;
        let result = self.store_managed_config_plan(
            actor,
            request,
            resource,
            ManagedPlanStorage {
                plan_id,
                proposal: proposal.clone(),
                operation_type: MANAGED_CONFIG_OPERATION,
                request_digest,
            },
            now_ms,
        );
        if result
            .as_ref()
            .map_or(true, |stored| stored.plan_id != created_plan_id)
        {
            let _cleanup = remove_proposal(&self.paths, &proposal);
        }
        result.and_then(|stored| {
            let ledger = self.open_ledger()?;
            ledger.managed_config_plan_view(&stored)
        })
    }

    pub(super) fn plan_managed_config_restore(
        &self,
        actor: &Subject,
        request: &ManagedConfigRestorePlanRequest,
        now_ms: i64,
    ) -> Result<ManagedConfigPlanView, OpsError> {
        request.validate().map_err(OpsError::Rejected)?;
        let ledger = self.open_ledger()?;
        let source = ledger.load_operation(&request.source_operation_id)?;
        if source.plan.actor.uid != actor.uid
            || !matches!(
                source.plan.operation_type.as_str(),
                MANAGED_CONFIG_OPERATION | MANAGED_CONFIG_RESTORE_OPERATION
            )
            || source.stage != OperationStage::Succeeded
        {
            return Err(OpsError::Rejected("restore_source_unavailable"));
        }
        let record = source
            .snapshot
            .as_ref()
            .ok_or(OpsError::Rejected("restore_source_unavailable"))?;
        let snapshot = read_managed_config_snapshot(&self.paths, record)?;
        let resource = discover_managed_config(&self.paths, &snapshot.resource_id)?;
        if resource.content_digest != request.expected_content_digest
            || resource.metadata_digest != request.expected_metadata_digest
        {
            return Err(OpsError::Rejected("stale_resource"));
        }
        validate_managed_config_candidate(resource.adapter, &resource.content, &snapshot.content)?;
        let plan_id = random_id("plan")?;
        let created_plan_id = plan_id.clone();
        let proposal = write_proposal(&self.paths, &self.policy, &plan_id, &snapshot.content)?;
        let internal = ManagedConfigPlanRequest {
            schema_version: request.schema_version,
            operation_type: String::from(MANAGED_CONFIG_OPERATION),
            resource_id: snapshot.resource_id,
            expected_content_digest: request.expected_content_digest.clone(),
            expected_metadata_digest: request.expected_metadata_digest.clone(),
            proposed_content: snapshot.content,
            service_action: jw_contracts::ServiceAction::Reload,
            idempotency_key: request.idempotency_key.clone(),
        };
        let request_digest = canonical_digest(
            b"jw-agent/operation-request/v1",
            &ManagedRestorePlanRequestDigest {
                operation_type: MANAGED_CONFIG_RESTORE_OPERATION,
                actor,
                request,
            },
        )?;
        let result = self.store_managed_config_plan(
            actor,
            &internal,
            resource,
            ManagedPlanStorage {
                plan_id,
                proposal: proposal.clone(),
                operation_type: MANAGED_CONFIG_RESTORE_OPERATION,
                request_digest,
            },
            now_ms,
        );
        if result
            .as_ref()
            .map_or(true, |stored| stored.plan_id != created_plan_id)
        {
            let _cleanup = remove_proposal(&self.paths, &proposal);
        }
        result.and_then(|stored| self.open_ledger()?.managed_config_plan_view(&stored))
    }

    fn store_managed_config_plan(
        &self,
        actor: &Subject,
        request: &ManagedConfigPlanRequest,
        resource: crate::managed_config::ManagedConfigResource,
        storage: ManagedPlanStorage,
        now_ms: i64,
    ) -> Result<StoredPlan, OpsError> {
        let ttl_ms = i64::try_from(self.policy.plan_ttl.as_millis())
            .map_err(|_| OpsError::Storage(String::from("plan ttl overflow")))?;
        let expires_at_ms = now_ms.saturating_add(ttl_ms);
        let stats = diff_stats(&resource.content, &request.proposed_content);
        let current_bytes =
            u32::try_from(resource.content.len()).map_err(|_| OpsError::Rejected("size_limit"))?;
        let proposed_bytes = u32::try_from(request.proposed_content.len())
            .map_err(|_| OpsError::Rejected("size_limit"))?;
        let payload = ManagedConfigPlanPayload {
            proposal_relative_path: storage.proposal.relative_path,
            proposal_digest: storage.proposal.digest,
            proposed_content_digest: sha256_digest(request.proposed_content.as_bytes()),
            current_bytes,
            proposed_bytes,
            added_lines: stats.added_lines,
            removed_lines: stats.removed_lines,
            diff_summary: stats.summary,
            service_action: request.service_action,
        };
        let mut plan = StoredPlan {
            operation_type: String::from(storage.operation_type),
            plan_id: storage.plan_id,
            plan_hash: String::new(),
            actor: actor.clone(),
            site_id: resource.resource_id,
            display_name: resource.display_name,
            current_state: NginxSiteState::Disabled,
            target_state: NginxSiteState::Disabled,
            available_digest: resource.content_digest,
            enabled_state_digest: resource.metadata_digest,
            created_at_ms: now_ms,
            expires_at_ms,
            idempotency_key: request.idempotency_key.clone(),
            request_digest: storage.request_digest,
            resource_key: format!(
                "config/{}/{}",
                resource.adapter.adapter_id(),
                request.resource_id
            ),
            assurance: managed_config_assurance(resource.adapter),
            managed_config: Some(payload),
            certbot_renew: None,
            certbot_issue: None,
            certbot_attach: None,
        };
        plan.plan_hash = managed_config_plan_hash(&plan)?;
        let mut ledger = self.open_ledger()?;
        ledger.create_or_reuse_plan(&plan)
    }

    pub(super) fn approve_managed_config(
        &self,
        actor: &Subject,
        plan_id: &str,
        plan_hash: &str,
        idempotency_key: &str,
        approval_intent: &ManagedConfigApprovalIntent,
        now_ms: i64,
    ) -> Result<OperationReceiptView, OpsError> {
        approval_intent.validate().map_err(OpsError::Rejected)?;
        let mut ledger = self.open_ledger()?;
        let plan = ledger.load_plan(plan_id)?;
        if plan.operation_type != MANAGED_CONFIG_OPERATION
            && plan.operation_type != MANAGED_CONFIG_RESTORE_OPERATION
        {
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
        );
        let operation = match operation {
            Ok(operation) => operation,
            Err(OpsError::Rejected("plan_expired")) => {
                self.remove_plan_proposal(&plan);
                return Err(OpsError::Rejected("plan_expired"));
            }
            Err(error) => return Err(error),
        };
        ledger.receipt(&operation.operation_id)
    }
}
