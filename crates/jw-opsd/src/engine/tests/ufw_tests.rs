use std::sync::{Arc, Mutex};

use jw_contracts::{
    OperationStage, Role, Subject, UFW_RULE_OPERATION, UfwProtocol, UfwRuleMutation,
    UfwRulePlanRequest, UfwStatus, sha256_digest,
};

use crate::config::{OpsPaths, OpsPolicy};
use crate::error::OpsError;
use crate::runner::{CommandClass, CommandEvidence, OperationRunner, StreamEvidence};
use crate::ufw::{UfwCommand, UfwRuleSpec};

use super::OpsService;

#[derive(Debug)]
struct StatefulUfwRunner {
    rules: Mutex<Vec<UfwRuleSpec>>,
    mutations_visible: bool,
}

impl StatefulUfwRunner {
    fn working() -> Self {
        Self {
            rules: Mutex::new(Vec::new()),
            mutations_visible: true,
        }
    }

    fn invisible_mutation() -> Self {
        Self {
            rules: Mutex::new(Vec::new()),
            mutations_visible: false,
        }
    }

    fn status(&self) -> Result<String, OpsError> {
        let rules = self
            .rules
            .lock()
            .map_err(|_| OpsError::Command(String::from("fake UFW state poisoned")))?;
        let mut output = String::from("Status: active\n");
        for (index, rule) in rules.iter().enumerate() {
            output.push_str(&format!(
                "[ {}] {}/{} {} IN {} # jw-agent:{}\n",
                index.saturating_add(1),
                rule.port,
                rule.protocol.as_str(),
                rule.mutation.as_str().to_ascii_uppercase(),
                if rule.source == "any" {
                    "Anywhere"
                } else {
                    &rule.source
                },
                rule.rule_id
            ));
        }
        Ok(output)
    }
}

impl OperationRunner for StatefulUfwRunner {
    fn run(&self, _class: CommandClass) -> Result<CommandEvidence, OpsError> {
        Err(OpsError::Command(String::from("unexpected fixed command")))
    }

    fn run_ufw(&self, command: &UfwCommand) -> Result<CommandEvidence, OpsError> {
        let class = match command {
            UfwCommand::Status => CommandClass::UfwStatus,
            UfwCommand::Add(_) => CommandClass::UfwRuleAdd,
            UfwCommand::Delete { .. } => CommandClass::UfwRuleDelete,
        };
        match command {
            UfwCommand::Status => {}
            UfwCommand::Add(rule) if self.mutations_visible => {
                self.rules
                    .lock()
                    .map_err(|_| OpsError::Command(String::from("fake UFW state poisoned")))?
                    .push(rule.clone());
            }
            UfwCommand::Delete { sequence } if self.mutations_visible => {
                let mut rules = self
                    .rules
                    .lock()
                    .map_err(|_| OpsError::Command(String::from("fake UFW state poisoned")))?;
                let index = usize::from(*sequence).saturating_sub(1);
                if index >= rules.len() {
                    return Ok(evidence(class, false, ""));
                }
                rules.remove(index);
            }
            UfwCommand::Add(_) | UfwCommand::Delete { .. } => {}
        }
        let output = if matches!(command, UfwCommand::Status) {
            self.status()?
        } else {
            String::from("Rule updated\n")
        };
        Ok(evidence(class, true, &output))
    }
}

#[test]
fn missing_ufw_is_observed_as_not_installed_without_running_a_command() -> Result<(), String> {
    let root = test_root("ufw-not-installed")?;
    let mut paths = OpsPaths::for_test(&root);
    paths.enforce_root_ownership = true;
    let service = OpsService::new(
        paths,
        OpsPolicy::default(),
        Arc::new(StatefulUfwRunner::working()),
    );
    let inventory = service
        .ufw_inventory(900)
        .map_err(|error| error.to_string())?;

    assert_eq!(inventory.status, UfwStatus::NotInstalled);
    assert!(!inventory.mutation_available);
    assert_eq!(
        inventory.blocked_reason.as_deref(),
        Some("ufw_not_installed")
    );
    Ok(())
}

#[test]
fn typed_ufw_add_reaches_verified_receipt() -> Result<(), String> {
    let root = test_root("ufw-add")?;
    let runner = Arc::new(StatefulUfwRunner::working());
    let service = OpsService::new(
        OpsPaths::for_test(&root),
        OpsPolicy::default(),
        runner.clone(),
    );
    service
        .initialize(1_000)
        .map_err(|error| error.to_string())?;
    let inventory = service
        .ufw_inventory(1_001)
        .map_err(|error| error.to_string())?;
    let request = add_request(inventory.state_digest, "ufw-add-key-0001");
    let plan = service
        .plan_ufw_rule(&actor(), &request, 1_002)
        .map_err(|error| error.to_string())?;
    let approved = service
        .approve_ufw_rule(
            &actor(),
            &plan.plan_id,
            &plan.plan_hash,
            "ufw-add-key-0001",
            1_003,
        )
        .map_err(|error| error.to_string())?;
    let receipt = service
        .execute_operation(&actor(), &approved.operation_id, 1_004)
        .map_err(|error| error.to_string())?;

    assert_eq!(receipt.operation_type, UFW_RULE_OPERATION);
    assert_eq!(receipt.terminal_state, OperationStage::Succeeded);
    assert_eq!(
        runner
            .rules
            .lock()
            .map_err(|_| String::from("fake state poisoned"))?
            .len(),
        1
    );
    std::fs::remove_dir_all(root).map_err(|error| error.to_string())
}

#[test]
fn missing_ufw_read_back_rolls_back_instead_of_reporting_success() -> Result<(), String> {
    let root = test_root("ufw-rollback")?;
    let runner = Arc::new(StatefulUfwRunner::invisible_mutation());
    let service = OpsService::new(OpsPaths::for_test(&root), OpsPolicy::default(), runner);
    service
        .initialize(2_000)
        .map_err(|error| error.to_string())?;
    let inventory = service
        .ufw_inventory(2_001)
        .map_err(|error| error.to_string())?;
    let request = add_request(inventory.state_digest, "ufw-add-key-0002");
    let plan = service
        .plan_ufw_rule(&actor(), &request, 2_002)
        .map_err(|error| error.to_string())?;
    let approved = service
        .approve_ufw_rule(
            &actor(),
            &plan.plan_id,
            &plan.plan_hash,
            "ufw-add-key-0002",
            2_003,
        )
        .map_err(|error| error.to_string())?;
    let receipt = service
        .execute_operation(&actor(), &approved.operation_id, 2_004)
        .map_err(|error| error.to_string())?;

    assert_eq!(receipt.terminal_state, OperationStage::RolledBack);
    assert_eq!(receipt.rollback_result.as_deref(), Some("restored"));
    std::fs::remove_dir_all(root).map_err(|error| error.to_string())
}

fn add_request(state_digest: String, key: &str) -> UfwRulePlanRequest {
    UfwRulePlanRequest {
        schema_version: 1,
        operation_type: String::from(UFW_RULE_OPERATION),
        mutation: UfwRuleMutation::Allow,
        protocol: Some(UfwProtocol::Tcp),
        port: Some(8080),
        source: None,
        rule_id: None,
        expected_state_digest: state_digest,
        idempotency_key: String::from(key),
    }
}

fn actor() -> Subject {
    Subject {
        uid: 1_000,
        username: String::from("operator"),
        role: Role::Admin,
    }
}

fn evidence(class: CommandClass, success: bool, output: &str) -> CommandEvidence {
    CommandEvidence {
        class,
        success,
        exit_code: Some(if success { 0 } else { 1 }),
        timed_out: false,
        stdout: StreamEvidence {
            digest: sha256_digest(output.as_bytes()),
            captured: output.as_bytes().to_vec(),
            truncated: false,
        },
        stderr: StreamEvidence {
            digest: sha256_digest(&[]),
            captured: Vec::new(),
            truncated: false,
        },
    }
}

fn test_root(label: &str) -> Result<std::path::PathBuf, String> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|error| error.to_string())?;
    Ok(std::env::temp_dir().join(format!(
        "jw-opsd-{label}-{}-{}",
        std::process::id(),
        u64::from_le_bytes(random)
    )))
}
