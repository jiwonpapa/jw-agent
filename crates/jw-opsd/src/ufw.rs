use jw_contracts::{
    AssuranceLevel, AssuranceView, RollbackSupport, UFW_COMMENT_PREFIX, UFW_RULE_MAX_ENTRIES,
    UfwProtocol, UfwRuleMutation, UfwRuleView, UfwStatus, UfwView, sha256_digest,
    ufw_protected_tcp_port,
};
use serde::{Deserialize, Serialize};

use crate::error::OpsError;
use crate::runner::{CommandClass, CommandEvidence, OperationRunner};

pub const UFW_IMPACT: [&str; 2] = [
    "활성 UFW에 JW Agent 소유 인바운드 규칙 하나를 추가하거나 삭제합니다.",
    "SSH·HTTPS·독립 관리 edge와 기존 사용자 규칙은 변경하지 않습니다.",
];
pub const UFW_RECOVERY_PATH: [&str; 4] = [
    "독립 JW Agent edge 또는 SSH로 서버에 접속합니다.",
    "JW Agent receipt의 operation ID와 UFW status digest를 확인합니다.",
    "sudo ufw status numbered로 제품 소유 comment를 확인합니다.",
    "자동 원복이 실패한 제품 소유 규칙만 수동으로 복구합니다.",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UfwRuleSpec {
    pub mutation: UfwRuleMutation,
    pub protocol: UfwProtocol,
    pub port: u16,
    pub source: String,
    pub rule_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UfwPlanPayload {
    pub requested_mutation: UfwRuleMutation,
    pub rule: UfwRuleSpec,
    pub delete_sequences: Vec<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UfwCommand {
    Status,
    Add(UfwRuleSpec),
    Delete { sequence: u16 },
}

impl UfwCommand {
    pub(crate) fn registered_arguments(&self) -> (CommandClass, Vec<String>) {
        match self {
            Self::Status => (
                CommandClass::UfwStatus,
                vec![String::from("status"), String::from("numbered")],
            ),
            Self::Add(rule) => (
                CommandClass::UfwRuleAdd,
                vec![
                    String::from(rule.mutation.as_str()),
                    String::from("from"),
                    rule.source.clone(),
                    String::from("to"),
                    String::from("any"),
                    String::from("port"),
                    rule.port.to_string(),
                    String::from("proto"),
                    String::from(rule.protocol.as_str()),
                    String::from("comment"),
                    format!("{UFW_COMMENT_PREFIX}{}", rule.rule_id),
                ],
            ),
            Self::Delete { sequence } => (
                CommandClass::UfwRuleDelete,
                vec![
                    String::from("--force"),
                    String::from("delete"),
                    sequence.to_string(),
                ],
            ),
        }
    }
}

pub fn observe_ufw(runner: &dyn OperationRunner, observed_at: String) -> Result<UfwView, OpsError> {
    let evidence = runner.run_ufw(&UfwCommand::Status)?;
    Ok(parse_ufw_status(&evidence, observed_at))
}

#[must_use]
pub fn parse_ufw_status(evidence: &CommandEvidence, observed_at: String) -> UfwView {
    let output = String::from_utf8_lossy(&evidence.stdout.captured);
    let status = if output.lines().any(|line| line.trim() == "Status: active") {
        UfwStatus::Active
    } else if output.lines().any(|line| line.trim() == "Status: inactive") {
        UfwStatus::Inactive
    } else {
        UfwStatus::Unavailable
    };
    let mut rules = output
        .lines()
        .filter_map(parse_numbered_rule)
        .collect::<Vec<_>>();
    let truncated = rules.len() > UFW_RULE_MAX_ENTRIES || evidence.stdout.truncated;
    rules.truncate(UFW_RULE_MAX_ENTRIES);
    let mutation_available = status == UfwStatus::Active && evidence.success && !truncated;
    let blocked_reason = if status == UfwStatus::Inactive {
        Some(String::from("ufw_inactive"))
    } else if !evidence.success || status == UfwStatus::Unavailable {
        Some(String::from("ufw_unavailable"))
    } else if truncated {
        Some(String::from("rule_inventory_truncated"))
    } else {
        None
    };
    UfwView {
        observed_at,
        status,
        default_incoming: None,
        default_outgoing: None,
        rules,
        state_digest: sha256_digest(&evidence.stdout.captured),
        truncated,
        mutation_available,
        blocked_reason: blocked_reason.clone(),
        assurance: ufw_assurance(mutation_available, blocked_reason),
    }
}

#[must_use]
pub fn ufw_assurance(operation_available: bool, reason: Option<String>) -> AssuranceView {
    AssuranceView {
        level: AssuranceLevel::G2ReversibleConfig,
        rollback_support: RollbackSupport::AutomaticBounded,
        operation_available,
        scope: vec![String::from(
            "이번 작업의 JW Agent 소유 UFW 규칙 한 개와 verified status read-back",
        )],
        excluded_effects: vec![
            String::from("기존 사용자 규칙, default policy, cloud firewall"),
            String::from("SSH 22, HTTPS 443, 독립 관리 edge 9443"),
            String::from("동시에 수행된 제품 밖 root 변경"),
        ],
        apply_verifier: vec![
            String::from("ufw status numbered before digest"),
            String::from("제품 comment와 typed rule exact read-back"),
        ],
        rollback_verifier: vec![String::from(
            "이번 product effect의 inverse operation과 status read-back",
        )],
        reason,
    }
}

#[must_use]
pub fn matching_owned_rule<'a>(view: &'a UfwView, rule_id: &str) -> Option<&'a UfwRuleView> {
    view.rules
        .iter()
        .find(|rule| rule.owned && rule.rule_id.as_deref() == Some(rule_id))
}

#[must_use]
pub fn rule_matches_spec(rule: &UfwRuleView, spec: &UfwRuleSpec) -> bool {
    rule.owned
        && rule.rule_id.as_deref() == Some(spec.rule_id.as_str())
        && rule.protocol == Some(spec.protocol)
        && rule.port == Some(spec.port)
        && normalized_source(&rule.source) == normalized_source(&spec.source)
        && rule.action.eq_ignore_ascii_case(spec.mutation.as_str())
}

fn parse_numbered_rule(line: &str) -> Option<UfwRuleView> {
    let trimmed = line.trim();
    let closing = trimmed.find(']')?;
    let sequence = trimmed.get(1..closing)?.trim().parse::<u16>().ok()?;
    let body = trimmed.get(closing + 1..)?.trim();
    let (columns, comment) = body
        .split_once('#')
        .map_or((body, None), |(columns, comment)| {
            (columns.trim(), Some(comment.trim()))
        });
    let tokens = columns.split_whitespace().collect::<Vec<_>>();
    let action_index = tokens
        .iter()
        .position(|token| matches!(*token, "ALLOW" | "DENY" | "REJECT" | "LIMIT"))?;
    let target = tokens
        .first()
        .copied()
        .map_or("any", std::convert::identity);
    let action = tokens.get(action_index)?.to_ascii_lowercase();
    let source_start = action_index.saturating_add(1)
        + usize::from(
            tokens
                .get(action_index.saturating_add(1))
                .is_some_and(|value| matches!(*value, "IN" | "OUT" | "FWD")),
        );
    let source = tokens
        .get(source_start..)
        .filter(|parts| !parts.is_empty())
        .map_or_else(|| String::from("any"), |parts| parts.join(" "));
    let (port, protocol) = parse_target(target);
    let ipv6 = columns.contains("(v6)");
    let rule_id = comment.and_then(|value| {
        value
            .split_whitespace()
            .find_map(|part| part.strip_prefix(UFW_COMMENT_PREFIX))
            .filter(|value| value.starts_with("ufr_") && value.len() == 28)
            .map(str::to_owned)
    });
    let owned = rule_id.is_some();
    let protected = protocol == Some(UfwProtocol::Tcp) && port.is_some_and(ufw_protected_tcp_port);
    Some(UfwRuleView {
        sequence,
        rule_id,
        action: action.clone(),
        protocol,
        port,
        source: source.clone(),
        destination: String::from(target),
        ipv6,
        owned,
        protected,
        summary: format!("{action} {target} · {source}"),
    })
}

fn parse_target(value: &str) -> (Option<u16>, Option<UfwProtocol>) {
    let Some((port, protocol)) = value.split_once('/') else {
        return (value.parse::<u16>().ok(), None);
    };
    let protocol = match protocol {
        "tcp" => Some(UfwProtocol::Tcp),
        "udp" => Some(UfwProtocol::Udp),
        _ => None,
    };
    (port.parse::<u16>().ok(), protocol)
}

pub(crate) fn normalized_source(value: &str) -> &str {
    if value.starts_with("Anywhere") || value == "any" {
        "any"
    } else {
        value
            .strip_suffix(" (v6)")
            .map_or(value, std::convert::identity)
    }
}

#[cfg(test)]
mod tests {
    use crate::runner::StreamEvidence;

    use super::*;

    fn evidence(output: &str) -> CommandEvidence {
        CommandEvidence {
            class: CommandClass::UfwStatus,
            success: true,
            exit_code: Some(0),
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

    #[test]
    fn parses_owned_numbered_rules_and_protects_management_ports() {
        let output = "Status: active\n\
             [ 1] 22/tcp ALLOW IN Anywhere\n\
             [ 2] 8080/tcp DENY IN 203.0.113.0/24 # jw-agent:ufr_0123456789abcdef01234567\n";
        let view = parse_ufw_status(&evidence(output), String::from("2026-07-24T00:00:00Z"));
        assert_eq!(view.status, UfwStatus::Active);
        assert_eq!(view.rules.len(), 2);
        assert!(view.rules[0].protected);
        assert!(view.rules[1].owned);
        assert_eq!(
            view.rules[1].rule_id.as_deref(),
            Some("ufr_0123456789abcdef01234567")
        );
    }

    #[test]
    fn command_builder_never_accepts_free_form_argv() {
        let rule = UfwRuleSpec {
            mutation: UfwRuleMutation::Allow,
            protocol: UfwProtocol::Tcp,
            port: 8080,
            source: String::from("any"),
            rule_id: String::from("ufr_0123456789abcdef01234567"),
        };
        let (_, arguments) = UfwCommand::Add(rule).registered_arguments();
        assert_eq!(
            arguments,
            vec![
                "allow",
                "from",
                "any",
                "to",
                "any",
                "port",
                "8080",
                "proto",
                "tcp",
                "comment",
                "jw-agent:ufr_0123456789abcdef01234567"
            ]
        );
    }
}
