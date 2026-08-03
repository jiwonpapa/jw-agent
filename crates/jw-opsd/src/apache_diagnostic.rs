use crate::config_diagnostic::{
    ParsedConfigDiagnostic, ParsedSeverity, generic_validator_diagnostic, validator_output,
};
use crate::runner::CommandEvidence;

pub(crate) fn parse_apache_config_diagnostics(
    evidence: &CommandEvidence,
) -> Vec<ParsedConfigDiagnostic> {
    let output = validator_output(evidence);
    let mut diagnostics = Vec::new();
    for line in output.lines() {
        let Some((line_number, path)) = apache_location(line) else {
            continue;
        };
        diagnostics.push(ParsedConfigDiagnostic {
            path: Some(path),
            line: Some(line_number),
            column: None,
            severity: ParsedSeverity::Error,
            code: apache_code(&output),
            message: apache_message(&output),
        });
    }
    if diagnostics.is_empty() && !evidence.success {
        diagnostics.push(generic_validator_diagnostic(
            if evidence.timed_out {
                "validator_timeout"
            } else {
                "validator_rejected"
            },
            if evidence.timed_out {
                "Apache 문법 검사가 제한 시간을 초과했습니다."
            } else {
                "Apache가 현재 설정을 거부했습니다."
            },
        ));
    }
    diagnostics
}

fn apache_location(line: &str) -> Option<(u32, String)> {
    let marker = "Syntax error on line ";
    let after = line.split_once(marker)?.1;
    let (line_number, path) = after.split_once(" of ")?;
    let line_number = line_number.parse::<u32>().ok().filter(|value| *value > 0)?;
    let path = path.trim().trim_end_matches(':');
    (!path.is_empty()).then(|| (line_number, String::from(path)))
}

fn apache_code(output: &str) -> &'static str {
    let lowered = output.to_ascii_lowercase();
    if lowered.contains("invalid command") {
        "unknown_directive"
    } else if lowered.contains("multiple listeners") || lowered.contains("address already in use") {
        "listener_conflict"
    } else if lowered.contains("expected </") || lowered.contains("without matching") {
        "unmatched_block"
    } else {
        "validator_rejected"
    }
}

fn apache_message(output: &str) -> &'static str {
    match apache_code(output) {
        "unknown_directive" => "Apache가 알 수 없는 지시어를 발견했습니다.",
        "listener_conflict" => "Apache listen 주소 또는 포트가 충돌합니다.",
        "unmatched_block" => "Apache 설정 블록의 시작과 끝이 맞지 않습니다.",
        _ => "Apache가 현재 설정을 거부했습니다.",
    }
}

#[cfg(test)]
mod tests {
    use crate::runner::{CommandClass, CommandEvidence, StreamEvidence};

    use super::parse_apache_config_diagnostics;

    #[test]
    fn parses_native_file_and_line_without_exposing_reason_text() {
        let evidence = evidence(
            b"AH00526: Syntax error on line 18 of /etc/apache2/sites-enabled/example.conf:\nInvalid command 'SecretValue'\n",
        );
        let diagnostics = parse_apache_config_diagnostics(&evidence);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].path.as_deref(),
            Some("/etc/apache2/sites-enabled/example.conf")
        );
        assert_eq!(diagnostics[0].line, Some(18));
        assert_eq!(diagnostics[0].code, "unknown_directive");
        assert!(!diagnostics[0].message.contains("SecretValue"));
    }

    fn evidence(stderr: &[u8]) -> CommandEvidence {
        CommandEvidence {
            class: CommandClass::ApacheConfigTest,
            success: false,
            exit_code: Some(1),
            timed_out: false,
            stdout: StreamEvidence {
                digest: String::from("sha256:stdout"),
                captured: Vec::new(),
                truncated: false,
            },
            stderr: StreamEvidence {
                digest: String::from("sha256:stderr"),
                captured: stderr.to_vec(),
                truncated: false,
            },
        }
    }
}
