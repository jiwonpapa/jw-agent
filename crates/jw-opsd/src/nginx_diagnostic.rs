use crate::config_diagnostic::{
    ParsedConfigDiagnostic, ParsedSeverity, generic_validator_diagnostic, validator_output,
};
use crate::runner::CommandEvidence;

pub(crate) fn nginx_config_failure_code(evidence: &CommandEvidence, basename: &str) -> String {
    selected_resource_line(&evidence.stderr.captured, basename).map_or_else(
        || String::from("nginx_config_test_failed"),
        |line| format!("nginx_config_test_failed:line={line}"),
    )
}

pub(crate) fn parse_nginx_config_diagnostics(
    evidence: &CommandEvidence,
) -> Vec<ParsedConfigDiagnostic> {
    let output = validator_output(evidence);
    let mut diagnostics = Vec::new();
    for line in output.lines() {
        let Some((path, line_number)) = nginx_location(line) else {
            continue;
        };
        diagnostics.push(ParsedConfigDiagnostic {
            path: Some(path),
            line: Some(line_number),
            column: None,
            severity: if line.contains("[warn]") {
                ParsedSeverity::Warning
            } else {
                ParsedSeverity::Error
            },
            code: nginx_code(line),
            message: nginx_message(line),
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
                "Nginx 문법 검사가 제한 시간을 초과했습니다."
            } else {
                "Nginx가 현재 설정을 거부했습니다."
            },
        ));
    }
    diagnostics
}

fn nginx_location(line: &str) -> Option<(String, u32)> {
    let (_, location) = line.rsplit_once(" in ")?;
    let (path, line_number) = location.rsplit_once(':')?;
    let line_number = line_number
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)?;
    let path = path.trim();
    (!path.is_empty()).then(|| (String::from(path), line_number))
}

fn nginx_code(line: &str) -> &'static str {
    let lowered = line.to_ascii_lowercase();
    if lowered.contains("unknown directive") {
        "unknown_directive"
    } else if lowered.contains("duplicate") {
        "duplicate_directive"
    } else if lowered.contains("unexpected") || lowered.contains("expecting") {
        "unexpected_token"
    } else if lowered.contains("address already in use") || lowered.contains("bind()") {
        "listener_conflict"
    } else if lowered.contains("invalid number") || lowered.contains("invalid value") {
        "invalid_value"
    } else {
        "validator_rejected"
    }
}

fn nginx_message(line: &str) -> &'static str {
    match nginx_code(line) {
        "unknown_directive" => {
            "알 수 없는 지시어입니다. 보고된 줄뿐 아니라 앞 변경 줄의 세미콜론(;)·중괄호 누락도 확인하세요."
        }
        "duplicate_directive" => "Nginx 설정에 중복된 지시어가 있습니다.",
        "unexpected_token" => {
            "Nginx가 해석을 중단한 위치입니다. 실제 원인은 앞 변경 줄의 세미콜론(;)·중괄호 누락일 수 있습니다."
        }
        "listener_conflict" => "Nginx listen 주소 또는 포트가 충돌합니다.",
        "invalid_value" => "Nginx 지시어 값이 올바르지 않습니다.",
        _ => "Nginx가 현재 설정을 거부했습니다.",
    }
}

fn selected_resource_line(stderr: &[u8], basename: &str) -> Option<u32> {
    if basename.is_empty() || basename.contains('/') || basename.contains('\\') {
        return None;
    }
    let output = std::str::from_utf8(stderr).ok()?;
    let marker = format!("/{basename}:");
    output.lines().find_map(|line| {
        let suffix = line.rsplit_once(&marker)?.1;
        let digits: String = suffix
            .chars()
            .take_while(char::is_ascii_digit)
            .take(10)
            .collect();
        if digits.is_empty() {
            return None;
        }
        digits.parse::<u32>().ok().filter(|value| *value > 0)
    })
}

#[cfg(test)]
mod tests {
    use crate::runner::{CommandClass, CommandEvidence, StreamEvidence};

    use super::{parse_nginx_config_diagnostics, selected_resource_line};

    #[test]
    fn exposes_only_the_selected_resource_line() {
        assert_eq!(
            selected_resource_line(
                b"nginx: [emerg] unexpected end of file in /etc/nginx/sites-enabled/example:17\n",
                "example",
            ),
            Some(17),
        );
        assert_eq!(
            selected_resource_line(
                b"nginx: [emerg] invalid directive in /etc/nginx/nginx.conf:42\n",
                "example",
            ),
            None,
        );
        assert_eq!(
            selected_resource_line(b"secret=value\n", "../example"),
            None
        );
    }

    #[test]
    fn parses_native_include_path_and_line_without_echoing_directive() {
        let evidence = CommandEvidence {
            class: CommandClass::NginxConfigTest,
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
                captured: b"nginx: [emerg] unknown directive \"SecretValue\" in /etc/nginx/conf.d/example.conf:13\n".to_vec(),
                truncated: false,
            },
        };
        let diagnostics = parse_nginx_config_diagnostics(&evidence);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].path.as_deref(),
            Some("/etc/nginx/conf.d/example.conf")
        );
        assert_eq!(diagnostics[0].line, Some(13));
        assert_eq!(diagnostics[0].code, "unknown_directive");
        assert!(!diagnostics[0].message.contains("SecretValue"));
        assert!(diagnostics[0].message.contains("앞 변경 줄"));
    }
}
