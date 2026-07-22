use crate::runner::CommandEvidence;

#[must_use]
pub fn php_fpm_config_test_succeeded(evidence: &CommandEvidence) -> bool {
    evidence.success && syntax_line(evidence).is_none() && !contains_syntax_error(evidence)
}

#[must_use]
pub fn php_fpm_config_failure_code(evidence: &CommandEvidence) -> String {
    syntax_line(evidence).map_or_else(
        || String::from("php_fpm_config_invalid"),
        |line| format!("php_fpm_config_syntax_line_{line}"),
    )
}

fn syntax_line(evidence: &CommandEvidence) -> Option<u32> {
    let text = diagnostic_text(evidence);
    let marker = " on line ";
    let start = text.rfind(marker)?.saturating_add(marker.len());
    let digits = text
        .get(start..)?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    (!digits.is_empty())
        .then(|| digits.parse::<u32>().ok())
        .flatten()
}

fn contains_syntax_error(evidence: &CommandEvidence) -> bool {
    diagnostic_text(evidence)
        .to_ascii_lowercase()
        .contains("syntax error")
}

fn diagnostic_text(evidence: &CommandEvidence) -> String {
    let mut value = String::from_utf8_lossy(&evidence.stderr.captured).into_owned();
    value.push('\n');
    value.push_str(&String::from_utf8_lossy(&evidence.stdout.captured));
    value
}

#[cfg(test)]
mod tests {
    use crate::runner::{CommandClass, CommandEvidence, StreamEvidence};

    use super::{php_fpm_config_failure_code, php_fpm_config_test_succeeded};

    #[test]
    fn rejects_php_ini_syntax_warning_even_when_process_exits_zero() {
        let evidence = evidence(
            true,
            b"PHP: syntax error, unexpected '=' in /etc/php/8.3/fpm/php.ini on line 42\n",
        );
        assert!(!php_fpm_config_test_succeeded(&evidence));
        assert_eq!(
            php_fpm_config_failure_code(&evidence),
            "php_fpm_config_syntax_line_42"
        );
    }

    #[test]
    fn accepts_clean_fpm_test() {
        assert!(php_fpm_config_test_succeeded(&evidence(
            true,
            b"NOTICE: configuration file test is successful\n",
        )));
    }

    fn evidence(success: bool, stderr: &[u8]) -> CommandEvidence {
        CommandEvidence {
            class: CommandClass::PhpFpm83ConfigTest,
            success,
            exit_code: Some(if success { 0 } else { 78 }),
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
