use std::collections::BTreeSet;

use crate::runner::CommandEvidence;

pub fn validate_php_ini_candidate(current: &str, proposed: &str) -> Result<(), String> {
    validate_ini_candidate(current, proposed, valid_ini_key)
}

pub fn validate_php_fpm_candidate(current: &str, proposed: &str) -> Result<(), String> {
    validate_ini_candidate(current, proposed, valid_fpm_key)
}

fn validate_ini_candidate(
    current: &str,
    proposed: &str,
    valid_key: fn(&str) -> bool,
) -> Result<(), String> {
    if proposed.trim().is_empty() {
        return Err(String::from("empty_config"));
    }
    let known = current
        .lines()
        .filter_map(|line| known_ini_key(line, valid_key))
        .collect::<BTreeSet<_>>();
    if known.is_empty() {
        return Err(String::from("directive_inventory_unavailable"));
    }
    for (index, line) in proposed.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            continue;
        }
        let Some((raw_key, _)) = trimmed.split_once('=') else {
            return Err(format!(
                "ignored_directive_line_{}",
                index.saturating_add(1)
            ));
        };
        let key = raw_key.trim().to_ascii_lowercase();
        if !valid_key(&key) {
            return Err(format!(
                "invalid_directive_line_{}",
                index.saturating_add(1)
            ));
        }
        if !known.contains(&key) {
            return Err(format!(
                "unknown_directive_line_{}",
                index.saturating_add(1)
            ));
        }
    }
    Ok(())
}

fn known_ini_key(line: &str, valid_key: fn(&str) -> bool) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
        return None;
    }
    let candidate = match trimmed.strip_prefix(';').map(str::trim) {
        Some(value) => value,
        None => trimmed,
    };
    let (raw_key, _) = candidate.split_once('=')?;
    let key = raw_key.trim().to_ascii_lowercase();
    valid_key(&key).then_some(key)
}

fn valid_ini_key(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn valid_fpm_key(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'[' | b']' | b'$')
        })
}

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

    use super::{
        php_fpm_config_failure_code, php_fpm_config_test_succeeded, validate_php_fpm_candidate,
        validate_php_ini_candidate,
    };

    const BASELINE: &str = "[PHP]\n; memory_limit = 128M\npost_max_size = 8M\n";

    #[test]
    fn rejects_empty_and_ignored_php_ini_content() {
        assert_eq!(
            validate_php_ini_candidate(BASELINE, "\n\t"),
            Err(String::from("empty_config"))
        );
        assert_eq!(
            validate_php_ini_candidate(BASELINE, "[PHP]\naaaaa\n"),
            Err(String::from("ignored_directive_line_2"))
        );
    }

    #[test]
    fn rejects_unknown_directive_and_accepts_uncommented_vendor_directive() {
        assert_eq!(
            validate_php_ini_candidate(BASELINE, "[PHP]\nnot_registered = 1\n"),
            Err(String::from("unknown_directive_line_2"))
        );
        assert!(
            validate_php_ini_candidate(
                BASELINE,
                "[PHP]\nmemory_limit = 256M\npost_max_size = 16M\n"
            )
            .is_ok()
        );
    }

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
    fn validates_fpm_pool_keys_and_rejects_ignored_lines() {
        let baseline = "[www]\nuser = www-data\n; env[HOSTNAME] = $HOSTNAME\n";
        assert!(
            validate_php_fpm_candidate(
                baseline,
                "[www]\nuser = www-data\nenv[HOSTNAME] = $HOSTNAME\n"
            )
            .is_ok()
        );
        assert_eq!(
            validate_php_fpm_candidate(baseline, "[www]\naaaaa\n"),
            Err(String::from("ignored_directive_line_2"))
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
