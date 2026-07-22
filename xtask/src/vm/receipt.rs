const NGINX_CONFIG_FAILURE: &str = "nginx_config_test_failed";

pub(super) fn contains_nginx_config_failure_result(receipt: &str) -> bool {
    let mut remaining = receipt;
    while let Some((_, tail)) = remaining.split_once("\"resultCode\":\"") {
        let Some((result_code, rest)) = tail.split_once('"') else {
            return false;
        };
        if result_code == NGINX_CONFIG_FAILURE || valid_line_result(result_code) {
            return true;
        }
        remaining = rest;
    }
    false
}

fn valid_line_result(result_code: &str) -> bool {
    let Some(line) = result_code.strip_prefix("nginx_config_test_failed:line=") else {
        return false;
    };
    !line.is_empty()
        && line.len() <= 10
        && line.bytes().all(|value| value.is_ascii_digit())
        && line.parse::<u32>().is_ok_and(|value| value > 0)
}

#[cfg(test)]
mod tests {
    use super::contains_nginx_config_failure_result;

    #[test]
    fn accepts_only_base_or_positive_bounded_line_result() {
        assert!(contains_nginx_config_failure_result(
            r#"{"resultCode":"nginx_config_test_failed"}"#,
        ));
        assert!(contains_nginx_config_failure_result(
            r#"{"resultCode":"nginx_config_test_failed:line=17"}"#,
        ));
        for rejected in [
            r#"{"resultCode":"nginx_config_test_failed:line=0"}"#,
            r#"{"resultCode":"nginx_config_test_failed:line=17:secret"}"#,
            r#"{"resultCode":"nginx_config_test_failed:line=99999999999"}"#,
            r#"{"resultCode":"unrelated"}"#,
        ] {
            assert!(!contains_nginx_config_failure_result(rejected));
        }
    }
}
