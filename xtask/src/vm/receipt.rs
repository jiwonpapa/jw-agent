use super::{json_string, json_string_field};

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

pub(super) fn require_managed_config_diagnostic(
    body: &str,
    service: &str,
    validator: &str,
    masked_path: &str,
    expected_line: Option<u32>,
) -> Result<u32, String> {
    let marker = format!("\"service\":\"{service}\",\"validator\":\"{validator}\"");
    let diagnostic = body
        .find(&marker)
        .map(|start| &body[start..])
        .ok_or_else(|| format!("{service} receipt omitted its structured validator diagnostic"))?;
    let object_end = diagnostic
        .find("]}")
        .map(|end| end + 2)
        .ok_or_else(|| format!("{service} diagnostic object was incomplete"))?;
    let diagnostic = &diagnostic[..object_end];
    let has_masked_path =
        diagnostic.contains(&format!("\"maskedPath\":{}", json_string(masked_path)));
    let has_error_severity = diagnostic.contains("\"severity\":\"error\"");
    let has_code = diagnostic.contains("\"code\":\"");
    let has_message = diagnostic.contains("\"message\":\"");
    if !has_masked_path || !has_error_severity || !has_code || !has_message {
        let actual_masked_path = match json_string_field(diagnostic, "maskedPath") {
            Ok(value) => value,
            Err(_) => String::from("<none>"),
        };
        return Err(format!(
            "{service} diagnostic shape mismatch: masked_path={has_masked_path}, \
             actual_masked_path={actual_masked_path}, error_severity={has_error_severity}, \
             code={has_code}, message={has_message}"
        ));
    }
    let line_marker = "\"line\":";
    let line_value = diagnostic
        .find(line_marker)
        .map(|start| &diagnostic[start + line_marker.len()..])
        .and_then(|rest| rest.split(',').next())
        .ok_or_else(|| format!("{service} diagnostic omitted its line"))?;
    let line = line_value
        .parse::<u32>()
        .map_err(|_| format!("{service} diagnostic line was not a positive integer"))?;
    if line == 0 || expected_line.is_some_and(|expected| expected != line) {
        return Err(format!(
            "{service} diagnostic reported line {line}, expected {expected_line:?}"
        ));
    }
    if !diagnostic.contains(&format!("\"relatedChangedLines\":[{line}]")) {
        return Err(format!(
            "{service} diagnostic did not relate line {line} to the submitted diff"
        ));
    }
    Ok(line)
}

pub(super) fn require_managed_config_cause_candidate(
    body: &str,
    masked_path: &str,
    expected_line: u32,
    expected_candidate: u32,
) -> Result<(), String> {
    let marker = "\"service\":\"nginx\",\"validator\":\"nginx_config_test\"";
    let diagnostic = body
        .find(marker)
        .map(|start| &body[start..])
        .ok_or_else(|| String::from("Nginx receipt omitted its structured validator diagnostic"))?;
    let object_end = diagnostic
        .find("]}")
        .map(|end| end + 2)
        .ok_or_else(|| String::from("Nginx diagnostic object was incomplete"))?;
    let diagnostic = &diagnostic[..object_end];
    let expected_location = format!(
        "\"maskedPath\":{},\"line\":{expected_line}",
        json_string(masked_path)
    );
    if !diagnostic.contains(&expected_location)
        || !diagnostic.contains("\"relatedChangedLines\":[]")
        || !diagnostic.contains(&format!("\"causeCandidateLines\":[{expected_candidate}]"))
    {
        return Err(format!(
            "Nginx diagnostic did not preserve official line {expected_line} and candidate line {expected_candidate}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{contains_nginx_config_failure_result, require_managed_config_diagnostic};

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

    #[test]
    fn accepts_only_the_expected_structured_diagnostic_location() {
        let receipt = r#"{"service":"nginx","validator":"nginx_config_test","resourceId":"ngf_0123456789abcdef01234567","maskedPath":"/etc/nginx/nginx.conf","line":13,"column":null,"severity":"error","code":"unknown_directive","message":"Nginx rejected a directive.","relatedChangedLines":[13],"causeCandidateLines":[]}"#;
        assert_eq!(
            require_managed_config_diagnostic(
                receipt,
                "nginx",
                "nginx_config_test",
                "/etc/nginx/nginx.conf",
                Some(13),
            ),
            Ok(13)
        );
        assert!(
            require_managed_config_diagnostic(
                receipt,
                "nginx",
                "nginx_config_test",
                "/etc/nginx/sites-enabled/default",
                Some(13),
            )
            .is_err()
        );
    }

    #[test]
    fn accepts_a_separate_bounded_cause_candidate_without_rewriting_the_native_line() {
        let receipt = r#"{"service":"nginx","validator":"nginx_config_test","resourceId":"ngf_0123456789abcdef01234567","maskedPath":"/etc/nginx/nginx.conf","line":18,"column":null,"severity":"error","code":"unknown_directive","message":"Nginx rejected a directive.","relatedChangedLines":[],"causeCandidateLines":[13]}"#;
        assert_eq!(
            super::require_managed_config_cause_candidate(receipt, "/etc/nginx/nginx.conf", 18, 13,),
            Ok(())
        );
    }
}
