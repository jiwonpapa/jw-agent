use crate::runner::CommandEvidence;

pub(crate) fn nginx_config_failure_code(evidence: &CommandEvidence, basename: &str) -> String {
    selected_resource_line(&evidence.stderr.captured, basename).map_or_else(
        || String::from("nginx_config_test_failed"),
        |line| format!("nginx_config_test_failed:line={line}"),
    )
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
    use super::selected_resource_line;

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
}
