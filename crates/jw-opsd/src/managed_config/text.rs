use crate::error::OpsError;

use super::DiffStats;

#[must_use]
pub fn diff_stats(current: &str, proposed: &str) -> DiffStats {
    let before: Vec<&str> = current.lines().collect();
    let after: Vec<&str> = proposed.lines().collect();
    let prefix = before
        .iter()
        .zip(after.iter())
        .take_while(|(left, right)| left == right)
        .count();
    let max_suffix = before
        .len()
        .saturating_sub(prefix)
        .min(after.len().saturating_sub(prefix));
    let suffix = (0..max_suffix)
        .take_while(|offset| {
            before[before.len().saturating_sub(1 + offset)]
                == after[after.len().saturating_sub(1 + offset)]
        })
        .count();
    let removed = &before[prefix..before.len().saturating_sub(suffix)];
    let added = &after[prefix..after.len().saturating_sub(suffix)];
    let mut summary = Vec::new();
    for line in removed.iter().take(20) {
        summary.push(format!("-{}", bounded_line(line)));
    }
    for line in added.iter().take(20) {
        summary.push(format!("+{}", bounded_line(line)));
    }
    if removed.len().saturating_add(added.len()) > summary.len() {
        summary.push(String::from("… diff preview truncated"));
    }
    DiffStats {
        added_lines: u32::try_from(added.len()).map_or(u32::MAX, std::convert::identity),
        removed_lines: u32::try_from(removed.len()).map_or(u32::MAX, std::convert::identity),
        summary,
    }
}

pub(super) fn validate_relative_path(value: &str) -> Result<(), OpsError> {
    if value.starts_with('/')
        || value
            .split('/')
            .any(|component| matches!(component, "" | "." | ".."))
    {
        Err(OpsError::Rejected("proposal_path_rejected"))
    } else {
        Ok(())
    }
}

fn bounded_line(value: &str) -> String {
    let mut output = value.chars().take(160).collect::<String>();
    if value.chars().count() > 160 {
        output.push('…');
    }
    output
}
