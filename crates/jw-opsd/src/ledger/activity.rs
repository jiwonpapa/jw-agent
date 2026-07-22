use jw_contracts::OperationListView;
use rusqlite::params;

use super::Ledger;
use crate::error::OpsError;

pub(super) fn recent_receipts(
    ledger: &Ledger,
    actor_uid: u32,
    limit: u8,
) -> Result<OperationListView, OpsError> {
    let mut statement = ledger.connection.prepare(
        "SELECT operations.operation_id
         FROM operations
         INNER JOIN plans ON plans.plan_id = operations.plan_id
         WHERE plans.actor_uid = ?1
         ORDER BY operations.updated_at_ms DESC, operations.operation_id DESC
         LIMIT ?2",
    )?;
    let rows = statement.query_map(params![i64::from(actor_uid), i64::from(limit)], |row| {
        row.get::<_, String>(0)
    })?;
    let mut operations = Vec::new();
    for row in rows {
        operations.push(ledger.receipt(&row?)?);
    }
    Ok(OperationListView { operations })
}
