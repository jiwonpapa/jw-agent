use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpsError {
    Rejected(&'static str),
    RejectedOwned(String),
    Storage(String),
    Filesystem(String),
    Command(String),
    ForensicLockdown,
}

impl OpsError {
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Rejected(code) => code,
            Self::RejectedOwned(code) => code,
            Self::Storage(_) => "ledger_failure",
            Self::Filesystem(_) => "filesystem_failure",
            Self::Command(_) => "command_failure",
            Self::ForensicLockdown => "forensic_lockdown",
        }
    }
}

impl fmt::Display for OpsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(code) => write!(formatter, "operation rejected: {code}"),
            Self::RejectedOwned(code) => write!(formatter, "operation rejected: {code}"),
            Self::Storage(message) => write!(formatter, "storage failure: {message}"),
            Self::Filesystem(message) => write!(formatter, "filesystem failure: {message}"),
            Self::Command(message) => write!(formatter, "command failure: {message}"),
            Self::ForensicLockdown => formatter.write_str("forensic lockdown"),
        }
    }
}

impl std::error::Error for OpsError {}

impl From<rusqlite::Error> for OpsError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.to_string())
    }
}
