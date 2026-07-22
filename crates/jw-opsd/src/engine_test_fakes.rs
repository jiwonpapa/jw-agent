use std::collections::VecDeque;
use std::sync::Mutex;

use jw_contracts::{
    CertbotCommand, CertbotCommandClass, CertbotCommandEvidence, CertificateEnvironment,
    sha256_digest,
};

use crate::certbot_runner::CertbotRunner;
use crate::error::OpsError;
use crate::runner::{CommandClass, CommandEvidence, OperationRunner, StreamEvidence};

#[derive(Debug)]
pub(crate) struct FakeRunner {
    results: Mutex<VecDeque<(CommandClass, bool)>>,
}

impl FakeRunner {
    pub(crate) fn all_success() -> Self {
        Self {
            results: Mutex::new(VecDeque::from([
                (CommandClass::NginxConfigTest, true),
                (CommandClass::NginxReload, true),
                (CommandClass::NginxActive, true),
            ])),
        }
    }

    pub(crate) fn syntax_failure_then_rollback() -> Self {
        Self {
            results: Mutex::new(VecDeque::from([
                (CommandClass::NginxConfigTest, false),
                (CommandClass::NginxConfigTest, true),
                (CommandClass::NginxReload, true),
                (CommandClass::NginxActive, true),
            ])),
        }
    }

    pub(crate) fn reload_failure_then_rollback() -> Self {
        Self {
            results: Mutex::new(VecDeque::from([
                (CommandClass::NginxConfigTest, true),
                (CommandClass::NginxReload, false),
                (CommandClass::NginxConfigTest, true),
                (CommandClass::NginxReload, true),
                (CommandClass::NginxActive, true),
            ])),
        }
    }

    pub(crate) fn syntax_and_rollback_validation_fail() -> Self {
        Self {
            results: Mutex::new(VecDeque::from([
                (CommandClass::NginxConfigTest, false),
                (CommandClass::NginxConfigTest, false),
            ])),
        }
    }

    pub(crate) fn noop_success() -> Self {
        Self {
            results: Mutex::new(VecDeque::from([
                (CommandClass::NginxConfigTest, true),
                (CommandClass::NginxActive, true),
            ])),
        }
    }

    pub(crate) fn certbot_timer_success(count: usize) -> Self {
        let mut results = VecDeque::new();
        for _ in 0..count {
            results.push_back((CommandClass::CertbotTimerEnabled, true));
            results.push_back((CommandClass::CertbotTimerActive, true));
        }
        Self {
            results: Mutex::new(results),
        }
    }

    pub(crate) fn certbot_issue_staging_and_production_plan() -> Self {
        Self {
            results: Mutex::new(VecDeque::from([
                (CommandClass::CertbotTimerEnabled, true),
                (CommandClass::CertbotTimerActive, true),
                (CommandClass::CertbotTimerEnabled, true),
                (CommandClass::CertbotTimerActive, true),
                (CommandClass::NginxConfigTest, true),
                (CommandClass::NginxActive, true),
                (CommandClass::CertbotTimerEnabled, true),
                (CommandClass::CertbotTimerActive, true),
                (CommandClass::CertbotTimerEnabled, true),
                (CommandClass::CertbotTimerActive, true),
                (CommandClass::CertbotTimerEnabled, true),
                (CommandClass::CertbotTimerActive, true),
                (CommandClass::CertbotTimerEnabled, true),
                (CommandClass::CertbotTimerActive, true),
                (CommandClass::NginxConfigTest, true),
                (CommandClass::NginxActive, true),
            ])),
        }
    }

    pub(crate) fn certbot_attach_success() -> Self {
        Self {
            results: Mutex::new(Self::certbot_attach_results()),
        }
    }

    pub(crate) fn certbot_attach_tls_failure_then_rollback() -> Self {
        let mut values = Self::certbot_attach_results();
        values.extend([
            (CommandClass::NginxConfigTest, true),
            (CommandClass::NginxReload, true),
            (CommandClass::NginxActive, true),
        ]);
        Self {
            results: Mutex::new(values),
        }
    }

    fn certbot_attach_results() -> VecDeque<(CommandClass, bool)> {
        VecDeque::from([
            (CommandClass::CertbotTimerEnabled, true),
            (CommandClass::CertbotTimerActive, true),
            (CommandClass::CertbotTimerEnabled, true),
            (CommandClass::CertbotTimerActive, true),
            (CommandClass::NginxConfigTest, true),
            (CommandClass::NginxActive, true),
            (CommandClass::CertbotTimerEnabled, true),
            (CommandClass::CertbotTimerActive, true),
            (CommandClass::NginxConfigTest, true),
            (CommandClass::NginxReload, true),
            (CommandClass::NginxActive, true),
            (CommandClass::CertbotTimerEnabled, true),
            (CommandClass::CertbotTimerActive, true),
        ])
    }
}

impl OperationRunner for FakeRunner {
    fn run(&self, class: CommandClass) -> Result<CommandEvidence, OpsError> {
        let mut results = self
            .results
            .lock()
            .map_err(|_| OpsError::Command(String::from("fake runner poisoned")))?;
        let Some((expected, success)) = results.pop_front() else {
            return Err(OpsError::Command(String::from("unexpected command")));
        };
        if expected != class {
            return Err(OpsError::Command(String::from("command order mismatch")));
        }
        let empty = sha256_digest(b"");
        Ok(CommandEvidence {
            class,
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            timed_out: false,
            stdout: StreamEvidence {
                digest: empty.clone(),
                captured: Vec::new(),
                truncated: false,
            },
            stderr: StreamEvidence {
                digest: empty,
                captured: Vec::new(),
                truncated: false,
            },
        })
    }
}

#[derive(Debug)]
pub(crate) struct FakeCertbotRunner {
    success: bool,
    pub(crate) calls: Mutex<u32>,
}

impl FakeCertbotRunner {
    pub(crate) fn new(success: bool) -> Self {
        Self {
            success,
            calls: Mutex::new(0),
        }
    }
}

impl CertbotRunner for FakeCertbotRunner {
    fn run(
        &self,
        command: CertbotCommand,
        _now_ms: i64,
    ) -> Result<CertbotCommandEvidence, OpsError> {
        let command_class = match command {
            CertbotCommand::RenewDryRun => CertbotCommandClass::RenewDryRun,
            CertbotCommand::Issue { environment, .. } => match environment {
                CertificateEnvironment::Staging => CertbotCommandClass::IssueStaging,
                CertificateEnvironment::Production => CertbotCommandClass::IssueProduction,
            },
            CertbotCommand::VerifyLocalTls { .. } => CertbotCommandClass::VerifyLocalTls,
        };
        let mut calls = self
            .calls
            .lock()
            .map_err(|_| OpsError::Command(String::from("fake certbot runner poisoned")))?;
        *calls = calls.saturating_add(1);
        let digest = sha256_digest(b"redacted certbot stream");
        Ok(CertbotCommandEvidence {
            command_class,
            success: self.success,
            exit_code: Some(if self.success { 0 } else { 1 }),
            timed_out: false,
            stdout_digest: digest.clone(),
            stdout_truncated: false,
            stderr_digest: digest,
            stderr_truncated: false,
        })
    }
}
