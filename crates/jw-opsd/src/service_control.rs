use jw_contracts::{
    AssuranceLevel, AssuranceView, ManagedServiceAction, RollbackSupport, service_id, sha256_digest,
};

use crate::error::OpsError;
use crate::runner::{CommandClass, OperationRunner};

pub const SERVICE_CONTROL_IMPACT: [&str; 3] = [
    "등록된 systemd 서비스 하나에 선택한 lifecycle 동작을 실행합니다.",
    "실행 전 상태를 기록하고 동작 후 active 상태를 다시 확인합니다.",
    "검증 실패 시 실행 전 active/inactive 상태로 복구를 시도합니다.",
];

pub const SERVICE_CONTROL_RECOVERY_PATH: [&str; 3] = [
    "터미널 또는 SSH로 서버에 접속합니다.",
    "systemctl status로 대상 서비스와 최근 journal을 확인합니다.",
    "설정 문법을 확인한 뒤 이전 상태에 맞게 start 또는 stop합니다.",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisteredService {
    Nginx,
    Apache,
    PhpFpm83,
}

impl RegisteredService {
    #[must_use]
    pub const fn unit_name(self) -> &'static str {
        match self {
            Self::Nginx => "nginx.service",
            Self::Apache => "apache2.service",
            Self::PhpFpm83 => "php8.3-fpm.service",
        }
    }

    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Nginx => "Nginx",
            Self::Apache => "Apache HTTP Server",
            Self::PhpFpm83 => "PHP 8.3 FPM",
        }
    }

    #[must_use]
    pub const fn active_command(self) -> CommandClass {
        match self {
            Self::Nginx => CommandClass::NginxActive,
            Self::Apache => CommandClass::ApacheActive,
            Self::PhpFpm83 => CommandClass::PhpFpm83Active,
        }
    }

    #[must_use]
    pub const fn action_command(self, action: ManagedServiceAction) -> CommandClass {
        match (self, action) {
            (Self::Nginx, ManagedServiceAction::Start) => CommandClass::NginxStart,
            (Self::Nginx, ManagedServiceAction::Stop) => CommandClass::NginxStop,
            (Self::Nginx, ManagedServiceAction::Restart) => CommandClass::NginxRestart,
            (Self::Nginx, ManagedServiceAction::Reload) => CommandClass::NginxReload,
            (Self::Apache, ManagedServiceAction::Start) => CommandClass::ApacheStart,
            (Self::Apache, ManagedServiceAction::Stop) => CommandClass::ApacheStop,
            (Self::Apache, ManagedServiceAction::Restart) => CommandClass::ApacheRestart,
            (Self::Apache, ManagedServiceAction::Reload) => CommandClass::ApacheReload,
            (Self::PhpFpm83, ManagedServiceAction::Start) => CommandClass::PhpFpm83Start,
            (Self::PhpFpm83, ManagedServiceAction::Stop) => CommandClass::PhpFpm83Stop,
            (Self::PhpFpm83, ManagedServiceAction::Restart) => CommandClass::PhpFpm83Restart,
            (Self::PhpFpm83, ManagedServiceAction::Reload) => CommandClass::PhpFpm83Reload,
        }
    }

    #[must_use]
    pub const fn restore_command(self, active: bool) -> CommandClass {
        match (self, active) {
            (Self::Nginx, true) => CommandClass::NginxStart,
            (Self::Nginx, false) => CommandClass::NginxStop,
            (Self::Apache, true) => CommandClass::ApacheStart,
            (Self::Apache, false) => CommandClass::ApacheStop,
            (Self::PhpFpm83, true) => CommandClass::PhpFpm83Start,
            (Self::PhpFpm83, false) => CommandClass::PhpFpm83Stop,
        }
    }
}

pub fn registered_service(service_identifier: &str) -> Result<RegisteredService, OpsError> {
    [
        RegisteredService::Nginx,
        RegisteredService::Apache,
        RegisteredService::PhpFpm83,
    ]
    .into_iter()
    .find(|service| service_id(service.unit_name()) == service_identifier)
    .ok_or(OpsError::Rejected("service_not_managed"))
}

pub fn management_edge_ready(runner: &dyn OperationRunner) -> Result<bool, OpsError> {
    runner.management_edge_ready()
}

#[must_use]
pub fn service_action_digest(action: ManagedServiceAction) -> String {
    sha256_digest(action.as_storage_value().as_bytes())
}

pub fn service_action_from_digest(value: &str) -> Result<ManagedServiceAction, OpsError> {
    [
        ManagedServiceAction::Start,
        ManagedServiceAction::Stop,
        ManagedServiceAction::Restart,
        ManagedServiceAction::Reload,
    ]
    .into_iter()
    .find(|action| service_action_digest(*action) == value)
    .ok_or(OpsError::ForensicLockdown)
}

#[must_use]
pub fn expected_active(action: ManagedServiceAction) -> bool {
    action != ManagedServiceAction::Stop
}

#[must_use]
pub fn service_control_assurance(service: RegisteredService) -> AssuranceView {
    AssuranceView {
        level: AssuranceLevel::G2ReversibleConfig,
        rollback_support: RollbackSupport::AutomaticBounded,
        operation_available: true,
        scope: vec![format!(
            "{}의 active/inactive 상태와 등록된 lifecycle 동작",
            service.unit_name()
        )],
        excluded_effects: vec![
            String::from("서비스 외부 의존성과 진행 중 요청의 애플리케이션 상태"),
            String::from("서비스 설정 파일과 데이터 파일"),
        ],
        apply_verifier: vec![
            String::from("systemctl 동작 결과"),
            String::from("is-active read-back"),
        ],
        rollback_verifier: vec![
            String::from("이전 active/inactive 상태 복원"),
            String::from("is-active read-back"),
        ],
        reason: None,
    }
}
