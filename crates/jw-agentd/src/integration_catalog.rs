use std::path::PathBuf;

use jw_contracts::{
    AssuranceLevel, AssuranceView, IntegrationCatalogView, IntegrationCategory, IntegrationId,
    IntegrationInstallStatus, IntegrationLifecycleStatus, IntegrationView, ObservationStatus,
    RollbackSupport,
};

#[derive(Clone, Debug)]
pub struct IntegrationPathProfile {
    pub executable: PathBuf,
    pub setup_marker: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct IntegrationObservationProfile {
    pub platform_supported: bool,
    pub vps_guard: IntegrationPathProfile,
    pub g7_installer: IntegrationPathProfile,
    pub g7_media_booster: IntegrationPathProfile,
    pub g7_telegram_devops: IntegrationPathProfile,
}

impl Default for IntegrationObservationProfile {
    fn default() -> Self {
        Self {
            platform_supported: cfg!(target_os = "linux"),
            vps_guard: IntegrationPathProfile {
                executable: PathBuf::from("/usr/local/bin/vps-guard"),
                setup_marker: Some(PathBuf::from("/usr/local/lib/vps-guard/current")),
            },
            g7_installer: IntegrationPathProfile {
                executable: PathBuf::from("/usr/local/bin/g7inst"),
                setup_marker: Some(PathBuf::from("/etc/g7-installer/config.toml")),
            },
            g7_media_booster: IntegrationPathProfile {
                executable: PathBuf::from("/usr/local/bin/g7mbctl"),
                setup_marker: Some(PathBuf::from("/etc/g7mediabooster/g7mb.toml")),
            },
            g7_telegram_devops: IntegrationPathProfile {
                executable: PathBuf::from("/usr/bin/g7tg"),
                setup_marker: Some(PathBuf::from("/etc/g7telegram-devops/agent.toml")),
            },
        }
    }
}

pub fn observe_integrations(
    profile: &IntegrationObservationProfile,
    observed_at: String,
) -> IntegrationCatalogView {
    let status = if profile.platform_supported {
        ObservationStatus::Observed
    } else {
        ObservationStatus::UnsupportedPlatform
    };

    IntegrationCatalogView {
        observed_at,
        status,
        entries: vec![
            integration(
                profile,
                IntegrationDefinition {
                    id: IntegrationId::G7TelegramDevops,
                    name: "G7Telegram DevOps",
                    summary: "Telegram에서 서버 상태와 장애를 확인하고 승인된 서비스 작업을 수행합니다.",
                    category: IntegrationCategory::Notification,
                    paths: &profile.g7_telegram_devops,
                    blockers: &[
                        "독립 Release 서명이 아직 JW Agent 신뢰 저장소에 등록되지 않았습니다.",
                        "JW Agent용 Ubuntu VM 설치·제거 adapter 증거가 없습니다.",
                    ],
                    resource_claims: &[
                        "g7tg-agent systemd 서비스",
                        "Telegram Bot token과 outbound HTTPS",
                        "root 전용 설정과 SQLite 상태",
                    ],
                    setup_steps: &[
                        "BotFather에서 Bot token을 발급합니다.",
                        "제품의 숨김 입력 setup에서 token을 직접 등록합니다.",
                        "일회용 연결 코드로 Telegram owner를 연결합니다.",
                    ],
                    source_url: "https://github.com/jiwonpapa/g7Telegram-devops",
                },
            ),
            integration(
                profile,
                IntegrationDefinition {
                    id: IntegrationId::G7MediaBooster,
                    name: "G7MediaBooster",
                    summary: "Gnuboard 미디어 업로드와 이미지·영상 가공을 별도 Rust 서비스로 처리합니다.",
                    category: IntegrationCategory::Media,
                    paths: &profile.g7_media_booster,
                    blockers: &[
                        "서버 bundle의 독립 Release 서명이 JW Agent에 등록되지 않았습니다.",
                        "native dependency와 G7 module 호환 VM 증거가 없습니다.",
                    ],
                    resource_claims: &[
                        "g7mediabooster systemd target",
                        "libvips와 FFmpeg runtime",
                        "loopback API 127.0.0.1:8088",
                        "R2 또는 S3 credential",
                    ],
                    setup_steps: &[
                        "스토리지 provider와 G7 origin을 준비합니다.",
                        "제품 setup에서 credential을 직접 입력합니다.",
                        "doctor와 G7 module 호환 검사를 완료합니다.",
                    ],
                    source_url: "https://github.com/jiwonpapa/g7mediabooster",
                },
            ),
            integration(
                profile,
                IntegrationDefinition {
                    id: IntegrationId::G7Installer,
                    name: "G7 Installer",
                    summary: "신규 Ubuntu VPS에 웹서버·PHP·DB·TLS와 Gnuboard 설치 환경을 구성합니다.",
                    category: IntegrationCategory::Provisioning,
                    paths: &profile.g7_installer,
                    blockers: &[
                        "신규 VPS 전용의 광범위한 변경은 JW Agent G2 원복 보장 대상이 아닙니다.",
                        "서명된 package 설치와 handoff VM 증거가 없습니다.",
                    ],
                    resource_claims: &[
                        "apt package와 repository",
                        "Nginx 또는 Apache",
                        "PHP-FPM과 MySQL",
                        "Certbot 인증서와 사이트 계정",
                    ],
                    setup_steps: &[
                        "운영 데이터가 없는 신규 VPS인지 확인합니다.",
                        "VPS snapshot과 SSH 복구 경로를 준비합니다.",
                        "별도 웹 설치 마법사에서 계획을 다시 승인합니다.",
                    ],
                    source_url: "https://github.com/jiwonpapa/g7-installer",
                },
            ),
            integration(
                profile,
                IntegrationDefinition {
                    id: IntegrationId::VpsGuard,
                    name: "VPSGuard",
                    summary: "봇·AI 크롤러·과다 트래픽을 감지하고 프록시와 Cloudflare 방어를 단계적으로 적용합니다.",
                    category: IntegrationCategory::Security,
                    paths: &profile.vps_guard,
                    blockers: &[
                        "public 80/443 cutover와 bypass·rollback의 JW Agent VM 증거가 없습니다.",
                        "Nginx·TLS·DNS·Cloudflare resource 충돌 검사가 아직 구현되지 않았습니다.",
                        "서명된 stable Release가 JW Agent 신뢰 저장소에 등록되지 않았습니다.",
                    ],
                    resource_claims: &[
                        "public 80/443 listener",
                        "Nginx upstream과 인증서",
                        "Cloudflare API credential",
                        "vps-guard control·edge systemd 서비스",
                    ],
                    setup_steps: &[
                        "기존 80/443·인증서·DNS 소유권을 확인합니다.",
                        "트래픽을 전환하지 않는 shadow 검증을 수행합니다.",
                        "bypass 경로 확인 후 별도 고위험 plan으로 활성화합니다.",
                    ],
                    source_url: "https://github.com/jiwonpapa/VPSGuard",
                },
            ),
        ],
    }
}

struct IntegrationDefinition<'a> {
    id: IntegrationId,
    name: &'a str,
    summary: &'a str,
    category: IntegrationCategory,
    paths: &'a IntegrationPathProfile,
    blockers: &'a [&'a str],
    resource_claims: &'a [&'a str],
    setup_steps: &'a [&'a str],
    source_url: &'a str,
}

fn integration(
    profile: &IntegrationObservationProfile,
    definition: IntegrationDefinition<'_>,
) -> IntegrationView {
    let executable = profile.platform_supported && definition.paths.executable.is_file();
    let setup_marker = profile.platform_supported
        && definition
            .paths
            .setup_marker
            .as_ref()
            .is_some_and(|path| path.exists());
    let lifecycle_status = lifecycle(profile.platform_supported, executable, setup_marker);
    let mut blockers = definition
        .blockers
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<String>>();
    if !profile.platform_supported {
        blockers.insert(
            0,
            String::from("Ubuntu Linux가 아니므로 설치 상태와 호환성을 판정할 수 없습니다."),
        );
    }
    let mut detected_components = Vec::new();
    if executable {
        detected_components.push(String::from("실행 파일 감지"));
    }
    if setup_marker {
        detected_components.push(String::from("설정 또는 활성 release 감지"));
    }

    IntegrationView {
        id: definition.id,
        name: definition.name.to_owned(),
        summary: definition.summary.to_owned(),
        category: definition.category,
        lifecycle_status,
        install_status: IntegrationInstallStatus::Blocked,
        detected_components,
        install_blockers: blockers,
        resource_claims: definition
            .resource_claims
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        setup_steps: definition
            .setup_steps
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        source_url: definition.source_url.to_owned(),
        assurance: AssuranceView {
            level: AssuranceLevel::G0ObserveOnly,
            rollback_support: RollbackSupport::NotApplicable,
            operation_available: false,
            scope: vec![String::from("설치 흔적과 준비 조건 조회")],
            excluded_effects: vec![String::from("package 설치·설정·활성화·제거")],
            apply_verifier: Vec::new(),
            rollback_verifier: Vec::new(),
            reason: Some(String::from(
                "현재 카탈로그는 조회 전용이며 서명·VM 증거 전에는 설치를 실행하지 않습니다.",
            )),
        },
    }
}

const fn lifecycle(
    platform_supported: bool,
    executable: bool,
    setup_marker: bool,
) -> IntegrationLifecycleStatus {
    if !platform_supported {
        IntegrationLifecycleStatus::Unknown
    } else if executable && setup_marker {
        IntegrationLifecycleStatus::Installed
    } else if executable {
        IntegrationLifecycleStatus::NeedsSetup
    } else if setup_marker {
        IntegrationLifecycleStatus::Partial
    } else {
        IntegrationLifecycleStatus::NotInstalled
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{IntegrationObservationProfile, observe_integrations};
    use jw_contracts::{IntegrationId, IntegrationInstallStatus, IntegrationLifecycleStatus};

    #[test]
    fn catalog_has_four_unique_fail_closed_entries() {
        let profile = IntegrationObservationProfile {
            platform_supported: false,
            ..IntegrationObservationProfile::default()
        };
        let catalog = observe_integrations(&profile, String::from("2026-07-21T00:00:00Z"));
        let ids = catalog
            .entries
            .iter()
            .map(|entry| entry.id)
            .collect::<BTreeSet<IntegrationId>>();

        assert_eq!(catalog.entries.len(), 4);
        assert_eq!(ids.len(), 4);
        assert!(catalog.entries.iter().all(|entry| {
            entry.install_status == IntegrationInstallStatus::Blocked
                && !entry.assurance.operation_available
                && entry.lifecycle_status == IntegrationLifecycleStatus::Unknown
        }));
    }
}
