# Capability Status

Status: Accepted  
Authority: Generated Capability Snapshot  
Owner: Maintainers  
Last reviewed: 2026-08-18

이 문서는 [capabilities-v1.json](../00-governance/capabilities-v1.json)에서 생성됩니다. 직접 수정하지 않습니다. 상태를 바꾼 뒤 `cargo xtask render-capabilities`를 실행하고 `GOV-009`로 검증합니다.

현재 등록: 전체 37개 · 구현 18개 · 부분 구현 1개 · 미구현 10개 · 제외/금지 8개

## P1 기반

| 기능 | 범위 | 구현 | 지원 | 증거 | 보장 | 기준·남은 조건 |
|---|---|---|---|---|---|---|
| `auth.pam-login` [Linux PAM 로그인](../90-specs/auth/pam-login-v1.md) | MVP | 구현 | 지원 | VM_PASS | 해당 없음 | Identity Maintainer · — |
| `observability.host` [호스트 자원 관찰](../90-specs/ui/overview-v1.md) | MVP | 구현 | 지원 | VM_PASS | G0 | Observation Maintainer · — |
| `web.dashboard-shell` [작업 중심 반응형 Web UI](../90-specs/ui/responsive-shell-v1.md) | MVP | 구현 | 지원 | BROWSER_PASS | 해당 없음 | Web Maintainer · — |

## P2 로컬 유지보수

| 기능 | 범위 | 구현 | 지원 | 증거 | 보장 | 기준·남은 조건 |
|---|---|---|---|---|---|---|
| `access.independent-edge` [Nginx 독립 관리 edge](../90-specs/adr/0018-independent-rust-management-edge.md) | MVP | 구현 | 지원 | VM_PASS | G0 | Access Edge Maintainer · — |
| `access.openssh-terminal` [non-root OpenSSH 터미널](../90-specs/access/openssh-terminal-sftp-v1.md) | MVP | 구현 | 제한 지원 | VM_PASS | G1 | Manual Access Maintainer · — |
| `access.public-profile` [공개 HTTPS 활성화·비활성화](../90-specs/operations/public-access-profile-v1.md) | MVP | 미구현 | 미검증 | UNVERIFIED | G2 | Ingress Maintainer · typed enable·disable API와 self-lockout VM evidence가 없습니다. |
| `access.sftp-read` [홈 범위 SFTP 읽기](../90-specs/access/openssh-sftp-readonly-v1.md) | MVP | 구현 | 제한 지원 | VM_PASS | G0 | Manual Access Maintainer · — |
| `access.sftp-upload` [홈 범위 SFTP 원자 업로드](../90-specs/access/openssh-sftp-atomic-upload-v1.md) | MVP | 구현 | 제한 지원 | VM_PASS | G1 | Manual Access Maintainer · — |
| `auth.admin-mode` [제한시간 관리자 모드](../90-specs/auth/administrative-access-v1.md) | MVP | 구현 | 지원 | VM_PASS | 해당 없음 | Security Maintainer · — |
| `auth.totp` [TOTP 추가 인증](../90-specs/auth/totp-step-up-v1.md) | MVP | 구현 | 지원 | VM_PASS | 해당 없음 | Security Maintainer · — |
| `certificate.certbot-lifecycle` [Certbot 인증서 lifecycle](../90-specs/operations/certbot-certificate-v1.md) | MVP | 부분 구현 | 제한 지원 | VM_PASS | 혼합 | Certificate Lifecycle Maintainer · 공인 도메인의 실제 CA 발급 성공은 아직 UNVERIFIED입니다. |
| `firewall.ufw-owned-rules` [제품 소유 UFW 규칙](../90-specs/operations/ufw-rule-v1.md) | MVP | 구현 | 제한 지원 | VM_PASS | G2 | Firewall Maintainers · — |
| `integration.curated-catalog` [읽기 전용 통합 카탈로그](../90-specs/ui/integration-catalog-v1.md) | MVP | 구현 | 제한 지원 | BROWSER_PASS | G0 | Integration Maintainer · — |
| `security.forensic-lockdown` [감사 손상 시 쓰기 잠금](../70-security/logging-and-forensics.md) | MVP | 구현 | 지원 | VM_PASS | 해당 없음 | Security Maintainer · — |
| `service.config-diagnostics` [공식 validator 진단 매핑](../90-specs/operations/managed-config-diagnostic-v1.md) | MVP | 구현 | 제한 지원 | VM_PASS | G2 | Managed Configuration Maintainer · — |
| `service.inventory` [주요·설치 서비스 inventory](../90-specs/observability/service-inventory-v1.md) | MVP | 구현 | 지원 | VM_PASS | G0 | Service Maintainer · — |
| `service.lifecycle` [Nginx·Apache·PHP-FPM lifecycle](../90-specs/operations/service-control-v1.md) | MVP | 구현 | 제한 지원 | VM_PASS | 혼합 | Service Maintainer · — |
| `service.managed-config` [Nginx·Apache·PHP-FPM 설정 편집·복원](../90-specs/operations/managed-config-file-v1.md) | MVP | 구현 | 제한 지원 | VM_PASS | G2 | Managed Configuration Maintainers · — |
| `service.nginx-site-state` [Nginx site 활성 상태](../90-specs/operations/nginx-site-state-set-v1.md) | MVP | 구현 | 제한 지원 | VM_PASS | G2 | P2 Safety Maintainers · — |
| `service.php-fpm-config` [PHP-FPM 설정 profile](../90-specs/operations/php-fpm-config-v1.md) | MVP | 구현 | 제한 지원 | VM_PASS | G2 | PHP-FPM Adapter Maintainer · — |

## P3 Community RC

| 기능 | 범위 | 구현 | 지원 | 증거 | 보장 | 기준·남은 조건 |
|---|---|---|---|---|---|---|
| `observability.backup-freshness` [백업 최신성 관찰](../10-product/mvp-scope.md) | MVP | 미구현 | 미검증 | UNVERIFIED | G0 | Observation Maintainer · 백업 제품을 소유하지 않는 read-only freshness 계약이 필요합니다. |
| `observability.database-cache-details` [MySQL·MariaDB·Redis 상세 관찰](../80-delivery/roadmap.md) | MVP | 미구현 | 미검증 | UNVERIFIED | G0 | Service Adapter Maintainers · 설치·active 이외의 버전·설정 위치·health read-only adapter가 없습니다. |
| `observability.limited-logs` [제한 로그 조회](../10-product/mvp-scope.md) | MVP | 미구현 | 미검증 | UNVERIFIED | G0 | Observation Maintainer · unit·기간·행·byte 제한과 비밀 마스킹 계약이 아직 구현되지 않았습니다. |
| `observability.security-updates` [보안 업데이트 개수](../10-product/mvp-scope.md) | MVP | 미구현 | 미검증 | UNVERIFIED | G0 | Observation Maintainer · 읽기 전용 apt metadata 관찰과 timeout 증거가 없습니다. |
| `release.community` [Community local MVP release](../80-delivery/packaging-release.md) | MVP | 미구현 | 미검증 | UNVERIFIED | 해당 없음 | Release Maintainer · release lane·서명·SBOM·upgrade/remove/recovery·법률 문서 증거가 없습니다. |
| `security.evidence-export` [감사 증거 export](../80-delivery/roadmap.md) | MVP | 미구현 | 미검증 | UNVERIFIED | G0 | Security Maintainer · 비밀 제외·크기 제한·체크포인트 포함 export 계약과 API가 없습니다. |

## P4 중앙 읽기 전용

| 기능 | 범위 | 구현 | 지원 | 증거 | 보장 | 기준·남은 조건 |
|---|---|---|---|---|---|---|
| `central.read-only` [중앙 읽기 전용 관제](../20-architecture/central-future.md) | 후순위 | 미구현 | 미검증 | UNVERIFIED | G0 | Future Central Maintainers · Community local RC 이후 별도 제품 승인 대상입니다. |

## P5 중앙 typed 작업

| 기능 | 범위 | 구현 | 지원 | 증거 | 보장 | 기준·남은 조건 |
|---|---|---|---|---|---|---|
| `central.typed-operations` [중앙 typed operation relay](../20-architecture/central-future.md) | 후순위 | 미구현 | 미검증 | UNVERIFIED | 혼합 | Future Central Maintainers · P4 read-only pilot와 로컬 operation release evidence가 선행돼야 합니다. |

## 후속 검토

| 기능 | 범위 | 구현 | 지원 | 증거 | 보장 | 기준·남은 조건 |
|---|---|---|---|---|---|---|
| `ai.direct-mutation` [AI 직접 변경·승인·원복 판단](../10-product/non-goals.md) | 금지 | 금지 | 미지원 | 정책 | 해당 없음 | Product Maintainer · AI는 구조화된 증거 요약만 허용합니다. |
| `audit.blockchain` [블록체인 감사 원장](../10-product/non-goals.md) | 금지 | 금지 | 미지원 | 정책 | 해당 없음 | Product Maintainer · 비용·운영 복잡도 대비 로컬 서버 신뢰 문제를 해결하지 못합니다. |
| `auth.passkey` [WebAuthn 패스키](../10-product/support-matrix.md) | 후순위 | 미구현 | 미검증 | UNVERIFIED | 해당 없음 | Security Maintainer · TOTP recovery와 local RC 안정화 이후 별도 provider로 검토합니다. |
| `integration.remote-installer` [원격 manifest 제품 설치](../10-product/non-goals.md) | 제외 | 제외 | 미지원 | 정책 | 해당 없음 | Product Maintainer · 현재 카탈로그는 고정된 읽기 전용 관찰만 허용합니다. |
| `platform.multi-distro` [다중 Linux 배포판](../10-product/non-goals.md) | 제외 | 제외 | 미지원 | 정책 | 해당 없음 | Product Maintainer · Ubuntu 24.04 LTS RC 이전에는 지원하지 않습니다. |
| `root.arbitrary-shell` [임의 root shell·argv API](../10-product/non-goals.md) | 금지 | 금지 | 미지원 | 정책 | 해당 없음 | Security Maintainer · root 작업은 typed allowlist operation만 허용합니다. |
| `root.generic-file-crud` [범용 root 파일 관리자](../10-product/non-goals.md) | 금지 | 금지 | 미지원 | 정책 | 해당 없음 | Security Maintainer · adapter allowlist 설정 resource만 편집합니다. |
| `service.database-write` [MySQL·MariaDB 데이터 쓰기](../10-product/support-matrix.md) | 제외 | 제외 | 미지원 | 정책 | 해당 없음 | Product Maintainer · 로컬 MVP는 데이터 변경과 DB 복구 보장을 소유하지 않습니다. |
| `web.native-mobile` [Tauri·PWA·native mobile](../10-product/non-goals.md) | 제외 | 제외 | 미지원 | 정책 | 해당 없음 | Product Maintainer · 설정 mutation은 desktop Web UI를 우선합니다. |

