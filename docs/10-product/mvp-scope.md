# MVP Scope

Status: Accepted  
Authority: Product  
Owner: Product Maintainer  
Last reviewed: 2026-07-21

## 반드시 구현

### 공개·복구 접근

- Nginx+Certbot HTTPS 443 → agentd 전용 Unix socket
- agentd loopback endpoint와 SSH 터널 복구 경로
- Linux PAM ID·비밀번호 인증과 허용 group 기반 role
- 요청당 one-shot root `authd`; `pam_authenticate` 후 `pam_acct_mgmt`
- server-side opaque session, 재인증, CSRF·Origin·Host 방어
- React 작업 중심 desktop·tablet·mobile 반응형 UI
- 공개 모드 활성화·비활성화·복구 plan

P1 package는 existing valid certificate와 opt-in Nginx template까지만 제공합니다. typed 활성화·비활성화와 Certbot guided issuance는 P2 safety kernel 이후에만 구현합니다.

### 관찰

- hostname, Ubuntu version, kernel, uptime
- CPU, memory, filesystem 사용량과 관찰 시각
- failed systemd units
- Nginx 상태·발견된 site inventory
- PHP-FPM, MySQL/MariaDB, Redis의 설치·active 상태
- Certbot 인증서 만료와 보안 업데이트 개수
- unit·기간·행·byte가 제한된 로그 조회
- VPSGuard·G7 Installer·G7MediaBooster·G7Telegram DevOps curated catalog와 설치 흔적 조회

### Access setup operation

- `access.public.enable/v1` and `access.public.disable/v1`
- protected Nginx vhost, valid certificate, Host, UFW delta plan
- SSH recovery 확인 후 활성화; failure rollback과 session revoke
- user-owned Nginx/UFW/SSH/DNS/cloud rule 변경 금지

이 operation은 Accepted 제품 범위이지만 P1 구현 완료 주장이 아닙니다. P2 safety kernel과 fault evidence가 먼저 필요합니다.

### 첫 일반 서비스 쓰기 slice

- `nginx.site_state.set/v1`
- 기존 `sites-available` 항목의 enable/disable만 지원
- immutable plan, plan hash·expiry·precondition
- snapshot, apply, `nginx -t`, reload, read-back, rollback
- idempotency, resource lock, crash recovery, evidence
- 목록·plan·timeline·receipt에 rollback assurance와 정확한 보장 범위 표시

### 안전 설정 편집

- adapter allowlist에 등록된 서비스·논리 resource ID만 편집
- CodeMirror 6 기반 syntax highlighting·unified diff·도움말·주의사항·validation 진단 UI
- `save plan → snapshot → atomic replace → syntax test → reload/restart 승인 → health read-back`
- syntax failure면 service action 없이 종료; reload·health failure면 이전 설정 자동 원복·재검증
- Nginx active profile과 PHP 8.3 FPM 표준 `php.ini` profile만 VM gate 뒤 승격했으며 Redis와 다른 layout은 별도 fixture 전까지 제외

### Certificate lifecycle

- 기존 Ubuntu Certbot 설치·certificate inventory·timer 상태
- DNS·port·Nginx preflight와 staging 발급 검증
- typed guided issuance, Nginx 연결, 갱신 dry-run, 만료 경고
- CA 발급·rate limit은 G1 외부 효과, 제품 소유 Nginx 설정은 G2로 분리 표시

### 수동 OpenSSH 접근

- same-origin WSS 비-root terminal, xterm 기반 resize·UTF-8·bounded session
- 기존 OpenSSH 기반 SFTP list/read/download/upload와 공유 CodeMirror text editor
- Linux 사용자 권한, sshd policy, 짧은 single-use ticket, PAM 재인증 적용
- terminal과 일반 SFTP 쓰기는 G1이며 자동 원복을 약속하지 않음
- root login, root credential, browser key 저장, system-owned 설정의 SFTP write 금지

### 배포

- Ubuntu 24.04 amd64 `.deb`
- `agentd`, socket-activated `authd`, `opsd` systemd unit
- `/etc/pam.d/jw-agent`, 허용 Linux group, public ingress template
- install·upgrade·remove·recovery runbook

## 선행 gate 전 관찰만 구현

- systemd restart
- PHP-FPM 설정
- MySQL/MariaDB 데이터·설정
- Redis 설정
- Certbot 공인 CA 발급 성공은 public-domain operation gate 전
- UFW 규칙
- apt security update 적용
- 백업 최신성

이 항목들은 write operation이 별도 승격 기준을 통과하기 전까지 변경 버튼을 갖지 않습니다.

## MVP 밖

- 중앙관제·고객·직원·멀티테넌트
- 여러 서버 일괄 작업
- 원격 백업·알림·SSO·화이트라벨
- 통합 제품 package 설치·update·remove와 credential 대행 설정
- 다른 Linux 배포판과 container orchestrator
- LDAP·Kerberos·custom multi-prompt PAM과 password 변경 UI
- PWA·service worker·offline mutation·native mobile app
- 임의 root shell API, root web terminal, 범용 root file manager
