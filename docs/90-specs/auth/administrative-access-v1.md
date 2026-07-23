# AUTH-ADMINISTRATIVE-ACCESS-V1

Status: Accepted  
Authority: Authentication Specification  
Owner: Security Maintainer  
Last reviewed: 2026-07-23

## Purpose

`jw-agent-admin` 역할의 비-root Linux 계정이 공개 HTTPS 또는 SSH 복구 경로에서 관리 모드로 명시적으로 승격합니다. 관리 모드는 root 계정 세션이 아니라 root `opsd`의 allowlisted typed operation 화면을 여는 짧은 권한 상태입니다.

## Non-goals

- UID 0 로그인, root password, root shell·PTY·SFTP
- 브라우저·DB·로그에 Linux password 또는 TOTP code 저장
- arbitrary command, argv 또는 arbitrary root path 전달
- 관리 모드를 Linux `sudo` credential cache로 사용
- 관리 모드를 Linux `sudo` credential cache로 사용

## Contract

- 진입: `POST /api/v1/auth/administrative-access`
- 종료: `DELETE /api/v1/auth/administrative-access`
- 입력: 현재 admin session의 Linux password와 정책이 요구할 때 TOTP code
- PAM step-up context: `administrative-access/v1`
- 최대 수명: 15분이며 parent session absolute expiry를 넘지 않음
- 성공 시 session identifier와 CSRF token을 회전하고 기존 terminal·SFTP session을 닫음
- 종료는 현재 session의 관리 상태만 즉시 폐기하며 로그인 session은 유지
- `SessionView`는 `standard | administrative`, 관리 모드 만료 시각을 명시
- 관리 모드 진입·종료는 actor UID, ingress, result와 시각만 SQLite audit에 기록

## Root operation authorization

- Nginx·PHP-FPM·Certbot과 이후 추가되는 root service adapter의 plan과 approval API는 유효한 관리 모드가 아니면 `403 administrative_access_required`로 거부
- plan은 계속 immutable hash·single-use approval·CSRF·idempotency를 가지며 유효한 관리 모드가 G2 reversible operation의 step-up 근거입니다.
- 관리 모드 만료, stop, large deletion과 관리 접속 영향 작업은 정책이 요구하는 PAM·추가 인증을 다시 수행합니다.
- `opsd`는 관리 모드 token, password 또는 TOTP를 받지 않고 기존 typed request와 canonical actor만 받음
- management mode는 root login이나 sudo shell이 아니라 root `opsd` typed operation 승인 capability입니다.
- 화면은 `root 작업 잠김`과 `root opsd typed 작업 승인 가능`을 구분하고 15분 만료를 표시합니다.

## UI

- header는 `읽기 전용`, `관리 권한 · 표준 모드`, `관리 권한 · 관리 모드`를 구분
- 개요 첫 화면은 계정·현재 session·root 경계를 접지 않고 표시
- 다른 화면은 우측 account panel에서 같은 상태와 남은 시간을 표시
- root typed 작업의 직접 진입점에서 표준 모드이면 관리 모드 요청 dialog를 열고, 성공 뒤 원래 작업으로 복귀
- root로 실행되는 범위와 자동 원복 보장은 간결한 기본 요약과 접을 수 있는 기술 세부정보로 표시

## Acceptance

- admin PAM success, wrong password generic failure, viewer/operator/UID 0 denial
- configured TOTP success, missing/invalid/replayed code denial
- session/CSRF rotation, 15분 expiry, explicit exit, logout and daemon restart
- standard mode에서 모든 root plan·approval API server-side denial
- administrative mode에서도 arbitrary shell/root file endpoint 부재
- password/TOTP가 URL, storage, SQLite audit, log, screenshot, trace에 없음
- 관리 모드 안의 G2 설정은 반복 비밀번호 없이 승인되며 stop·large deletion은 추가 위험 확인을 요구
- 개요 default-expanded session panel과 다른 route account drawer

`jw-agent_0.2.0~p2.18_amd64.deb`에서 구현되었으며 Ubuntu 24.04 VM의 전체 `p2-vm` 26개 gate가 관리 모드 진입 뒤 Nginx·PHP-FPM·Certbot typed operation, TOTP 결합, PAM limiter 분리와 secret scan을 검증했습니다. SHA-256은 `80d7339e379bef72414c2294dcd8399f64818775abbff267577e7d6d50f3e7ba`입니다.
