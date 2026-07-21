# ADR-0010 — Local Maintenance Surfaces and P2 Entry

Status: Accepted  
Authority: Architecture Decision  
Owner: Architecture Maintainer  
Last reviewed: 2026-07-21

## Context

P1은 PAM 기반 공개·복구 접근과 관찰을 실제 Ubuntu VM에서 검증했습니다. 사용자는 2026-07-21에 P2 목표추진을 승인하고, 안전 설정 편집, Certbot 수명주기, 기존 OpenSSH 기반 비-root 웹 터미널·SFTP를 로컬 MVP에 포함하도록 결정했습니다.

기존 문구는 `opsd` 임의 root shell API 금지와 운영자의 기존 Linux 계정으로 여는 수동 OpenSSH 세션을 모두 “shell 금지”로 묶었습니다. 이 구분이 없으면 필요한 수동 복구 경로까지 막거나, 반대로 root helper에 범용 명령을 넣는 오류가 생깁니다.

## Decision

### P2 entry

- P2 구현 진입은 승인되었습니다.
- 첫 구현 기준점은 [OPS-NGINX-SITE-STATE-V1](../operations/nginx-site-state-set-v1.md)입니다.
- opsd safety kernel과 첫 G2 operation이 VM fault matrix를 통과하기 전에는 다른 root mutation을 활성화하지 않습니다.
- 새 서비스 adapter는 새 crate가 아니라 기존 `jw-opsd` 내부 module로 시작합니다.

### Privilege separation

- 설정 파일과 서비스 상태 변경은 `agentd → typed UDS → opsd`만 사용합니다.
- `opsd`에는 사용자 argv, shell string, PTY, 범용 path CRUD를 제공하지 않습니다.
- 웹 터미널과 SFTP는 `agentd → loopback OpenSSH` 경로를 사용하며 로그인한 Linux 사용자의 UID·group·sshd 정책을 그대로 따릅니다.
- 웹 터미널·SFTP에서 UID 0 직접 로그인, root password, SSH private key 업로드·저장, privilege escalation 자동화는 금지합니다.
- system-owned/protected 설정은 SFTP로 쓰지 못하며 typed config operation만 사용합니다.

### Assurance boundary

- terminal command execution: `G1 MANUAL_NON_REVERSIBLE`
- SFTP list/read/download: `G0 READ_ONLY`
- 일반 SFTP upload/delete/move/chmod: `G1 MANUAL_NON_REVERSIBLE`
- 지원 adapter가 snapshot·validation·rollback을 소유하는 단일 설정 파일 교체: `G2 REVERSIBLE_CONFIG`
- certificate authority에 대한 발급·폐기 같은 외부 효과: `G1`; 제품 소유 Nginx 연결 설정은 별도 `G2`

G1 화면은 자동 원복을 암시하지 않고 명시적 재인증·위험 확인·짧은 세션 만료를 요구합니다. G2 화면은 plan, snapshot 범위, verifier, excluded effects와 recovery path를 승인 전에 표시합니다.

### Managed configuration

- 최초 write 지원은 adapter가 allowlist한 논리 resource ID와 Ubuntu 24.04 표준 layout으로 제한합니다.
- 브라우저가 root path를 operation 입력으로 보내지 않습니다.
- 저장은 `plan → snapshot → atomic replace → syntax validation → explicit reload/restart approval → read-back/health → rollback`을 따릅니다.
- syntax validation이 실패하면 서비스 reload/restart를 실행하지 않습니다.
- rollback은 설정 파일 복원과 이전 설정으로의 재검증·reload까지만 보장하며 요청·연결의 과거 상태는 보장하지 않습니다.

### Certbot lifecycle

- 기존 Ubuntu apt Certbot과 systemd timer를 사용합니다. ACME client나 certificate store를 새로 구현하지 않습니다.
- DNS·80/443 reachability·Nginx layout·계정 동의·rate-limit 경고를 plan에 표시합니다.
- production 발급 전 staging dry run을 기본으로 하고, command·plugin·domain은 typed registry가 고정합니다.
- private key와 ACME credential은 브라우저, argv evidence, 감사 로그에 기록하지 않습니다.
- 갱신은 `certbot.timer` 상태와 `certbot renew --dry-run` 검증을 제공하고 임의 cron을 만들지 않습니다.

### Web transport

- terminal은 same-origin `WSS`만 사용하고 Nginx가 session·frame·idle·connection limit을 강제합니다.
- SFTP control은 REST, 전송 진행은 bounded streaming 또는 별도 typed channel을 사용합니다. 새 SFTP protocol server를 구현하지 않습니다.
- terminal transcript, password, SSH private key, file body를 browser localStorage·sessionStorage·IndexedDB에 저장하지 않습니다.
- terminal·SFTP 세션은 서버 측 단일 사용 ticket, 짧은 TTL, 사용자·session·origin binding을 요구합니다.

## Build consequences

- P2 safety kernel은 기존 exact-pinned `rusqlite`, `sha2`, `base64`, `nix`를 사용합니다.
- operation SSE는 Axum에서 custom bounded stream을 구현하기 위해 이미 Axum 의존 그래프에 존재하는 exact-pinned `futures-core`만 agentd의 direct dependency로 승격합니다. 새 runtime node, codegen, native dependency는 추가하지 않으며 owner는 Agent API Maintainer입니다.
- `nix`의 typed filesystem·process-group 구현에 필요한 최소 feature 확장은 허용하되 lockfile과 build-time 차이를 기록합니다.
- terminal/SFTP dependency는 safety kernel 완료 뒤 별도 compatibility spike에서 exact pin, default-feature 축소, clean/incremental build 비용, Ubuntu VM 동작을 증명해야 합니다.
- Tauri, native desktop signing, 새로운 TLS stack, OpenSSL system dependency, xterm/Monaco 외 무거운 UI framework를 추가하지 않습니다.
- 기존 프로젝트의 source, crate, protocol, ticket format, storage, release artifact는 복사·연결하지 않습니다.

## Rejected alternatives

- root opsd shell/PTY API: agentd 침해를 임의 root 실행으로 확대합니다.
- 브라우저 자체 SSH/SFTP protocol 구현: key·protocol·supply-chain 표면이 커집니다.
- Tauri 우선: 항상 켜진 서버 관리와 모바일·태블릿 요구를 충족하지 못합니다.
- 범용 `/etc` 편집: 서비스별 validation·rollback 의미가 없습니다.
- 모든 수동 작업의 자동 rollback 주장: terminal·SFTP의 외부 효과를 복원할 수 없습니다.

## Acceptance

- P2 safety kernel과 `nginx.site_state.set/v1`이 먼저 `VM_PASS + G2`를 획득
- managed config는 syntax failure 시 reload 없음, reload/health failure 시 verified rollback
- Certbot staging·production·renewal의 rate limit, secret, rollback 경계가 UI와 receipt에 표시
- terminal/SFTP는 non-root, same-origin, short-lived, bounded, audited이며 root helper를 우회하지 않음
- 기능별 spec과 xtask gate 없이 UI route·API·capability를 노출하지 않음
