# Workspace Layout and Dependency Rules

Status: Accepted  
Authority: Architecture  
Owner: Architecture Maintainer  
Last reviewed: 2026-07-21

## 목표 구조

```text
Cargo.toml
crates/
  jw-contracts/   # process boundary DTO and operation state
  jw-agentd/      # non-root API, session, observation, UI host
  jw-authd/       # root one-shot PAM broker, no network or DB
  jw-certd/       # root one-shot fixed Certbot runner
  ffi-pam/        # only workspace crate allowed to contain PAM unsafe FFI
  jw-opsd/        # root networkless safety executor
xtask/            # sole verification and evidence tool
apps/web/         # React + TypeScript SPA
packaging/debian/ # .deb metadata and systemd units
tests/vm/         # disposable Ubuntu scenarios and fixtures
docs/
```

P1 workspace member는 `jw-contracts`, `jw-agentd`, `jw-authd`, `ffi-pam`, `jw-opsd`, `xtask`입니다. Web은 `apps/web`의 독립 Bun package이며 Rust build graph에 포함하지 않습니다.

## 의존 방향

```text
web --HTTPS--> Nginx --UDS REST/SSE--> agentd --> jw-contracts
                                           │
                                           ├--one-request UDS--> authd --> jw-contracts
                                           │                         └--> ffi-pam
                                           └--typed UDS runtime--> opsd --> jw-contracts
                                                                      └--root-only UDS--> certd --> fixed Certbot
```

P2 수동 접근은 같은 public/recovery ingress와 PAM session을 재사용하되 root helper를 통과하지 않습니다.

```text
web terminal --same-origin WSS--> agentd --loopback SSH--> existing sshd (non-root)
web files ----REST/stream-------> agentd --loopback SFTP-> existing sshd (non-root)
managed config --REST----------> agentd --typed UDS-----> opsd (root, allowlisted resource)
```

- `jw-contracts`는 serde/schema 외 DB·Tokio·Axum·OS 명령을 모릅니다.
- `jw-authd`는 HTTP·TLS·DB·operation dependency가 없고 PAM 인증 후 종료합니다.
- `jw-certd`는 HTTP·DB·Nginx mutation을 모르며 fixed Certbot 요청 하나 후 종료합니다.
- `ffi-pam`만 unsafe와 libpam link를 허용합니다.
- `jw-opsd`는 `jw-agentd`, HTTP, TLS, WebSocket을 의존하지 않습니다.
- `agentd`는 `authd`·`opsd` 내부 상태를 직접 읽지 않습니다.
- daemon은 compile-time service plugin을 공유하지 않습니다.
- terminal·SFTP session code는 `agentd` module로 시작하며 dependency spike 전 새 crate를 만들지 않습니다.
- service config·Certbot adapter는 `opsd` module이며 HTTP·WebSocket을 알지 못합니다.

## crate 생성 기준

새 crate는 다음 중 하나가 입증될 때만 허용합니다.

1. 별도 프로세스·권한·배포 artifact
2. 두 runtime이 쓰는 안정된 계약
3. 격리해야 하는 FFI/unsafe
4. 측정된 빌드 병목과 안정된 독립 API

서비스 adapter, DB layer, ledger는 먼저 소유 daemon 내부 module로 둡니다. `authd`와 `ffi-pam`은 root credential 경계와 unsafe FFI라는 제1·3 기준으로, `certd`는 외부 네트워크가 금지된 `opsd`와 분리해야 하는 one-shot network privilege 경계라는 제1 기준으로 허용된 예외입니다.
