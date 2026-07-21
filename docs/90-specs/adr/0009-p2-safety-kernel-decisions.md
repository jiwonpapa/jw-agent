# ADR-0009 — P2 Safety Kernel Decisions

Status: Accepted  
Authority: Architecture Decision  
Owner: Safety Maintainer  
Last reviewed: 2026-07-21

## Context

P2의 첫 변경 작업은 Nginx site enable·disable 하나입니다. 구현 전에 IPC 호환성, durable snapshot, ledger 연속성, 자식 프로세스 종료, site identity와 추가 인증 provider를 고정하지 않으면 서로 다른 기본값이 opsd·agentd·UI에 퍼집니다.

## Decision

### IPC compatibility

- P2 전체에서 agentd↔opsd IPC는 `protocol_version = 1` exact match만 허용합니다.
- 알 수 없는 version, field 또는 operation version은 명시적으로 거부하고 downgrade fallback을 하지 않습니다.
- stable local release 전에는 mixed-version rolling upgrade를 지원하지 않습니다. `.deb`가 두 daemon을 같은 artifact로 교체하고 호환되지 않는 이전 binary가 남으면 write를 차단합니다.

### Durable state and snapshot

- opsd authority DB는 `/var/lib/jw-agent/opsd/opsd.sqlite3`의 SQLite WAL이며 `foreign_keys=ON`, bounded busy timeout, `synchronous=FULL`을 사용합니다.
- stage transition과 event append는 한 transaction이고 write 경쟁은 `BEGIN IMMEDIATE`에서 fail closed 합니다.
- snapshot은 `/var/lib/jw-agent/opsd/snapshots/{operation_id}` 아래 root `0700` directory와 create-new file만 사용합니다.
- snapshot body write, file `fsync`, SHA-256 read-back, directory `fsync`가 모두 성공한 뒤에만 `SNAPSHOTTED`를 기록합니다.

### Ledger continuity

- event는 schema version, sequence, previous digest, operation·plan ID, stage, result, timestamp와 allowlisted evidence를 canonical field order로 직렬화합니다.
- digest는 ASCII `jw-agent/ledger/v1` 뒤의 단일 NUL byte를 domain separator로 둔 `SHA-256(prefix || NUL || previous_digest || canonical_event)`입니다. 문자 `\\`와 `0` 두 바이트를 사용하지 않습니다.
- terminal transition 또는 128 event 중 먼저 도달한 시점에 root-owned checkpoint를 원자 교체하고 file·directory를 `fsync`합니다.
- sequence gap, digest mismatch, checkpoint rollback 또는 SQLite integrity failure는 `FORENSIC_LOCKDOWN`을 발생시킵니다. 이는 blockchain이나 root 공격에 대한 절대 불변성 주장이 아닙니다.

### Process cancellation

- executable과 argv는 operation registry가 고정하며 shell, user argv, environment inheritance를 금지합니다.
- 각 command는 새 process group에서 실행합니다.
- timeout 시 group에 `SIGTERM`, 2초 유예 후 `SIGKILL`을 보내고 모든 pipe를 회수합니다.
- stdout·stderr는 각각 64 KiB까지만 evidence 대상으로 보존하고 전체 stream digest와 truncated 여부를 기록합니다.

### Nginx layout and site identity

- P2 write 지원 layout ID는 `ubuntu-nginx-sites-v1` 하나입니다.
- available entry는 `/etc/nginx/sites-available`의 단일 UTF-8 basename이어야 하며 separator, `.`·`..`, 외부 symlink와 link loop를 거부합니다.
- `site_id`는 `ngs_`와 `SHA-256(layout_id || NUL || basename)` 앞 18 byte의 base64url-no-pad 조합입니다. path는 API identity가 아니며 display name으로만 별도 반환합니다.
- plan과 apply 직전에 basename, canonical root, source digest와 enabled-link state를 다시 확인합니다.

### First additional-auth provider

- 첫 provider는 RFC 6238 TOTP이며 provider ID는 `totp/v1`입니다.
- PAM 재인증은 항상 먼저 수행하며 TOTP는 PAM을 대체하지 않습니다.
- 세부 enrollment·verification·recovery 계약은 [AUTH-TOTP-STEP-UP-V1](../auth/totp-step-up-v1.md)이 소유합니다.

## Build consequences

- 새 crate, ORM, code generator, database 또는 background broker를 추가하지 않습니다.
- process group은 Rust 표준 Unix process API로 우선 구현하고 불가피한 unsafe/native dependency가 필요하면 별도 ADR 없이는 진행하지 않습니다.
- SHA-256과 base64는 workspace의 기존 exact-pin dependency를 재사용합니다.
- TOTP crypto dependency는 구현 진입 시 lockfile·build-time 검증을 거친 최소 묶음으로만 추가합니다.

## Rejected alternatives

- version 자동 fallback: incompatible request를 다른 의미로 실행할 수 있습니다.
- SQLite `NORMAL`과 DB stage만으로 복구: power loss 뒤 snapshot durability를 과장합니다.
- blockchain: local root compromise를 해결하지 못하고 MVP 운영비와 복잡도만 늘립니다.
- raw path site ID: path injection과 layout drift가 API 계약으로 노출됩니다.
- WebAuthn first: 공개 RP ID와 SSH recovery origin, browser compatibility를 동시에 해결해야 해 첫 provider로는 범위가 큽니다.
- PAM multi-prompt OTP: P1의 단일 masked prompt와 지원 PAM 경계를 깨뜨립니다.

## Acceptance

- [OPS-NGINX-SITE-STATE-V1](../operations/nginx-site-state-set-v1.md)의 schema·fixture와 동일한 identifiers
- crash, power-loss, disk-full, duplicate, process-tree timeout acceptance scenarios
- ledger tamper가 write를 차단하고 read-only diagnosis를 유지
- TOTP secret·code·recovery code가 log·URL·browser storage·평문 DB에 없음
- P2 진입은 [ADR-0010](0010-local-maintenance-surfaces.md)으로 승인되었으며 첫 mutation은 Nginx site state 범위만 활성화
