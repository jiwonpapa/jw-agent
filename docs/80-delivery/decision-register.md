# Decision Register

Status: Accepted  
Authority: Delivery  
Owner: Maintainers  
Last reviewed: 2026-07-21

## 고정

- 독립 신규 제품과 clean-room 경계
- Ubuntu 24.04 LTS amd64 MVP
- Rust 2024, agentd/opsd 분리
- five runtime/support crates and one xtask
- Nginx+Certbot public HTTPS 443 with agentd UDS
- loopback UI and SSH tunnel recovery
- one-shot root authd, ffi-pam, Ubuntu local pam_unix
- Linux group admin/operator/viewer roles and root web denial
- responsive mobile/tablet/desktop web; no PWA/offline cache
- SQLite WAL daemon별 소유
- React/TypeScript/Vite/Bun/Tailwind CLI/shadcn/TanStack
- `rusqlite` with system SQLite; no bundled SQLite or ORM
- Rust `utoipa` OpenAPI → `openapi-typescript` + `openapi-fetch`
- direct libpam FFI with one masked prompt and 32-message hard limit; unsafe is isolated to `ffi-pam`
- IPC version 1; auth frame 16 KiB, ops capability frame 64 KiB
- public session idle/absolute 15 minutes/8 hours; recovery 10 minutes/2 hours; reauth claim 5 minutes
- exact locked Rust and Bun dependency versions
- additional auth policy values `disabled | risky_operations | all_mutations`
- P1 default `disabled`, UI recommendation `risky_operations`; provider status is explicit
- local-only verification, no GitHub Actions
- first write operation Nginx site enable/disable
- P2 IPC v1 exact match; mixed-version rolling upgrade 없음
- opsd SQLite `synchronous=FULL`, file·directory fsync 뒤 snapshot 확정
- SHA-256 chained ledger, terminal 또는 128 event checkpoint, 손상 시 `FORENSIC_LOCKDOWN`
- fixed argv process group timeout: `SIGTERM` → 2초 → `SIGKILL`, stream별 64 KiB evidence cap
- Nginx layout `ubuntu-nginx-sites-v1`과 hashed `ngs_` site ID
- first additional-auth provider `totp/v1`; PAM-first enrollment·recovery contract
- no shell/PTY/SFTP/file CRUD/blockchain
- central implementation after local release

## P1 마감 결정과 증거

- PAM unsafe는 `ffi-pam` 하나에만 있고 source buffer와 error-path copy를 zeroize합니다. 성공 response copy는 Linux-PAM ownership으로 이전되므로 외부 PAM 내부 메모리까지 zeroize한다고 주장하지 않습니다.
- build/runtime native package는 Ubuntu `libpam0g-dev`/`libpam0g`, `libsqlite3-dev`/`libsqlite3-0`이며 VM package/link gate가 확인합니다.
- dedicated PAM control order는 `pam_faildelay → pam_unix auth → pam_unix account`입니다. `pam_faillock`을 추가하지 않고 agentd memory의 global·source·subject budget으로 SSH account lockout을 피합니다.
- P1 public activation은 기존 valid certificate를 관리자가 opt-in template에 연결하는 방식입니다. agentd·package는 Certbot issuance, DNS, UFW를 호출하지 않습니다.
- `access.public.enable/disable/v1` 자동 변경과 guided issuance는 P2 safety kernel 이후 별도 구현입니다.
- host/Nginx discovery는 API request마다 OS를 다시 읽고 UI는 15초 stale time과 명시적 refetch를 사용합니다. background poller는 P1에 없습니다.
- `p1-local`, `p1-browser`, `p1-vm`과 package install·upgrade·remove·reboot evidence가 PASS했습니다. public DNS·공인 CA·signed release는 미증명입니다.
- 최초 P1 source push는 license 미부여 개발 스냅샷입니다. 잘못된 임시 Apache 표기를 제거하며 `LICENSE`와 실제 오픈소스 권한은 P3에서 명시적으로 선택하기 전까지 주장하지 않습니다.

## P2 진입 결정

모든 선행 결정은 [ADR-0009](../90-specs/adr/0009-p2-safety-kernel-decisions.md), [OPS-NGINX-SITE-STATE-V1](../90-specs/operations/nginx-site-state-set-v1.md), [AUTH-TOTP-STEP-UP-V1](../90-specs/auth/totp-step-up-v1.md)에서 Accepted 상태입니다. 실제 P2 mutation 구현은 별도 진입 승인 전 금지합니다.

## P3 전에 선택

- open-source license
- signing key custody and public key distribution
- snapshot/log default retention and quota
- supported upgrade/downgrade window
- legal terms, privacy, vulnerability response SLA

## 중앙관제 단계에만 선택

- self-hosted vs hosted first release
- PostgreSQL RLS use
- agent transport and certificate authority model
- tenant hierarchy and ownership transfer
- billing, domain, TLS, email/SMS provider

미결정 항목은 코드 default로 몰래 확정하지 않습니다.
