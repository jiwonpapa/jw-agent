# MVP Delivery Roadmap

Status: Accepted  
Authority: Delivery  
Owner: Delivery Maintainer  
Last reviewed: 2026-07-21

## P0 — Foundation

구현:

- constitution, document hierarchy, ADR/spec lifecycle
- single `xtask` governance gate
- domain/workspace/UI/security/release design

완료 증거:

- local links and mandatory documents PASS
- remote Actions absence PASS
- decision register has no silent blocker

제품 code·package·VM evidence는 이 단계에서 만들지 않습니다.

## P1 — Identity, public edge, and read-only vertical slice

구현:

- five runtime/support crates and one Bun web package
- one-shot PAM authd, local Linux account roles, server-side session
- Nginx+Certbot public HTTPS profile and loopback SSH recovery
- agentd host observation and Nginx discovery
- curated integration catalog and fixed-path read-only discovery
- opsd UDS handshake and read-only capability response
- responsive login, Overview, Nginx inventory, access settings UI
- responsive integration inventory and assurance inspector
- local SQLite migrations and generated OpenAPI client

최종 완료 증거:

- `p1-local`, `p1-browser`, `p1-vm` lane
- contract compatibility and negative IPC tests
- PAM auth/account/group/secret VM gates
- public TLS/proxy/rate-limit/session/recovery gates
- Playwright login and real API overview at mobile/tablet/desktop viewports
- Ubuntu VM `.deb` install, systemd start, public HTTPS and SSH tunnel recovery

P1 public/PAM gates는 VM_PASS했지만 이것만으로 P2 write operation 진입이 승인되지는 않습니다. 별도 P2 진입 승인 전까지 general service write, central, broad service mutations는 계속 금지합니다.

현재 `p1-local` 18개, `p1-browser` 8개, `p1-vm` 12개 gate가 PASS했습니다. 폐기 가능한 Ubuntu 24.04 VM에서 `.deb` 설치·업그레이드·제거/재설치·재부팅, PAM 실패 동등성, 공개 HTTPS, Nginx 장애 중 SSH recovery를 검증했습니다. 테스트 CA 기반 VM 증거이므로 실제 공인 DNS·Certbot 발급, 서명 release와 운영 안전은 아직 주장하지 않습니다. P2 진입은 별도 승인 사항입니다.

P1 public profile 범위는 existing certificate와 administrator-owned opt-in template입니다. 자동 public enable/disable과 Certbot guided issuance는 P1 완료 주장에 포함하지 않습니다.

## P2 — Safety kernel and first operation

진입 상태: architecture·operation·TOTP spec은 Accepted, implementation entry approval 대기.

구현:

- plan, approval, idempotency, lock, ledger, snapshot state machine
- `nginx.site_state.set/v1`
- 목록부터 plan·timeline·receipt까지 rollback assurance와 recovery UI

완료 증거:

- success/no-op/validation failure/reload failure
- automatic rollback and rollback-failure state
- `G0/G1/G2/unknown` 표시와 mutation CTA 차단 browser evidence
- kill at each stage, disk full, duplicate request, external drift
- traversal/external symlink/output-limit/timeout negatives
- `SUPPORTED + VM_PASS + G2`
- first additional-auth provider and enrollment/recovery spec accepted

## P3 — Community local MVP release

구현:

- limited logs, failed units, SSL expiry, security update count
- PHP-FPM, MySQL/MariaDB, Redis, UFW read-only adapters
- forensic lockdown, evidence export, update/recovery UX
- signed `.deb`, SBOM, checksum, docs

완료 증거:

- clean release lane with no skipped required gate
- fresh install, upgrade, restart, removal, recovery on Ubuntu 24.04
- security, accessibility, supply-chain evidence bundle
- support and legal documents reviewed

## P4 — Central read-only pilot

별도 승인 후 central stack, enrollment, tenant/RBAC, outbound health, alerts를 구현합니다. 원격 write는 포함하지 않습니다.

## P5 — Central typed operations

로컬 operation 증거를 재사용해 중앙 plan/approval/receipt relay를 추가합니다. terminal/SFTP는 별도 제품 결정 없이는 포함하지 않습니다.
