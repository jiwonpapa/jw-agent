# MVP Delivery Roadmap

Status: Accepted  
Authority: Delivery  
Owner: Delivery Maintainer  
Last reviewed: 2026-07-22

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

P1 public/PAM gates는 VM_PASS했습니다. P2 write operation 진입은 2026-07-21 사용자 목표추진 지시와 [ADR-0010](../90-specs/adr/0010-local-maintenance-surfaces.md)으로 승인되었습니다. 중앙관제와 미등록 broad mutation은 계속 금지합니다.

현재 `p1-local` 18개, `p1-browser` 8개, `p1-vm` 12개 gate가 PASS했습니다. 폐기 가능한 Ubuntu 24.04 VM에서 `.deb` 설치·업그레이드·제거/재설치·재부팅, PAM 실패 동등성, 공개 HTTPS, Nginx 장애 중 SSH recovery를 검증했습니다. 테스트 CA 기반 VM 증거이므로 실제 공인 DNS·Certbot 발급, 서명 release와 운영 안전은 아직 주장하지 않습니다.

P1 public profile 범위는 existing certificate와 administrator-owned opt-in template입니다. 자동 public enable/disable과 Certbot guided issuance는 P1 완료 주장에 포함하지 않습니다.

## P2 — Safety kernel and first operation

진입 상태: Approved. 첫 활성 scope는 safety kernel과 Nginx site-state입니다.

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

현재 기준선:

- `p2-local` 20개, `p2-browser` 8개 gate와 Playwright 27개 scenario가 PASS했습니다.
- `p2-vm` 21개 gate에서 Nginx fault matrix, forensic lockdown, Certbot lifecycle과 non-root OpenSSH terminal을 검증했습니다.
- Ubuntu 24.04 VM에 `jw-agent_0.2.0~p2.8_amd64.deb`를 설치했고 SHA-256은 `d1b8591a57a66255e4d7260f5c568613497dbe0d3cf29667698f32716509ff64`입니다.
- 제품 관리 vhost는 파일명과 무관하게 content marker/include로 보호되며 plan 단계에서 변경을 거부합니다.
- 승인 API는 `202 Accepted` 뒤 durable operation을 실행하고 SSE sequence replay와 canonical receipt 조회를 제공합니다.

P2 전체 milestone은 아직 완료가 아닙니다. 모든 durable stage의 강제 종료 matrix와 command timeout·output cap 확대는 후속 adapter 전에 계속 보강합니다.

## P2B — Managed configuration

구현:

- allowlisted Nginx resource editor, diff, syntax, reload approval, health read-back
- snapshot·atomic replace·verified rollback과 recovery receipt
- inline help, glossary, warnings, mobile approval UX

완료 증거:

- valid save, syntax rejection without reload, reload/health failure rollback
- external edit, symlink/traversal, disk full, kill/restart, concurrent edit negatives
- browser G2 assurance and Ubuntu VM service continuity proof

현재 기준선:

- Nginx active resource profile은 `SUPPORTED + VM_PASS + G2`입니다.
- 24 KiB UTF-8 content, 64 KiB JSON envelope, root:root regular file, exact active symlink, reload만 허용합니다.
- valid/no-op, syntax·reload rollback, external drift, inactive denial, 제안 원문 정리, 내부 temp 비노출·startup cleanup을 실제 VM에서 검증했습니다.
- 배포된 공개 HTTPS UI에서 editor·byte cap·G2 scope/exclusion·planned-only 경고와 console error 0을 확인했습니다.

## P2C — Certificate lifecycle

구현:

- Certbot inventory, DNS/port preflight, staging/production guided issuance
- Nginx attach, timer status, renewal dry-run and expiry warnings

완료 증거:

- staging ACME VM/domain harness, bounded command and redaction proof
- failed challenge/rate-limit/attach rollback/recovery scenarios
- G1 external effect and G2 local config boundary UI evidence

현재 one-shot `jw-certd` root-only UDS, fixed argv, email argv 비노출과 digest-only output은 `VM_PASS`입니다. 표준 lineage의 SAN·만료·fingerprint·timer 조회와 `certbot.certificate.renew_test/v1`도 실제 VM에서 정상/비정상 timer 양쪽을 검증했습니다. `certbot.certificate.issue/v1`은 DNS exact-match, 80/443 listener, 보호된 Nginx webroot, staging-first, PAM과 두 개의 외부효과 동의를 요구하며, 계정 이메일은 root 0600 임시 proposal 뒤 삭제됩니다. private-LAN `.test` VM에서는 실제 CA 실패가 `REJECTED`되고 inventory·Nginx가 보존되는 경로까지 `VM_PASS`입니다. `certbot.certificate.attach/v1`은 보호 vhost의 두 TLS 지시문만 교체하며 Nginx 문법·reload·active, timer와 `127.0.0.1:443` SNI 지문을 검증하고 실패 시 원문 bytes·owner·mode를 원복하는 `VM_PASS + G2`입니다. 공인 CA 발급 성공은 아직 `UNVERIFIED`입니다.

## P2D — Manual OpenSSH access

현재 구현:

- same-origin WSS non-root terminal and bounded xterm UI
- short ticket, PAM reauth, role/path/quota/session policy, audit summary

다음 구현:

- existing OpenSSH SFTP list/read/download/upload and Monaco text editing
- SFTP path/size/quota policy와 metadata-only transfer audit

완료 증거:

- root denial, ticket replay, wrong origin, idle/max lifetime, frame/transfer cap
- disconnect/reconnect, mobile/tablet terminal, large file and traversal negatives
- no browser secret/transcript persistence and no opsd shell/PTY surface

터미널은 Ubuntu 24.04 package VM에서 non-root PAM/OpenSSH 로그인, 명령 I/O, 40×100 resize, replay·wrong-origin 차단, logout revoke, metadata-only audit와 process/FIFO cleanup을 `VM_PASS + G1`로 검증했습니다. VM의 password 인증은 `Match LocalAddress 127.0.0.1`에만 허용해 LAN SSH 정책을 넓히지 않았습니다. SFTP는 아직 `UNIMPLEMENTED`입니다.

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

로컬 operation 증거를 재사용해 중앙 plan/approval/receipt relay를 추가합니다. terminal/SFTP session은 중앙에서 장기 보관하거나 root로 승격하지 않습니다.
