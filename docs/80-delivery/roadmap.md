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

- `p2-local` 23개, `p2-browser` 8개 gate와 Playwright 42개 scenario가 PASS했습니다.
- `p2-vm` 27개 gate에서 독립 Rust management edge, 서비스 인벤토리·lifecycle, Nginx·PHP-FPM fault matrix와 manual restore, forensic lockdown, Certbot lifecycle, non-root OpenSSH terminal, home-scoped SFTP G0/G1과 TOTP step-up을 검증했습니다.
- Ubuntu 24.04 VM에 `jw-agent_0.2.0~p2.19_amd64.deb`를 설치했고 SHA-256은 `abff57f506c5fb1f1e0041a8319c195ef87d9097171fc14a693d5ca92b85e2c7`입니다.
- `jw-edge`가 비권한 9443 기본 관리 ingress를 소유하며, edge 부재 시 Nginx stop은 차단되고 Nginx 중단 뒤에도 `:9443` UI·API가 유지됩니다.
- 공개 HTTPS 실브라우저에서 grouped navigation, account drawer, 자원 meter, 서비스 family card, SFTP 3-pane과 terminal-first surface를 확인했습니다.
- 제품 관리 vhost는 파일명과 무관하게 content marker/include로 보호되며 plan 단계에서 변경을 거부합니다.
- 승인 API는 `202 Accepted` 뒤 durable operation을 실행하고 SSE sequence replay와 canonical receipt 조회를 제공합니다.

P2 전체 milestone은 아직 완료가 아닙니다. 모든 durable stage의 강제 종료 matrix와 command timeout·output cap 확대는 후속 adapter 전에 계속 보강합니다.

2026-07-22 safety-kernel hardening에서 `APPROVED`, `SNAPSHOTTED`, `APPLYING`, `VALIDATING`, `RELOADING`, `VERIFYING`, `ROLLING_BACK` 재시작 판정을 한 table test로 고정했습니다. fixed command registry, environment clear, stdout·stderr cap과 full-stream digest, timeout 회수도 기존 `RUST-TEST`가 직접 검증합니다. Ubuntu 24.04 source checkout에서는 자손이 pipe를 잡은 process group timeout까지 PASS했지만, 이는 package daemon을 stage마다 실제 kill한 `p2-vm` 증거를 대신하지 않습니다.

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
- Nginx는 24 KiB content, PHP-FPM은 128 KiB content이며 exact managed-config plan path·ops frame만 256 KiB입니다. root:root regular file과 reload만 허용합니다.
- valid/no-op, syntax·reload rollback, external drift, inactive denial, 제안 원문 정리, 내부 temp 비노출·startup cleanup을 실제 VM에서 검증했습니다.
- 배포된 공개 HTTPS UI에서 editor·byte cap·G2 scope/exclusion·planned-only 경고와 console error 0을 확인했습니다.

[OPS-PHP-FPM-CONFIG-V1](../90-specs/operations/php-fpm-config-v1.md)은 Ubuntu 24.04 apt PHP 8.3의 상태·extension·설정 위치 관찰과 표준 `php.ini` G2 변경으로 `VM_PASS`를 획득했습니다. 실제 73 KiB 파일의 valid save, 종료코드 0 syntax warning 포착, reload 전 차단, exact rollback과 active continuity를 검증했으며 pool·extension 설치·다른 version은 계속 제외합니다.

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
- existing OpenSSH SFTP v3 기반 home-scoped list/stat/text-read/download G0
- memory-only file session, canonical home 경계, path·entry·text·download 상한, path digest audit
- 320px부터 desktop까지 반응형 파일 탐색·UTF-8 미리보기·bounded download UI
- PAM 재인증·2분 single-use plan 기반 일반 파일 생성과 명시적 교체 G1
- same-directory exclusive temp, OpenSSH fsync·POSIX rename, mode·size·SHA-256 read-back
- 8 MiB upload와 256 KiB textarea 저장, stale target·symlink·directory·traversal 차단
- G1 scope·자동 원복 불가·수동 복구 경로를 최종 적용 버튼 위에 유지

계속 제외:

- delete, move, chmod/chown, mkdir, recursive transfer, resume, root/system path SFTP
- CodeMirror 6 공유 text editor는 [ADR-0014](../90-specs/adr/0014-codemirror-config-editor.md)의 build budget 안에서 도입

완료 증거:

- root denial, ticket replay, wrong origin, idle/max lifetime, frame/transfer cap
- disconnect/reconnect, mobile/tablet terminal, large file and traversal negatives
- no browser secret/transcript persistence and no opsd shell/PTY surface

터미널은 Ubuntu 24.04 package VM에서 non-root PAM/OpenSSH 로그인, 명령 I/O, 40×100 resize, replay·wrong-origin 차단, logout revoke, metadata-only audit와 process/FIFO cleanup을 `VM_PASS + G1`로 검증했습니다. SFTP G0는 같은 loopback OpenSSH 경계에서 홈 list/stat/text/download와 경계 부정 시나리오를 검증했습니다. SFTP G1은 PAM plan 뒤 create/replace, mode·size·digest read-back, stale target·symlink·directory·traversal·digest·wrong-origin·replay 차단, metadata-only audit와 temp cleanup을 `VM_PASS`로 검증했습니다. VM의 password 인증은 `Match LocalAddress 127.0.0.1`에만 허용해 LAN SSH 정책을 넓히지 않았습니다. delete·move·chmod·root/system path 쓰기는 구현하지 않았습니다.

웹 terminal·SFTP session owner는 route component에서 authenticated app shell로 이동했습니다. 메뉴 이동은 연결을 닫지 않으며 terminal·SFTP 자체 max lifetime은 `0`입니다. 명시적 종료·logout·로그인 session 만료·연결 상실·서버 재시작은 계속 종료 경계입니다. 같은 ticket/token을 재사용하는 browser gate와 p2.18 실제 OpenSSH endpoint VM gate가 통과했습니다.

## P2E — Local TOTP step-up

현재 구현:

- recovery ingress·admin PAM 전용 등록과 복구 초기화
- RFC 6238 SHA-1, 6자리, 30초, ±1 window, 동일 time-step 재사용 차단
- 두 개의 연속 code 확인, 10개 one-time recovery code
- DB 밖 mode `0600` wrapping key와 ChaCha20-Poly1305 encrypted seed
- exact session·UID·plan hash에 결합된 5분 single-use claim
- browser-memory QR와 mobile-friendly 등록 ceremony

VM에서 `risky_operations` 정책 활성화, PAM+TOTP Nginx typed no-op 승인, 동일 claim 재사용 403, 복구 코드 reset, session revoke, 암호화 key 권한과 평문 secret 비보존을 검증했습니다. Linux PAM·SSH MFA 변경, 공용 bypass와 console recovery 자동화는 제공하지 않습니다.

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
