# Decision Register

Status: Accepted  
Authority: Delivery  
Owner: Maintainers  
Last reviewed: 2026-07-22

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
- no opsd arbitrary shell/PTY/user argv, root terminal, generic root file CRUD, custom SSH/SFTP server or blockchain
- existing OpenSSH 기반 non-root terminal은 G1, SFTP list/read/download는 G0, 향후 SFTP write는 G1으로 분리
- adapter allowlisted managed config는 G2, Certbot CA effect는 G1/local attach는 G2
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

P2 구현 진입은 2026-07-21 사용자 목표추진 지시와 [ADR-0010](../90-specs/adr/0010-local-maintenance-surfaces.md)으로 승인되었습니다. safety kernel·Nginx site state에 이어 active-resource managed config까지 활성화했으며, Certbot·OpenSSH 표면은 각 선행 gate 뒤 순차 활성화합니다.

## P2 Nginx 기준선 결정과 증거

- opsd는 private network namespace와 `CAP_NET_BIND_SERVICE`만 사용하며 외부 network API나 listening socket을 갖지 않습니다.
- 제품 관리 vhost는 legacy basename뿐 아니라 versioned content marker와 제품 include로 판정합니다. 보호 resource는 operation type/schema를 노출하지 않고 opsd plan도 재검증합니다.
- mutation 승인은 `202 Accepted`이며 durable ledger가 실행 상태를 소유합니다. 브라우저 SSE는 durable sequence를 event ID로 사용하고 canonical receipt를 다시 조회합니다.
- `p2-local` 21개, `p2-browser` 8개, Playwright 31개, `p2-vm` 23개 gate가 PASS했습니다.
- VM package는 `jw-agent_0.2.0~p2.10_amd64.deb`, SHA-256 `4916eba6d93a81148eb4768141ac8b7815e86461a1d57f7c1fa9a55fa0ae64cd`입니다.
- managed Nginx config는 활성 exact symlink, root:root, UTF-8 24 KiB content·64 KiB request envelope, reload profile만 `VM_PASS + G2`입니다.
- 현재 `SUPPORTED + VM_PASS + G2` write 표면은 `nginx.site_state.set/v1`, active Nginx profile의 `service.config_file.set/v1`, 보호 vhost의 `certbot.certificate.attach/v1`입니다. `certbot.certificate.renew_test/v1`은 `SUPPORTED + VM_PASS + G1`이며, `certbot.certificate.issue/v1`은 실패 안전성까지 `VM_PASS`이나 공인 CA 성공은 `UNVERIFIED`입니다.
- `jw-certd` one-shot network privilege boundary, sanitized inventory, PAM 승인 renewal dry-run, DNS·listener·webroot preflight, 실패 영수증과 고정 loopback SNI probe는 `VM_PASS`입니다.
- `jw-certd`의 추가 명령은 `127.0.0.1:443` 고정 SNI fingerprint probe뿐이며 `opsd` network 차단은 유지합니다. attach 정상 경로와 probe 강제 실패의 exact rollback은 `VM_PASS + G2`입니다.
- P2D terminal은 system OpenSSH client, one-shot memory/FIFO password broker, same-origin WSS, non-root PTY와 metadata-only audit로 `VM_PASS + G1`입니다. SFTP list/stat/text-read/download는 fixed OpenSSH subsystem과 canonical home confinement으로 `VM_PASS + G0`입니다. 일반 파일 create/replace는 PAM plan, fsync·atomic rename, mode·size·digest read-back과 metadata-only audit로 `VM_PASS + G1`입니다. package는 sshd 정책을 자동 변경하지 않으며 VM fixture만 loopback password 인증을 허용합니다. delete·move·chmod·root/system path 쓰기는 제외합니다.
- opsd는 SQLite ledger event와 외부 checkpoint 파일 사이의 일관된 판정을 위해 typed request 전체를 직렬화합니다. 실행 중 receipt 조회는 완료까지 대기하며 중간 checkpoint를 훼손으로 오판하지 않습니다.

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
