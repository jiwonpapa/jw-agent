# Test Strategy and Fault Matrix

Status: Accepted  
Authority: Delivery  
Owner: Verification Maintainer  
Last reviewed: 2026-07-22

## 시험 소유권

| Layer | Owner | 목적 |
|---|---|---|
| unit | package | pure invariant and parser |
| contract | jw-contracts/consumers | version and negative shape |
| integration | owning daemon | DB, command runner, UDS, projection |
| browser | web via Playwright | local mock 계약과 VM real-API user workflow |
| VM | xtask + disposable Ubuntu | privilege, package, service, fault recovery |
| release | xtask | artifact, signature, install evidence |

같은 판단을 여러 layer에서 복사하지 않습니다. Unit은 logic, VM은 실제 OS/권한/장애라는 서로 다른 실패 모델을 가집니다.

`RUST-TEST`는 `jw-opsd`가 normative Nginx fixture를 직접 읽어 site ID·content digest·enabled-state digest drift를 검증하는 단일 owner입니다. 별도 script나 중복 fixture gate를 만들지 않습니다.

같은 gate의 runner test는 fixed executable·argv, environment clear, stdout·stderr cap, full-stream digest와 timeout 판정을 소유합니다. Linux process-group과 pipe 회수는 disposable Ubuntu source checkout에서 추가 실행할 수 있지만 package daemon fault matrix와 같은 증거로 승격하지 않습니다.

`p1-browser`는 mock API로 UI route·세션 비밀 비저장·viewport·접근성을 검증합니다. 실제 agentd API·PAM과 결합된 browser flow는 Ubuntu VM gate에서 검증되었습니다. 이 증거는 P2 mutation·terminal·SFTP까지 자동 확장되지 않으며 각 기능은 별도 browser+VM gate를 가져야 합니다.

## Operation fault injection

- before/after each durable stage process kill
- timeout and bounded stdout/stderr
- disk full before snapshot and during ledger write
- duplicate request and concurrent resource lock
- external config/symlink drift
- syntax test failure, reload failure
- rollback failure and repeated restart
- missing/corrupt snapshot and ledger continuity failure

## Browser scenarios

- real host values and observation time
- unsupported hides write capability
- operation 진입 전 rollback assurance·scope를 표시
- typed root mutation은 G1·unknown·stale assurance에 CTA 없음; G1 terminal, G0 SFTP read, G1 SFTP write는 각각 격리된 session/plan approval UI만 허용
- no mutation before approval
- plan hash/idempotency in approval
- double click creates one operation
- SSE timeline survives refresh/reconnect
- rollback-complete vs recovery-required distinction
- planned assurance·scope와 terminal receipt가 일치
- expired/drifted plan blocked
- connection loss shows stale, not zero
- integration catalog unknown·partial·installed와 install-blocked 상태
- integration 상세의 resource claims·blockers·G0 assurance
- deep link/back/refresh
- keyboard-only approval
- protected deep link → PAM login → safe relative return
- unknown/wrong/locked/denied account의 동일 public error
- session rotation, expiry, revoke, logout cache clearing
- viewer/operator/admin role and exact-plan step-up
- public HTTP password form disabled
- public/recovery cookie cross-channel replay rejected
- loopback recovery listener rejects non-loopback bind·Host·Origin and all forwarded headers
- mobile full plan→reauth→approve→SSE flow
- tablet portrait/landscape navigation and inspector
- terminal ticket replay·wrong-origin·idle/max lifetime·frame/output cap
- SFTP G0 home root·traversal·external symlink·size·session binding·secret non-persistence
- SFTP G1 exact plan, mobile 위험 고지, stale-digest·atomic upload와 secret 비저장
- managed config syntax failure에는 service action 없음; reload/health failure에는 G2 rollback receipt
- Certbot external G1 effect와 local attach G2 result가 분리 표시

## Public edge and PAM VM scenarios

- PAM success, wrong, unknown, root, locked, expired, denied group
- authd peer UID/version/size/timeout and one-shot exit
- bounded worker/queue and distributed login abuse
- password absent from journal, DB, evidence, process arguments and browser trace
- valid/invalid/expired certificate and exact Host/Origin
- forwarded-header spoof, body/header/slow-request limits
- internal agentd TCP, authd and opsd sockets not public
- Nginx management vhost protected from site operation
- UFW active/inactive and existing SSH/user rule preservation
- Nginx/TLS failure followed by SSH fallback public disable
- P2 opsd no-follow/dirfd path policy, snapshot fsync, crash/disk-full reconciliation
- OpenSSH non-root/root-denial, host-key mismatch, session revoke and normal SSH independence
- OpenSSH SFTP home confinement, bounded G0 read와 planned G1 atomic create/replace, path/entry/transfer cap, stale/symlink/type/session/origin/replay denial과 metadata-only audit
- Certbot staging challenge, local attach rollback and secret scan

## 환경

VM은 폐기 가능하고 fixture로 재현합니다. PAM account·group·lockout와 public DNS/TLS fixture도 disposable environment만 사용합니다. 개발자 host에서 root integration을 직접 실행하지 않고 실제 production server를 test target으로 사용하지 않습니다.
