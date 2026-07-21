# Test Strategy and Fault Matrix

Status: Accepted  
Authority: Delivery  
Owner: Verification Maintainer  
Last reviewed: 2026-07-21

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

현재 `p1-browser`는 mock API로 UI route·세션 비밀 비저장·viewport·접근성을 검증합니다. 실제 agentd API·PAM과 결합된 browser flow는 Ubuntu VM gate의 책임이며 아직 미검증입니다.

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
- G1·unknown·stale assurance에는 mutation CTA 없음
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

## 환경

VM은 폐기 가능하고 fixture로 재현합니다. PAM account·group·lockout와 public DNS/TLS fixture도 disposable environment만 사용합니다. 개발자 host에서 root integration을 직접 실행하지 않고 실제 production server를 test target으로 사용하지 않습니다.
