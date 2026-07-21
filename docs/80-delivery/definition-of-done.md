# Definition of Done

Status: Accepted  
Authority: Delivery  
Owner: Delivery Maintainer  
Last reviewed: 2026-07-21

## 모든 작업

- Accepted spec ID와 scope가 있음
- non-goal과 failure behavior가 명시됨
- 권위 원본을 중복하지 않음
- 새 dependency/crate/codegen이 정책을 통과함
- 관련 GateId가 한 번만 실행됨
- docs와 runbook drift가 없음
- 결과를 evidence level보다 크게 표현하지 않음

## Rust 변경

- `#![forbid(unsafe_code)]`, FFI 예외 별도 crate
- unwrap/expect/panic/todo/unimplemented/dbg 금지 lint
- 외부 작업 Result, timeout, output cap, redaction
- bounded concurrency와 cancellation behavior
- atomic state transition and restart behavior
- unit/contract/fault test가 책임 owner에 존재

## Web 변경

- generated API type 사용, direct fetch 없음
- loading/fresh/stale/empty/unsupported/error 구현
- keyboard, focus, responsive, reduced motion 확인
- capability와 permission을 UI hardcode로 추측하지 않음
- mutation 진입 전 assurance·rollback scope·제외 효과를 표시
- G1·unknown·stale·unsupported에 mutation CTA가 없음
- mutation retry·optimistic success 없음
- Playwright trace/screenshot evidence
- mobile 320/390, tablet portrait/landscape, desktop에서 기능 동일
- auth/session data가 URL·storage·trace에 없음

## PAM·public access

- authd와 opsd password/operation 경계 분리
- PAM auth + account + canonical user + role 검증
- root·locked·expired·denied group·unknown user negative tests
- public failure response account enumeration 없음
- password zeroize and secret scan evidence
- valid TLS, exact Host/Origin, proxy UDS, rate limits
- agentd/authd/opsd internal endpoint public 비노출
- protected management vhost와 SSH fallback recovery
- public disable and session revoke VM proof

## Operation 승격

- typed schema와 version
- deterministic plan, precondition, expiry
- idempotency, resource lock
- snapshot 또는 명시적 non-reversible 표시
- read-back, verifier, rollback/recovery
- user-facing assurance·rollback scope·excluded effects와 실제 receipt 일치
- VM fault matrix PASS
- support matrix and user-facing risk copy

## Release

- clean checkout, pinned toolchain/lockfile
- full + VM + release required gates PASS
- signed package/checksum/SBOM/evidence
- install/upgrade/recovery proof
- known limitations and rollback guarantee published
