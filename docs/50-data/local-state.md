# Local State Model

Status: Accepted  
Authority: Data  
Owner: Data Maintainer  
Last reviewed: 2026-07-21

## agentd SQLite WAL

예정 aggregate:

- schema migration state
- host observation snapshot and freshness
- discovered service inventory projection
- opaque server-side session digest, canonical Linux UID·username·role, auth/expiry times
- opsd receipt cursor and UI projection
- local UI preferences excluding secrets

PAM password, PAM handle, raw authentication token, plaintext session ID는 저장하지 않습니다. Linux identity와 role은 PAM/NSS가 권위 원본이며 session은 제한된 snapshot입니다.

## opsd SQLite WAL

예정 aggregate:

- operation and immutable plan
- resource lock and idempotency claim
- lifecycle event sequence
- snapshot metadata and digest
- recovery marker and forensic checkpoint

## 설계 규칙

- daemon별 DB 파일과 Unix owner를 분리합니다.
- foreign key, busy timeout, transaction boundary를 migration과 함께 검증합니다.
- ledger event는 수정·삭제 API가 없습니다.
- retention은 operation terminal state와 evidence export 상태를 고려합니다.
- wall clock만으로 순서를 판단하지 않고 sequence를 사용합니다.
- migration은 forward upgrade를 기본으로 하며 downgrade 호환을 과장하지 않습니다.

정확한 table/schema는 implementation spec에서 migration을 권위 원본으로 확정합니다. 이 문서는 수기 DB schema가 아닙니다.
