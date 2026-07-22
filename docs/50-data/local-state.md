# Local State Model

Status: Accepted  
Authority: Data  
Owner: Data Maintainer  
Last reviewed: 2026-07-22

## agentd SQLite WAL

구현 aggregate:

- schema migration state
- opaque server-side session digest, canonical Linux UID·username·role, auth/expiry times
- exact-plan reauthentication claim
- additional-auth settings excluding secrets
- terminal·file session과 path-digest 기반 access/upload audit metadata

host observation·service inventory와 opsd receipt는 현재 OS·opsd에서 읽어 응답하며 agentd DB의 권위 상태로 복제하지 않습니다.

PAM password, PAM handle, raw authentication token, plaintext session ID는 저장하지 않습니다. Linux identity와 role은 PAM/NSS가 권위 원본이며 session은 제한된 snapshot입니다.

## opsd SQLite WAL

구현 aggregate:

- operation and immutable plan
- resource lock and idempotency claim
- lifecycle event sequence
- snapshot metadata and digest
- recovery marker and forensic checkpoint

operation별 snapshot body와 ledger checkpoint는 DB 밖 root-owned 파일이며 SQLite에는 digest·metadata·relative locator만 저장합니다.

## 설계 규칙

- daemon별 DB 파일과 Unix owner를 분리합니다.
- foreign key, busy timeout, transaction boundary를 migration과 함께 검증합니다.
- ledger event는 수정·삭제 API가 없습니다.
- retention은 operation terminal state와 evidence export 상태를 고려합니다.
- wall clock만으로 순서를 판단하지 않고 sequence를 사용합니다.
- migration은 forward upgrade를 기본으로 하며 downgrade 호환을 과장하지 않습니다.

정확한 table/schema는 implementation spec에서 migration을 권위 원본으로 확정합니다. 이 문서는 수기 DB schema가 아닙니다.
