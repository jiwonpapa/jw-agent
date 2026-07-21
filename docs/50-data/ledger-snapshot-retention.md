# Ledger, Snapshot, and Retention

Status: Accepted  
Authority: Data  
Owner: Security Maintainer  
Last reviewed: 2026-07-21

## 분리

- Ledger: 실행 사실과 단계 evidence
- Snapshot: 한 operation을 되돌리기 위한 최소 사본
- Backup: 독립된 장기 보존·restore 검증 체계, MVP 밖

## Snapshot 규칙

- root-only directory, random operation ID 하위에 저장
- user path를 directory 이름으로 사용하지 않음
- write 후 fsync와 digest 검증 뒤 `SNAPSHOTTED` 확정
- symlink를 따라 외부 대상을 복사하지 않음
- rollback terminal 전 자동 삭제 금지

## Retention

- 기본 보존값은 구현 전 용량 시험과 privacy 검토로 정합니다.
- byte quota, age, operation terminal state를 함께 사용합니다.
- quota 초과가 예상되면 write를 시작하지 않고 읽기 진단을 유지합니다.
- 강제 정리는 가장 오래된 verified terminal snapshot부터 수행하고 ledger는 별도 정책을 따릅니다.
- 사용자가 export한 bundle은 앱이 임의 삭제하지 않습니다.

## 삭제·손상

ledger 삭제 API는 제공하지 않습니다. 파일 누락·digest mismatch·sequence gap은 `FORENSIC_LOCKDOWN`을 발생시키고 읽기·export를 유지합니다.

