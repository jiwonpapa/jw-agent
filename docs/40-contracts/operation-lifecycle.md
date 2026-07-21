# Operation Lifecycle Contract

Status: Accepted  
Authority: Contract  
Owner: Safety Maintainer  
Last reviewed: 2026-07-21

## 상태

```text
RECEIVED → PLANNED → SNAPSHOTTED → APPLYING → VERIFYING → SUCCEEDED
                                      │            │
                                      └────────────┴→ ROLLING_BACK
                                                        │
                                      ROLLED_BACK ←─────┤
                                      RECOVERY_REQUIRED ← failure
```

`REJECTED`, `EXPIRED`, `CANCELLED_BEFORE_APPLY`는 side effect 전 terminal state입니다.

## 상태 의미

- `PLANNED`: immutable plan과 precondition이 저장됨
- `SNAPSHOTTED`: 사본과 digest가 durable 검증됨
- `APPLYING`: side effect가 시작됐거나 시작 여부를 read-back해야 함
- `VERIFYING`: 적용 후 OS 상태 검증 중
- `SUCCEEDED`: 목표 상태와 verifier가 모두 일치
- `ROLLING_BACK`: 보장 범위 복원 중
- `ROLLED_BACK`: snapshot 상태 복원과 verifier 통과
- `RECOVERY_REQUIRED`: 자동 판단·복원이 안전하지 않음

## 재시작 규칙

- 각 non-terminal stage는 재시작 handler를 가집니다.
- DB stage만 보고 명령을 반복하지 않고 OS 상태를 먼저 읽습니다.
- idempotent no-op을 success로 기록하되 실제 변경이 없음을 receipt에 남깁니다.
- event sequence와 state transition은 같은 SQLite transaction입니다.

## 사용자 표시

내부 상태를 숨기지 않고 다음 의미로 번역합니다: 완료, 실패·원복 완료, 실패·수동 확인 필요, 중단됨·복구 중, 계획 만료, 지원되지 않음.

