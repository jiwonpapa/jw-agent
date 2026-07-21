# Assurance Levels

Status: Accepted  
Authority: Contract  
Owner: Safety Maintainer  
Last reviewed: 2026-07-21

| Level | 의미 | 사용자 기본 표시 | 예시 |
|---|---|---|---|
| `G0 OBSERVE_ONLY` | 변경 없음 | 변경 없음 | CPU, unit 상태, 로그 조회 |
| `G1 VERIFIED_ACTION` | 결과 검증 가능, 이전 상태 복원 보장 없음 | 자동 원복 보장 없음 | service restart 후보 |
| `G2 REVERSIBLE_CONFIG` | config/link exact snapshot과 자동 원복 검증 | 제한된 설정 자동 원복 지원 | Nginx site enable/disable |
| `G3 RESTORE_VALIDATED_DATA` | 격리된 사본에서 실제 restore 검증 | 복원 검증된 데이터 복구 | 미래 데이터 backup |

## 규칙

- 보장 등급은 operation version에 귀속됩니다.
- UI는 `G2`를 “서버 전체 복원”으로 표현하지 않습니다.
- service restart는 이전 process state로 돌아갈 수 없으므로 rollback이라 부르지 않습니다.
- package·kernel·DB·UFW 변경은 rescue path와 VM 증거 전까지 G2가 될 수 없습니다.
- snapshot 생성 성공은 restore 성공이 아닙니다.
- UI는 보장 등급뿐 아니라 rollback scope·제외 효과·verifier·실패 시 recovery path를 함께 표시합니다.
- assurance가 없거나 stale이면 자동 원복 지원을 추측하지 않고 mutation approval을 제공하지 않습니다.
- 구체적인 노출 위치와 acceptance는 [UI-ROLLBACK-ASSURANCE-V1](../90-specs/ui/rollback-assurance-v1.md)이 소유합니다.

## 증거 축 분리

Operation maturity, evidence level, assurance는 서로 다른 축입니다.

```text
SUPPORTED + VM_PASS + G2
```

위 표현처럼 각각 선언하며 “안전함” 한 단어로 합치지 않습니다.
