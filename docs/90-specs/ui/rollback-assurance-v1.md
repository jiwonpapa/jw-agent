# UI-ROLLBACK-ASSURANCE-V1

Status: Accepted  
Authority: UI Specification  
Owner: Product Designer  
Last reviewed: 2026-07-21

## User job

사용자는 설정을 열거나 승인하기 전에 해당 작업이 변경을 만드는지, 자동 원복을 보장하는지, 무엇까지 복원하는지 판단할 수 있어야 합니다.

## Scope and non-goals

적용 화면:

- 설정·서비스 목록의 mutation 진입점
- 설정 상세와 변경 plan
- operation 실행 timeline·결과·이력
- mobile·tablet·desktop의 동일 작업면

비목표:

- `G2`를 서버 전체 backup 또는 무중단 보장으로 표현
- snapshot 생성만으로 원복 가능하다고 표시
- 지원하지 않는 작업에 경고만 붙이고 실행 허용
- UI가 backend capability나 assurance를 추측

## Authoritative data contract

보장 의미와 사용자 표시는 [Assurance Levels](../../40-contracts/assurance-levels.md)가 소유합니다. UI는 operation version에 귀속된 다음 값을 server contract에서 받습니다.

- operation ID and version
- maturity and evidence level
- assurance level
- rollback scope and excluded effects
- snapshot description
- apply verifier
- rollback trigger and rollback verifier
- interruption and residual risk
- unsupported or recovery-required reason

값이 없거나 stale이면 자동 원복을 지원한다고 표시하지 않고 mutation approval을 제공하지 않습니다.

## Mandatory disclosure

모든 operation surface는 다음 user-facing 상태 중 하나를 text와 icon으로 표시합니다.

| Assurance | 기본 표시 | Mutation action |
|---|---|---|
| `G0 OBSERVE_ONLY` | 변경 없음 | 없음 |
| `G1 VERIFIED_ACTION` | 자동 원복 보장 없음 | MVP에서는 없음 |
| `G2 REVERSIBLE_CONFIG` | 제한된 설정 자동 원복 지원 | `SUPPORTED + VM_PASS`일 때만 plan 진입 |
| `G3 RESTORE_VALIDATED_DATA` | 복원 검증된 데이터 복구 | MVP에서는 없음 |

`안전`, `완전 복구`, `무중단`처럼 범위를 숨기는 단독 문구를 사용하지 않습니다.

## Placement

### 목록과 설정 진입점

- 설정 이름·현재 상태 옆에 보장 표시를 둡니다.
- 실행 버튼을 누른 뒤 처음 알려주지 않습니다.
- `G1`, `UNSUPPORTED`, `UNVERIFIED`, stale에는 변경 CTA를 표시하지 않습니다.
- 행에는 하나의 다음 행동만 두고 보장 상세로 이동할 수 있습니다.

### 변경 plan

승인 CTA 위에 다음을 펼친 상태로 표시합니다.

1. current → target
2. 영향받는 exact resource
3. reload·restart·예상 중단
4. snapshot과 자동 원복 범위
5. 원복되지 않는 효과
6. apply·rollback verifier
7. 원복 실패 시 `RECOVERY_REQUIRED`와 복구 경로

작은 confirm modal 또는 tooltip만으로 이 고지를 대체하지 않습니다. 승인에는 exact-plan PAM 재인증, plan hash, idempotency key가 필요합니다.

### 실행과 결과

- timeline은 snapshot·apply·verify·rollback 단계를 숨기지 않습니다.
- 실패 후 검증된 복원은 `실패 · 원복 완료`로 표시합니다.
- 복원 검증 실패는 `실패 · 수동 복구 필요`로 표시하고 성공 색상·아이콘을 사용하지 않습니다.
- 결과 receipt는 계획 당시 보장과 실제 실행 결과를 함께 보존합니다.

## Responsive and accessibility

- 320px mobile에서도 보장 표시와 원복 범위를 CTA 위에 유지합니다.
- 색상만으로 보장 수준을 전달하지 않습니다.
- badge·icon에는 화면에 보이는 text label이 따라야 합니다.
- 보장 상세는 keyboard와 screen reader로 접근할 수 있습니다.
- timeline의 단계 변경은 요약된 `aria-live` message로 전달합니다.

## Telemetry and evidence

- 외부 telemetry를 사용하지 않습니다.
- plan/receipt에는 assurance ID·rollback scope identifier·verifier result를 기록합니다.
- config 원문·secret·전체 command output은 browser trace와 evidence에 남기지 않습니다.

## Playwright acceptance

- 설정 목록에서 mutation 진입 전 보장 표시를 확인할 수 있음
- `G0`, `G1`, `G2`, unknown·stale·unsupported가 서로 다른 text 상태로 표시됨
- `G1`, unknown·stale·unsupported에는 mutation CTA가 없음
- `G2` plan에서 scope·제외 효과·verifier·recovery path가 승인 CTA보다 먼저 표시됨
- double click과 browser retry가 operation을 중복 생성하지 않음
- validation/reload 실패 후 `ROLLED_BACK`과 `RECOVERY_REQUIRED`가 명확히 구분됨
- refresh·SSE reconnect 후 canonical assurance와 operation state를 재조회함
- 320·390 mobile, tablet portrait/landscape, desktop에서 필수 고지 손실 없음
- keyboard-only와 axe critical/serious 0

## Entry gate

이 spec은 P2 UI 계약입니다. P1의 PAM·public edge·recovery VM gate와 operation의 `SUPPORTED + VM_PASS`가 충족되기 전에는 실제 mutation CTA를 구현하거나 노출하지 않습니다.
