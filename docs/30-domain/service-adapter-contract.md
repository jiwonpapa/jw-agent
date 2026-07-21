# Service Adapter Contract

Status: Accepted  
Authority: Domain  
Owner: Service Maintainer  
Last reviewed: 2026-07-21

## 목적

서비스 차이를 숨기는 범용 shell 대신, 각 서비스가 동일한 안전 수명주기를 구현하도록 합니다. Adapter는 opsd 내부 module이며 dynamic plugin이나 crate가 아닙니다.

## 필수 책임

1. `discover`: package·unit·layout과 근거 수집
2. `observe`: 현재 상태와 관찰 시각 반환
3. `capabilities`: 지원 operation·version·maturity·evidence·assurance와 거부 이유 선언
4. `plan`: 현재→목표, 대상, 영향, precondition 생성
5. `snapshot`: operation 보장에 필요한 최소 사본 생성
6. `apply`: fixed executable/argv 또는 typed filesystem primitive 실행
7. `read_back`: 실제 OS 상태 재조회
8. `verify`: 명시된 성공 조건 판단
9. `rollback`: 보장된 범위만 복원하고 다시 검증
10. `diagnose`: 제한된 근거와 recovery hint 반환

`capabilities`와 `plan`은 rollback scope, 제외 효과, apply verifier, rollback verifier를 반환합니다. UI와 agentd는 이 값을 추측하거나 서비스 이름으로 보장 수준을 하드코딩하지 않습니다.

## Adapter 승인 조건

- 지원 OS·package·version·layout 선언
- canonical path와 symlink/traversal 방어
- 명령 timeout·output cap·redaction
- resource lock와 external drift 처리
- idempotency·crash recovery
- operation별 assurance 등급
- Ubuntu VM success/failure/fault scenario

## 금지

- 사용자 입력을 shell string으로 조립
- 임의 path와 command 전달
- adapter가 HTTP·central·browser를 인지
- unsupported 환경에서 best guess 적용
- 서비스 하나 추가할 때 새 crate·Cargo feature 생성
