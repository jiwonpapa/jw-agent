# Specification Lifecycle

Status: Accepted  
Authority: Governance  
Owner: Maintainers  
Last reviewed: 2026-07-21

## 흐름

```text
problem → scope → spec → acceptance scenarios → ADR if needed
        → contract/schema → gate selection → implementation
        → evidence → Verified
```

## 구현 진입 조건

- 고유 spec ID와 owner
- 목적·비목표·지원 환경
- typed input/output/error 또는 UI state 계약
- 권한, 데이터 소유권, 실패 의미
- acceptance scenario와 요구 evidence 수준
- 새 dependency·crate·codegen이면 ADR

## 변경 규칙

- 동작을 바꾸면 spec을 먼저 바꿉니다.
- 구현 중 발견된 예외를 코드 hardcode로 숨기지 않습니다.
- acceptance가 불명확하면 구현을 멈추고 spec을 보완합니다.
- Verified spec의 호환되지 않는 변경은 새 version을 만듭니다.

## 작업 완료 단위

한 작업은 하나의 작고 검증 가능한 vertical slice를 가집니다. 로컬 MVP 작업에 중앙관제·멀티테넌트 gate를 끼워 넣지 않습니다.

