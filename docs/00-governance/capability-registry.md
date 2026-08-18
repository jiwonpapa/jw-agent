# Capability Registry

Status: Accepted  
Authority: Governance  
Owner: Product Maintainer  
Last reviewed: 2026-08-18

## 목적

구현됨, 부분 구현, 미구현, 제외, 금지 상태와 실제 support·evidence를
[capabilities-v1.json](capabilities-v1.json) 한 곳에서 소유합니다. 지원표·roadmap·spec
설명이 서로 다른 상태를 주장하지 못하게 하는 것이 목적입니다.

## 필드

- `id`: 재사용하지 않는 안정 capability ID
- `phase`: P1·P2·P3·P4·P5·future
- `release_scope`: MVP·후순위·제외·금지
- `implementation`: implemented·partial·planned·excluded·forbidden
- `support`: supported·limited·unverified·unsupported
- `evidence`: policy·doc·local_pass·browser_pass·vm_pass·release_pass·unverified
- `assurance`: G0·G1·G2·mixed·none
- `reference`, `spec`: 권위 기준과 선택적인 accepted spec
- `api_paths`, `operation_types`, `gates`: 실제 구현·검증 근거
- `blocker`: 부분 구현·미구현·제외 이유와 다음 완료 조건

## 변경 흐름

1. 높은 권위의 product decision·spec을 먼저 변경합니다.
2. registry 상태와 근거를 변경합니다.
3. `cargo xtask render-capabilities`로
   [Capability Status](../10-product/capability-status.md)를 갱신합니다.
4. `GOV-009`가 JSON schema, 중복 ID, 파일·spec index, OpenAPI path, typed operation,
   GateId와 생성 문서 drift를 검사합니다.
5. 관련 local·browser·VM gate가 통과하기 전 evidence를 승격하지 않습니다.

## 금지

- 문서에 gate 개수를 수작업으로 복사하지 않습니다.
- 코드·UI 존재만으로 `VM_PASS` 또는 `RELEASE_PASS`를 주장하지 않습니다.
- partial capability의 미검증 하위 범위를 숨기지 않습니다.
- registry 검사를 별도 shell·Make·웹 harness에 복제하지 않습니다.

이 registry는 제품 상태를 분류하는 metadata입니다. operation 안전 검증과 VM
scenario를 대체하지 않으며 기존 `xtask` GateId만 참조합니다.
