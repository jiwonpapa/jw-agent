# ADR-0022 Capability Registry and Generated Status

Status: Accepted  
Authority: Architecture Decision Record  
Owner: Product Maintainer  
Last reviewed: 2026-08-18

## Context

support matrix, spec index와 roadmap에 구현·검증 상태와 gate 개수를 수작업으로
복사하면서 실제 코드·VM evidence보다 오래된 주장이 남았습니다. 문서 lifecycle은
`Verified`를 정의하지만 capability별 부분 검증과 공개 환경 미검증을 표현할 권위
원본이 없었습니다.

## Decision

- versioned local JSON registry가 capability의 구현·지원·증거·제외 상태를 소유합니다.
- 기존 `xtask`에 `GOV-009`를 추가해 registry와 OpenAPI, typed operation, GateId,
  spec index를 대조합니다.
- 사람이 읽는 status 문서는 registry에서 결정적으로 생성하고 byte drift를
  governance lane에서 거부합니다.
- workspace에 이미 고정된 `serde`·`serde_json`만 `xtask`에서 사용합니다.
- 새 crate, shell generator, 원격 workflow와 별도 검증 harness는 만들지 않습니다.

## Consequences

- 구현 상태 변경은 권위 문서·registry·evidence gate 순서로 진행됩니다.
- 문서의 고정 gate 개수와 중복 상태 요약을 제거할 수 있습니다.
- registry는 runtime capability API가 아니며 Agent 권한이나 operation 범위를
  확장하지 않습니다.
- 생성 명령은 문서를 갱신할 뿐이고 판정 로직은 `GOV-009` 한 곳이 소유합니다.

## Rejected alternatives

- 여러 Markdown 표를 계속 수작업 동기화
- 중앙 DB나 별도 상태 서비스 도입
- remote manifest를 제품 상태 권위 원본으로 사용
- 새 codegen crate·JavaScript generator·GitHub Actions 추가
