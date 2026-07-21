# Document Authority and Ownership

Status: Accepted  
Authority: Governance  
Owner: Maintainers  
Last reviewed: 2026-07-21

## 권위 순서

1. Constitution
2. Accepted ADR
3. Accepted product·operation·UI spec
4. Architecture·security·delivery policy
5. Generated contract snapshot
6. Implementation and tests

낮은 권위 문서는 높은 권위 결정을 바꿀 수 없습니다. 충돌은 구현을 고치는 이유이지 문서를 무시할 이유가 아닙니다.

## 상태

- `Draft`: 논의 중, 구현 근거 아님
- `Accepted`: 구현 가능한 승인 기준
- `Implementing`: 구현 중, 아직 증거 없음
- `Verified`: 요구된 gate evidence가 존재
- `Deprecated`: 대체 문서 링크가 존재

## 필수 헤더

모든 정책·spec·ADR 문서는 `Status`, `Authority`, `Owner`, `Last reviewed`를 가집니다. Generated 문서는 생성 원본과 commit을 추가합니다.

## 중복 방지

각 사실은 한 문서만 소유합니다. 다른 문서는 요약을 복사하지 않고 링크합니다. 지원 버전·operation 상태·gate 목록은 향후 registry에서 생성합니다.

