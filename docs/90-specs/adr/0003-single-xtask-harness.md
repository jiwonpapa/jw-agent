# ADR-0003 — Single xtask Harness

Status: Accepted  
Authority: Architecture Decision  
Owner: Verification Maintainer  
Last reviewed: 2026-07-21

## Decision

모든 검증 GateId, lane composition, evidence receipt를 Rust `xtask` 한 곳이 소유합니다.

## 이유

Makefile·shell·Git hook·문서 명령이 같은 검사를 복제하면 실행 순서와 실패 의미가 drift하고 빌드 시간이 증가합니다.

## 결과

- wrapper는 xtask 호출만 가능
- gate registry가 문서와 실행의 원본
- P0에는 governance만 두고, 실제 코드가 생긴 P1에서 `p1-local`·`p1-browser`를 같은 registry에 추가
- remote Actions 없음
- release 신뢰는 서명된 local evidence
