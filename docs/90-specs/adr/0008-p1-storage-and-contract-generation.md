# ADR-0008 — P1 Storage and Contract Generation

Status: Accepted  
Authority: Architecture Decision  
Owner: Build Maintainer  
Last reviewed: 2026-07-21

## Context

P1은 SQLite WAL 상태와 Rust→OpenAPI→TypeScript 단일 계약 흐름이 필요합니다. native SQLite를 매번 번들 컴파일하거나 Rust·Web type을 수기로 복제하면 빌드시간과 drift가 증가합니다.

## Decision

- agentd SQLite는 exact-pin `rusqlite`와 운영체제의 system SQLite를 사용합니다.
- `bundled`, build-time bindgen, SQL ORM·migration macro는 사용하지 않습니다.
- Ubuntu clean build에는 `libsqlite3-dev`, runtime에는 배포판 `libsqlite3-0`을 사용하고 실제 24.04 VM에서 WAL·busy timeout·migration을 검증합니다.
- Rust REST DTO와 route annotation은 exact-pin `utoipa`가 OpenAPI snapshot을 생성합니다.
- `api/openapi.json`은 재현 가능하게 생성해 저장하고 수기 편집하지 않습니다.
- Web type은 exact-pin `openapi-typescript`, runtime client는 `openapi-fetch` 한 곳에서만 생성·호출합니다.
- OpenAPI와 Web type 생성은 명시적 local `xtask` gate가 소유하며 Vite나 Cargo의 일반 증분 build에서 자동 실행하지 않습니다.
- lockfile과 generated snapshot drift는 local verification에서 fail closed 합니다.

## Build-graph controls

- 최소 feature만 활성화하고 `tokio = full` 또는 `utoipa` UI feature를 사용하지 않습니다.
- Rust·Bun dependency는 manifest에 exact pin하며 갱신은 별도 작은 변경으로 수행합니다.
- system SQLite 최소 버전과 실제 runtime link는 Ubuntu VM evidence에 기록합니다.
- 새로운 code generator, ORM, second API client 또는 bundled SQLite는 새 ADR 없이는 추가할 수 없습니다.

## Consequences

개발 host에 SQLite development library가 필요하지만, 반복 C 컴파일을 피하고 배포판 보안 업데이트를 따릅니다. OpenAPI proc macro 비용은 생기지만 브라우저 계약 복제와 drift를 제거하는 제한된 비용으로 수용합니다.

## Acceptance

- clean local Rust build and test
- Ubuntu 24.04 system SQLite link evidence
- deterministic OpenAPI generation
- generated TypeScript drift gate
- direct feature/route `fetch` absence
- dependency graph and build-time evidence
