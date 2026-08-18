# ADR-0023 Bounded Node Runtime for OpenAPI Generation

Status: Accepted  
Authority: Architecture Decision Record  
Owner: Build Maintainer  
Last reviewed: 2026-08-18

## Context

웹 package manager와 일반 script runtime은 Bun 하나지만 `openapi-typescript`의 배포
CLI는 Node shebang과 Node ESM loader를 사용합니다. macOS에 오래 남아 있던
`node_modules`에서는 Node와 Bun 모두 ESM import가 180초 안에 끝나지 않았습니다.
같은 `bun.lock`으로 `bun install --frozen-lockfile`을 다시 수행한 clean dependency
tree에서는 Node 24 generator가 60.5ms에 완료되고 committed schema와 일치했습니다.

따라서 검증되지 않은 global Node와 오래된 dependency cache가 gate 결과를 조용히
좌우하지 않도록 runtime 범위와 cache 복구 조건을 명시해야 합니다.

## Decision

- Bun은 웹 package manager·일반 script runtime으로 계속 단독 사용합니다.
- `OPENAPI-DRIFT`만 `openapi-typescript` upstream CLI 실행을 위해 Node 22–24를
  compatibility runtime으로 사용합니다.
- `xtask`는 `JW_OPENAPI_NODE`, 사용자 로컬 official Node 24, Homebrew `node@24`,
  system Node 순서로 탐색합니다. 허용 major와 2초 비동기 파일 I/O probe를 모두
  통과한 runtime으로 CLI 파일을 명시적으로 실행합니다.
- Node 25 이상이나 22 미만으로 조용히 fallback하지 않고 설치·환경변수 안내와 함께
  fail closed합니다.
- dependency 설치와 lockfile 소유권은 계속 Bun에만 있습니다. npm·pnpm·Yarn을
  사용하지 않습니다.
- generator I/O timeout이 재현되면 lockfile을 바꾸지 않고
  `bun install --frozen-lockfile`로 dependency tree를 재구성한 뒤 다시 검증합니다.
  timeout을 늘리거나 schema drift 검사를 우회하지 않습니다.

## Consequences

- Mac과 Ubuntu 개발 환경은 Node 22–24 중 하나를 OpenAPI compatibility runtime으로
  준비해야 합니다. Homebrew 동적 libuv 조합처럼 I/O probe에 실패한 build는
  major가 맞아도 사용하지 않습니다.
- 최신 global Node가 generator 안정성을 바꾸지 않습니다.
- `node_modules`는 평상시 보존하는 build cache이지만 generator I/O timeout 증거가
  있으면 동일 lockfile 기반 clean install로 복구할 수 있습니다.
- 허용 범위 변경은 별도 toolchain upgrade와 `OPENAPI-DRIFT` evidence가 필요합니다.

## Rejected alternatives

- OpenAPI schema drift 검사를 제거하거나 timeout만 늘리기
- Node 25를 검증 없이 계속 사용하기
- TypeScript schema generator를 Rust로 다시 구현하기
- npm 기반 별도 OpenAPI toolchain 추가
