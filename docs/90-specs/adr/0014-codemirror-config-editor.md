# ADR-0014 — CodeMirror 6 for Managed Text Configuration

Status: Accepted  
Authority: Architecture Decision  
Owner: Web Maintainer  
Last reviewed: 2026-07-22

## Context

`OPS-MANAGED-CONFIG-FILE-V1`은 줄 번호, syntax highlighting, diff, validation
진단을 제공하는 모바일·태블릿 대응 편집기가 필요합니다. 기존 문서는 Monaco를
후보로 적었지만 build-graph 승인을 받지 않았고 실제 dependency도 없었습니다.
Monaco는 공식적으로 mobile browser를 지원하지 않아 320px부터 지원하는 제품 계약과
맞지 않습니다.

기준선 `bun run build`는 Mac mini에서 1.54초였고 Nginx route chunk는 28.44 kB,
gzip 7.83 kB였습니다.

## Decision

- managed config와 SFTP UTF-8 text surface는 CodeMirror 6 component 하나를 공유합니다.
- Nginx는 `@codemirror/legacy-modes/mode/nginx` parser를 사용합니다.
- 변경 계획은 `@codemirror/merge` unified read-only diff로 표시합니다.
- 서버 validator가 안전하게 추출한 selected-resource 줄 번호만 경량 line decoration·gutter marker로 표시합니다.
- raw command output, canonical root path, file body는 diagnostic·audit log에 저장하지 않습니다.
- exact direct dependency는 다음으로 고정합니다.
  - `@codemirror/commands 6.10.4`
  - `@codemirror/language 6.12.4`
  - `@codemirror/legacy-modes 6.5.3`
  - `@codemirror/merge 6.12.2`
  - `@codemirror/state 6.7.1`
  - `@codemirror/view 6.43.6`

모두 MIT, browser-only JavaScript이며 native dependency, build script, code generator,
runtime network fetch를 추가하지 않습니다. Bun lockfile이 transitive graph를 고정합니다.

## Build budget

- incremental production web build: 2.5초 이하
- editor core gzip: 105 kB 이하
- unified diff gzip: 10 kB 이하, 계획 화면에서만 추가 lazy load
- editor core는 Nginx·SFTP route에서만 shared lazy chunk로 내려받음
- React wrapper package를 추가하지 않고 lifecycle adapter를 `shared/ui` 한 파일이 소유
- Monaco, second editor, custom Rust highlighter를 동시에 유지하지 않음

예산을 넘으면 merge view를 먼저 제거하고 최소 CodeMirror editor만 유지한 뒤 ADR을
재검토합니다.

최종 측정은 production build 2.38초, editor core gzip 100.97 kB, unified diff gzip
7.72 kB, Nginx route 자체 gzip 8.66 kB입니다. 범용 lint·autocomplete·search 묶음과
React wrapper는 포함하지 않았습니다.

## Security and accessibility

- editor value는 browser storage에 저장하지 않습니다.
- `aria-label`, keyboard navigation, line number, focus ring, horizontal scroll을 제공합니다.
- native validator 진단 위치가 없으면 줄 번호를 추측하지 않습니다.
- G2 plan·PAM 재인증·typed opsd 경계는 editor 도입으로 완화하지 않습니다.

## Rejected alternatives

- Monaco: mobile browser 지원 계약과 맞지 않고 현재 작업면에 과도합니다.
- textarea 유지: 줄 번호·syntax·diagnostic·diff 요구를 충족하지 못합니다.
- VIM/Rust highlighter 포팅: browser 편집기의 접근성·IME·selection 문제를 다시 구현합니다.
- generic `/etc` editor: adapter allowlist와 typed operation 경계를 무너뜨립니다.

## Acceptance

- desktop·tablet·320px에서 Nginx 편집·unified diff·오류 줄 이동이 동작
- CodeMirror 입력이 기존 exact plan, byte cap, two-intent PAM 승인으로만 적용
- syntax failure는 reload 없이 exact rollback하고 selected-resource 줄 번호만 표시
- web typecheck, unit, lint, production build, P2 browser와 Ubuntu VM managed-config gate 통과
- 최종 build time과 chunk 증거는 delivery decision register에 기록
