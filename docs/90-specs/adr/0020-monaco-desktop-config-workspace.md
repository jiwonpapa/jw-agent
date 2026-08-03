# ADR-0020 — Monaco Desktop Configuration Workspace

Status: Accepted  
Authority: Architecture Decision  
Owner: Web Maintainer  
Last reviewed: 2026-07-24

## Context

설정 파일이 여러 directory와 include 관계에 걸쳐 있고 공식 validator가 다른 파일의
오류를 지목할 수 있으므로 단일 textarea 성격의 편집기로는 실제 유지보수 흐름을 충분히
지원하지 못합니다. 사용자는 모바일에서 설정을 변경하지 않고 desktop에서 파일 tree,
multi-model 편집, diff와 복수 진단을 제공하도록 제품 방향을 확정했습니다.

[ADR-0014](0014-codemirror-config-editor.md)는 320px 편집 지원을 전제로 CodeMirror를
선택했으므로 이 결정과 충돌합니다.

## Decision

- managed service config와 SFTP UTF-8 text 편집은 desktop browser에서 Monaco Editor
  하나를 공유합니다.
- 모바일·태블릿은 상태·이력·파일 목록·read-only preview만 제공하고 설정 및 SFTP text
  mutation CTA를 노출하지 않습니다. viewport는 보안 경계가 아니며 backend 권한 검증은
  그대로 유지합니다.
- Monaco는 config workspace route에서만 lazy-load하고 dashboard·login 초기 chunk에
  포함하지 않습니다.
- `monaco-editor-core 0.56.0`을 직접 사용하며 React wrapper, language server,
  runtime CDN, WebAssembly parser와 별도 editor framework를 추가하지 않습니다.
- Monaco source는 dependency upgrade 때 `bun run vendor:monaco`로 한 번만 빌드해
  same-origin 정적 자산으로 고정합니다. 일반 `bun run build`는 이 source graph를 다시
  컴파일하지 않습니다.
- Nginx·Apache·PHP-FPM highlighting은 source-owned language definition이 담당합니다.
  PHP directive completion·hover는 backend가 반환하는 versioned schema를 권위 원본으로
  사용하며 UI에 directive 목록을 수기 복제하지 않습니다.
- native validator가 반환한 구조화 진단만 marker와 Problems panel에 표시합니다.
  위치가 없으면 추측하지 않으며 changed hunk와의 관계는 참고 정보로만 표시합니다.
- editor model과 draft는 memory에만 유지하고 localStorage, sessionStorage, IndexedDB,
  URL, trace와 감사 로그에 파일 body를 기록하지 않습니다.
- CodeMirror migration이 끝난 같은 batch에서 기존 CodeMirror direct dependency와
  lifecycle adapter를 제거합니다. 두 editor의 장기 병존을 금지합니다.

## Build budget

- Mac mini 동일 `HEAD` archive와 동일 Bun/Vite에서 production build 3회 중앙값을
  측정합니다.
- app shell 초기 gzip 증가는 5 KiB 이하이며 Monaco worker와 editor는 config route
  진입 전 내려받지 않습니다.
- 일반 production build 중앙값 증가는 같은 checkout 3회 측정 기준 20% 이하로
  제한합니다. 직접 source bundling이 이를 넘으면 same-origin 정적 vendor 자산으로
  격리하며 두 editor를 병존시키지 않습니다.
- static Monaco runtime은 gzip 900 KiB 이하, CSS gzip 20 KiB 이하, editor worker는
  raw 320 KiB 이하로 제한합니다.
- exact version, Bun lockfile diff, lazy asset 크기와 build 시간은 decision register에
  기록합니다.

## Compatibility spike evidence

- package: `monaco-editor-core 0.56.0`, MIT, unpacked 39.83 MB
- CodeMirror baseline production build: `484ms / 200ms / 179ms`, median `200ms`
- Monaco source-direct production build: `548ms / 443ms / 462ms`, median `462ms`
  (`+131%`)로 예산 초과하여 채택하지 않음
- static vendor production build: `217ms / 180ms / 177ms`, median `180ms`
  (`-10%`)
- app shell gzip: `71.62 kB → 71.62 kB`
- lazy vendor: runtime `841.96 kB gzip`, CSS `16.77 kB gzip`, worker `301.05 kB raw`

## Security and accessibility

- 설정 적용은 기존 PAM 관리 모드와 typed `opsd` operation만 사용합니다.
- Monaco는 root path, command, argv 또는 service action을 생성하지 않습니다.
- keyboard navigation, focus visibility, high contrast, reduced motion, Korean IME,
  large-file bound와 dirty-close 확인을 browser gate에서 검증합니다.
- raw validator stdout·stderr와 canonical path는 브라우저에 전달하지 않습니다.

## Rejected

- CodeMirror 유지: desktop multi-file diagnostics와 schema 도움말 목표에 맞지 않습니다.
- Monaco와 CodeMirror 병존: build graph와 UX 권위 원본이 이중화됩니다.
- Elektra·Augeas runtime: native dependency와 별도 mutation engine을 추가하고 기존
  snapshot·ledger·typed adapter 계약을 중복합니다.
- 초기 LSP 도입: 별도 process·protocol·worker와 completion 권위 중복을 만듭니다.
- 모바일 설정 편집: 작은 화면에서 root mutation 검토 품질을 낮춥니다.

## Acceptance

- desktop file tree, tabs, diff, Problems panel, sticky 저장·취소와 dirty guard
- Nginx·Apache·PHP-FPM structured diagnostic의 정확한 file·line·column 이동
- PHP versioned schema 기반 completion·hover
- mobile·tablet mutation CTA 부재와 read-only 상태 유지
- app shell lazy-load, build budget, no runtime CDN, no second editor
- web typecheck, unit, lint, production build, browser와 Ubuntu VM managed-config gate PASS
