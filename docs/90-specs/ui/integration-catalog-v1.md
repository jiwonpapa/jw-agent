# UI-INTEGRATION-CATALOG-V1

Status: Accepted  
Authority: UI Specification  
Owner: Product Designer  
Last reviewed: 2026-07-21

## User job

사용자는 JW Agent와 독립된 형님 제품들의 설치 흔적, 용도, 자원 충돌, 설정 단계와 현재 설치 가능 여부를 한 화면에서 판단합니다.

## Scope

- Route: `/integrations`
- API: `GET /api/v1/integrations`
- Curated entries: VPSGuard, G7 Installer, G7MediaBooster, G7Telegram DevOps
- fixed-path read-only discovery
- product purpose, lifecycle, resource claims, setup steps, source link
- rollback assurance and fail-closed install blockers

## Non-goals

- arbitrary marketplace or dynamic plugin
- remote manifest command execution
- existing product code·DB·protocol·installer ownership sharing
- signature·Ubuntu VM evidence 없는 package install·update·remove
- product credential을 JW Agent가 저장하거나 대신 설정

## States

- catalog: loading, observed, unsupported platform, failed, stale
- lifecycle: unknown, not installed, needs setup, installed, partial
- install: blocked or available
- assurance: server-provided G0–G3 only

현재 catalog entries는 `G0 OBSERVE_ONLY`이며 설치 실행은 모두 차단합니다. 차단은 미구현을 숨기기 위한 것이 아니라 서명·resource conflict·VM proof가 충족되지 않은 공급망 안전 상태입니다.

## Interaction

- desktop은 구분선 중심 목록과 우측 inspector를 사용합니다.
- mobile·tablet은 같은 정보를 labeled row와 sheet로 표시합니다.
- 제품 행은 lifecycle·install readiness·assurance를 실행 전 표시합니다.
- 상세는 resource claims, blockers, setup steps와 독립 source를 보여줍니다.
- 광고 banner, 자동 설치 prompt, 위험 경고를 가리는 promotion을 금지합니다.

## Security and privacy

- agentd는 고정된 indicator path의 존재만 확인하고 config 내용을 읽지 않습니다.
- 외부 network request, package manager, shell, root helper를 호출하지 않습니다.
- browser는 product secret·token·credential을 입력하거나 저장하지 않습니다.
- 외부 source link는 정보 확인용이며 install action이 아닙니다.

## Acceptance

- API가 네 제품을 stable ID로 한 번씩 반환
- non-Linux는 installed로 추측하지 않고 unknown·unsupported 표시
- 모든 entry가 install blocker와 G0 assurance를 가짐
- `/integrations`에서 lifecycle·설치 차단·원복 보장을 실행 전 확인
- 상세 inspector에서 자원·차단 사유·설정 순서를 확인
- 320·390, tablet portrait/landscape, desktop horizontal overflow 0
- keyboard-only, visible focus, axe critical/serious 0
- 외부 API·광고·telemetry request 0
