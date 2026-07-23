# UI-OVERVIEW-V1

Status: Accepted  
Authority: UI Specification  
Owner: Product Designer  
Last reviewed: 2026-07-21

## User job

서버에 지금 조치할 문제가 있는지 30초 안에 판단하고 근거 화면으로 이동합니다.

## Route and data

- Route: `/overview`
- Host identity and observation freshness
- write/forensic-lockdown capability
- canonical Linux subject, role, public/recovery access status
- attention items
- CPU 200ms delta, load average 1·5·15, memory와 root filesystem resource observations
- 최근 bounded load sample과 logical CPU로 정규화한 코어당 부하
- Nginx site inventory
- recent operation receipts

`GET /api/v1/activity`는 현재 canonical Linux UID가 실행한 최근 typed operation receipt를
최대 8개 반환합니다. background 관찰 조회와 terminal command 내용은 이 목록에 넣지 않습니다.

정확한 REST type은 generated client가 소유합니다.

## Layout

1. 계정·현재 session과 management mode를 첫 화면에서 펼쳐 표시
2. CPU·load 1·5·15·memory·root disk를 숫자, ring·progress bar·짧은 추세로 함께 표시하는 resource rail
3. 원인·영향·권장 조치를 함께 표시하며 여러 문제를 숨기지 않는 Attention Queue
4. catalog 기반 주요 서비스 card grid
5. Nginx site card grid
6. 지원되는 typed 관리 작업 진입점과 펼칠 수 있는 최근 operation receipt

## Required states

- loading skeleton without fake values
- fresh
- stale with last-known values and timestamp
- partial observation
- empty attention queue
- unsupported service
- session expired
- role changed / reauthentication required
- agentd/opsd disconnected
- forensic lockdown

## Interaction

- row action is one clear next step
- write action exists only when backend capability permits
- site change opens full plan page, not modal
- no auto-refresh that steals focus
- exact time available alongside relative time

## Responsive/accessibility

- desktop/tablet/mobile layouts from UI policy, 320px reflow
- keyboard navigation through attention and tables
- semantic table on desktop and labeled rows on mobile
- status text/icon in addition to color
- focus remains stable after background refresh
- live updates summarized, not announced per metric
- 주요 section은 border panel로 분리하고 desktop은 가능한 항목을 2~5열로 배치

## Playwright acceptance

- real API values and freshness
- unsupported/lockdown removes write action
- stale is not rendered as zero
- deep link and refresh preserve route
- no horizontal overflow at 390×844
- keyboard reaches every action
- light/dark snapshots and axe critical/serious 0
- CPU·memory·root disk의 숫자와 접근 가능한 graph label 일치
- load 1·5·15, logical CPU와 코어당 부하의 숫자·경고가 일치
- 최근 receipt를 펼치면 actor, operation type, before/after digest와 stage가 표시
