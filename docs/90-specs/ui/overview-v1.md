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
- resource observations
- Nginx site inventory
- recent operation receipts

정확한 REST type은 generated client가 소유합니다.

## Layout

1. identity/freshness/write state line
2. prioritized Attention Queue
3. resource status rail
4. Nginx site table
5. recent operation ledger

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

## Playwright acceptance

- real API values and freshness
- unsupported/lockdown removes write action
- stale is not rendered as zero
- deep link and refresh preserve route
- no horizontal overflow at 390×844
- keyboard reaches every action
- light/dark snapshots and axe critical/serious 0
