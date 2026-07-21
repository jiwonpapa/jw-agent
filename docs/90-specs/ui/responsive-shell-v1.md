# UI-RESPONSIVE-SHELL-V1

Status: Accepted  
Authority: UI Specification  
Owner: Product Designer  
Last reviewed: 2026-07-21

## Goal

Desktop, tablet portrait/landscape, mobile에서 기능을 줄이지 않고 동일한 관찰·plan·approval·timeline 작업을 수행합니다.

## Layout contract

- Desktop: sidebar, workspace, optional inspector
- Tablet landscape: navigation rail, workspace, inspector sheet
- Tablet portrait: identity top bar, navigation sheet, workspace
- Mobile: identity top bar, navigation sheet, one column, sticky approval bar
- Sheet component 하나를 tablet/mobile navigation에 재사용하며 별도 Drawer dependency를 추가하지 않음

## Content contract

- same typed row view model for table and labeled list
- target·impact·snapshot·verify·rollback never omitted
- only diff and long path panes can scroll horizontally
- no hover-only, swipe-only, hidden row action
- stale/unknown/unsupported/zero remain distinct
- background resume reconnects SSE and fetches canonical state

## Viewport evidence

- 320×800 mobile minimum
- 390×844 common mobile
- 768×1024 tablet portrait
- 1024×768 tablet landscape
- 1440×900 desktop

각 viewport에서 login, overview, Nginx table/list, plan, reauth, execution timeline, recovery-required, settings/access를 검증합니다. Orientation 변경은 route와 selection을 유지하고 sticky action은 마지막 content를 가리지 않습니다.
