# Information Architecture

Status: Accepted  
Authority: UI Specification  
Owner: Product Designer  
Last reviewed: 2026-07-21

UI는 지표 구경용 dashboard가 아니라 `문제 확인 → 계획 검토 → 실행 → 검증·원복 확인` 작업면입니다.

## MVP routes

- `/login`
- `/session/reauth`
- `/overview`
- `/services`
- `/services/nginx`
- `/services/nginx/sites/$siteId`
- `/services/nginx/sites/$siteId/change`
- `/operations`
- `/operations/$operationId`
- `/integrations`
- `/settings`
- `/settings/access`

`/login` 외 route는 authenticated layout 아래에 둡니다. `/`는 session에 따라 login 또는 overview로 이동하고, 보호 deep link의 `returnTo`는 same-origin 상대경로만 허용합니다.

중앙관제용 `/clients`, `/servers`, `/alerts`는 MVP에 만들지 않습니다. `/integrations`는 중앙 marketplace가 아니라 현재 서버의 고정된 read-only curated catalog입니다.

## Overview 순서

1. 서버 identity, 관찰 시각, read/write 상태
2. Attention Queue: recovery → interrupted → failed unit → unsupported → warning
3. CPU·memory·disk·uptime 상태선
4. 주요 서비스와 실패 unit 요약
5. Nginx site table과 변경별 rollback assurance
6. 최근 operation ledger

건강한 상태는 차분하게 표시하고 action이 필요한 예외만 강조합니다. 원형 gauge, KPI card mosaic, 장식 차트를 사용하지 않습니다.

## Desktop layout

- 220px left navigation
- primary workspace
- 선택 항목의 우측 inspector

## Responsive shell

- Desktop: 220px sidebar + workspace + optional inspector
- Tablet landscape: navigation rail + workspace + inspector sheet
- Tablet portrait: top bar + navigation sheet + single workspace
- Mobile: server identity top bar + navigation sheet + one column

Mobile과 tablet에서도 plan target·impact·snapshot·rollback assurance·제외 효과를 생략하지 않습니다. 표는 같은 row view model을 desktop table과 mobile labeled list로 표현합니다.
