# Design System and Dashboard Standard

Status: Accepted  
Authority: UI Specification  
Owner: Product Designer  
Last reviewed: 2026-07-21

## 시각 원칙

- cold neutral canvas
- cobalt 단일 action accent
- 조밀하지만 읽기 쉬운 operator table
- 최소 chrome, 구분선 중심 hierarchy
- card는 독립 상호작용 단위일 때만 사용
- gradient, glass effect, 과도한 shadow·radius 금지

## Semantic tokens

- surface: `canvas`, `surface`, `subtle`, `border`
- text: `text`, `muted`
- action: `action`, `action-foreground`
- status: `success`, `warning`, `danger`, `info`, `stale`
- spacing: 4px base role scale
- radius: 6px and 10px
- motion: 120–180ms meaningful transition only

Tailwind v4 CSS-first theme과 OKLCH token을 사용합니다. feature 코드의 raw hex, `blue-500`, arbitrary spacing·shadow, `bg-${status}`를 금지합니다.

## Standard states

모든 데이터 surface는 다음 상태를 구현합니다.

- initial loading skeleton
- fresh
- stale with last-known timestamp
- empty
- unsupported with reason
- permission denied
- connection lost
- partial observation
- failed with recovery action
- authentication required / reauthentication required
- role denied / session expired / HTTPS required

`unknown`, `0`, `not installed`, `unsupported`, `stale`를 같은 값으로 합치지 않습니다.

## Login surface

로그인 panel은 독립 상호작용 단위이므로 card를 허용합니다. 장식용 marketing hero, account list, root shortcut은 사용하지 않습니다. ID·password, generic error, retry delay, HTTPS 상태, recovery 안내만 표시합니다.

## Table contract

행에는 대상, 현재 상태, 근거 시각, capability, rollback assurance, 마지막 변경, 단일 다음 행동을 표시합니다. 모바일에서는 정보 손실 없이 labeled rows로 전환합니다.

Rollback assurance badge는 색상만으로 구분하지 않고 `변경 없음`, `자동 원복 보장 없음`, `제한된 설정 자동 원복 지원`, `복원 검증된 데이터 복구` text를 사용합니다. 단독 `안전` badge와 shield icon으로 보장 범위를 축약하지 않습니다.
