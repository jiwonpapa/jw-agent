# UI-LOGIN-SESSION-V1

Status: Accepted  
Authority: UI Specification  
Owner: Product Designer  
Last reviewed: 2026-07-21

## User jobs

- 허용된 Linux 계정으로 안전하게 로그인합니다.
- session·role·HTTPS 상태를 이해합니다.
- 쓰기 승인 직전에 같은 PAM 계정으로 재인증합니다.
- shared mobile device에서 확실히 로그아웃합니다.

## Routes

- `/login`: public
- `/session/reauth`: authenticated, single-use return to plan
- `/settings/access`: current subject, role, sessions, public/recovery status

## Form contract

- username and password only
- password form enabled only on validated HTTPS or explicit loopback recovery context
- autocomplete username/current-password
- paste and password manager supported
- no account list, root option, password change, remember-me
- generic invalid-credentials response for unknown/wrong/locked/denied
- rate limit response includes safe retry time without account detail

## Session states

- anonymous
- authenticating
- authenticated viewer/operator/admin
- reauthentication required
- session expired/revoked
- PAM unavailable/timeout
- HTTPS required
- public ingress degraded with recovery path

## Security interaction

- protected deep link returns only to validated relative path
- login and step-up rotate session identifier
- logout clears Query cache and sensitive view state
- browser never reads HttpOnly token
- public and recovery cookie/session namespaces cannot cross ingress
- UI hides unsupported action but server role remains authoritative
- reauth result is bound to exact plan and cannot approve another plan
- access settings exposes `disabled | risky_operations | all_mutations`; default is disabled and risky operations is recommended
- provider가 준비되지 않으면 additional auth를 활성 상태로 표현하지 않고 mutation approval unavailable을 표시
- every policy change requires admin and a recent PAM reauth claim; downgrade also shows residual-risk warning

## Responsive and accessibility

- login form works at 320×800 through desktop without horizontal scroll
- error summary receives focus and fields retain username but clear password
- password visibility control has stateful accessible name
- touch targets at least 44×44px
- mobile virtual keyboard does not hide submit/error
- tablet orientation change preserves safe route, never password

## Playwright acceptance

- PAM success and all generic failure variants
- protected deep link login return; external/open redirect rejected
- session rotation, expiry, logout/back-button denial
- viewer write action absent; server denial still tested
- plan step-up and exact return
- credential absent from URL, storage, screenshot, trace, request log fixture
- public HTTP form disabled
- loopback recovery mode label and cross-channel cookie rejection
- 320/390/768/1024/1440 viewport suite and keyboard-only flow
