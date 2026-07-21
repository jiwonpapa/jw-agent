# Interaction, Responsive, and Accessibility

Status: Accepted  
Authority: UI Specification  
Owner: Product Designer  
Last reviewed: 2026-07-21

## 안전 변경 UX

변경 승인은 작은 confirm modal이 아니라 전용 plan page에서 수행합니다.

설정·서비스 목록의 mutation 진입점부터 [UI-ROLLBACK-ASSURANCE-V1](../90-specs/ui/rollback-assurance-v1.md)에 따른 보장 수준을 표시합니다. 사용자가 실행 버튼을 누른 뒤 처음 알게 해서는 안 됩니다.

- current → target
- exact resource
- impact and expected interruption
- snapshot scope
- verifier and rollback guarantee
- excluded effects and recovery-required path
- created/expires time
- plan hash and drift state

승인에는 plan hash와 idempotency key가 필요합니다. mutation은 자동 retry·optimistic success를 사용하지 않습니다. execution timeline은 SSE server event만 반영합니다.

## 반응형

- Desktop: sidebar + workspace + optional inspector
- Tablet landscape: navigation rail + inspector sheet
- Tablet portrait: top bar + navigation sheet + one column
- Mobile: persistent server identity bar + navigation sheet + one column
- sticky approval action uses dynamic viewport and safe-area inset
- diff만 제한된 horizontal scroll 허용
- hover-only action 금지
- swipe-only·hidden row action 금지
- background 복귀 시 SSE reconnect 후 canonical operation state 재조회

모바일에서도 plan target·impact·snapshot·rollback을 CTA 위에 모두 표시합니다. 화면 크기를 이유로 위험 정보를 접어 기본 비표시하지 않습니다.

## Login and session UX

- HTTPS form-based Linux account login; HTTP Basic 금지
- `autocomplete="username"` and `autocomplete="current-password"`
- password manager·paste 허용, custom keyboard 금지
- unknown user·wrong password·locked account에 동일한 public error
- rate-limit retry delay를 접근 가능한 text로 표시
- password를 URL·web storage·query cache에 넣지 않음
- 공개 HTTP에서는 password form disabled
- root login, account creation, password change, `Remember me` 없음
- logout·expiry 시 Query cache와 sensitive screen memory 제거
- write approval reauth 후 원래 plan으로 안전하게 복귀

## 접근성 기준

- WCAG 2.2 AA 목표
- 320 CSS px reflow
- skip link, landmark, heading order
- keyboard-only full workflow and visible focus
- primary touch target 44px 이상
- 200% zoom과 narrow viewport reflow
- status를 color로만 전달하지 않음
- reduced motion
- dialog/sheet focus trap과 focus return
- SSE `aria-live`는 단계 요약만 throttle해서 알림

## 브라우저 완료 증거

- 1440×900, 1024×768, 768×1024, 390×844, 320×800
- light/dark visual snapshots
- Chromium, Firefox, WebKit 핵심 흐름
- axe critical/serious 0과 수동 keyboard 확인
- 실패 trace·video·screenshot·HTML report
- 외부 광고·telemetry request 0
- orientation change 후 route·selection 유지
- allowed diff/path 외 horizontal overflow 0
- credential의 URL·storage·trace 노출 0
