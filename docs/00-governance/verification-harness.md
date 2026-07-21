# Single Verification Harness

Status: Accepted  
Authority: Governance  
Owner: Verification Maintainer  
Last reviewed: 2026-07-21

## 유일한 입구

검증 로직은 `xtask`만 소유합니다.

```bash
cargo xtask list
cargo xtask verify governance
cargo xtask verify p1-local
cargo xtask verify p1-browser
```

존재하는 검사만 등록합니다. Ubuntu VM과 release lane은 실제 fixture·artifact가 생기기 전 성공하는 placeholder로 만들지 않습니다.

## 현재 lane

| Lane | 목적 | 증거 수준 |
|---|---|---|
| governance | 문서·정책·dependency source·원격 Actions 경계 | DOC/AUTO |
| p1-local | governance + Rust policy/fmt/clippy/test + OpenAPI drift + 웹 type/lint/unit/build | LOCAL_PASS |
| p1-browser | governance + mock API 브라우저 세션·반응형·접근성 | LOCAL_PASS |

`p1-browser`는 UI 계약 검증이며 실제 PAM·systemd·Nginx 통합 증거가 아닙니다. `p1-vm`과 `release`는 구현되지 않았습니다.

## Gate metadata

- `GateId`: 절대 재사용하지 않는 ID
- `owner`: 판단 규칙 소유자
- `scope`, `inputs`, `lanes`
- `timeout`
- `evidence output`
- `failure_policy`

결과는 `PASS`, `FAIL`, `BLOCKED`, `SKIPPED`입니다. Release 필수 gate는 `SKIPPED`일 수 없습니다.

## 중복 방지

- wrapper는 GateId를 호출만 합니다.
- 동일 명령을 lane마다 복사하지 않습니다.
- local Cargo cache와 VM base image만 cache합니다. PASS 결과를 cache하지 않습니다.
- release는 필수 gate evidence를 새로 생성합니다.
- service-specific safety는 `opsd`와 해당 operation VM scenario 한 곳이 소유합니다.

## Ubuntu VM gate ownership

다음 GateId는 disposable Ubuntu fixture와 실행기가 준비될 때만 registry에 추가합니다. 현재는 문서에만 계획하며 성공 처리하지 않습니다.

- `PUBLIC_EDGE_VM`: TLS, proxy UDS, Host, UFW, internal port 비노출
- `PAM_AUTH_VM`: PAM success/failure/account/group/peer boundary
- `WEB_SESSION_BROWSER`: cookie, rotation, timeout, revoke, CSRF, CSP
- `AUTH_ABUSE_VM`: rate limit, enumeration, bounded worker/queue
- `AUTH_SECRET_SCAN`: password/session secret의 log·DB·evidence 비노출
- `PUBLIC_RECOVERY_VM`: Nginx/TLS 장애, SSH fallback, public disable

Mobile·tablet은 기존 browser GateId의 viewport matrix이며 별도 중복 하네스를 만들지 않습니다.
