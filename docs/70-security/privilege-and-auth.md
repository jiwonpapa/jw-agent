# Privilege, Identity, and Session

Status: Accepted  
Authority: Security  
Owner: Security Maintainer  
Last reviewed: 2026-07-21

## Process privilege

- `agentd`: dedicated non-root account, public proxy UDS and loopback recovery API
- `authd`: root, systemd socket-activated one-shot, PAM/account/role only
- `opsd`: root, long-running networkless typed operation executor
- browser: no root password, SSH key, authd/opsd token

`authd`와 `opsd`는 서로의 socket·protocol·responsibility를 공유하지 않습니다. systemd sandbox directive는 실제 PAM·NSS·service dependency를 Ubuntu VM에서 확인한 뒤 최소화합니다.

## Authentication and authorization

- identity proof: Linux PAM service `jw-agent`
- account validity: `pam_acct_mgmt`
- authorization: canonical UID와 explicit Linux group
- `jw-agent-admin`: access·security 설정과 모든 supported operation
- `jw-agent-operator`: supported operation plan·approval, security 설정 제외
- `jw-agent-viewer`: read-only observation·evidence

PAM 성공만으로 제품 접근을 허용하지 않습니다. UID 0 root 웹 로그인, 허용 group 밖 계정, 둘 이상의 제품 role group에 동시에 속한 계정은 거부합니다. group name·role mapping은 root-owned policy 한 곳에서 관리합니다.

## Session

- CSPRNG로 생성한 최소 256-bit opaque ID, server-side state
- public HTTPS는 `__Host-jw_session`: `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`
- SSH tunnel의 loopback HTTP recovery는 별도 `jw_recovery_session`: host-only, `HttpOnly`, `SameSite=Strict`, no `Domain`, 더 짧은 lifetime
- recovery cookie는 loopback listener에서만 발급·수락하고 public proxy UDS에서는 항상 거부
- public cookie는 recovery listener에서 거부하여 channel 간 session replay를 차단
- login·reauth·role change에 session ID rotation
- named idle·absolute timeout과 전체 session revoke
- plaintext session ID 대신 digest만 agentd DB에 저장
- JWT, URL token, localStorage, sessionStorage, `Remember me` 금지
- logout·session expiry 후 API cache와 화면 memory 제거

## Write reauthentication and optional additional auth

지원 operation 승인은 항상 최근 PAM 재인증이 필요합니다. 성공 결과는 session ID, canonical actor UID, role, plan hash, expiry에 묶인 single-use claim으로 저장합니다. plan drift, session rotation, role change, 사용 완료 시 폐기합니다.

추가 인증은 강제 고정값이 아니라 관리자 설정입니다.

- `disabled`: PAM 재인증만 요구
- `risky_operations`: 위험 operation에 등록된 추가 인증 요구
- `all_mutations`: 모든 변경에 등록된 추가 인증 요구

P1 기본값은 `disabled`, UI 권장값은 `risky_operations`입니다. provider가 `not_implemented` 또는 `not_configured`이면 보호가 활성화된 것처럼 표시하지 않고 해당 mutation approval을 사용할 수 없다고 반환합니다. 모든 정책 변경은 admin과 최근 PAM 재인증이 필요하고, 정책 완화는 잔여 위험 경고와 감사 event를 추가합니다. provider·등록·복구 ceremony는 별도 Accepted spec 전에는 구현하지 않습니다.

## Request protection

- exact Host·Origin allowlist, CORS disabled
- session-bound CSRF token and JSON-only mutation
- login·mutation response `Cache-Control: no-store`
- CSP self-only, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`
- frame denial, no-referrer, validated HSTS
- protected route의 client guard는 UX만 담당하고 server가 최종 role을 검사
- `returnTo`는 검증된 same-origin 상대경로만 허용
- recovery listener는 127.0.0.1/::1에만 bind하고 forwarded header를 무시하며 exact local Host·Origin과 CSRF를 검사

Loopback recovery의 browser↔SSH client 구간은 host 내부 loopback이고 이후 구간은 SSH가 암호화합니다. Public HTTPS session과 동일한 cookie를 재사용하지 않으며 UI에 recovery mode를 명확히 표시합니다.

## Excluded

- Linux account 생성·삭제·password 변경 UI
- root web login
- HTTP Basic/Digest authentication
- shared service password
- PAM raw error/message를 browser로 전달
- password-only 장기 session

## Sources

- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
