# Public HTTPS Ingress

Status: Accepted  
Authority: Architecture  
Owner: Security Maintainer  
Last reviewed: 2026-07-21

## Decision

MVP 공개 접속은 `Internet → Nginx+Certbot 443 → agentd 전용 Unix socket`만 지원합니다. agentd 직접 rustls·ACME·public bind는 후순위입니다.

## 이유

- 기존 MVP의 Nginx·Certbot 지원을 재사용합니다.
- agentd에 ACME, TLS private key, privileged socket을 추가하지 않습니다.
- certificate renewal과 connection limiting을 Nginx가 소유합니다.
- Nginx 장애 시 loopback·SSH tunnel로 독립 복구합니다.

## Ingress contract

- valid HTTPS 외 login form 비활성화
- exact Host·Origin allowlist, CORS disabled
- public proxy는 dedicated UDS만 사용
- Nginx가 inbound `Forwarded`와 `X-Forwarded-*`를 제거하고 실제 remote 정보로 재작성
- agentd는 proxy UDS에서 받은 metadata만 trusted proxy input으로 처리
- request line/header/body/time/burst limits
- API·인증 response `Cache-Control: no-store`
- CSP self-only, frame denial, no-referrer, validated HSTS

## Protected resource

관리 vhost·certificate mapping·proxy socket은 `system-owned/protected` capability입니다. Nginx site toggle과 임의 service adapter는 이를 발견 목록에는 표시할 수 있지만 변경 대상으로 반환하지 않습니다.

## Activation

설치 script가 DNS·certificate·UFW를 몰래 바꾸지 않습니다. P1은 관리자가 기존 valid certificate path를 opt-in template에 연결하고 `nginx -t`와 HTTPS/SSH recovery를 직접 확인하는 범위입니다. plan 기반 typed 활성화·비활성화, 제품 소유 UFW rule과 자동 원복은 Accepted contract일 뿐이며 별도 P2 진입 승인 전에는 구현하거나 제공했다고 주장하지 않습니다.

## Sources

- [NGINX proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
