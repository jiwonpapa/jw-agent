# Public HTTPS Ingress

Status: Accepted  
Authority: Architecture  
Owner: Security Maintainer  
Last reviewed: 2026-07-23

## Decision

기본 공개 관리 경로는 `Internet → jw-edge Rustls 9443 → agentd 전용 Unix socket`입니다.
`Nginx+Certbot 443`은 선택적 호환 경로이며 agentd 직접 public TCP bind는 계속 금지합니다.

## 이유

- 관리 대상 Nginx가 중지되어도 브라우저 관리 경로를 유지합니다.
- TLS와 public socket을 agentd에서 분리한 비권한 프로세스가 소유합니다.
- 인증서 발급·갱신은 기존 Certbot typed operation을 재사용하되 edge key path는 분리합니다.
- edge 장애 시 Nginx 443 또는 loopback·SSH tunnel 복구 경로를 사용합니다.

## Ingress contract

- valid HTTPS 외 login form 비활성화
- exact Host·Origin allowlist, CORS disabled
- `jw-edge`와 Nginx public proxy는 같은 dedicated UDS만 사용
- edge가 inbound `Forwarded`와 `X-Forwarded-*`를 제거하고 socket peer 정보로 재작성
- agentd는 proxy UDS에서 받은 metadata만 trusted proxy input으로 처리
- edge는 TLS handshake·connection·request line/header/time을 제한하고 agentd는 endpoint body를 제한
- API·인증 response `Cache-Control: no-store`
- operation SSE는 same-origin session을 재사용하고 upstream `X-Accel-Buffering: no`, 10초 keepalive, durable sequence replay를 적용
- CSP self-only, frame denial, no-referrer, validated HSTS

## Protected resource

edge unit·certificate mapping·proxy socket과 호환 관리 vhost는 `system-owned/protected` capability입니다.
Nginx 중지는 agentd가 edge active·ready 상태를 관찰하고, `opsd`가
`/run/jw-agent-edge/ready.sock`의 고정 응답을 계획·실행 직전에 직접 확인한 경우에만 노출·실행합니다.
health socket은 비밀이나 명령을 받지 않으며 쓰기 불가능한 persistent runtime directory 안에서
`jw-edge` 생존과 agentd proxy UDS 연결 가능 여부만 증명합니다. agentd 재시작은 edge process를
중지하지 않으며, edge는 upstream이 돌아오면 별도 운영자 조치 없이 다시 proxy합니다.
관리 vhost 판정은 설치 파일명에 의존하지 않고 package marker 또는 전용 proxy include를 agentd와 opsd가 동일하게 검사합니다.

## Activation

설치 script가 DNS·certificate·UFW를 몰래 바꾸지 않습니다. 관리자가 valid certificate와 key를
`/etc/jw-agent/edge`에 설치해야 `jw-edge`를 활성화합니다. 기본 9443 방화벽 개방도 명시적 작업입니다.
Nginx 443 호환 경로는 기존 opt-in template을 유지합니다.

## Sources

- [NGINX proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
