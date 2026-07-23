# ADR-0018 — Independent Rust Management Edge

Status: Accepted  
Authority: Architecture Decision  
Owner: Access Edge Maintainer  
Last reviewed: 2026-07-23

## Context

기존 공개 경로 `Nginx 443 → agentd UDS`는 관리 대상 Nginx를 중지하면 관리 UI도 함께 중단합니다.
Agent와 root helper는 살아 있어도 브라우저 진입점이 사라지므로 서비스 관리 제품의 독립성 요구를 충족하지 못합니다.

## Decision

```text
Browser → jw-edge Rust TLS :9443 → dedicated UDS → agentd non-root
Browser → optional Nginx 443 ─────→ dedicated UDS → agentd non-root
SSH tunnel → loopback :8787 ─────→ agentd recovery
agentd → typed UDS → authd / opsd
```

- `jw-edge`는 별도 비권한 프로세스이며 TLS 종료, exact Host·Origin 정규화, client-address 주입,
  forwarding-header 제거, header·handshake·connection bound만 담당합니다.
- `jw-edge`는 PAM·DB·opsd socket에 접근하지 않고 agentd public UDS 하나에만 연결합니다.
- agentd direct public TCP bind는 계속 금지합니다.
- 기본 독립 포트는 `9443`입니다. 동일 IP의 Nginx 443과 충돌하지 않으며 운영자가 명시적으로 방화벽을 엽니다.
- 별도 IP가 있을 때만 `jw-edge`를 해당 IP의 443에 bind할 수 있습니다.
- TLS 인증서와 key는 `/etc/jw-agent/edge`에 두고 root와 `jw-agent`만 읽습니다. URL·argv·로그에 key를 노출하지 않습니다.
- Nginx proxy는 호환 경로이며 제거를 강제하지 않습니다.

## Nginx self-lockout rule

- agentd는 Nginx `stop` capability를 표시하기 전에 `jw-edge.service active`와 ready file을 확인합니다.
- networkless `opsd`는 plan과 apply 직전에 `/run/jw-agent-edge/ready.sock`의 고정 응답을 직접 확인합니다.
- runtime directory는 tmpfiles가 만들고 edge 재시작 때 제거하지 않아 `opsd` mount namespace에서 stale path가 되지 않습니다.
- health socket은 입력·명령·비밀을 받지 않으며 agentd UDS 연결이 성공한 경우에만 `JW-EDGE-READY-V1`을 반환합니다.
- `jw-edge`는 agentd를 `Wants/After`로만 참조합니다. agentd가 재시작되는 동안 프로세스와 9443 listener를
  유지하고, 최초 시작 시 upstream이 없으면 종료 반복 대신 내부에서 준비를 기다립니다.
- readiness가 없으면 `management_ingress_dependency`로 side effect 전에 거부합니다.
- Nginx reload·restart는 기존 검증·복구 계약을 유지합니다.
- `jw-edge`, `jw-agentd`, `jw-authd`, `jw-opsd`는 일반 service lifecycle 대상이 아닙니다.

## Build and dependency impact

`jw-edge`는 독립 network/TLS privilege와 안정 계약을 가지므로 헌법 제1조의 crate 분리 사유를 충족합니다.
TLS stack은 Rustls 하나만 사용하며 OpenSSL link와 code generation을 추가하지 않습니다.
Rustls의 `ring` crypto provider가 C·assembly build script를 추가하므로 native dependency 예외를 이 ADR에
명시하고 macOS cross build와 Ubuntu package runtime 증거를 모두 요구합니다.
직접 의존성은 exact pin하고 transitive dependency는 lockfile로 고정합니다.

## Migration

1. 패키지는 edge unit과 기본 `9443` 설정을 설치하되 인증서가 없으면 시작하지 않습니다.
2. 기존 Nginx 443 공개 경로는 그대로 유지합니다.
3. 관리 인증서/key를 전용 경로에 설치하고 `jw-edge`를 시작합니다.
4. `https://host:9443` login·API·terminal·SFTP를 검증합니다.
5. Nginx를 중지한 상태에서도 edge UI·API가 동작함을 검증한 뒤 Nginx stop capability를 노출합니다.

## Acceptance

- malformed TLS, oversized header, wrong Host·Origin과 forged forwarding header 거부
- public client IP는 edge가 peer socket에서 생성하고 browser 값을 신뢰하지 않음
- Nginx active·inactive 양쪽에서 edge의 login·SPA deep link·API 동작
- terminal WebSocket과 SSE가 route-independent session 계약을 유지
- edge 중단 또는 readiness 누락 시 Nginx stop plan이 side effect 전에 거부됨
- agentd public TCP socket, edge의 authd·opsd 접근과 root capability가 없음
- SSH recovery는 edge와 Nginx 장애 중에도 유지

## Evidence

- package: `jw-agent_0.2.0~p2.19_amd64.deb`
- SHA-256: `abff57f506c5fb1f1e0041a8319c195ef87d9097171fc14a693d5ca92b85e2c7`
- `VM-P2-INDEPENDENT-EDGE`: edge 부재 시 Nginx stop 거부, edge 준비 후 Nginx stop 성공,
  Nginx inactive 상태의 authenticated `:9443` UI·API 지속성 PASS
- `VM-PACKAGE-RUNTIME`, `VM-PUBLIC-RECOVERY`, `VM-P2-SERVICE-CONTROL` PASS

## Superseded rule

ADR-0007과 헌법 제10조의 “Nginx+Certbot 443만 공개” 제한을 위 결정으로 대체합니다.
PAM one-shot authd, typed opsd, public/recovery session 분리와 direct agentd bind 금지는 대체하지 않습니다.
