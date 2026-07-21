# ADR-0002 — agentd and opsd Privilege Split

Status: Accepted  
Authority: Architecture Decision  
Owner: Security Maintainer  
Last reviewed: 2026-07-21

## Decision

네트워크·UI·관찰을 비-root `agentd`, typed privileged operation을 networkless root `opsd`가 담당합니다.

## 이유

장기 실행 네트워크 daemon의 compromise를 arbitrary root shell로 곧바로 확대하지 않기 위해서입니다.

## 결과

- versioned bounded UDS contract 필요
- peer UID와 apply-time policy 검증 필요
- 두 daemon state DB 분리
- opsd dependency graph에서 HTTP/TLS/WebSocket 금지
- IPC와 운영 복잡성이 늘지만 보안 경계로 정당화됨

ADR-0007은 이 분리를 유지하면서 PAM password를 opsd에 넣지 않는 별도 one-shot authd 경계를 추가합니다.
