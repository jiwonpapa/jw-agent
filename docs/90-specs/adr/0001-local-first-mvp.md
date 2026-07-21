# ADR-0001 — Local-first MVP

Status: Superseded by ADR-0007  
Authority: Architecture Decision  
Owner: Architecture Maintainer  
Last reviewed: 2026-07-21

## Decision

단일 서버 loopback UI와 SSH tunnel 복구 경로를 중앙관제보다 먼저 완성합니다.

## 이유

- 서버 한 대 사용자도 독립 가치를 얻습니다.
- 중앙 장애·도메인·TLS·상시 VPS 비용에 종속되지 않습니다.
- 안전 operation과 crash recovery를 작은 범위에서 증명할 수 있습니다.

## 결과

중앙 seam은 agentd outbound 경계로만 문서화하고 P0–P3 workspace·DB·route에 구현하지 않습니다.

## Supersession

단일 서버 우선과 SSH 복구 원칙은 유지하지만 loopback-only 접근은 폐기했습니다. 공개 HTTPS·PAM 요구는 [ADR-0007](0007-public-https-pam-boundary.md)이 대체합니다.
