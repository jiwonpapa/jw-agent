# Future Central Management Boundary

Status: Draft  
Authority: Architecture  
Owner: Architecture Maintainer  
Last reviewed: 2026-07-21

중앙관제는 로컬 MVP 이후 별도 phase입니다. 현재 workspace에 central crate·DB·UI route를 만들지 않습니다.

## 예정 stack

- Rust 2024
- Axum + Tokio
- PostgreSQL
- SQLx runtime query/migrations
- OpenAPI REST API
- SSE for browser state, WebSocket only for explicitly approved terminal session
- PostgreSQL queue/outbox first; Redis·Kafka·Kubernetes 없음

정확한 version은 phase 진입 시 compatibility spike 후 pin합니다.

## 책임

- organization, client, server tenancy
- staff account와 scoped RBAC
- agent enrollment·certificate rotation
- read-only fleet health·alerts·report
- remote typed operation plan·approval·receipt relay

## Agent 통신

- agentd가 outbound-only authenticated connection을 소유
- one-time enrollment code는 짧은 수명과 single use
- 장기 identity는 server-generated non-exportable private key와 rotating certificate
- 중앙은 root password·SSH private key를 저장하지 않음
- disconnect 동안 local operation과 evidence가 독립 동작

## 진입 gate

- local MVP `RELEASE_PASS`
- agent/opsd contract versioning proven
- tenancy threat model and negative isolation tests
- PostgreSQL ownership/RLS decision ADR
- customer-owned disconnect/export workflow spec

