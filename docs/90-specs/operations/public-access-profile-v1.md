# OPS-PUBLIC-ACCESS-PROFILE-V1

Status: Accepted  
Authority: Operation Specification  
Owner: Access Edge Maintainer  
Last reviewed: 2026-07-21

## Purpose

SSH tunnel recovery에서 검토한 plan으로 독립 `jw-edge` HTTPS profile과 선택적 Nginx 호환 profile을 활성화·비활성화합니다. 이는 일반 service operation이 아니라 제품 access 설정 operation입니다.

독립 관리 ingress는 [ADR-0018](../adr/0018-independent-rust-management-edge.md)을 따릅니다. Nginx template은 표준 443 호환 경로이며 관리 UI의 필수 의존성이 아닙니다.

## Operation IDs

- `access.public.enable/v1`
- `access.public.disable/v1`

## Assurance and UX

- Assurance: `G2 REVERSIBLE_CONFIG`
- 자동 원복 범위: 제품 소유 vhost·access profile·제품이 추가한 UFW rule
- 제외 효과: DNS·certificate·cloud firewall·user-owned Nginx/UFW/SSH resource
- UI는 공개 설정 진입점부터 이 범위와 SSH recovery 필요성을 표시합니다.

## Preconditions

- supported jw-edge TLS layout 또는 선택적 Nginx·Certbot layout
- exact FQDN/Host and valid certificate
- protected management vhost marker와 전용 proxy include 판별 가능
- proxy UDS permission verified
- at least one non-root PAM admin verified
- SSH recovery connectivity confirmed
- UFW/cloud firewall current state observed
- no conflicting operation/resource lock

## Plan

- current and target access profile
- domain/certificate identity and expiry
- exact jw-edge endpoint와 선택적 protected Nginx resource
- ports and product-owned firewall delta
- HTTPS health and Host checks
- rollback and session revoke behavior
- rollback scope and excluded external effects
- external cloud firewall action separated from product action

## Apply and verify

1. snapshot product-owned edge/access configuration
2. verify edge certificate·key permission and bind the planned address
3. probe edge HTTPS through expected Host and optional protected Nginx vhost
4. verify agentd internal TCP is not public and both edge paths use UDS
5. if UFW is active, add only the planned 9443 또는 optional 443 rule last
6. read back TLS, headers, login form and SSH fallback
7. commit profile; otherwise restore only product-owned changes

## Disable

Public disable stops the product edge, removes only product-owned firewall rules, revokes all public sessions and retains loopback SSH recovery. 선택적 Nginx product vhost도 제거할 수 있지만 Nginx, UFW, Certbot, SSH 또는 user-owned rule을 전역 중지하지 않습니다.

## Failure and acceptance

- invalid/mismatched/expired certificate
- Host/Origin/proxy-header spoof rejection
- Nginx config/reload/health failure and rollback
- UFW active/inactive and existing rule preservation
- cloud firewall unresolved is explicit external blocker
- process kill/disk full at each durable stage
- management vhost excluded from Nginx site toggle
- public disable during Nginx/TLS degradation through SSH fallback
