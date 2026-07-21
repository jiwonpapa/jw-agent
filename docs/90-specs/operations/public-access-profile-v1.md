# OPS-PUBLIC-ACCESS-PROFILE-V1

Status: Accepted  
Authority: Operation Specification  
Owner: Access Edge Maintainer  
Last reviewed: 2026-07-21

## Purpose

SSH tunnel recovery에서 검토한 plan으로 공개 HTTPS profile을 활성화·비활성화합니다. 이는 일반 service operation이 아니라 제품 access 설정 operation입니다.

이 문서는 P2 계약을 고정하지만 구현 진입을 승인하지 않습니다. P1 runtime은 기존 valid certificate와 administrator-owned opt-in Nginx template만 지원하며 아래 typed operation·UFW mutation·자동 rollback은 별도 P2 진입 승인 전에는 노출하지 않습니다.

## Operation IDs

- `access.public.enable/v1`
- `access.public.disable/v1`

## Assurance and UX

- Assurance: `G2 REVERSIBLE_CONFIG`
- 자동 원복 범위: 제품 소유 vhost·access profile·제품이 추가한 UFW rule
- 제외 효과: DNS·certificate·cloud firewall·user-owned Nginx/UFW/SSH resource
- UI는 공개 설정 진입점부터 이 범위와 SSH recovery 필요성을 표시합니다.

## Preconditions

- supported Nginx and Certbot layout
- exact FQDN/Host and valid certificate
- protected management vhost name available
- proxy UDS permission verified
- at least one non-root PAM admin verified
- SSH recovery connectivity confirmed
- UFW/cloud firewall current state observed
- no conflicting operation/resource lock

## Plan

- current and target access profile
- domain/certificate identity and expiry
- exact protected Nginx resource
- ports and product-owned firewall delta
- HTTPS health and Host checks
- rollback and session revoke behavior
- rollback scope and excluded external effects
- external cloud firewall action separated from product action

## Apply and verify

1. snapshot product-owned vhost/access configuration
2. stage protected vhost and run Nginx syntax check
3. reload and probe HTTPS through expected Host
4. verify agentd internal TCP is not public and proxy uses UDS
5. if UFW is active, add only planned 443 rule last
6. read back TLS, headers, login form and SSH fallback
7. commit profile; otherwise restore only product-owned changes

## Disable

Public disable removes the product vhost/rule, revokes all public sessions and retains loopback SSH recovery. It never disables Nginx, UFW, Certbot, SSH or user-owned rules globally.

## Failure and acceptance

- invalid/mismatched/expired certificate
- Host/Origin/proxy-header spoof rejection
- Nginx config/reload/health failure and rollback
- UFW active/inactive and existing rule preservation
- cloud firewall unresolved is explicit external blocker
- process kill/disk full at each durable stage
- management vhost excluded from Nginx site toggle
- public disable during Nginx/TLS degradation through SSH fallback
