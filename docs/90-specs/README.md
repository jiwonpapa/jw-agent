# Specification Index

Status: Accepted  
Authority: Specification Index  
Owner: Maintainers  
Last reviewed: 2026-07-22

## Operation specs

- [OPS-NGINX-SITE-STATE-V1](operations/nginx-site-state-set-v1.md) — Accepted, P2 active implementation
- [OPS-PUBLIC-ACCESS-PROFILE-V1](operations/public-access-profile-v1.md) — Accepted
- [OPS-MANAGED-CONFIG-FILE-V1](operations/managed-config-file-v1.md) — Accepted, Nginx active-resource implementation `VM_PASS`
- [OPS-PHP-FPM-CONFIG-V1](operations/php-fpm-config-v1.md) — Accepted, strict multi-resource profile pending current VM gate
- [OPS-MANAGED-CONFIG-RESTORE-V1](operations/managed-config-restore-v1.md) — Accepted
- [OPS-SERVICE-CONTROL-V1](operations/service-control-v1.md) — Accepted
- [OPS-UFW-RULE-V1](operations/ufw-rule-v1.md) — Accepted, typed product-owned rule 구현·VM gate 대기
- [OPS-CERTBOT-CERTIFICATE-V1](operations/certbot-certificate-v1.md) — Accepted, runner/inventory/renew-test, private-LAN issuance failure and protected-vhost attach rollback `VM_PASS`; public-CA success pending

## Access specs

- [ACCESS-OPENSSH-TERMINAL-SFTP-V1](access/openssh-terminal-sftp-v1.md) — Accepted, terminal G1 and SFTP read G0/write G1 `VM_PASS`
- [ACCESS-OPENSSH-PASSWORD-BROKER-V1](access/openssh-password-broker-v1.md) — Accepted, memory-only one-shot credential boundary
- [ACCESS-OPENSSH-SFTP-READONLY-V1](access/openssh-sftp-readonly-v1.md) — Accepted, home-scoped G0 `VM_PASS`
- [ACCESS-OPENSSH-SFTP-ATOMIC-UPLOAD-V1](access/openssh-sftp-atomic-upload-v1.md) — Accepted, bounded G1 `VM_PASS`

## Authentication specs

- [AUTH-PAM-LOGIN-V1](auth/pam-login-v1.md) — Accepted
- [AUTH-TOTP-STEP-UP-V1](auth/totp-step-up-v1.md) — Accepted, p2.18 Ubuntu VM evidence
- [AUTH-ADMINISTRATIVE-ACCESS-V1](auth/administrative-access-v1.md) — Accepted, non-root admin에서 root typed operation 관리 모드

## Observability specs

- [OBS-SERVICE-INVENTORY-V1](observability/service-inventory-v1.md) — Accepted, Ubuntu 24.04 주요 서비스 template 기반 G0 inventory

## UI specs

- [UI-OVERVIEW-V1](ui/overview-v1.md) — Accepted
- [UI-MANAGED-CONFIG-WIZARD-V1](ui/managed-config-wizard-v1.md) — Accepted
- [UI-LOGIN-SESSION-V1](ui/login-session-v1.md) — Accepted
- [UI-RESPONSIVE-SHELL-V1](ui/responsive-shell-v1.md) — Accepted
- [UI-ROLLBACK-ASSURANCE-V1](ui/rollback-assurance-v1.md) — Accepted
- [UI-INTEGRATION-CATALOG-V1](ui/integration-catalog-v1.md) — Accepted

## ADRs

- [ADR-0001 Local-first MVP](adr/0001-local-first-mvp.md) — Superseded
- [ADR-0002 agentd/opsd split](adr/0002-agentd-opsd-split.md) — Accepted
- [ADR-0003 single xtask harness](adr/0003-single-xtask-harness.md) — Accepted
- [ADR-0004 web toolchain](adr/0004-web-toolchain.md) — Accepted
- [ADR-0005 minimal workspace](adr/0005-minimal-workspace.md) — Superseded
- [ADR-0006 clean-room reference lessons](adr/0006-clean-room-reference-lessons.md) — Accepted
- [ADR-0007 public HTTPS and PAM boundary](adr/0007-public-https-pam-boundary.md) — Accepted
- [ADR-0008 P1 storage and contract generation](adr/0008-p1-storage-and-contract-generation.md) — Accepted
- [ADR-0009 P2 safety kernel decisions](adr/0009-p2-safety-kernel-decisions.md) — Accepted
- [ADR-0010 Local maintenance surfaces and P2 entry](adr/0010-local-maintenance-surfaces.md) — Accepted
- [ADR-0011 One-shot Certbot network runner](adr/0011-certbot-network-runner.md) — Accepted
- [ADR-0012 One-shot loopback TLS verifier](adr/0012-loopback-tls-verifier.md) — Accepted
- [ADR-0013 System OpenSSH client](adr/0013-system-openssh-client.md) — Accepted
- [ADR-0014 CodeMirror managed config editor](adr/0014-codemirror-config-editor.md) — Accepted
- [ADR-0015 PHP-FPM managed config envelope](adr/0015-php-fpm-managed-config-envelope.md) — Accepted
- [ADR-0016 TOTP crypto and enrollment boundary](adr/0016-totp-crypto-and-enrollment-boundary.md) — Accepted
- [ADR-0017 Risk-tiered operation approval](adr/0017-risk-tiered-operation-approval.md) — Accepted
- [ADR-0018 Independent Rust management edge](adr/0018-independent-rust-management-edge.md) — Accepted
- [ADR-0019 Managed service config and firewall boundary](adr/0019-managed-service-config-and-firewall-boundary.md) — Accepted

## Spec template requirements

모든 operation spec은 목적, 비목표, support, ID/version, typed input/output/error, privilege, assurance, plan, precondition, lock, snapshot, apply, read-back, verify, rollback, crash recovery, timeout, redaction, evidence, acceptance scenario를 포함합니다.

모든 UI spec은 user job, route, data contract, loading/fresh/stale/empty/unsupported/error, permission/capability, interaction, responsive, accessibility, telemetry policy, Playwright evidence를 포함합니다.

모든 auth spec은 credential lifetime, trusted channel, canonical identity, account check, authorization mapping, public error equivalence, rate/timeout, session issuance, secret erasure, abuse and VM scenarios를 포함합니다.
