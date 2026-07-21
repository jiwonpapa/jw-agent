# Specification Index

Status: Accepted  
Authority: Specification Index  
Owner: Maintainers  
Last reviewed: 2026-07-21

## Operation specs

- [OPS-NGINX-SITE-STATE-V1](operations/nginx-site-state-set-v1.md) — Accepted, implementation requires P2 entry approval
- [OPS-PUBLIC-ACCESS-PROFILE-V1](operations/public-access-profile-v1.md) — Accepted

## Authentication specs

- [AUTH-PAM-LOGIN-V1](auth/pam-login-v1.md) — Accepted
- [AUTH-TOTP-STEP-UP-V1](auth/totp-step-up-v1.md) — Accepted, implementation requires P2 entry approval

## UI specs

- [UI-OVERVIEW-V1](ui/overview-v1.md) — Accepted
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

## Spec template requirements

모든 operation spec은 목적, 비목표, support, ID/version, typed input/output/error, privilege, assurance, plan, precondition, lock, snapshot, apply, read-back, verify, rollback, crash recovery, timeout, redaction, evidence, acceptance scenario를 포함합니다.

모든 UI spec은 user job, route, data contract, loading/fresh/stale/empty/unsupported/error, permission/capability, interaction, responsive, accessibility, telemetry policy, Playwright evidence를 포함합니다.

모든 auth spec은 credential lifetime, trusted channel, canonical identity, account check, authorization mapping, public error equivalence, rate/timeout, session issuance, secret erasure, abuse and VM scenarios를 포함합니다.
