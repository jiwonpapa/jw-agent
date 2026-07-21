# Packaging and Release Plan

Status: Draft  
Authority: Delivery  
Owner: Release Maintainer  
Last reviewed: 2026-07-21

## Package contents

- `jw-agentd`, `jw-authd`, `jw-opsd`
- embedded/static web assets
- systemd units/socket, tmpfiles/sysusers rules
- dedicated PAM service and product role groups
- protected Nginx public ingress template
- default configuration with no secret
- license, support matrix, verification instructions

## Maintainer script rules

- no network access
- no hidden package upgrade
- no edit of managed service config outside product paths
- dedicated user/group creation is idempotent
- permissions and UDS paths fail closed
- uninstall does not remove user service data without explicit purge
- operation in progress blocks unsafe upgrade or enters documented recovery
- install default is loopback; no automatic DNS/certificate/UFW/cloud firewall mutation
- authd socket and PAM file owner/mode fail closed
- removal of package does not alter Linux user password or unrelated PAM service

## Release command target

```text
cargo xtask verify release --version X.Y.Z
```

P3 전에는 이 command를 구현하거나 성공했다고 표시하지 않습니다.

## Required evidence

- toolchain, lockfile, source commit and clean status
- full and VM gate results
- artifact and SBOM hashes
- package signature
- fresh install and first login
- restart and crash recovery
- upgrade from supported previous version
- downgrade policy result
- remove/purge behavior
- offline verification steps
- PAM native dependency and auth VM proof
- public HTTPS enable/disable and SSH fallback proof
- mobile/tablet/desktop browser evidence

## Remote automation

GitHub Actions workflow는 없습니다. 공개 release artifact 업로드는 검증·서명 이후 별도 명시적 작업으로 수행합니다.
