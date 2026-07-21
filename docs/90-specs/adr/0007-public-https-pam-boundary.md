# ADR-0007 — Public HTTPS and PAM Boundary

Status: Accepted  
Authority: Architecture Decision  
Owner: Security Maintainer  
Last reviewed: 2026-07-21

## Context

단일 서버 UI는 공개 접속, Linux PAM ID·비밀번호, mobile·tablet web을 지원해야 합니다. 이는 ADR-0001의 loopback-only 접근과 ADR-0005의 3-crate 구성을 대체합니다.

## Decision

```text
Internet → Nginx+Certbot 443 → dedicated UDS → agentd non-root
SSH tunnel → loopback recovery ─────────────→ agentd
agentd → one-request UDS → authd root → ffi-pam → Linux PAM/NSS
agentd → typed UDS ───────→ opsd root → Ubuntu services
```

- agentd direct public bind와 HTTP login은 금지합니다.
- authd는 systemd socket activation one-shot이며 PAM auth/account/role만 수행합니다.
- password는 opsd로 보내지 않습니다.
- public management Nginx resource는 protected입니다.
- 반응형 web은 MVP이고 native/PWA는 제외합니다.

## Workspace consequence

허용 crate는 `jw-contracts`, `jw-agentd`, `jw-authd`, `ffi-pam`, `jw-opsd`, tool `xtask`입니다. 추가 두 crate는 각각 별도 root process와 unsafe FFI라는 헌법상 분리 사유가 있습니다.

`ffi-pam`만 unsafe/libpam을 허용하고 `jw-authd`는 network·DB·operation dependency가 없습니다. Native `libpam` dependency는 Ubuntu clean build와 VM auth evidence가 필요합니다.

## Public mode consequence

- install default는 loopback recovery
- public profile은 explicit plan으로 활성화
- valid FQDN/certificate, Host allowlist, PAM admin, SSH fallback 필수
- UFW/DNS/cloud firewall을 package script가 몰래 변경하지 않음
- Nginx·TLS failure 후 public disable과 session revoke 가능

## Rejected alternatives

- agentd가 PAM을 직접 호출: 임의 local account 검증 권한과 FFI가 network daemon에 섞임
- opsd가 PAM 처리: password와 service operation root 경계가 결합됨
- application이 `unix_chkpwd` 직접 호출: PAM 내부 interface이며 current-user helper
- agentd direct rustls/ACME: certificate·key·renewal·public socket 책임이 Rust daemon에 추가됨
- JWT/localStorage: revoke와 browser secret exposure가 불리함

## Sources

- [Ubuntu 24.04 unix_chkpwd](https://manpages.ubuntu.com/manpages/noble/man8/unix_chkpwd.8.html)
- [Linux-PAM pam_authenticate](https://man7.org/linux/man-pages/man3/pam_authenticate.3.html)
- [Linux-PAM pam_acct_mgmt](https://www.man7.org/linux/man-pages/man3/pam_acct_mgmt.3.html)
- [NGINX proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
