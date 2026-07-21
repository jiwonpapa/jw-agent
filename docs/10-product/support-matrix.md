# Supported Matrix

Status: Accepted  
Authority: Product  
Owner: Support Maintainer  
Last reviewed: 2026-07-21

| Surface | MVP support | Mode |
|---|---|---|
| OS | Ubuntu 24.04 LTS amd64 | Supported |
| init | systemd | Observe |
| package source | Ubuntu apt packages | Discover |
| Nginx | Ubuntu standard layout | Observe + site-state and active managed-config G2 `VM_PASS` |
| PHP-FPM | apt-installed units | Observe |
| MySQL/MariaDB | apt-installed units | Observe |
| Redis | apt-installed unit | Observe |
| Certificate/Certbot | Ubuntu apt Certbot + Nginx webroot | lineage/timer observe + renewal dry-run `G1 VM_PASS`; guided issue failure-safe `VM_PASS`; public success/attach pending |
| UFW | installed status | Observe |
| Linux identity | Ubuntu local `pam_unix` account | Supported |
| Product role | explicit `jw-agent-*` Linux groups | Supported |
| Public browser | Nginx+Certbot HTTPS 443 → agentd UDS | Opt-in supported |
| Recovery browser | loopback through SSH tunnel | Required fallback |
| Responsive web | 320px mobile through desktop | Supported |
| Web terminal | existing OpenSSH, non-root Linux user | P2 G1 after gate |
| SFTP | existing OpenSSH subsystem, non-root Linux user | P2 G0/G1 after gate |
| Managed config | adapter allowlisted resource | Nginx active profile `VM_PASS`; others after gate |
| Direct agentd Internet bind | any TCP port | Unsupported |

## 판정 원칙

- 실제 package·unit·path를 discovery하고 capability로 반환합니다.
- 버전 문자열만 보고 설정 layout을 추측하지 않습니다.
- custom source build, containerized service, non-standard path는 write `UNSUPPORTED`입니다.
- LDAP·SSSD·Kerberos·multi-prompt PAM은 별도 VM 증거 전 `UNVERIFIED`입니다.
- P2C one-shot runner, SAN·만료·fingerprint·timer 조회, `certbot.certificate.renew_test/v1`, DNS·listener·webroot preflight와 두 번의 명시 동의를 요구하는 guided issue의 CA 실패 경로를 VM에서 검증했습니다. 공인 CA 성공과 Nginx attach는 별도 gate 전까지 `UNVERIFIED`입니다.
- `nginx.site_state.set/v1`과 활성 standard-layout 리소스의 `service.config_file.set/v1`은 `SUPPORTED + VM_PASS + G2`입니다.
- 비활성 site, 24 KiB 초과, UTF-8이 아닌 파일, NUL·보호 marker, 비표준 owner/mode·symlink·hardlink는 설정 편집 `UNSUPPORTED`입니다.
- terminal·SFTP는 OpenSSH 발견, non-root account, same-origin WSS와 session policy가 모두 충족될 때만 capability를 반환합니다.
- 관찰 실패, 미설치, 지원 불가, 권한 부족을 서로 다른 상태로 표시합니다.
- 지원표는 구현 단계에서 capability registry로 이전하고 문서를 생성합니다.

## 보류

- arm64
- Ubuntu point release별 차이
- Nginx PPA·custom module
- MySQL과 MariaDB의 write operation
- WebAuthn/passkey step-up; P2 first provider는 `totp/v1`

보류 항목은 VM 증거와 별도 승인 없이 지원한다고 표시하지 않습니다.
