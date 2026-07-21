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
| Nginx | Ubuntu standard layout | Observe + one write operation |
| PHP-FPM | apt-installed units | Observe |
| MySQL/MariaDB | apt-installed units | Observe |
| Redis | apt-installed unit | Observe |
| Certificate/Certbot | existing valid certificate path | P1 connect/verify only; issuance unsupported |
| UFW | installed status | Observe |
| Linux identity | Ubuntu local `pam_unix` account | Supported |
| Product role | explicit `jw-agent-*` Linux groups | Supported |
| Public browser | Nginx+Certbot HTTPS 443 → agentd UDS | Opt-in supported |
| Recovery browser | loopback through SSH tunnel | Required fallback |
| Responsive web | 320px mobile through desktop | Supported |
| Direct agentd Internet bind | any TCP port | Unsupported |

## 판정 원칙

- 실제 package·unit·path를 discovery하고 capability로 반환합니다.
- 버전 문자열만 보고 설정 layout을 추측하지 않습니다.
- custom source build, containerized service, non-standard path는 write `UNSUPPORTED`입니다.
- LDAP·SSSD·Kerberos·multi-prompt PAM은 별도 VM 증거 전 `UNVERIFIED`입니다.
- P1은 Certbot command를 호출하지 않습니다. guided issuance·renewal operation은 별도 승격 전 `UNSUPPORTED`입니다.
- 관찰 실패, 미설치, 지원 불가, 권한 부족을 서로 다른 상태로 표시합니다.
- 지원표는 구현 단계에서 capability registry로 이전하고 문서를 생성합니다.

## 보류

- arm64
- Ubuntu point release별 차이
- Nginx PPA·custom module
- MySQL과 MariaDB의 write operation
- WebAuthn/passkey step-up; P2 first provider는 `totp/v1`

보류 항목은 VM 증거와 별도 승인 없이 지원한다고 표시하지 않습니다.
