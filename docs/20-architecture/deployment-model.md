# Deployment Model

Status: Accepted  
Authority: Architecture  
Owner: Release Maintainer  
Last reviewed: 2026-07-21

## 단일 서버

- 하나의 `.deb`가 `agentd`, `authd`, `opsd`, embedded web assets, systemd units를 설치합니다.
- agentd는 전용 일반 계정으로 실행하고 공개 proxy UDS와 loopback 복구 endpoint를 분리합니다.
- authd는 root systemd socket activation으로 요청당 실행하며 PAM 호출 후 종료합니다.
- opsd는 root로 실행하고 외부 socket을 만들지 않습니다.
- 기본 설치는 loopback만 활성화하고 사용자가 public profile을 명시적으로 활성화합니다.
- public profile은 valid TLS의 Nginx+Certbot 443에서 agentd 전용 UDS로 proxy합니다.
- 사용자는 공개 HTTPS 또는 OpenSSH local port forwarding 복구 경로로 접속합니다.
- 제거해도 Nginx·OpenSSH·사용자 데이터가 제품에 종속되지 않습니다.

## 파일 소유

- `/usr/bin`: immutable binaries
- `/usr/share/jw-agent`: web assets and product metadata
- `/etc/jw-agent`: access profile·Host allowlist·role mapping, secret permission 분리
- `/etc/pam.d/jw-agent`: dedicated PAM service
- `/var/lib/jw-agent/agentd`: agentd state
- `/var/lib/jw-agent/opsd`: P2 operation 진입 후에만 생성할 root ledger and snapshots
- `/run/jw-agent`: runtime socket and locks

정확한 package path는 packaging spec에서 확정하며 코드에 분산하지 않습니다.

## Public profile

- FQDN과 유효한 certificate가 필수입니다.
- agentd TCP port를 인터넷에 열지 않습니다.
- inbound forwarded header를 Nginx가 제거하고 직접 생성합니다.
- 관리 vhost는 `system-owned/protected`이며 일반 site toggle 대상에서 제외합니다.
- UFW가 inactive면 임의 활성화하지 않고, active일 때도 SSH rule을 변경하지 않습니다.
- proxy·certificate·Host 검증 후 마지막 단계에서 제품이 소유한 443 rule만 적용합니다.
- disable 시 public session을 모두 폐기하고 SSH tunnel 복구를 유지합니다.

## 중앙관제 이후

24/7 관제는 별도 VPS 또는 사용자가 관리하는 항상 켜진 host에 배포합니다. 도메인과 TLS는 중앙관제 단계의 비용·운영 선택이며 로컬 MVP 사용에 필수가 아닙니다.
