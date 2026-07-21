# ADR-0011 — One-shot Certbot Network Runner

Status: Accepted  
Authority: Architecture Decision  
Owner: Certificate Lifecycle Maintainer  
Last reviewed: 2026-07-21

## Context

`opsd`는 root 설정 변경을 소유하지만 systemd `IPAddressDeny=any`로 외부 네트워크를 사용할 수 없습니다. Certbot은 ACME CA와 통신해야 합니다. `opsd`의 네트워크 차단을 해제하면 장기 실행 root daemon 전체가 외부 연결 능력을 얻게 되어 기존 신뢰 경계를 약화합니다.

## Decision

- `jw-certd`는 socket-activated one-shot root worker로 추가합니다.
- root:root `0600` Unix socket에서 peer UID 0인 `opsd` 요청만 받습니다.
- 입력은 canonical FQDN·account email·staging/production·ToS 동의 또는 renewal dry-run뿐입니다.
- executable, webroot, Certbot directories, plugin, CA environment mapping, timeout과 output cap은 binary가 고정합니다.
- account email은 root-only temporary config로 전달하고 argv·response·journal에 넣지 않습니다.
- stdout·stderr 원문은 반환하거나 기록하지 않고 전체 digest·truncation·exit/timeout만 반환합니다.
- worker는 요청 하나를 처리한 뒤 종료하며 DB·HTTP·브라우저 session·Nginx 변경 권한을 갖지 않습니다.
- `opsd`가 ledger, plan, lock, certificate read-back, local Nginx snapshot·attach·rollback과 receipt를 계속 소유합니다.
- `agentd`는 `jw-certd` socket에 접근할 수 없습니다.

`jw-certd`는 별도 process·network privilege·package artifact를 가지므로 workspace crate 생성 기준을 충족합니다. 새 native library, code generation, async runtime은 추가하지 않습니다.

## Systemd boundary

- `jw-certd@.service`만 `AF_INET/AF_INET6`를 허용합니다.
- writable path는 `/etc/letsencrypt`, `/var/lib/letsencrypt`, `/var/log/letsencrypt`, 고정 webroot와 전용 runtime directory로 제한합니다.
- shell, caller argv, caller path, DNS plugin, deploy hook, certificate key export API는 제공하지 않습니다.
- `opsd`의 `IPAddressDeny=any`와 root networkless 정책은 유지합니다.

## Rejected alternatives

- `opsd` 네트워크 차단 해제: 장기 실행 root attack surface가 커집니다.
- `agentd`가 Certbot 직접 실행: unprivileged public parser가 certificate store mutation을 소유하게 됩니다.
- `systemd-run` 범용 호출: 침해된 `opsd`가 arbitrary transient root unit을 만들 수 있습니다.
- 브라우저/새 ACME client 구현: key와 protocol 책임 및 dependency graph가 커집니다.

## Acceptance

- non-root peer, oversized/expired/unknown request를 명령 실행 전에 거부
- fixed command construction과 email argv 비노출 unit proof
- timeout 시 process group 종료, bounded digest-only response
- package socket permission과 `opsd` network denial을 VM에서 함께 검증
- challenge·rate-limit·certificate read-back·attach rollback은 operation spec의 VM lane에서 별도 검증
