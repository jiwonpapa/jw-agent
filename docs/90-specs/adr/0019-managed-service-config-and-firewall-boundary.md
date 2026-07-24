# ADR-0019 — Managed Service Configuration and Firewall Boundary

Status: Accepted  
Authority: Architecture Decision  
Owner: Architecture Maintainer  
Last reviewed: 2026-07-24

## Context

Nginx active site와 PHP 8.3 FPM 단일 파일만으로는 Ubuntu 웹 서버 유지보수의 실제
설정 위치를 충분히 다룰 수 없습니다. 반대로 범용 `/etc` 편집기나 사용자가 만든 root
argv는 agentd 침해를 root 명령 실행으로 확대합니다. UFW도 기존 규칙 전체를 수정하거나
전역 enable/disable을 제공하면 원격 접속 단절 위험이 큽니다.

## Decision

- 기존 `service.config_file.set/v1` safety kernel을 재사용하고 새 설정 엔진을 만들지 않습니다.
- Ubuntu 24.04 표준 package layout의 아래 root만 `opsd`에 추가합니다.
  - `/etc/nginx`: `nginx.conf`, active `conf.d/*.conf`, 기존 active site
  - `/etc/apache2`: `apache2.conf`, `ports.conf`, active `conf-enabled/*.conf`,
    active `sites-enabled/*.conf`가 정확히 가리키는 available file
  - `/etc/php/8.3/fpm`: `php.ini`, `php-fpm.conf`, root-owned `pool.d/*.conf`
- API는 path가 아닌 adapter registry가 발급한 opaque resource ID만 받습니다.
- symlink, hardlink, 비표준 owner/mode, 비활성 include, unsupported version은 쓰기를 닫습니다.
- 모든 설정 변경은 해당 서비스의 공식 validator, reload, active read-back과 exact file
  rollback을 거칩니다.
- Apache service lifecycle은 `apache2.service`의 start, stop, restart, reload만 등록합니다.
- UFW는 별도 typed operation으로 관찰하며, 활성 UFW에 JW Agent comment가 붙은 제한 규칙만
  추가하거나 삭제합니다.
- UFW request는 action, protocol, port, source CIDR만 받고 executable, argv, rule number,
  file path를 받지 않습니다.
- SSH 22, 독립 관리 edge 9443, HTTPS 443에 대한 deny와 삭제, 기존 사용자 규칙 삭제,
  UFW enable/disable/default policy 변경은 금지합니다.
- UFW 적용 전 product rule set을 snapshot하고 status digest를 재검사합니다. apply 또는
  read-back 실패 시 product-owned effect만 되돌리고 status를 재검증합니다.
- `opsd`는 host UFW를 제어하기 위해 host network namespace, `AF_NETLINK`,
  `CAP_NET_ADMIN`, `/etc/ufw` 제한 쓰기를 가집니다. `IPAddressDeny=any`, 사용자 argv 금지,
  외부 listener 부재는 유지하며 UFW 외 네트워크 API를 추가하지 않습니다.

## Build and dependency impact

- 새 crate, native dependency, code generation, Cargo feature를 추가하지 않습니다.
- 기존 Rust contract, opsd runner, ledger, agentd REST/OpenAPI, React route만 확장합니다.
- 검증 로직은 기존 `xtask` GateId와 lane에서만 소유합니다.

## Rejected

- 범용 root 파일 CRUD와 임의 `/etc` 탐색
- shell, user argv, `sudo` command relay
- raw `iptables`/`nft` rule 편집
- 기존 UFW rule 전체 restore로 다른 관리자의 동시 변경을 덮어쓰기
- browser에서 root terminal로 같은 기능을 우회

## Acceptance

- adapter별 exact resource discovery와 inactive/symlink/hardlink 차단
- Nginx, Apache, PHP-FPM valid save, syntax failure rollback, reload/active read-back
- Apache lifecycle success와 failure recovery
- UFW active/inactive observation, bounded add/delete, protected rule rejection, stale rule
  cancellation, product effect rollback
- Ubuntu 24.04 VM에서 package 설치 상태로 API, browser, command, ledger continuity와
  관리 edge 지속성을 검증
