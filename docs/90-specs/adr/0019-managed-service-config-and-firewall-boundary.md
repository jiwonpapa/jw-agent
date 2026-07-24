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
- Ubuntu 24.04 표준 package layout의 아래 service-owned root를 bounded tree로 관찰합니다.
  - `/etc/nginx`
  - `/etc/apache2`
  - `/etc/php/8.3/fpm`
- 해당 root 안의 기존 regular UTF-8 text config는 active·inactive 여부와 관계없이 파일 트리에
  표시하고, 쓰기 가능 여부와 차단 사유를 파일별로 반환합니다.
- 탐색은 depth·entry·byte 상한을 갖습니다. directory·file 생성, 삭제, 이동, rename,
  permission·owner 변경은 제공하지 않습니다.
- API는 path가 아닌 adapter registry가 발급한 opaque resource ID만 받습니다.
- 사용자가 입력한 path를 `opsd`에 전달하지 않습니다. resource ID는 고정 root와 발견된
  relative path에 결합하며 apply 직전 같은 identity와 metadata를 재검증합니다.
- symlink 자체, root 밖 canonical target, hardlink, 비표준 owner/mode, binary/NUL,
  secret·private-key 후보, unsupported version은 쓰기를 닫습니다.
- 서비스가 실행 중이면 `저장 → 공식 validator → reload → active/read-back`을 수행합니다.
  서비스가 중지 상태이면 `저장 → 공식 validator → read-back`까지만 수행하고 서비스를
  임의로 시작하지 않습니다.
- validation, reload, active 또는 read-back 실패 시 exact file bytes·owner·mode를 원복하고
  이전 설정을 다시 검증합니다.
- Nginx site enable/disable은 설정 파일 편집의 주 작업이 아니며 site context의 보조
  lifecycle action으로만 노출합니다.
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

- 범용 root 파일 CRUD와 service root 밖 임의 `/etc` 탐색
- 사용자가 입력한 path·glob·depth로 탐색 범위를 늘리는 API
- shell, user argv, `sudo` command relay
- raw `iptables`/`nft` rule 편집
- 기존 UFW rule 전체 restore로 다른 관리자의 동시 변경을 덮어쓰기
- browser에서 root terminal로 같은 기능을 우회

## Acceptance

- service root별 bounded recursive discovery와 safe/blocked file 구분
- active·inactive 설정 파일 열기, inactive service의 validate-only save
- traversal·root escape·symlink·hardlink·secret·binary 차단
- Nginx, Apache, PHP-FPM valid save, syntax failure rollback, active service reload/read-back
- desktop에서는 tree와 전체 폭 editor, mobile에서는 list→editor 흐름을 사용하며
  right drawer와 별도 plan wizard를 사용하지 않음
- Apache lifecycle success와 failure recovery
- UFW active/inactive observation, bounded add/delete, protected rule rejection, stale rule
  cancellation, product effect rollback
- Ubuntu 24.04 VM에서 package 설치 상태로 API, browser, command, ledger continuity와
  관리 edge 지속성을 검증
