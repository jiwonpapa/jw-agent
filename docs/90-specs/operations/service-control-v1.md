# OPS-SERVICE-CONTROL-V1

Status: Accepted  
Authority: Operation Specification  
Owner: Service Maintainer  
Last reviewed: 2026-07-23

## 목적과 경계

Ubuntu 24.04 service catalog가 `managed_control`로 선언한 unit만 시작·중지·reload·재시작합니다.
사용자 unit/path/argv를 받는 범용 systemd API가 아닙니다.

- Operation ID: `service.lifecycle.set/v1`
- action: `start | stop | reload | restart`
- 최초 allowlist: `nginx.service`, `php8.3-fpm.service`
- Apache·MySQL·MariaDB·Redis는 상태 관찰만 하며 각 adapter와 장애 증거가 승인되기 전에는 제어하지 않습니다.
- JW Agent unit, OpenSSH, UFW, protected management ingress와 system unit은 차단합니다.
- catalog가 unit별 허용 action, timeout, verifier와 위험 등급의 권위 원본입니다.

## 실행

1. 현재 unit state와 catalog capability를 재확인합니다.
2. 계획에 downtime 가능성, 현재·목표 state와 verifier를 표시합니다.
3. 관리 모드에서 승인한 뒤 fixed systemctl command class를 실행합니다.
4. `systemctl is-active`와 adapter health를 read-back합니다.
5. start/reload/restart 실패 시 가능한 경우 이전 active state를 복구하고 검증합니다.
6. stop 성공은 의도된 downtime으로 기록하며 자동 재시작하지 않습니다.

## Acceptance

- allowlisted unit의 start·stop·reload·restart와 no-op
- unknown/system/JW Agent/OpenSSH/UFW unit 거부
- stale state, timeout, command failure와 recovery receipt
- UI는 지원 action만 표시하고 stop은 downtime 확인을 요구
- VM에서 Nginx reload, PHP-FPM restart·stop·start와 관리 접속 지속성을 검증

## Evidence

`jw-agent_0.2.0~p2.18_amd64.deb`의 `VM-P2-SERVICE-CONTROL`이 Ubuntu 24.04 VM에서
Nginx reload, PHP-FPM restart·stop·start, receipt와 관리 HTTPS 지속성을 검증했습니다.
