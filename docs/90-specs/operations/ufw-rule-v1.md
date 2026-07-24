# OPS-UFW-RULE-V1

Status: Accepted  
Authority: Operation Specification  
Owner: Firewall Adapter Maintainer  
Last reviewed: 2026-07-24

Architecture: [ADR-0019](../adr/0019-managed-service-config-and-firewall-boundary.md)

## 목적과 경계

Ubuntu 24.04 UFW 상태와 규칙을 읽고, 기존 사용자 규칙을 건드리지 않는 JW Agent 소유
인바운드 규칙을 추가·삭제합니다.

- Observation: `GET /api/v1/firewall/ufw`
- Operation: `ufw.rule.set/v1`
- 지원 상태: active UFW만 mutation 가능; inactive는 관찰만
- 지원 action: `allow | deny | delete`
- protocol: `tcp | udp`
- port: `1..65535`
- source: 생략 또는 canonical IPv4/IPv6 CIDR
- rule identity: UFW comment의 opaque `jw-agent:<rule-id>`
- assurance: product-owned rule effect에 한정한 G2

## 보호 정책

- 22/tcp, 443/tcp, 9443/tcp에 대한 deny와 delete를 거부합니다.
- 기존 사용자 규칙, comment가 없거나 JW Agent namespace가 아닌 규칙은 삭제하지 않습니다.
- UFW enable, disable, reset, default policy, route rule, outgoing rule, application profile,
  raw nftables/iptables는 지원하지 않습니다.
- rule number는 관찰 결과에서 서버가 결정하며 client 입력으로 받지 않습니다.
- shell과 사용자 argv를 사용하지 않습니다.

## Plan and execution

1. root helper가 fixed `/usr/sbin/ufw status numbered`를 실행하고 상태와 canonical digest를 만듭니다.
2. plan은 현재 status digest, exact typed rule, self-lockout 보호, 영향과 원복 범위를 고정합니다.
   관리 모드가 활성이고 입력 화면에 동작·protocol·port·source·보호 포트가 이미 표시된 경우
   UI는 한 번의 `규칙 추가`로 plan과 approval을 연속 수행할 수 있습니다. 서버는 두 요청과
   plan hash 검증을 생략하지 않습니다.
3. apply 직전 status digest와 rule identity를 다시 확인합니다.
4. product rule set을 durable snapshot에 기록합니다.
5. fixed UFW command builder가 검증된 enum·port·CIDR만 argv로 변환합니다.
6. add 또는 delete 후 status를 다시 읽어 exact effect를 확인합니다.
7. 실패하면 이번 operation의 product-owned effect만 inverse operation으로 되돌리고 status를
   재검증합니다.
8. rollback도 확인되지 않으면 `RECOVERY_REQUIRED`로 종료합니다.

## Typed errors

`ufw_not_installed`, `ufw_inactive`, `invalid_protocol`, `invalid_port`, `invalid_source`,
`protected_management_rule`, `rule_not_owned`, `rule_missing`, `precondition_changed`,
`rule_apply_failed`, `rule_verify_failed`, `rule_rollback_failed`, `forensic_lockdown`.

## Acceptance

- active/inactive, IPv4/IPv6, numbered rule과 comment를 bounded parser로 관찰
- allow·deny product rule add와 exact read-back
- product rule delete와 user-owned/protected rule rejection
- stale numbered rule와 changed status digest를 side effect 전에 차단
- command timeout, output cap, environment clear, stdout/stderr digest evidence
- apply/verify failure의 inverse rollback과 `RECOVERY_REQUIRED`
- UI에서 상태, 허용/차단 규칙, 추가 form, 제품 소유 삭제만 간결하게 노출
- Ubuntu 24.04 VM에서 SSH와 `jw-edge` 접근을 유지하며 allow·delete success,
  protected deny, stale-plan negative와 원래 UFW fixture의 exact restore 검증

## Evidence

`jw-agent_0.2.0~p2.20_amd64.deb`의 `VM-P2-UFW-RULE`이 Ubuntu 24.04 VM에서
product-owned allow·delete, 22/tcp deny 거부, 외부 drift 뒤 apply 전 취소,
SSH·9443 관리 접속 연속성과 원래 inactive UFW 상태 복원을 검증했습니다.
apply/verify failure inverse rollback과 `RECOVERY_REQUIRED`는 Rust fault test 증거이며
실제 VM fault injection으로 과장하지 않습니다.
