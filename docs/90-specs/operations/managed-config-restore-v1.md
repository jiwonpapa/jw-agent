# OPS-MANAGED-CONFIG-RESTORE-V1

Status: Accepted  
Authority: Operation Specification  
Owner: Managed Configuration Maintainer  
Last reviewed: 2026-07-23

## 목적

현재 관리 리소스를 성공한 과거 operation snapshot의 exact bytes·owner·mode로 되돌리되,
기존 이력을 덮어쓰지 않고 새 계획과 receipt를 남깁니다.

## 계약

- Operation ID: `service.config_file.restore/v1`
- 입력: source operation ID, 현재 resource digest, idempotency key
- source는 같은 actor가 볼 수 있는 `SUCCEEDED` managed-config operation이며 snapshot이 존재해야 합니다.
- 현재 리소스와 source snapshot의 resource ID가 같아야 합니다.
- 계획은 현재↔복원 대상 diff, source 시각·actor, service action, 검증과 원복 범위를 표시합니다.
- 승인과 실행은 `service.config_file.set/v1`의 lock·snapshot·validator·reload·read-back·rollback을 재사용합니다.
- snapshot path·content는 agentd·브라우저·로그로 전달하지 않습니다.

## 실패

`source_missing`, `source_not_restorable`, `snapshot_missing`, `resource_mismatch`,
`stale_resource`, `plan_expired`, `approval_invalid`, `rollback_failed`, `forensic_lockdown`.

## Acceptance

- 성공 이력에서 복원 계획과 제한된 diff를 조회합니다.
- 현재 파일 외부 변경은 side effect 전에 차단됩니다.
- 복원 성공은 새 operation receipt를 만들고 이전 receipt는 불변입니다.
- 복원 검증 실패는 복원 직전 현재 파일로 자동 원복합니다.
- source content와 snapshot path는 REST·로그·브라우저 저장소에 없습니다.
- Ubuntu VM의 PHP-FPM 관리 리소스에서 변경 성공 receipt를 source로 복원하고 exact bytes·reload·active를 검증합니다.

## Evidence

`jw-agent_0.2.0~p2.18_amd64.deb`의 `VM-P2-MANAGED-CONFIG`이 PHP-FPM 변경 성공
receipt의 snapshot을 source로 삼아 exact bytes 복원, 문법 검사, reload와 active read-back을 검증했습니다.
