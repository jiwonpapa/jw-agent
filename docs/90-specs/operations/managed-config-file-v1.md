# OPS-MANAGED-CONFIG-FILE-V1

Status: Accepted  
Authority: Operation Specification  
Owner: Managed Configuration Maintainer  
Last reviewed: 2026-07-21

## 목적

Ubuntu 24.04 표준 layout의 service-owned config root를 파일 트리로 관찰하고, 기존 텍스트
설정 resource 하나를 편집합니다. 저장 후 공식 validator와 필요한 service reload를
수행하며 실패 시 직전 파일을 복원합니다.

## 비목표

- 사용자가 전달한 절대·상대 path의 root 파일 편집
- service root 밖 directory 탐색
- directory·file 생성·삭제·이동·rename, permission·owner 변경
- binary file, secret·private-key 후보
- include graph 전체나 runtime state의 완전 복원
- database data·package·firewall·SSH daemon 설정 변경
- SFTP를 통한 system-owned/protected 설정 우회

## Identity and support

- Operation ID: `service.config_file.set/v1`
- Schema version: `1`
- Target: discovery가 반환한 `resourceId`
- Assurance target: `G2 REVERSIBLE_CONFIG`
- 지원 adapter와 root:
  - `nginx/ubuntu-24.04-tree-v1`: `/etc/nginx`
  - `apache/ubuntu-24.04-tree-v1`: `/etc/apache2`
  - `php-fpm/ubuntu-24.04-8.3-tree-v1`: `/etc/php/8.3/fpm`
- 기존 active-resource adapter ID는 저장된 receipt와 restore 호환을 위해 유지하지만 신규
  inventory는 tree adapter를 사용합니다.
- tree discovery는 최대 depth `5`, 서비스별 최대 `256` entry, regular file 최대
  `128 KiB`로 제한합니다.
- 목록 응답은 path·상태·차단 사유만 반환하고 복구 보장 세부정보를 파일마다 반복하지
  않습니다. 전체 보장 계약은 선택한 resource detail과 저장 결과에서 제공합니다.
- extension은 `.conf`, `.load`, `.ini`, 확장자 없는 표준 config file을 허용합니다.
  certificate·private key·credential·password·secret·token 후보 이름과 PEM private-key
  marker는 보호 resource로 차단합니다.
- inline UTF-8 body 최대는 adapter가 소유합니다. service action은 실행 중 service의
  `reload`, 중지 service의 `validate_only`만 허용합니다.
- managed-config plan JSON request와 ops IPC envelope: `256 KiB`; 다른 API body는 `64 KiB`를 유지하며 NUL과 layout whitespace 외 ASCII control을 거부합니다.
- Redis는 adapter별 fixture와 VM evidence 전 `UNSUPPORTED`입니다.

resource registry는 logical ID, supported package/layout, root-owned canonical path, 최대 byte, encoding, syntax command class, service action, health verifier, protected 여부를 소유합니다. API는 canonical root path를 identity로 받지 않습니다.

## Typed request

Plan request:

- exact `schemaVersion`, `operationType`, `resourceId`
- `expectedContentDigest`, `expectedMetadataDigest`
- UTF-8 `proposedContent` 또는 별도 single-use body reference
- `serviceAction`: `reload | validate_only`; inventory가 반환한 허용값과 일치해야 함
- `idempotencyKey`: 16–64 ASCII

Approval request:

- exact `planId`, `planHash`, `idempotencyKey`
- single-use `reauthToken`
- 정책이 요구할 때 `additionalAuthClaim`
- UI가 validation 성공과 service action을 별도로 확인한 `approvalIntent`

unknown field, path, command, environment, mode, owner는 거부합니다. 파일 body는 감사 event·URL·argv에 기록하지 않습니다.

## Plan

plan은 resource display name, masked path, unified diff summary, current/proposed digest, byte/line delta, syntax verifier, reload/restart 영향, snapshot scope, health read-back, rollback 범위와 excluded effects를 반환합니다. 최대 10분 뒤 만료하며 apply 직전 모든 precondition을 재검증합니다.

## Preflight and lock

- adapter package·version·layout·unit 발견
- regular file, expected owner/mode, max size, UTF-8, no NUL
- canonical parent와 file descriptor가 allowlisted root 안이며 symlink·hardlink policy 충족
- current content·metadata digest가 plan과 일치
- service root와 relative path를 재결합한 canonical file identity가 plan 때와 동일
- service가 중지 상태이면 `validate_only`, 실행 중이면 `reload`만 허용
- ledger continuity, snapshot 공간, temp file용 동일 filesystem 공간 확인
- lock key `config/{adapterId}/{resourceId}`와 service action global lock

## Execution

1. before bytes·owner·mode·digest를 durable snapshot으로 저장
2. same-directory create-new temp file에 exact bytes를 쓰고 mode·owner 적용, file `fsync`
3. temp file을 대상으로 가능한 adapter syntax validation 수행
4. validation 성공만 ledger에 기록하고 approval intent를 재확인
5. atomic rename, directory `fsync`, content·metadata read-back
6. `reload` plan이면 fixed systemd reload primitive 실행; `validate_only`이면 생략
7. syntax, content/metadata read-back을 검증하고 `reload` plan이면 unit active와 adapter
   health probe까지 검증
8. 모든 조건이 맞을 때만 `SUCCEEDED`

Nginx처럼 temp 단일 파일 검사가 불가능한 include layout은 snapshot 뒤 atomic replace하고 `nginx -t`를 실행하되, failure 시 service action 없이 즉시 파일을 원복하고 이전 config로 `nginx -t`를 재검증합니다.

## Rollback and recovery

- validation, service action, health, read-back 실패는 `ROLLING_BACK`
- snapshot의 exact bytes·owner·mode를 atomic restore하고 file·directory `fsync`
- 이전 syntax check와 같은 service action, health, digest read-back을 수행
- 검증된 복원은 `ROLLED_BACK`, 불명확하거나 실패하면 `RECOVERY_REQUIRED`
- crash restart는 ledger와 OS digest를 비교하고 이미 수행된 effect를 맹목적으로 반복하지 않음
- root-only 제안 원문은 성공·취소·원복·복구필요 terminal과 만료 cleanup에서 제거
- `.jw-agent-<16 hex>.tmp`는 operator resource에서 제외하며 restart 시 owner·hardlink를 검증한 뒤 제거

보장 범위는 대상 파일 bytes·owner·mode와 수행된 validator·read-back입니다. `reload`
plan에서만 실행 중 service 상태까지 포함합니다. active connection, in-memory history,
다른 관리자의 동시 외부 변경, include graph에 실제로 포함되지 않은 inactive file의 runtime
적용은 제외합니다.

## Command and evidence policy

executable, argv, cwd, environment allowlist, timeout, output cap은 adapter registry가 고정합니다. shell은 사용하지 않습니다. receipt는 actor, resource ID, digests, diff 통계, stage, command class·exit·timeout·truncation, health, rollback과 recovery path를 기록하며 content·secret은 기록하지 않습니다.

## Typed errors

`unsupported_environment`, `protected_resource`, `stale_resource`, `invalid_encoding`, `size_limit`, `path_policy`, `resource_busy`, `plan_expired`, `approval_invalid`, `snapshot_failed`, `syntax_failed`, `service_action_failed`, `health_failed`, `rollback_failed`, `forensic_lockdown`.

## Acceptance scenarios

- valid save and verified reload
- inactive service validate-only save without implicit start
- active·inactive existing config tree discovery
- unchanged no-op
- syntax failure with no reload
- reload and health failure with verified rollback
- external edit between plan and approval
- traversal, symlink, hardlink, protected resource, oversized/NUL body rejection
- disk full before snapshot/temp/state transition
- kill at each durable stage and restart reconciliation
- duplicate/idempotency conflict and concurrent resource/service lock
- rollback failure produces `RECOVERY_REQUIRED` and exact runbook
- desktop/tablet/mobile UI는 저장을 primary action으로 제공하고 plan·G2·digest는 기술
  세부정보에만 표시
- selected-resource syntax diagnostic가 안전하게 추출되면 오류 줄을 editor gutter에 표시하고, 위치가 없으면 추측하지 않음

`jw-agent_0.2.0~p2.21_amd64.deb`의 `VM-P2-MANAGED-CONFIG`이 Nginx와 Apache
service-tree, PHP-FPM resource의 valid save, 공식 validator, reload, syntax rollback,
read-back과 서비스 연속성을 검증했습니다. package SHA-256은
`f649e29e9c9560f508b8a9d57ec8b0776ed070ee35adb69986da9f95f4038865`입니다.
registry 밖 root와 차단된 resource는 계속 `UNSUPPORTED`입니다.
