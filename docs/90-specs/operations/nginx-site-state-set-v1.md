# OPS-NGINX-SITE-STATE-V1

Status: Accepted  
Authority: Operation Specification  
Owner: Nginx Adapter Maintainer  
Last reviewed: 2026-07-21

## 목적

Ubuntu 표준 Nginx layout에서 이미 발견된 site의 `sites-enabled` symlink 상태만 enable/disable합니다.

## 비목표

- config 내용 편집
- arbitrary path 또는 server block 생성·삭제
- custom build/container/PPA layout 지원
- 프로세스·기존 연결의 과거 상태 복원 보장
- `system-owned/protected` public management vhost 변경

## Identity and assurance

- Operation ID: `nginx.site_state.set/v1`
- Target: stable discovered `site_id`
- Maturity target: `SUPPORTED`
- Evidence target: `VM_PASS`
- Assurance: `G2 REVERSIBLE_CONFIG`

UI는 목록 진입점부터 `제한된 설정 자동 원복 지원`을 표시합니다. 보장 범위는 discovered site의 이전 enabled-link 존재 상태이며 Nginx process·기존 연결·available config 내용은 복원 대상이 아닙니다.

## Normative identifiers and schema

- layout ID: `ubuntu-nginx-sites-v1`
- site ID: [ADR-0009](../adr/0009-p2-safety-kernel-decisions.md)의 `ngs_` identifier
- operation type: `nginx.site_state.set/v1`
- schema version: `1`
- unknown field는 모든 mutation request에서 거부합니다.

Plan request:

| Field | Type | Rule |
|---|---|---|
| `schemaVersion` | integer | exactly `1` |
| `operationType` | string | exactly `nginx.site_state.set/v1` |
| `siteId` | string | discovered `ngs_` identifier |
| `targetState` | enum | `enabled | disabled` |
| `expectedAvailableDigest` | string | `sha256:` + 64 lowercase hex |
| `expectedEnabledStateDigest` | string | `sha256:` + 64 lowercase hex |
| `idempotencyKey` | string | opaque 16–64 ASCII characters |

Plan response는 `planId`, `planHash`, `createdAt`, `expiresAt`, canonical actor, target display name, current/target state, precondition digest, impact, snapshot scope, verifier, assurance와 excluded effects를 반환합니다. `planHash`는 canonical immutable plan의 domain-separated SHA-256입니다.

Approval request는 `schemaVersion`, `planId`, exact `planHash`, `idempotencyKey`, single-use `reauthToken`과 정책이 요구할 때만 `additionalAuthClaim`을 받습니다. path·command·config body는 어떤 request에도 없습니다.

Receipt는 `operationId`, `planId`, `planHash`, actor, terminal state, ordered stage evidence, before/after digest, verifier, rollback result, assurance와 recovery path를 포함합니다. allowed terminal state는 `SUCCEEDED | ROLLED_BACK | RECOVERY_REQUIRED | REJECTED | EXPIRED | CANCELLED_BEFORE_APPLY`입니다.

Normative acceptance vector는 [tests/spec-fixtures/nginx-site-state-set-v1.json](../../../tests/spec-fixtures/nginx-site-state-set-v1.json)입니다. 이 fixture는 구현 증거가 아니며 P2 Rust contract가 추가되면 generated schema와 drift gate가 같은 값을 강제해야 합니다.

## Typed operation input

- `site_id`
- `target_state`: `enabled | disabled`
- available file digest
- current enabled-link state digest
- idempotency key

사용자가 path, shell, command argument를 제공하지 않습니다.

## Plan output

- current and target state
- resolved available file and managed link display path
- impact: reload and possible request handling risk
- precondition digest and expiry
- snapshot scope
- verifier: symlink read-back, `nginx -t`, unit active after reload
- rollback: exact previous link/presence restoration and revalidation
- excluded effects: process history, active connection history, available config content
- unsupported reason if any

## Preflight and lock

- installed package and expected directories discovered
- canonical targets remain inside approved roots
- no traversal, link loop, outside symlink, missing source
- available digest and link state match plan
- site capability is user-managed, never system-owned/protected
- lock key `nginx/site/{site_id}` and global reload serialization
- disk space and ledger continuity sufficient

## Execution

1. persist `SNAPSHOTTED` only after previous link state and digest are durable
2. persist `APPLYING`
3. create/remove managed symlink with typed filesystem primitive
4. run fixed `nginx -t` argv with timeout/output cap
5. run fixed systemd reload primitive
6. read back link, syntax result, unit state
7. persist `SUCCEEDED` only when all verifier conditions pass

## Rollback and recovery

- validation/reload/read-back failure enters `ROLLING_BACK`
- restore exact previous link/presence
- rerun syntax check and reload/read-back
- verified restoration becomes `ROLLED_BACK`
- ambiguous or failed restoration becomes `RECOVERY_REQUIRED`
- restart in any non-terminal stage reads OS before repeating an action

## Typed errors

- unsupported environment
- site missing or changed
- plan expired/hash mismatch
- resource busy/idempotency conflict
- path/symlink policy violation
- snapshot/disk/ledger failure
- command timeout/output truncated
- syntax/reload/read-back failure
- rollback failed/recovery required

## Evidence

Plan/operation IDs, actor correlation, site ID, redacted display paths, before/after digests, stage times, command class and exit/timeout, bounded output digest, verifier and rollback results. Config contents and secrets are not recorded.

## Acceptance scenarios

- enable, disable, already-target no-op
- syntax failure and rollback
- reload failure and rollback
- process kill at every durable stage
- disk full before snapshot and during state transition
- duplicate and concurrent request
- external link/config drift
- traversal/outside symlink/link loop rejection
- protected management vhost rejection
- command timeout and oversized stderr
- rollback failure → `RECOVERY_REQUIRED`

이 spec은 구현 가능한 계약 기준입니다. 실제 mutation endpoint, opsd state와 UI CTA는 별도 P2 진입 승인 전에는 추가하지 않습니다.
