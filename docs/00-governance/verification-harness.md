# Single Verification Harness

Status: Accepted  
Authority: Governance  
Owner: Verification Maintainer  
Last reviewed: 2026-08-18

## 유일한 입구

검증 로직은 `xtask`만 소유합니다.

```bash
cargo xtask list
cargo xtask render-capabilities
cargo xtask verify-gate WEB-TYPECHECK
cargo xtask verify governance
cargo xtask verify p2-local
cargo xtask verify p2-browser
cargo xtask verify p2-vm
```

존재하는 검사만 등록합니다. Ubuntu VM과 release lane은 실제 fixture·artifact가 생기기 전 성공하는 placeholder로 만들지 않습니다.

개발 중에는 `verify-gate GATE-ID`로 registry의 기존 검사 하나만 빠르게 실행합니다. 검증 로직을 복제하는 별도 명령이 아니며 commit 전에는 해당 단계의 전체 lane을 다시 실행합니다.

## 현재 lane

| Lane | 목적 | 증거 수준 |
|---|---|---|
| governance | 문서·정책·dependency source·제품 version·changelog·원격 Actions 경계 | DOC/AUTO |
| p1-local / p2-local | governance + 단계별 Rust policy/fmt/clippy/test + OpenAPI drift + 웹 type/lint/unit/build | LOCAL_PASS |
| p1-browser / p2-browser | governance + mock API 브라우저 세션·반응형·접근성 | LOCAL_PASS |
| p1-vm / p2-vm | 실제 Ubuntu package·권한·PAM·공개 edge·typed operation·OpenSSH fault scenario | VM_PASS |

browser lane은 UI 계약 검증이며 실제 PAM·systemd·Nginx 통합 증거가 아닙니다. VM lane은 폐기 가능한 Ubuntu fixture의 현재 package에만 유효합니다. signed release lane은 아직 구현되지 않았습니다.

## Gate metadata

- `GateId`: 절대 재사용하지 않는 ID
- `owner`: 판단 규칙 소유자
- `scope`, `inputs`, `lanes`
- `timeout`
- `evidence output`
- `failure_policy`

결과는 `PASS`, `FAIL`, `BLOCKED`, `SKIPPED`입니다. Release 필수 gate는 `SKIPPED`일 수 없습니다.

`GOV-009`는 [Capability Registry](capability-registry.md)의 상태 주장이 실제 OpenAPI,
typed operation, GateId와 spec index를 가리키는지 검증합니다. capability 상태 문서
생성은 별도 검증 하네스가 아니며 같은 `xtask` 구현을 사용합니다.

`OPENAPI-DRIFT`는 [ADR-0023](../90-specs/adr/0023-openapi-node-runtime.md)의 Node
22–24 compatibility runtime으로 고정된 upstream generator를 실행합니다. 웹 package
설치와 나머지 script는 계속 Bun만 사용합니다.

generator가 I/O timeout되면 timeout을 늘리지 않습니다. 먼저 현재 lockfile을 유지한
채 `apps/web`에서 `bun install --frozen-lockfile`로 dependency tree를 재구성하고 같은
GateId를 다시 실행합니다. 새 설치가 통과해야만 기존 cache 손상으로 판정합니다.

## 중복 방지

- wrapper는 GateId를 호출만 합니다.
- 동일 명령을 lane마다 복사하지 않습니다.
- local Cargo cache와 VM base image만 cache합니다. PASS 결과를 cache하지 않습니다.
- release는 필수 gate evidence를 새로 생성합니다.
- service-specific safety는 `opsd`와 해당 operation VM scenario 한 곳이 소유합니다.

## Ubuntu VM gate ownership

실행 가능한 VM GateId와 metadata의 권위 원본은 `xtask`의 `GATES` registry입니다. 문서는 GateId 목록을 복제하지 않고 다음 실패 모델만 고정합니다.

- public/PAM: TLS·proxy UDS·Host/Origin·PAM account/role·SSH recovery
- typed operation: plan·approval·snapshot·apply·read-back·rollback·forensic lockdown
- Certbot: one-shot network helper·inventory·renew/issue/attach 결과
- OpenSSH: non-root terminal, home-confined SFTP G0 read와 planned G1 atomic create/replace
- secret scan: journal·SQLite·snapshot·argv·package evidence의 fixture secret 비노출

Mobile·tablet은 기존 browser GateId의 viewport matrix이며 별도 중복 하네스를 만들지 않습니다.
