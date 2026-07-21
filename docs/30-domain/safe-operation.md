# Safe Operation Domain

Status: Accepted  
Authority: Domain  
Owner: Safety Maintainer  
Last reviewed: 2026-07-21

## Aggregate

Operation은 다음을 한 aggregate로 관리합니다.

- operation ID·type·version
- actor/session correlation
- canonical Linux UID·role and exact-plan step-up claim
- immutable plan ID·hash·expiry
- precondition revision/digest
- target resource와 lock key
- current durable stage
- snapshot locator·digest
- step receipts와 bounded outputs
- terminal result와 recovery state
- operation version에 귀속된 assurance level
- rollback scope·excluded effects·apply/rollback verifier

## 불변식

- 승인되지 않은 plan은 apply할 수 없습니다.
- public session의 write는 유효한 role과 exact-plan PAM step-up 없이는 apply할 수 없습니다.
- plan과 현재 precondition이 다르면 새 plan이 필요합니다.
- 같은 idempotency key와 의미가 다른 요청은 거부합니다.
- 같은 resource에는 쓰기 operation 하나만 진행됩니다.
- side effect 전에 다음 stage를 durable 기록합니다.
- 성공은 read-back과 verify 후에만 확정합니다.
- 자동 복구 판단이 불가능하면 `RECOVERY_REQUIRED`입니다.
- assurance가 없거나 현재 capability와 일치하지 않으면 plan을 승인할 수 없습니다.
- plan과 receipt의 assurance·rollback scope는 UI에서 임의로 축약하거나 상향하지 않습니다.

## Operation 승격

```text
DRAFT → EXPERIMENTAL → SUPPORTED → STABLE
```

MVP UI write 노출은 최소 `SUPPORTED + VM_PASS`입니다. 실험적 operation을 숨겨 배포하지 않고 등록 자체를 하지 않습니다.
