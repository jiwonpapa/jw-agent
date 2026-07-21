# State Ownership

Status: Accepted  
Authority: Architecture  
Owner: Architecture Maintainer  
Last reviewed: 2026-07-21

| State | Authority | Storage |
|---|---|---|
| 실제 service/config | Ubuntu와 service | OS |
| observation·inventory·session | agentd | agent-owned SQLite WAL |
| PAM password | none | memory only in agentd/authd, immediate zeroize |
| Linux identity·account state | PAM/NSS | OS identity sources |
| operation lifecycle·ledger (P2+) | opsd | root-owned SQLite WAL |
| operation snapshot (P2+) | opsd | root-only directory |
| UI operation history (P2+) | agentd | receipt projection, 재생성 가능 |
| tenant·customer·staff | future central | PostgreSQL, MVP 없음 |

## 규칙

- 두 daemon은 같은 SQLite 파일을 열지 않습니다.
- authd는 DB가 없고 요청 하나 처리 후 종료합니다.
- agentd session에는 canonical UID·username·role·auth time만 저장하며 password나 PAM token을 저장하지 않습니다.
- P1 opsd는 stateless read-only capability responder이며 DB·ledger·snapshot을 만들지 않습니다.
- P2 진입 후 opsd ledger가 operation의 유일한 권위 원본입니다.
- snapshot body는 SQLite blob이 아니라 파일로 저장하고 DB에는 digest·metadata·relative locator만 둡니다.
- DB에 저장된 OS 상태를 현재 진실로 가정하지 않습니다. 실행 직전 다시 읽습니다.
- P2 stage transition과 event append는 한 transaction입니다.
- P2 agentd projection 손상은 opsd receipt로 복구합니다.
- SQLite schema 변경은 소유 daemon migration만 수행합니다.
- local SQLite는 runtime query를 사용해 build-time DB와 `DATABASE_URL`을 요구하지 않습니다.
