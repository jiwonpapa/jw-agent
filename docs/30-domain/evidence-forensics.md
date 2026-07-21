# Evidence and Forensics Domain

Status: Accepted  
Authority: Domain  
Owner: Security Maintainer  
Last reviewed: 2026-07-21

## Evidence 목적

사고 후 “제품이 무엇을 관찰했고 어떤 명령·파일 변경을 수행했는지”를 재구성합니다. 사용자가 하지 않은 일을 증명하거나 법적 책임을 자동 판정하는 시스템은 아닙니다.

## 필수 event

- plan created/expired/approved/rejected
- PAM login/reauth generic result, canonical actor UID·role, session lifecycle; password와 raw PAM reason 제외
- preflight passed/failed
- snapshot created/verified
- stage transition
- command identity, sanitized argv class, exit/timeout, bounded output digest
- filesystem before/after digest
- read-back·verify result
- rollback·recovery result
- process restart·ledger continuity check
- detected external drift

## 연속성

- event는 append-only sequence와 previous-record digest를 가집니다.
- periodic checkpoint를 별도 root-owned metadata로 확정합니다.
- chain은 tamper evidence이지 blockchain이나 절대 불변성을 의미하지 않습니다.
- continuity 실패 시 `FORENSIC_LOCKDOWN`으로 전환합니다.

## 분석 출력

AI나 진단 도구는 signed/hashed evidence bundle을 읽어 요약할 수 있지만, 관찰 사실·상관관계·추론·확신도를 분리해야 합니다. 변경 권한은 갖지 않습니다.
