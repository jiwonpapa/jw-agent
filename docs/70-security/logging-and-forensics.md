# Logging and Forensics Security

Status: Accepted  
Authority: Security  
Owner: Security Maintainer  
Last reviewed: 2026-07-21

## Structured allowlist

로그는 미리 허용한 필드만 기록합니다. login/reauth body, PAM conversation·raw message, environment dump, full command output, secret type의 `Debug`를 금지합니다.

필수 correlation:

- request ID
- plan/operation ID
- actor/session pseudonymous ID
- canonical actor UID and role after successful authentication
- service/resource stable ID
- stage and result code
- observation/event timestamp

## Secret defense

- secret type은 display/debug serialization을 명시적으로 제한
- argv, URL, browser state, analytics, panic message 금지
- PAM password는 agentd/authd memory에서 즉시 zeroize하고 core dump를 금지
- unknown/wrong/locked/group-denied의 public 응답과 browser log를 동일하게 처리
- stdout/stderr는 크기 제한 후 redaction하고 원문 전체를 ledger에 저장하지 않음
- source뿐 아니라 test fixture와 evidence bundle도 secret scan
- Playwright trace·video·screenshot·HAR와 mobile browser storage도 secret scan

## Tamper response

- sequence gap, digest mismatch, DB integrity failure, missing checkpoint를 구분
- write operations 즉시 차단
- read-only observation·diagnostics·export 유지
- 화면에 마지막 신뢰 checkpoint와 손상 범위 표시
- 복구는 runbook과 새 integrity baseline의 명시적 승인 필요

로그가 없다고 사용자의 책임을 자동 확정하지 않습니다. 외부 root 작업은 가능한 범위에서 drift로 기록할 뿐 행위자를 추측하지 않습니다.
