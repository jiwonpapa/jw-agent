# AUTH-PAM-LOGIN-V1

Status: Accepted  
Authority: Authentication Specification  
Owner: Security Maintainer  
Last reviewed: 2026-07-24

## Purpose and support

Ubuntu 24.04 local `pam_unix` account의 username/password를 검증하고 explicit Linux group을 JW Agent role로 매핑합니다.

## Non-goals

- root web login
- account/password lifecycle UI
- shell/PAM session creation
- SSSD·LDAP·Kerberos·OTP·binary/multi-prompt support claim
- password storage or recovery

## Input

- bounded username
- secret bounded password
- trusted remote address only from public proxy UDS, otherwise recovery marker
- purpose `login | step_up`
- request correlation and deadline

## Authd result

- generic success/failure class
- canonical username and UID
- role `admin | operator | viewer`
- account validation timestamp
- no PAM raw text or password-derived value

## Invariants

- new process and PAM handle per request
- peer UID is agentd
- authenticate then account management then canonical user lookup
- UID 0, no-role group, multiple-role group fail closed
- password zeroized before exit
- timeout, unsupported conversation, PAM unavailable fail closed
- public response cannot enumerate user existence, lock, group, password state

## Session issuance

Login creates a rotated opaque server-side session. Administrative step-up rotates
the session and opens a bounded 15-minute management capability. Exact-plan
single-use claims remain available for stop·large deletion·관리 접속 영향 작업처럼
정책이 별도 승인을 요구하는 작업이며 새 일반 session을 만들 수 없습니다.

PAM reauthentication is mandatory when entering administrative mode, not for every
routine G2 write inside that mode. Optional additional authentication is a separate
policy/provider boundary and never replaces PAM account validation.

## Acceptance

- exactly one valid admin/operator/viewer group
- wrong password, unknown user, disallowed group share public response
- root, locked, expired, deleted, UID-changed user denied
- password-expired behavior documented without raw PAM message
- peer UID/version/size/deadline negatives
- PAM timeout/crash and bounded concurrency
- no secret in DB/log/journal/evidence/core/browser trace
- agentd/authd restart and session revoke behavior
