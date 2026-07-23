# AUTH-TOTP-STEP-UP-V1

Status: Accepted  
Authority: Authentication Specification  
Owner: Security Maintainer  
Last reviewed: 2026-07-23

## Purpose

`risky_operations | all_mutations` 정책에서 PAM 재인증 뒤 RFC 6238 TOTP를 추가 step-up으로 검증합니다. 공개 HTTPS에서 탈취된 Linux 비밀번호 하나만으로 write를 승인하지 못하게 하는 것이 목적입니다.

## Non-goals

- Linux PAM·SSH MFA 설정 변경
- SMS·email OTP
- 중앙관제 계정 MFA
- local root 또는 `jw-agent` service account compromise 방어 주장
- TOTP가 PAM 재인증을 대체하는 동작

## Provider profile

- provider ID: `totp/v1`
- algorithm: HMAC-SHA-1 for authenticator compatibility
- digits: 6
- period: 30 seconds
- accepted window: current step ±1
- 같은 subject·time-step code의 재사용 금지
- 검증 budget은 PAM login budget과 분리하되 source·subject·global 상한을 모두 가집니다.

## Enrollment

1. SSH tunnel recovery ingress에서 admin PAM 재인증을 완료합니다.
2. server가 CSPRNG 160-bit secret과 10개의 128-bit one-time recovery code를 생성합니다.
3. `otpauth://` URI와 recovery code는 해당 response에서 한 번만 표시하고 cache·log·browser storage에 남기지 않습니다.
4. 사용자가 연속된 서로 다른 time-step의 유효 code 두 개를 입력해야 enrollment를 확정합니다.
5. 확정 전 secret은 durable policy로 사용하지 않고 만료·취소 시 제거합니다.
6. 첫 enrollment가 완료되기 전에는 additional-auth 정책을 활성화할 수 없습니다.

## Storage

- subject는 canonical Linux UID에 결합하고 username 변경은 read-back으로 갱신합니다.
- TOTP secret은 agentd 전용 random wrapping key로 AEAD 암호화해 agentd SQLite에 저장합니다.
- wrapping key는 DB와 분리된 mode `0600` file이며 package·evidence·snapshot export에 포함하지 않습니다.
- recovery code는 domain-separated SHA-256 digest만 저장하고 사용 시 원자적으로 소비합니다.
- DB-only 유출 방어와 local service-account compromise 한계를 UI·위협모델에 명시합니다.

## Verification

- PAM step-up이 성공한 동일 session·UID·plan hash에만 TOTP challenge를 발급합니다.
- code는 HTTPS/recovery JSON body의 secret field로만 받고 즉시 zeroize합니다.
- 성공 claim은 session, UID, provider, exact plan hash와 5분 이하 만료에 결합하며 한 번만 소비합니다.
- clock rollback, unavailable key, duplicate code, exhausted budget는 fail closed 합니다.

## Recovery and reset

- normal recovery는 SSH tunnel ingress, admin PAM 재인증과 unused recovery code 하나를 모두 요구합니다.
- reset은 해당 subject의 TOTP enrollment와 모든 additional-auth claim·session을 폐기하고 감사 event를 남깁니다.
- 다른 admin의 enrollment로 대신 승인하거나 공용 recovery code를 사용하지 않습니다.
- recovery code를 모두 잃은 경우 웹 bypass를 제공하지 않습니다. 운영체제 console에서 별도 audited recovery runbook을 수행해야 하며 그 구현은 이 spec의 승인 범위가 아닙니다.

## Public error and evidence

- wrong, replayed, expired, unenrolled code는 같은 public status/body를 반환합니다.
- provider ID, canonical UID, challenge/result class, plan hash digest, budget result와 timestamp만 기록합니다.
- secret, OTP, recovery code, otpauth URI, wrapping key와 raw authenticator label은 기록하지 않습니다.

## Acceptance

- enroll confirm 전 정책 활성화 거부
- valid, wrong, expired, ±1 window, replay, duplicate request
- PAM subject/session/plan mismatch
- clock rollback and key missing/corrupt
- recovery code single use, reset and session revoke
- source·subject·global budget
- DB/log/journal/process/URL/browser trace secret scan
- mobile password manager·authenticator paste와 accessibility

`jw-agent_0.2.0~p2.18_amd64.deb`에서 재검증되었으며 Ubuntu 24.04 VM의 `VM-P2-TOTP-STEP-UP`이 등록, 관리 모드 진입, exact-plan 승인, replay 차단, recovery reset과 encrypted-storage cleanup을 검증했습니다. SHA-256은 `80d7339e379bef72414c2294dcd8399f64818775abbff267577e7d6d50f3e7ba`입니다.
