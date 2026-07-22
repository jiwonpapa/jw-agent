# ADR-0016 — TOTP 암호 경계와 등록 ceremony

Status: Accepted  
Authority: Architecture Decision  
Owner: Security Maintainer  
Last reviewed: 2026-07-22

## Context

[AUTH-TOTP-STEP-UP-V1](../auth/totp-step-up-v1.md)은 RFC 6238 provider와 DB 밖 wrapping key를 요구하지만 암호 구현과 웹 등록 경계는 고정하지 않았습니다. 자체 암호 구현, 외부 QR 서비스, PAM·SSH 설정 변경은 비밀 노출과 빌드 위험을 키웁니다.

## Decision

- TOTP는 기존 `jw-agentd`와 SQLite session 소유권 안에 구현하며 새 crate를 만들지 않습니다.
- HMAC-SHA-1은 RustCrypto `hmac 0.12.1`과 이미 lock graph에 있던 `sha1 0.10.7`을 exact pin으로 사용합니다.
- TOTP secret은 pure-Rust `chacha20poly1305 0.10.1`로 암호화하고 256-bit wrapping key는 DB 옆 별도 mode `0600` regular file에 둡니다.
- wrapping key 누락·권한 이상·복호화 실패는 재생성하지 않고 provider를 unavailable로 판정합니다.
- QR은 browser memory에서 `qrcode 1.5.4`로 그리며 외부 QR endpoint, data upload와 browser storage를 사용하지 않습니다.
- 등록·초기화는 recovery ingress와 admin PAM 재인증을 요구합니다. 활성 정책의 operation 승인은 PAM claim과 TOTP claim을 같은 SQLite transaction에서 소비합니다.
- 새 native library, code generation, Cargo feature matrix와 원격 workflow는 추가하지 않습니다.

## Consequences

- dependency graph는 pure-Rust 암호 세 개와 browser QR renderer 하나만 증가합니다.
- DB-only 유출은 TOTP secret 원문을 제공하지 않지만 `jw-agent` 계정과 wrapping key가 함께 탈취된 상황은 방어한다고 주장하지 않습니다.
- QR URI·manual secret·recovery code·OTP는 response memory를 벗어나 로그·audit·browser persistence에 남기지 않습니다.
- 키 손상 복구는 웹 우회가 아니라 recovery code와 운영체제 console runbook 경계로 제한합니다.
