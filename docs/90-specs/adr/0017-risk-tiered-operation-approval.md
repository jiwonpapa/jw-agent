# ADR-0017 — Risk-tiered operation approval

Status: Accepted  
Authority: Architecture Decision  
Owner: Security Maintainer  
Last reviewed: 2026-07-23  
Date: 2026-07-23

## 결정

관리 모드 진입의 PAM+추가 인증을 짧은 root typed-operation step-up으로 사용합니다.
유효한 관리 모드 안의 G2 reversible config와 start/reload/restart는 exact plan hash·CSRF·single-use
approval만 요구하고 Linux 비밀번호를 반복 요구하지 않습니다. 관리 모드 만료, stop, large deletion과
관리 접속 영향 작업은 다시 step-up 또는 명시적 downtime 확인을 요구합니다.

## 이유

반복 비밀번호·체크박스는 backend 보장을 늘리지 않고 확인 피로와 자동 클릭을 유발합니다.
실제 보장은 서버 측 capability, immutable plan, precondition digest, idempotency, snapshot, verifier,
rollback과 ledger가 소유합니다.

## 금지

관리 모드를 sudo cache·root shell·arbitrary command 권한으로 사용할 수 없습니다.
