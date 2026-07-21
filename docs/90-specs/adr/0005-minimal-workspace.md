# ADR-0005 — Minimal Rust Workspace

Status: Superseded by ADR-0007  
Authority: Architecture Decision  
Owner: Architecture Maintainer  
Last reviewed: 2026-07-21

## Decision

MVP 제품 crate는 `jw-contracts`, `jw-agentd`, `jw-opsd` 세 개만 사용하고 `xtask`를 별도 도구 crate로 둡니다.

## 거부한 대안

- 서비스별 crate
- DB/repository/common/utils crate
- 중앙관제 crate 선생성
- dynamic plugin SDK
- 서비스별 Cargo feature matrix

## 결과

서비스 adapter와 ledger는 소유 daemon 내부 module에서 시작합니다. 실제 두 runtime 공유 계약, FFI, 별도 artifact, 측정된 병목이 생길 때만 ADR로 crate를 분리합니다.

## Supersession

Linux PAM 요구로 별도 root process와 unsafe FFI 경계가 실제 발생했습니다. 기존 crate 생성 기준을 만족하므로 [ADR-0007](0007-public-https-pam-boundary.md)이 `jw-authd`와 `ffi-pam`을 추가합니다.
