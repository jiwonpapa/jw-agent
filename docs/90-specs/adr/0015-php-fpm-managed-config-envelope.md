# ADR-0015 — PHP-FPM managed config와 bounded envelope

Status: Accepted  
Authority: Architecture Decision  
Owner: Runtime Architecture Maintainer  
Last reviewed: 2026-07-22

## Context

Ubuntu의 기본 FPM `php.ini`는 기존 Nginx resource의 24 KiB 상한보다 큽니다. 파일을 임의 조각으로 나누거나 범용 root 파일 API를 만들면 실제 활성 설정과 UI가 어긋납니다.

## Decision

- `service.config_file.set/v1` lifecycle과 ledger를 재사용하되 resource별 adapter가 path, 최대 크기, validator, service action과 read-back을 소유합니다.
- Nginx content 상한은 24 KiB로 유지합니다.
- PHP 8.3 FPM `php.ini` content 상한은 128 KiB입니다.
- managed-config plan JSON body와 ops IPC frame 상한은 256 KiB로 올립니다. 다른 API body, 인증 frame과 terminal frame은 변경하지 않습니다.
- 공개 Nginx edge도 exact managed-config plan path만 `256k`로 허용하며 전역 `64k`와 file-upload `8m` 경계는 유지합니다.
- fixed PHP 8.3 command class만 추가하고 동적 argv, 새 crate, Cargo feature, native dependency는 추가하지 않습니다.

## Consequences

- 큰 payload도 명시적 cap, UTF-8/control 검증, proposal file, snapshot과 redacted Debug 경계를 통과합니다.
- resource별 제한을 공통 request shape가 아닌 opsd adapter preflight에서 다시 강제합니다.
- 이후 서비스는 frame 상한을 다시 늘리지 않고 128 KiB 안에 들어오는지 먼저 입증해야 합니다.
- PHP의 다른 version/layout과 pool 편집은 별도 Accepted spec과 VM evidence 전까지 지원하지 않습니다.
