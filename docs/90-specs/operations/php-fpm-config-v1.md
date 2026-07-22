# OPS-PHP-FPM-CONFIG-V1

Status: Accepted  
Authority: Operation Specification  
Owner: PHP-FPM Adapter Maintainer  
Last reviewed: 2026-07-22

Envelope 결정: [ADR-0015](../adr/0015-php-fpm-managed-config-envelope.md)

## 목적

Ubuntu 24.04 기본 apt 패키지의 PHP 8.3 FPM 상태·활성 확장·설정 위치를 관찰하고, 표준 `php.ini` 한 파일을 문법 검사와 검증된 자동 원복 안에서 변경합니다.

## 지원 프로필

- adapter: `php-fpm/ubuntu-24.04-8.3-v1`
- package/layout: Ubuntu 24.04 apt `php8.3-fpm`, `/etc/php/8.3/fpm`
- managed resource: `/etc/php/8.3/fpm/php.ini`
- unit: `php8.3-fpm.service`
- validator: fixed `/usr/sbin/php-fpm8.3 -t`
- action: fixed `systemctl reload php8.3-fpm.service`
- opsd filesystem write allowlist: exact `/etc/php/8.3/fpm`; 다른 `/etc/php` version·SAPI 경로는 read-only
- validator가 여는 `/var/log/php8.3-fpm.log`는 opsd namespace에서 `/dev/null`로 exact bind하며 실제 PHP-FPM 로그 쓰기 권한은 주지 않습니다.
- read-back: unit active, validator success, exact content·owner·group·mode
- assurance: local file·service 경계 `G2`

custom build, container, PPA layout, 다른 PHP major/minor, symlink·hardlink·비표준 owner/mode는 관찰 또는 `UNSUPPORTED`이며 변경하지 않습니다.

## 읽기 모델

`GET /api/v1/services/php-fpm`은 다음만 반환합니다.

- 설치·지원 상태와 관찰 시각
- PHP version, FPM unit과 실제 runtime state
- masked `php.ini`, pool, `conf.d` 위치
- 활성 extension 이름과 개수; 최대 개수 초과 여부
- managed resource ID, 허용 operation, 보장 등급 또는 차단 이유

`phpinfo()` HTML, 환경 변수, request header, loaded secret, 전체 command output은 수집·저장·표시하지 않습니다.

## Typed operation

기존 `service.config_file.set/v1` lifecycle을 사용합니다.

- resource ID는 `php_` prefix의 opaque digest입니다.
- request는 resource ID, before content·metadata digest, UTF-8 proposed content, `reload`, idempotency key만 받습니다.
- inline content 최대 `128 KiB`, JSON·ops IPC frame 최대 `256 KiB`
- path, executable, unit, version, validator argv는 사용자 입력으로 받지 않습니다.
- plan은 변경 줄 수, byte 수, 문법 검사, reload 영향, 원복 범위와 SSH 복구 명령 class를 공개합니다.

## 실행과 원복

1. ledger continuity, resource lock, plan expiry와 before digest를 재검사합니다.
2. bytes·owner·group·mode snapshot을 durable 저장합니다.
3. 같은 디렉터리에 root-only 임시 파일을 만들고 fsync 후 atomic rename합니다.
4. `php-fpm8.3 -t`가 실패하면 reload하지 않고 즉시 snapshot을 복원합니다.
5. 문법 성공 뒤 `php8.3-fpm.service`를 reload하고 active 상태·문법·content metadata를 read-back합니다.
6. reload·active·read-back 실패 시 원문을 복원하고 다시 문법 검사·reload·active를 검증합니다.
7. 원복 검증 실패는 `RECOVERY_REQUIRED`이며 성공으로 표시하지 않습니다.

no-op도 기존 설정의 문법과 unit active를 검증해야 성공합니다. 외부 편집·resource drift는 side effect 전 `CANCELLED_BEFORE_APPLY`로 끝냅니다.

## Typed errors

`not_installed`, `unsupported_version`, `unsupported_layout`, `resource_missing`, `resource_not_regular`, `resource_metadata_rejected`, `size_limit`, `invalid_encoding`, `stale_resource`, `syntax_failed`, `reload_failed`, `service_inactive`, `read_back_failed`, `rollback_failed`, `forensic_lockdown`을 구분합니다.

## Acceptance scenarios

- PFC-01 표준 PHP 8.3 FPM과 활성 extension·경로가 비밀 없이 관찰됩니다.
- PFC-02 valid `php.ini` 변경이 plan → snapshot → syntax → reload → read-back으로 완료됩니다.
- PFC-03 문법 오류는 reload 전에 거부되고 원문 bytes·metadata가 복원됩니다.
- PFC-04 reload/active 강제 실패는 자동 원복과 재검증으로 끝납니다.
- PFC-05 stale digest, symlink, hardlink, oversized, non-UTF-8, non-standard layout은 적용 전에 차단됩니다.
- PFC-06 browser는 G2 범위·제외·검증·복구 경로를 승인 버튼 위에 표시합니다.
- PFC-07 API·ledger·journal·browser storage에 설정 원문, PAM 비밀번호, 환경 값이 남지 않습니다.
- PFC-08 Ubuntu 24.04 VM의 실제 `php8.3-fpm`에서 valid·syntax rollback·service continuity를 증명합니다.

## 명시적 제외

- pool file 편집, FPM socket·user/group 자동 변경
- CLI·Apache SAPI 설정 변경
- extension 설치·제거, apt operation
- arbitrary version/path/unit/command
- 웹 `phpinfo()` 페이지 생성
- MySQL/MariaDB 연결·credential·database 변경
