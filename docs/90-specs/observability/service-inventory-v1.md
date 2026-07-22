# OBS-SERVICE-INVENTORY-V1

Status: Accepted  
Authority: Product Specification  
Owner: Service Maintainer  
Last reviewed: 2026-07-22

## User job

운영자는 서버에 설치된 주요 서비스, 현재 상태, 역할과 JW Agent 지원 범위를 30초 안에
파악합니다. Ubuntu 내부 unit 소음은 기본 목록에서 제외하되 실패한 unit은 숨기지 않습니다.

## Support and non-goals

- Ubuntu 24.04 LTS systemd unit의 G0 읽기 전용 발견만 지원합니다.
- MVP 주요 템플릿은 Nginx, Apache, PHP-FPM, MySQL, MariaDB, PostgreSQL, Redis,
  Memcached, OpenSSH, UFW, Certbot, Fail2ban, Docker와 containerd입니다.
- Nginx·PHP-FPM·MySQL/MariaDB·Redis·OpenSSH·UFW·Certbot은 지원표의 관찰 surface입니다.
- 나머지 템플릿은 `known_read_only`, template 밖 로컬 unit은 `discovered_read_only`입니다.
- start·stop·restart·enable·disable, package 설치·삭제와 범용 systemd mutation은 비목표입니다.
- unit 이름만으로 package version, 열린 port 또는 정상 동작을 추측하지 않습니다.

## Template authority

`crates/jw-agentd/service-catalog/ubuntu-24.04-v1.json`이 서비스 이름·용도·분류·unit pattern과
지원 수준의 단일 권위 원본입니다. 화면과 API handler에 서비스별 조건문이나 설명을 복제하지
않습니다. pattern은 literal 또는 하나의 `*` wildcard만 허용하며 시작 시 schema와 중복 ID를
검증합니다.

## Discovery contract

- agentd가 고정된 `/usr/bin/systemctl show` 읽기 명령만 실행합니다.
- 환경을 비우고 `LANG=C`, 3초 timeout, stdout 512 KiB, stderr 32 KiB를 적용합니다.
- command와 argv는 registry 상수이며 HTTP 입력으로 변경할 수 없습니다.
- `LoadState=loaded`인 `.service`와 `.timer`만 후보로 받습니다.
- exact property block만 파싱하고 control character, 255 byte 초과 unit, 불완전 record는 버립니다.
- failed unit은 템플릿·visibility와 관계없이 응답과 Attention Queue에 남깁니다.
- template 일치 unit은 `primary`, `/etc/systemd/system`의 template 밖 unit은 `discovered`,
  나머지는 `system`으로 분류합니다.
- system과 제품 내부 unit은 API에 포함하되 `hiddenByDefault=true`로 반환합니다.
- 최대 512개를 안정 정렬해 반환하고 초과하면 `truncated=true`, 전체 상태는 `partial`입니다.

## REST output

`GET /api/v1/services`는 다음을 반환합니다.

- `observedAt`, `status`, `templateProfile`, `truncated`
- `serviceId`, catalog-derived optional `templateId`, `unitName`, `displayName`, `purpose`
- `category`, `runtimeState`, `activeState`, `subState`, `unitFileState`
- `visibility`, `support`, `readOnly`, `hiddenByDefault`

관찰 실패는 빈 정상 목록으로 바꾸지 않고 `partial`과 빈 목록을 반환합니다. 비-Linux는
`unsupported_platform`입니다. 비밀값, command output 원문과 환경값은 응답·로그에 넣지 않습니다.

## UI contract

- route는 `/services`입니다.
- 상단은 전체·실행·실패·중지 개수와 관찰 시각만 표시합니다.
- 본문은 `주요 서비스 → 발견된 서비스 → 시스템 서비스` 순서의 한 목록을 사용합니다.
- 시스템 서비스는 기본 접기지만 실패 항목은 주요 Attention 영역에도 표시합니다.
- 주요 서비스는 같은 `templateId`의 service·timer·instance를 하나의 서비스 가족으로 묶고,
  쉬운 역할 설명, child unit, 실행·자동시작 상태와 지원 수준을 표시합니다.
- 주요 서비스 가족은 desktop 다열·mobile 한 열의 작업 카드로 표시하고, 시스템 unit은 밀집 목록으로 유지합니다.
- `관리 지원`, `알려진 읽기 전용`, `발견된 읽기 전용`, `시스템 내부`를 혼동하지 않습니다.
- mobile 320px에서 상태·역할·지원 수준을 생략하지 않고 한 열로 reflow합니다.

## Acceptance scenarios

1. Nginx·PHP-FPM·MariaDB·Redis unit fixture가 템플릿 이름·한국어 용도·상태로 분류됩니다.
2. custom `/etc/systemd/system/example.service`는 발견된 읽기 전용으로 표시됩니다.
3. systemd 내부 unit은 기본 숨김으로 분류되지만 failed면 응답과 경고에서 사라지지 않습니다.
4. 미설치 주요 템플릿은 가짜 stopped row로 만들지 않습니다.
5. malformed·oversized·timeout command output은 정상으로 오인되지 않습니다.
6. `/services`는 desktop·tablet·320px mobile에서 overflow 없이 동작하고 axe critical/serious 0입니다.
7. Ubuntu VM에서 실제 Nginx와 JW Agent 내부 unit 분류, 실패 unit 노출, command bound를 검증합니다.

## Evidence

- parser·catalog unit tests와 Rust policy/fmt/clippy/test
- OpenAPI drift, web type/lint/unit/build
- 기존 `p2-browser` lane의 route·responsive·accessibility scenario
- 기존 `p2-vm` lane의 installed package와 실제 systemd inventory scenario
