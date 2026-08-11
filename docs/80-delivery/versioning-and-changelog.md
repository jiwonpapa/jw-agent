# Versioning and Changelog Policy

Status: Accepted  
Authority: Delivery  
Owner: Release Maintainer  
Last reviewed: 2026-08-11

## 규범

- 제품 버전은 [Semantic Versioning 2.0.0](https://semver.org/lang/ko/)을 따릅니다.
- 사용자용 [CHANGELOG.md](../../CHANGELOG.md)는
  [Keep a Changelog 1.1.0](https://keepachangelog.com/ko/1.1.0/)을 따릅니다.
- 공개한 버전·tag·artifact 내용은 변경하지 않습니다. 수정은 새 버전으로만 배포합니다.
- 현재 `0.y.z`는 초기 개발 단계입니다. 호환되지 않는 변경도 명시적으로 기록합니다.

## 공개 API 경계

SemVer가 보호하는 JW Agent의 공개 API는 다음과 같습니다.

- 공개 OpenAPI route, method, request·response·error schema
- `agentd`·`authd`·`opsd`·`certd` 사이의 versioned IPC frame과 typed operation schema
- 문서화된 package 파일·systemd unit·socket·설정 key와 설치·upgrade 계약
- 문서화된 지원 service, assurance level, 권한·복구 계약

웹 화면의 배치 자체와 내부 `xtask` CLI는 공개 API가 아닙니다. 다만 사용자 작업 흐름,
기능, 보안·권한·복구 동작의 주목할 만한 변화는 SemVer 호환 여부와 별개로 changelog에
기록합니다.

## 권위 원본

- 제품 SemVer의 권위 원본은 루트 `Cargo.toml`의 `[workspace.package].version`입니다.
- 배포되는 Rust 제품 crate는 `version.workspace = true`를 사용합니다.
- `apps/web/package.json`의 version과 제품 crate의 lockfile version은 권위 원본과 같아야
  합니다.
- 개발 도구 `xtask`는 배포 제품이 아니므로 자체 `0.0.0` version을 유지합니다.
- Debian changelog는 패키지 build 이력을 소유하며 루트 changelog를 대체하지 않습니다.

현재 제품 버전은 `0.2.0`입니다. `0.2.0~p2.24` 같은 Debian version은 같은 제품
기준선으로 만든 내부 VM 개발 패키지 순번이며 공개 SemVer release나 tag가 아닙니다.

## 버전 증가 규칙

| 단계 | 변경 | 다음 버전 |
|---|---|---|
| `0.y.z` | 호환되는 결함 수정 | patch 증가 |
| `0.y.z` | 기능 추가 또는 공개 API 비호환 변경 | minor 증가 |
| `1.0.0+` | 호환되는 결함 수정 | patch 증가 |
| `1.0.0+` | 호환되는 기능 추가·deprecation | minor 증가 |
| `1.0.0+` | 공개 API 비호환 변경 | major 증가 |

사전 배포판은 `X.Y.Z-rc.N`처럼 SemVer prerelease를 사용하고, build metadata는
`X.Y.Z+IDENTIFIER`처럼 우선순위에 영향을 주지 않는 식별에만 사용합니다. version 앞에
`v`를 붙이는 것은 Git tag 이름뿐이며 manifest version에는 붙이지 않습니다.

## Debian 매핑

- 공개 안정판 `X.Y.Z`의 첫 Debian package: `X.Y.Z-1`
- 공개 사전판 `X.Y.Z-rc.1`: `X.Y.Z~rc.1-1`
- P2 내부 VM package: `X.Y.Z~p2.N`

Debian의 `~` 표기는 package 정렬을 위한 것으로 제품 SemVer 문자열에 넣지 않습니다.
같은 Debian version의 package를 다른 내용으로 덮어쓰지 않습니다.

## Changelog 규칙

- 첫 section은 항상 `Unreleased`입니다.
- release는 최신순이며 `## [X.Y.Z] - YYYY-MM-DD` ISO 8601 날짜를 사용합니다.
- 분류는 `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`만 사용합니다.
- commit log를 그대로 붙이지 않고 사용자·운영자가 알아야 할 변화와 migration을 씁니다.
- 보안 수정은 악용을 돕는 세부사항 없이 영향, 대상 버전, 권장 조치를 기록합니다.
- 철회한 release도 삭제하지 않고 `[YANKED]`로 표시합니다.
- 첫 공개 release 전의 내부 `p1`·`p2` package 이력을 루트 changelog의 가짜 release로
  소급 생성하지 않습니다.

## 릴리스 절차

1. `Unreleased`의 사용자 영향과 migration을 완성합니다.
2. 공개 API 변화에 따라 다음 SemVer를 결정합니다.
3. workspace·web·lockfile·Debian version을 함께 갱신합니다.
4. `Unreleased` 내용을 version과 날짜가 있는 release section으로 이동합니다.
5. 새 빈 `Unreleased`와 Git comparison link를 만듭니다.
6. 단계별 local·browser·VM gate와 향후 release gate를 통과시킵니다.
7. 같은 commit으로 package, checksum, SBOM, signature와 evidence를 생성합니다.
8. immutable `vX.Y.Z` tag와 artifact를 공개합니다.

## 금지

- 이미 공개한 tag나 artifact 덮어쓰기
- 비호환 변경을 patch release에 숨기기
- Debian 개발 revision을 공개 제품 버전으로 표시하기
- Git commit 나열을 사용자 changelog로 대체하기
- build metadata로 새 버전 우선순위를 표현하기
