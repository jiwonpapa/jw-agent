# ADR-0021 — Semantic Versioning and Keep a Changelog

Status: Accepted  
Authority: Architecture Decision  
Owner: Release Maintainer  
Last reviewed: 2026-08-11

## Context

Rust crate, 웹 UI, Debian 개발 package가 서로 다른 목적의 version을 사용하지만 이를
구분하는 권위 규칙이 없었습니다. 특히 배포 process인 `jw-edge`만 `0.0.0`이었고,
`0.2.0~p2.N` 내부 package 순번을 공개 제품 release로 오해할 수 있었습니다. 헌법의
release 원칙을 개정하려면 영향 분석과 기존 version migration이 포함된 ADR이 필요합니다.

## Decision

- 제품 version은 Semantic Versioning 2.0.0을 따릅니다.
- 사용자 changelog는 repository root에서 Keep a Changelog 1.1.0 형식을 따릅니다.
- 공개 API 경계와 version 증가 규칙은
  [Versioning and Changelog Policy](../../80-delivery/versioning-and-changelog.md)가
  소유합니다.
- 루트 Cargo workspace version을 단일 권위 원본으로 두고 모든 배포 Rust crate와 웹
  package version을 일치시킵니다. 내부 개발 도구는 제품 version 계약에서 제외합니다.
- Debian changelog는 package build 이력을 계속 보존하며 제품 changelog를 대체하지
  않습니다.
- 공개 version·tag·artifact는 immutable이며 수정은 새 version으로만 배포합니다.
- `xtask` governance gate가 changelog 구조, SemVer 문법, manifest·lockfile·web version,
  Debian mapping을 검증합니다.

## 영향 분석

- `jw-edge` version이 다른 제품 process와 같은 `0.2.0`으로 정정됩니다. runtime protocol과
  package behavior는 변경되지 않습니다.
- release 준비 시 version 변경 파일을 빠뜨리거나 `Unreleased`·release date·comparison
  link가 깨지면 모든 검증 lane이 fail합니다.
- 별도 dependency, code generation, 원격 workflow는 추가하지 않습니다.
- 기존 Debian changelog와 VM evidence checksum은 변경하거나 재발행하지 않습니다.

## Migration

1. 현재 제품 기준 version `0.2.0`을 루트 workspace에 선언합니다.
2. 배포 Rust crate를 workspace version 상속으로 전환하고 `jw-edge` lockfile version을
   `0.2.0`으로 정렬합니다.
3. 루트 `CHANGELOG.md`는 `Unreleased`부터 시작합니다.
4. 기존 `0.2.0~p2.N` package는 내부 개발 snapshot으로 유지하고 공개 release section을
   소급 생성하지 않습니다.
5. 첫 공개 release에서 license, signature, SBOM, release gate와 함께 `vX.Y.Z` tag를
   만듭니다.

## Rejected

- Debian version을 제품 version 원본으로 사용: package 정렬용 `~p2.N`이 SemVer가
  아닙니다.
- Git log 자동 덤프만 제공: 사용자 영향, migration, 보안 분류를 설명하지 못합니다.
- CalVer: 공개 API 호환성을 version number로 전달하지 못합니다.
- 과거 개발 package를 공개 release로 소급 표기: 실제 release·서명 증거를 과장합니다.

## Acceptance

- 루트 changelog가 `Unreleased`, 허용 분류, ISO date와 comparison link 계약을 만족합니다.
- 제품 Cargo manifest, Cargo lock, web package, Debian package 기준 version이 일치합니다.
- 잘못된 SemVer, 중복·역순 release, 잘못된 changelog 분류, 제품 version drift를 fixture
  unit test와 `GOV-008`이 거부합니다.
- 기존 Debian changelog와 공개되지 않은 P2 evidence는 그대로 보존됩니다.
