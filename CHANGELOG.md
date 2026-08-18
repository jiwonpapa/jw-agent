# Changelog

이 프로젝트의 주목할 만한 변경 사항을 기록합니다.

형식은 [Keep a Changelog 1.1.0]을 따르고, 제품 버전은
[Semantic Versioning 2.0.0]을 따릅니다. 현재 `0.y.z` 버전은 초기 개발 단계이며
공개 API와 지원 범위가 안정화되기 전까지 호환되지 않는 변경이 있을 수 있습니다.

## [Unreleased]

### Added

- 사용자·운영자 관점의 변경을 기록하는 루트 변경 기록과 릴리스 정책 검증 gate를 추가했습니다.
- 구현·부분 구현·미구현·제외·금지 상태와 실제 evidence를 한 곳에서 관리하는 capability registry와 `GOV-009` drift gate를 추가했습니다.
- OpenAPI generator가 검증되지 않은 global Node에 끌려가지 않도록 Node 22–24 compatibility runtime 선택과 stale dependency cache 복구 기준을 추가했습니다.

### Changed

- Rust 제품 crate와 웹 UI의 제품 버전 기준을 workspace `0.2.0`으로 단일화했습니다.
- 제품 SemVer, Debian 개발 패키지 revision, 공개 tag의 역할을 분리했습니다.
- 지원표·spec index·roadmap의 오래된 UFW·PHP·gate 상태를 현재 구현 증거에 맞게 정리했습니다.

[Unreleased]: https://github.com/jiwonpapa/jw-agent/commits/main
[Keep a Changelog 1.1.0]: https://keepachangelog.com/ko/1.1.0/
[Semantic Versioning 2.0.0]: https://semver.org/lang/ko/
