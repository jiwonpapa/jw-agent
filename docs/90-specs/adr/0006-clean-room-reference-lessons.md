# ADR-0006 — Clean-room Reference Lessons

Status: Accepted  
Authority: Architecture Decision  
Owner: Architecture Maintainer  
Last reviewed: 2026-07-21

## Context

Rust 기반 공개 서버 관리 프로젝트 ServerBee의 공식 repository와 문서를 구조 참조용으로 조사했습니다. ServerBee는 AGPL-3.0-or-later이므로 코드·schema·protocol·fixture·UI asset을 복사하지 않습니다.

## 채택할 교훈

- Agent가 enrollment secret을 생성하고 durable 저장 후 single-use claim
- host capability와 policy를 서버가 명시
- 연결 실패 backoff와 모호한 응답 뒤 상태 재조회
- mock agent를 이용한 protocol integration scenario
- React SPA를 local server binary와 함께 배포할 수 있는 구조

위 항목은 아이디어 수준에서 JW Agent spec으로 독립 설계합니다.

## 거부할 구조

- network agent 전체를 root로 실행
- arbitrary exec, root PTY, broad file CRUD
- query string 장기 token
- Admin/Member 두 역할만으로 tenant 요구를 처리
- fleet central DB를 SQLite 하나로 확장
- 같은 host의 같은 source에서 checksum만 확인하고 restore 검증으로 표현

## 추가 교훈

조사 시 architecture 문서는 protocol v4를 설명하지만 source constant는 v6이었습니다. 수기 protocol 문서가 drift할 수 있으므로 JW Agent는 Rust contract에서 OpenAPI/schema snapshot을 생성합니다.

## Sources

- [ServerBee architecture](https://github.com/ZingerLittleBee/ServerBee/blob/main/apps/docs/content/docs/en/architecture.mdx)
- [Agent documentation](https://docs.serverbee.app/en/docs/agent)
- [Capability model](https://github.com/ZingerLittleBee/ServerBee/blob/main/apps/docs/content/docs/en/capabilities.mdx)
- [Enrollment implementation](https://github.com/ZingerLittleBee/ServerBee/blob/main/crates/agent/src/register.rs)
- [Run-token persistence](https://github.com/ZingerLittleBee/ServerBee/blob/main/crates/agent/src/run_token_store.rs)
- [Testing strategy](https://github.com/ZingerLittleBee/ServerBee/blob/main/apps/docs/content/docs/en/testing.mdx)
- [Protocol constants](https://github.com/ZingerLittleBee/ServerBee/blob/main/crates/common/src/constants.rs)
- [License](https://github.com/ZingerLittleBee/ServerBee/blob/main/LICENSE)

