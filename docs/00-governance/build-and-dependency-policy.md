# Build and Dependency Policy

Status: Accepted  
Authority: Governance  
Owner: Build Maintainer  
Last reviewed: 2026-07-21

## 고정 기준

- Rust toolchain: `rust-toolchain.toml`
- MSRV: root workspace `rust-version`
- Rust edition: 2024, virtual workspace `resolver = "3"`
- JavaScript runtime·package manager: Bun 하나
- 배포 target: Ubuntu 24.04 LTS amd64 glibc `.deb`

현재 1.96.0은 이 작업공간에서 실제 확인된 toolchain이라 P0에 고정했습니다. 변경은 작은 upgrade 작업과 gate 증거로만 수행합니다.

Rust 2024 virtual workspace는 resolver를 자동 추론할 루트 package가 없으므로 `resolver = "3"`을 명시합니다. [Rust Edition Guide](https://doc.rust-lang.org/edition-guide/rust-2024/cargo-resolver.html)

## Rust 금지

- 외부 git/path dependency
- `tokio = full`
- 서비스마다 crate 또는 feature 생성
- build-time DB 접속과 개인 `DATABASE_URL`
- 기본 경로의 OpenSSL system dependency
- 근거 없는 `build.rs`, proc-macro, ORM, gRPC
- 일상 fast lane의 전체 workspace clean rebuild

## Web 금지

- npm·pnpm·Yarn과 Bun 혼용
- Tailwind CLI와 Vite Tailwind plugin 동시 사용
- shadcn runtime registry 의존
- Storybook·monorepo orchestrator를 MVP 필수 도구로 추가
- `latest` 범위를 manifest나 release 명령에 남김

## 의존성 승인 질문

1. 표준 라이브러리나 기존 의존성으로 해결할 수 없는가?
2. runtime·build·native graph가 얼마나 늘어나는가?
3. 동일 책임의 도구가 이미 있는가?
4. Ubuntu VM과 clean install에서 재현되는가?
5. 제거·업데이트 owner가 누구인가?

답이 문서화되지 않으면 추가하지 않습니다.

## PAM native exception

ADR-0007은 Linux PAM 요구 때문에 `libpam` native dependency와 `ffi-pam` 경계를 승인합니다. 이는 blanket native 허용이 아닙니다. 정확한 binding·package는 P1 compatibility spike, unsafe review, Ubuntu 24.04 clean build, authd VM scenario가 통과한 뒤 pin합니다. agentd와 opsd dependency graph에는 PAM FFI를 넣지 않습니다.
