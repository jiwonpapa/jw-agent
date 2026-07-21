# Update and Supply-chain Security

Status: Accepted  
Authority: Security  
Owner: Release Maintainer  
Last reviewed: 2026-07-21

## Artifact

- `.deb`
- SHA-256 checksum manifest
- SBOM
- release signature and public verification instructions
- gate evidence manifest
- supported matrix and known limitations

## Update rules

- 자동 무승인 update 금지
- version과 release notes를 사용자에게 표시
- downgrade는 compatibility policy에 따라 거부하거나 명시적으로 복구
- maintainer script는 network call, user service edit, secret 출력 금지
- PAM service, authd socket, role group, Nginx template의 owner/mode를 artifact manifest에 포함
- DB migration 전 상태와 rollback limitation을 기록
- binary 교체 실패 후 이전 실행 가능 상태를 VM에서 검증

## Local release

`.github/workflows`를 사용하지 않습니다. release owner가 clean checkout에서 `xtask release` lane을 실행하고 evidence manifest와 artifact를 서명합니다.

로컬 검증은 committer의 악의적 우회를 기술적으로 막지 못합니다. 신뢰 기준은 branch badge가 아니라 서명 artifact, reproducible inputs, 공개 evidence입니다.
