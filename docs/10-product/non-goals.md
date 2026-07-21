# Non-goals

Status: Accepted  
Authority: Product  
Owner: Product Maintainer  
Last reviewed: 2026-07-21

## 절대 제외

- `opsd` 임의 shell command·PTY·사용자 argv API
- 공개 agentd/opsd/authd 포트와 root 웹 로그인·터미널
- 범용 root `/etc` 편집·파일 CRUD와 자체 SSH/SFTP protocol server 구현
- 브라우저에 SSH private key·root password 저장
- 감사 로그 삭제 시 앱 전체 종료 또는 진단 차단
- blockchain·외부 불변 원장
- AI의 직접 변경·승인·원복 판단
- 기존 프로젝트 코드·DB·프로토콜·설치기·release ownership 재사용; 고정된 read-only curated catalog는 허용
- 원격 GitHub Actions

## MVP 제외

- 중앙관제, PostgreSQL, 조직·고객·직원 RBAC
- Docker 앱스토어, Kubernetes, 메일·DNS hosting
- VM 생성·cloud provider billing
- multi-distro abstraction
- plugin marketplace·dynamic plugin ABI
- remote manifest 기반 임의 제품 설치와 command 실행
- native mobile app·Tauri·PWA·service worker·push notification
- Storybook·microfrontend·monorepo orchestrator

기존 OpenSSH를 사용하는 비-root terminal·SFTP client/relay, 그리고 adapter가 allowlist한 typed 설정 편집은 위 절대 제외에 해당하지 않습니다. 이 표면은 [ADR-0010](../90-specs/adr/0010-local-maintenance-surfaces.md)의 권한·보장 경계를 따릅니다.

## 후속 검토 조건

제외 기능은 사용자의 반복된 실제 문제, 안전 보장, 개발·운영 비용, 기존 범위 침식 여부를 근거로 새 product decision을 받아야 합니다.
