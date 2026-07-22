# JW Agent

Ubuntu 24.04 LTS 서버의 **범용 서비스 설정·유지보수 작업을 안전하게 수행하는 단일 서버 우선 관리 콘솔**입니다.

현재 단계는 `P2 Safe local operations`입니다. durable safety kernel, Nginx G2 작업, Certbot one-shot 경계·인증서 조회·G1 갱신 dry-run, guided 발급의 안전한 CA 실패 경로, 보호 vhost 인증서 연결 G2, non-root terminal G1과 home-scoped SFTP read G0/create·replace G1을 Ubuntu VM에서 검증했습니다. 공인 CA 발급 성공, 범용 SFTP 쓰기와 P2 전체 완료는 아직 주장하지 않습니다.

이 저장소의 P1 기준점은 공개 개발 스냅샷이며 아직 오픈소스 릴리스가 아닙니다. `LICENSE`가 추가되기 전에는 사용·수정·재배포 권한을 부여하지 않으며, 정식 라이선스는 P3 release 준비에서 명시적으로 결정합니다.

## 제품 한 줄 정의

> 변경 전에 계획과 영향을 보여주고, 정형화된 작업을 snapshot·검증·원복하는 Ubuntu 서버 케어 콘솔

## 현재 확정 범위

- 신규 독립 저장소·DB·프로토콜·설치·릴리스 체계
- Ubuntu 24.04 LTS amd64 우선
- 공개 HTTPS와 loopback·SSH 터널 복구 경로를 함께 지원
- 공개 경로는 Nginx+Certbot 443에서 agentd 전용 Unix socket으로 proxy
- Linux PAM ID·비밀번호, 허용 Linux group 기반 권한
- Rust `agentd` 비-root / `authd`·`opsd` root·networkless 분리
- React + TypeScript + Bun + Vite + Tailwind CSS CLI + shadcn/ui
- desktop·tablet·mobile 반응형 웹
- 호스트·Nginx 관찰, typed site state, 활성 allowlisted Nginx 설정 편집
- sanitized 인증서 inventory, 갱신 dry-run, DNS·webroot preflight 기반 Certbot 발급 계획·PAM 승인, 보호 vhost TLS 연결·원복
- 기존 OpenSSH 기반 non-root 웹 터미널, 홈 한정 파일 탐색·미리보기·다운로드와 계획된 일반 파일 생성·교체
- 계획→snapshot→적용→검증→자동 원복, 비동기 실행과 SSE 진행 증거
- 임의 shell·임의 path·보호된 관리 vhost 변경은 제공하지 않음
- 원격 GitHub Actions 사용 금지, 로컬 단일 `xtask` 검증

## 읽는 순서

1. [헌법](CONSTITUTION.md)
2. [문서 지도](docs/README.md)
3. [제품 경계](docs/10-product/product-boundary.md)
4. [MVP 범위](docs/10-product/mvp-scope.md)
5. [시스템 구조](docs/20-architecture/system-context.md)
6. [개발 단계](docs/80-delivery/roadmap.md)

## P2 검증

```bash
cargo xtask verify p2-local
cargo xtask verify p2-browser
```

`p2-local`은 문서, Rust safety kernel, OpenAPI drift, 웹 type/lint/unit/build를 검증합니다. `p2-browser`는 PAM 승인, 보장 범위 선표시, operation timeline, 실패·원복 표현, 320/390/768/1024/1440 반응형과 접근성을 검증합니다.

Ubuntu evidence는 별도 환경 입력과 immutable package checksum을 요구합니다.

```bash
cargo xtask verify p2-vm
```

현재 VM evidence와 private-LAN test CA 한계는 [tests/vm/README.md](tests/vm/README.md)에 기록합니다. 발급 실패 처리는 검증했지만 이것은 공인 DNS·공인 CA 발급 성공·signed release 또는 운영 안전 증거가 아닙니다.
