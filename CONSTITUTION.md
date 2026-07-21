# JW Agent Constitution

Status: Accepted  
Authority: Supreme  
Owner: Maintainers  
Last reviewed: 2026-07-21

이 문서는 제품·문서·검증·릴리스보다 높은 권위를 가집니다. 예외는 제12조 절차를 따릅니다.

## 제1조 — 빌드지옥 절대 금지

1. 검증된 Rust toolchain과 MSRV를 한 release line으로 고정하고 `Cargo.lock`을 커밋합니다.
2. workspace dependency·lint·profile의 권위 원본은 루트 manifest 한 곳입니다.
3. 외부 `git` dependency와 workspace 밖 `path` dependency를 금지합니다.
4. 서비스별 crate, 계층별 repository crate, 추상화만 있는 `common/utils/core` crate를 금지합니다.
5. crate는 프로세스·권한·안정 계약·FFI 또는 측정된 빌드 병목이 있을 때만 분리합니다.
6. `tokio = full`, 무차별 `--all-features`, 서비스 조합용 Cargo feature를 금지합니다.
7. native dependency, `build.rs`, macro-heavy ORM, build-time 외부 서비스 의존은 ADR과 Ubuntu VM 증거 없이 추가할 수 없습니다.
8. TLS stack은 하나만 사용하며 OpenSSL system dependency를 MVP 기본값으로 두지 않습니다.
9. 전체 clean build를 일상 검증으로 강제하지 않습니다. 변경 scope 검증 후 단계적으로 확장합니다.
10. `cargo clean`, 무근거 전체 rebuild, 도구체인 혼용으로 문제를 숨기지 않습니다.
11. 의존성 갱신은 작은 호환 묶음으로 수행하고 lockfile diff와 빌드 시간을 기록합니다.
12. 개인 전역 설정이나 비공개 환경 변수로만 성공하는 빌드는 실패입니다.

## 제2조 — 중복 검증 하네스 절대 금지

1. 검증 로직과 GateId registry의 유일한 소유자는 Rust `xtask`입니다.
2. Makefile·Git hook·셸은 `xtask` 호출만 할 수 있고 판단 로직을 가질 수 없습니다.
3. lane은 GateId를 조합하며 명령을 복사하지 않습니다.
4. 같은 위험을 서로 다른 도구로 반복 검사하지 않습니다. 중복이 필요하면 서로 다른 실패 모델을 문서화합니다.
5. gate 문서·실행·evidence 이름은 같은 registry에서 파생합니다.
6. 미구현 gate를 성공 처리하는 no-op, `SKIPPED`를 성공으로 포장하는 release를 금지합니다.
7. 각 gate는 owner, scope, timeout, 입력, 출력, 실패 정책을 하나만 가집니다.

## 제3조 — 지원 범위가 곧 보안 경계

1. 제품은 모든 Linux 관리 패널이 아닙니다.
2. 범용성은 임의 명령이 아니라 공통 `Service Adapter` 계약으로 얻습니다.
3. 서비스·버전·파일 layout·operation이 지원표에 없으면 관찰 또는 `UNSUPPORTED`로 종료합니다.
4. 추측한 경로·패키지·설정을 변경하지 않습니다.
5. MVP 범위를 벗어난 기능을 빈 UI, 플래그, 미완성 API로 미리 만들지 않습니다.

## 제4조 — 권한 분리와 typed operation

1. `agentd`는 비-root, `authd`와 `opsd`는 서로 분리된 root 경계로 실행합니다.
2. `authd`는 systemd socket activation으로 요청당 한 번 실행하며 Linux PAM 인증·account check·role 판정만 수행합니다.
3. `opsd`는 typed privileged operation만 수행합니다. 비밀번호와 PAM을 처리하지 않습니다.
4. `authd`와 `opsd`는 TCP listener가 없으며 각각 전용 Unix domain socket, peer UID, version, 크기, allowlist를 검증합니다.
5. PAM C FFI의 `unsafe`는 `ffi-pam`에만 허용하고 나머지 crate는 `#![forbid(unsafe_code)]`를 적용합니다.
6. UID 0 root의 웹 로그인, 임의 shell, PTY, root 웹 터미널, 범용 파일 CRUD, 임의 `/etc` 편집 API를 금지합니다.
7. UI와 `agentd`는 안전 여부를 최종 판정하지 않습니다. 적용 직전 preflight의 권위는 `opsd`입니다.

## 제5조 — Spec before code

1. 제품 코드는 Accepted spec과 acceptance scenario 없이 시작하지 않습니다.
2. 변경은 spec ID, domain owner, 위험·복구 보장, 필요한 gate를 선언합니다.
3. 중요한 구조 변경은 ADR로 결정하고 만료된 결정을 폐기합니다.
4. 코드·테스트·화면이 문서에 없는 새 동작을 만들면 drift 실패입니다.

## 제6조 — 단일 권위 원본과 하드코딩 금지

1. 환경값·경로·임계치·상태·capability·문구·색상·API type을 화면과 모듈에 흩뿌리지 않습니다.
2. 이름·단위·근거·owner가 있는 typed constant와 명시적 기본값은 허용합니다.
3. Ubuntu 표준 경로는 support profile 한 곳에서 관리하고 실행 전 discovery로 확인합니다.
4. IPC shape는 Rust contract type, REST shape는 생성 OpenAPI, DB는 migration, operation은 registry가 권위 원본입니다.
5. UI type과 capability 표는 권위 원본에서 생성합니다. 수기 복제를 금지합니다.
6. 동적 Tailwind class 문자열, raw color, 화면별 formatter와 직접 `fetch`를 금지합니다.

## 제7조 — 증거보다 큰 주장을 금지

1. 문서 승인, 로컬 자동검증, Ubuntu VM 검증, 릴리스 설치검증을 구분합니다.
2. `DOC_ACCEPTED`를 구현 완료로, `LOCAL_PASS`를 운영 안전으로 표현하지 않습니다.
3. release 필수 gate에는 `SKIPPED`를 허용하지 않습니다.
4. evidence에는 commit, dirty 상태, toolchain, lockfile hash, feature set, gate 결과와 artifact hash를 기록합니다.

## 제8조 — 안전 작업 상태기계

1. 모든 쓰기 작업은 `plan → snapshot → apply → read-back → verify → rollback` 의미를 명시합니다.
2. plan hash, 만료, precondition digest, idempotency key, resource lock이 필수입니다.
3. side effect 전 durable state를 기록하고 재시작 후 OS read-back으로 재개·원복을 결정합니다.
4. “rollback”은 operation별 보장 대상을 정확히 복원할 때만 사용합니다.
5. 원복 불가능한 행동은 그렇게 표시하고 MVP 쓰기 기능으로 노출하지 않습니다.

## 제9조 — 로그·비밀·포렌식

1. 감사 evidence는 허용 필드만 기록하고 PAM 비밀번호·session token 등 비밀은 URL query·argv·로그·DB·브라우저 저장소에 넣지 않습니다.
2. 외부 명령은 timeout, 출력 크기 제한, redaction, process-group 종료가 필수입니다.
3. ledger 손상·삭제·연속성 실패 시 쓰기 작업을 막는 `FORENSIC_LOCKDOWN`으로 전환합니다.
4. lockdown에서도 읽기 진단과 evidence export는 유지합니다.
5. 앱이 만든 로그만으로 사용자 과실을 단정하지 않으며, 관찰 사실과 추론을 구분합니다.

## 제10조 — 단일 서버와 이중 접근 경로 우선

1. MVP는 한 서버에서 공개 HTTPS와 loopback·SSH 터널 복구 경로를 모두 지원합니다.
2. 공개 모드는 명시적으로 활성화하며 Nginx+Certbot 443만 인터넷에 노출합니다. agentd 내부 listener와 Unix socket은 공개하지 않습니다.
3. HTTP 공개, 유효하지 않은 인증서, CORS 기반 외부 origin, direct agentd public bind를 금지합니다.
4. 공개 관리용 Nginx resource는 `system-owned/protected`로 분류하여 일반 service operation이 변경하지 못하게 합니다.
5. Nginx·TLS·DNS 장애에도 SSH 터널 복구와 공개 모드 해제가 가능해야 합니다.
6. 중앙관제 crate·PostgreSQL·멀티테넌트·원격 작업은 단일 서버 MVP gate가 통과한 뒤 시작합니다.
7. 중앙 장애나 제품 제거 후에도 서버 서비스와 OpenSSH는 독립적으로 작동해야 합니다.

## 제11조 — 로컬 릴리스와 공급망

1. 원격 GitHub Actions와 유료 원격 workflow 소비를 금지합니다.
2. 서명된 로컬 release evidence와 artifact가 최종 신뢰 기준입니다.
3. `.deb`, checksum, SBOM, signature, install·upgrade·recovery 증거를 함께 배포합니다.
4. 기존 제품의 crate·DB·protocol·installer·release 체계를 공유하지 않습니다.

## 제12조 — 개정과 예외

1. 헌법 개정은 ADR, 영향 분석, 이전 규칙 migration, 명시적 승인으로만 가능합니다.
2. 임시 예외는 이유·범위·owner·만료일·제거 gate를 기록합니다.
3. root·PAM 경계, root 웹 로그인 금지, 임의 shell 금지, 비밀 비노출, release 서명, 고객/tenant 격리에는 예외가 없습니다.
4. “일단 구현”과 일정 압박은 예외 사유가 아닙니다.
