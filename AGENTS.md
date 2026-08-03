# Repository Instructions

## 대화

- 존댓말을 사용하고 사용자를 “형님”이라고 부릅니다.
- 결론과 중요한 결과부터 간결하게 보고합니다.

## 작업 권위

1. [CONSTITUTION.md](CONSTITUTION.md)
2. Accepted ADR
3. Accepted specification
4. Architecture and delivery documents
5. Implementation

충돌 시 높은 권위 문서를 따릅니다. 코드나 테스트가 명세를 몰래 바꾸면 안 됩니다.

## 현재 단계

- P1은 Ubuntu VM 증거까지 완료되었고 현재 단계는 `P2 Safety kernel and local maintenance surfaces`입니다.
- 첫 활성 write scope는 Accepted `OPS-NGINX-SITE-STATE-V1`과 그 safety kernel·UI·fault evidence입니다.
- managed config, Certbot, non-root OpenSSH terminal·SFTP는 각각 Accepted spec과 선행 gate가 준비된 순서에만 구현합니다.
- `opsd` 임의 shell·PTY·사용자 argv, root 웹 터미널, 범용 root 파일 CRUD와 중앙관제 구현은 금지합니다.
- 기존 프로젝트 코드를 복사하거나 dependency로 연결하지 않습니다.
- `.github/workflows`를 만들거나 원격 Actions를 소비하지 않습니다.

## 변경 전 필수 확인

- 관련 spec ID와 acceptance scenario가 있는지 확인합니다.
- 새 crate·도구·검증 gate가 정말 별도 소유권을 가져야 하는지 확인합니다.
- 동일 검사가 기존 `xtask` GateId에 있는지 확인합니다.
- 빌드 그래프, native dependency, code generation, feature 조합을 늘리면 ADR이 필요합니다.

## 검증

- 검증 로직은 `xtask`만 소유합니다.
- Makefile, Git hook, 셸 wrapper는 검사를 재구현할 수 없습니다.
- 변경 단계에 맞는 lane을 실행하고 결과를 과장하지 않습니다.

## 작업공간 정리

- 빌드·테스트를 수행한 작업은 최종 보고 전에 프로젝트 소유 산출물 용량을 확인합니다.
- `.playwright-mcp`, `apps/web/dist`, `apps/web/playwright-report`, `apps/web/test-results`는 최종 증거를 `output/`에 보존한 뒤 작업 종료 시 정리합니다.
- 빌드 속도를 위해 `target/debug/incremental`, `target/debug/deps`, `target/release`, cross-target release와 `node_modules`는 자동 삭제하지 않습니다.
- `cargo clean`, 전체 `target` 삭제, `output/`과 VM·release evidence 자동 삭제는 금지합니다.
- 내부 디스크 여유가 100 GiB 미만이거나 한 프로젝트의 `target`이 20 GiB를 넘으면 용량만 보고하고, 캐시 삭제는 사용자 승인 뒤 수행합니다.
- `target`, `node_modules`, `dist`, test report와 coverage 등 재생성 가능 산출물은 프로젝트 백업 대상에서 제외합니다.
