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
