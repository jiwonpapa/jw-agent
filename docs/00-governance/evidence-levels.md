# Evidence Levels

Status: Accepted  
Authority: Governance  
Owner: Verification Maintainer  
Last reviewed: 2026-07-21

| Level | 뜻 | 허용 주장 |
|---|---|---|
| `DOC_ACCEPTED` | spec·정책이 승인됨 | 구현 계획 확정 |
| `LOCAL_PASS` | 고정 도구로 자동검증 통과 | 로컬 코드 검증 |
| `VM_PASS` | 폐기 가능한 Ubuntu VM 장애시험 통과 | 해당 환경의 운영 동작 검증 |
| `RELEASE_PASS` | 서명된 artifact 설치·업데이트·복구 통과 | 배포 후보 완료 |

Evidence에는 spec ID, commit, dirty 여부, toolchain, lockfile, 실행 환경, gate result, 시작·종료시각, artifact hash를 포함합니다.

현재 문서·Rust·계약·웹 unit/build와 mock browser 범위는 `LOCAL_PASS`를, 전용 Ubuntu 24.04 VM의 PAM·systemd·Nginx·TLS·`.deb` 설치·site-state·active managed-config·복구 범위는 `VM_PASS`를 획득했습니다. 이 증거는 private-LAN test CA와 unsigned local package에 한정되며, 공인 DNS·Certbot 발급·서명 release 또는 운영 안전을 주장하지 않습니다.
