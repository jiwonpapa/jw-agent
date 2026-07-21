# Domain Map

Status: Accepted  
Authority: Domain  
Owner: Architecture Maintainer  
Last reviewed: 2026-07-21

| Domain | 책임 | MVP owner |
|---|---|---|
| Host Observation | host resource와 OS facts | agentd |
| Service Inventory | 발견·상태·capability | agentd, authoritative preflight는 opsd |
| Access Edge | public HTTPS proxy·loopback recovery | Nginx/agentd |
| Identity | PAM auth·account·Linux group role | authd/PAM/NSS |
| Safe Operation | plan·lock·snapshot·apply·verify·rollback | opsd |
| Managed Configuration | adapter resource·diff·syntax·service health | opsd, projection은 agentd/web |
| Certificate Lifecycle | Certbot preflight·issuance·renewal·Nginx attach | opsd |
| Manual Access | non-root OpenSSH terminal·SFTP session | agentd/OpenSSH |
| Evidence | lifecycle receipt·digest·continuity | opsd |
| UI Projection | 사용자가 이해할 read model | agentd/web |
| Distribution | package·systemd·update·release evidence | packaging/xtask |
| Central Management | tenant·customer·outbound orchestration | post-MVP |

## 경계 기준

도메인은 다음이 다를 때 분리합니다.

- 불변식과 권위 원본
- 권한 주체와 공격 표면
- 실패·복구 의미
- lifecycle과 배포 단위

HTTP handler·DB table·화면 메뉴를 도메인으로 착각하지 않습니다.

## 핵심 언어

- `Observation`: 기준시각이 있는 읽기 사실
- `Capability`: 현재 host에서 가능한 typed 행동 선언
- `Plan`: 승인 가능한 immutable 예상 작업
- `Operation`: 승인 plan의 durable 실행
- `Receipt`: 단계와 근거를 담은 evidence
- `Snapshot`: 특정 operation rollback을 위한 사본
- `Backup`: 독립적인 보존·복구 제품 개념, snapshot과 다름
- `Manual Session`: 자동 rollback 대상이 아닌 짧은 G1 OpenSSH 접근
