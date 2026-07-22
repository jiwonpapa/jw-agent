# ACCESS-OPENSSH-SFTP-ATOMIC-UPLOAD-V1

Status: Accepted  
Authority: Access Specification  
Owner: Manual Access Maintainer  
Last reviewed: 2026-07-22

## User job

로그인한 non-root Linux 사용자가 자기 홈 안의 일반 파일을 새로 올리거나 명시적으로 교체합니다. 서버 설정 adapter의 G2 편집과 분리된 `G1 MANUAL_NON_REVERSIBLE` 작업이며 자동 백업·원복을 약속하지 않습니다.

## API and approval

- `POST /api/v1/files/upload/plans`: file session, 상대 path, byte 수, 새 content SHA-256, PAM password와 위험 동의를 검증
- `POST /api/v1/files/upload`: opaque file-session token과 single-use upload-plan token을 header로 받고 `application/octet-stream` body를 처리
- plan token은 URL·cookie·DB·log·browser storage에 저장하지 않고 memory에서 2분 뒤 폐기
- plan은 JW session·Linux subject·ingress·Origin·file session·path·before state·after digest·byte 수에 bind
- 기존 대상 교체는 별도 `overwriteConfirmed`, 모든 업로드는 `nonReversibleConfirmed`가 필요
- body 길이·digest 불일치, 만료·재사용·다른 session·Origin은 side effect 전에 차단

## Write boundary

- non-empty UTF-8 상대 path와 [read-only path contract](openssh-sftp-readonly-v1.md)를 그대로 사용
- parent를 `REALPATH`로 canonicalize하고 home root와 같거나 그 아래인지 확인
- 대상은 missing 또는 direct regular file만 허용하고 symlink·directory·other type은 거부
- 기존 파일은 최대 8 MiB까지 읽어 plan 시 SHA-256을 고정하고 apply 직전에 다시 비교
- reserved basename `.jw-agent-upload-` prefix는 user target으로 거부
- 새 파일 mode는 `0600`, 기존 파일은 type·special bit를 제외한 기존 permission을 보존
- opsd·authd·certd에는 path, body, SFTP write surface를 추가하지 않음

## Atomic apply and read-back

1. 감사 DB에 immutable plan metadata를 기록합니다.
2. apply 전에 plan을 single-use로 소비하고 감사 state를 `applying`으로 기록합니다.
3. 같은 parent에 random reserved temporary file을 exclusive create합니다.
4. 32 KiB 이하 chunk로 쓰고 OpenSSH `fsync@openssh.com` 성공을 요구합니다.
5. `posix-rename@openssh.com`으로 target을 원자 교체합니다.
6. target을 다시 읽어 size와 SHA-256이 plan과 같은지 검증합니다.
7. rename 전 실패는 temporary file 삭제를 시도하고 실패를 보고합니다.
8. rename 결과가 불명확하거나 read-back이 다르면 `manual_recovery_required`이며 성공·원복으로 표시하지 않습니다.

SFTP v3 handshake가 두 OpenSSH extension을 광고하지 않으면 write capability는 `UNSUPPORTED`입니다. v3 기본 `RENAME`으로 조용히 약화하지 않습니다.

## Limits and body handling

- upload 최대 8 MiB, request body는 선언 크기보다 1 byte라도 크면 즉시 중단
- public Nginx는 exact upload route만 8 MiB로 열고 다른 JSON route의 64 KiB limit는 유지
- agentd는 body를 직접 bounded collect하며 Content-Type과 Content-Length를 검증
- 동시 upload plan은 file session당 1개, 전역 8개 이하
- session idle 2분·max 10분과 logout/revoke/daemon restart 규칙을 재사용
- browser는 선택한 file bytes와 plan token을 memory에만 두며 재시작 resume을 제공하지 않음

## Text editing

- UTF-8 text preview의 digest를 before state로 사용하고 256 KiB 이하만 편집
- line ending을 표시하고 저장 시 사용자가 선택하지 않는 한 원문의 LF/CRLF를 유지
- textarea를 우선 사용하며 Monaco는 별도 build-graph ADR 전 추가하지 않음
- 저장도 upload plan/apply를 사용하므로 별도 우회 endpoint가 없음

## Audit and recovery

- DB에는 upload ID, actor/session, path domain-separated SHA-256, before/after digest, byte count, state, result, 시각만 저장
- password, token, 원문 path, file body, temporary basename은 DB·journal·argv·browser storage에 저장하지 않음
- plan audit 실패 시 OpenSSH write를 시작하지 않고, apply-start audit 실패 시 temporary file도 만들지 않음
- daemon 시작 시 남은 `applying` record는 `interrupted_manual_check`로 닫음
- 프로세스 강제 종료 뒤 user-owned reserved temp가 남을 수 있음을 UI와 receipt에 명시하며 자동 원복을 주장하지 않음

## Failure classes

`upload_too_large`, `upload_length_mismatch`, `upload_digest_mismatch`, `upload_plan_expired`, `upload_plan_rejected`, `overwrite_confirmation_required`, `target_changed`, `target_symlink_denied`, `target_type_unsupported`, `sftp_write_extension_unavailable`, `temporary_cleanup_failed`, `manual_recovery_required`를 구분합니다.

## Acceptance

- new file와 explicitly confirmed overwrite 성공, mode·size·digest read-back
- stale target digest, symlink, directory, traversal, home escape와 reserved name 거부
- 8 MiB+1, declared/body length와 digest 불일치가 side effect 전 거부
- plan replay, expiry, cross-session, wrong-Origin, logout 뒤 적용 거부
- write/close/fsync/rename failure에서 성공 또는 자동 원복으로 오표시하지 않음
- rename 전 failure의 temporary cleanup과 rename 결과 불명확 시 manual recovery 표시
- G1 경고·scope·원복 불가·검증 방법을 320px mobile에서도 승인 버튼 위에 표시
- password/token/path/body가 SQLite·journal·argv·browser storage에 없음
- normal SSH와 opsd safety kernel은 upload 실패와 무관하게 유지

## Evidence

- `p2-local`의 contract, Rust policy, OpenAPI drift, clippy/test/build gate 통과
- Playwright 320px flow에서 G1 범위·원복 불가·두 확인·PAM plan·최종 apply와 browser secret 비저장 통과
- Ubuntu 24.04 `VM-P2-OPENSSH-SFTP-ATOMIC-UPLOAD`에서 create/replace, mode·digest read-back, stale target, symlink·directory·traversal·digest·wrong-Origin·replay denial, metadata-only audit와 temp cleanup 통과
- VM package `jw-agent_0.2.0~p2.11_amd64.deb`, SHA-256 `f1f4719ccd0d73071f7a46cdf1c3dd2d373028a0b463ae054798c7b4c39f5186`, Lintian clean

## Excluded

delete, move, rename UI, mkdir, chmod/chown, symlink 생성, recursive transfer, resume, system-owned/protected config, root login, private-key storage, SFTP write 자동 rollback은 이 버전에 없습니다.
