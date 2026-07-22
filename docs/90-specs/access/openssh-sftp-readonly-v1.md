# ACCESS-OPENSSH-SFTP-READONLY-V1

Status: Accepted  
Authority: Access Specification  
Owner: Manual Access Maintainer  
Last reviewed: 2026-07-22

## User job

로그인한 Linux 사용자가 자신의 홈 디렉터리 안에서 파일을 찾아보고, 작은 텍스트를 확인하고, 제한된 크기의 파일을 내려받습니다. 이 단계는 파일을 변경하지 않는 `G0 READ_ONLY` 수직 기능입니다.

## API and session

- `GET /api/v1/files`: capability와 고정 limit
- `POST /api/v1/files/sessions`: PAM 재인증과 loopback OpenSSH SFTP subsystem 연결
- `POST /api/v1/files/list`, `/stat`, `/read`, `/download`: opaque memory-only file session token과 상대 경로 사용
- `POST /api/v1/files/sessions/close`: 즉시 프로세스와 토큰 폐기
- session token은 URL, cookie, DB, log, browser storage에 저장하지 않음
- 한 JW session당 file session 1개, 전체 8개, idle 2분, 최대 10분
- logout, JW session rotation, public disable, daemon restart 시 file session 폐기

비밀번호는 PAM과 one-shot FIFO askpass에만 잠시 존재하며 OpenSSH 인증 직후 폐기합니다. 인증된 SFTP process만 세션 수명 동안 유지합니다.

## Fixed OpenSSH boundary

- `/usr/bin/ssh -s ... 127.0.0.1 sftp`를 fixed argv로 실행
- password-only, strict loopback host key, forwarding·agent·local command·PTY 비활성
- browser가 SSH/SFTP protocol이나 host key를 처리하지 않음
- agentd가 SFTP v3의 `REALPATH`, `STAT`, `OPENDIR`, `READDIR`, `OPEN`, `READ`, `CLOSE`만 생성
- write 계열 message와 임의 subsystem·remote command·user argv는 구현하지 않음
- opsd에는 SFTP, path, file body, shell surface를 추가하지 않음

## Home confinement

- session 시작 때 server `REALPATH(".")` 결과를 canonical home root로 고정
- API 경로는 `/`로 시작하지 않는 UTF-8 상대 경로만 허용
- empty component, `.`, `..`, NUL, control, component 255 bytes 초과, 전체 1024 bytes 초과 거부
- 실제 접근 전에 server `REALPATH`를 수행하고 canonical target이 home root와 같거나 `home/` prefix인지 확인
- symlink가 home 밖을 가리키면 list/stat/read/download를 거부
- directory response의 unsafe filename과 500개 초과 entry를 거부

TOCTOU를 완전히 제거한다고 주장하지 않습니다. 공격자가 검사와 OPEN 사이에 경로를 교체할 수 있는 shared home은 잔여 위험이며, 쓰기 기능 전 별도 hardening을 요구합니다.

## Limits and data handling

- protocol packet 256 KiB, operation timeout 5초
- list 최대 500 entries
- text read 최대 256 KiB, UTF-8만 허용
- download 최대 8 MiB
- response에 `Cache-Control: no-store`, download에 safe fixed filename 처리
- password, session token, file body, 원문 path를 SQLite·journal·browser storage에 저장하지 않음

감사 evidence는 actor, session ID, ingress, start/end, close reason, action, path SHA-256, byte count, result만 저장합니다.

## Failure classes

`path_invalid`, `path_outside_home`, `not_found`, `permission_denied`, `not_directory`, `not_regular_file`, `text_too_large`, `download_too_large`, `binary_text`, `sftp_protocol_error`, `openssh_authentication_failed`, `session_expired`를 구분합니다. 실패가 sshd 설정이나 opsd 상태를 변경하지 않습니다.

## Acceptance

- non-root 홈의 list/stat/UTF-8 read/download 성공
- absolute/traversal/control/oversized path 거부
- home 밖 symlink escape 거부
- oversized text/download와 directory-as-file 거부
- wrong JW session/origin/ingress, replay after close, idle/max expiry 거부
- logout과 daemon restart 뒤 process/token 폐기
- package VM에서 LAN SSH password 정책을 넓히지 않고 loopback fixture만 사용
- SQLite, journal, `/proc` argv/environment, browser storage에 password/token/path/file body 없음
- opsd source와 API에 SFTP·shell·user path surface 없음

## Deferred G1

upload, create와 text save는 [ACCESS-OPENSSH-SFTP-ATOMIC-UPLOAD-V1](openssh-sftp-atomic-upload-v1.md)의 별도 G1 계약으로만 구현합니다. delete, move, chmod는 계속 이 spec 밖이며 UI와 API에서 차단합니다.
