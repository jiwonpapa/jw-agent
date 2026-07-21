# ACCESS-OPENSSH-PASSWORD-BROKER-V1

Status: Accepted  
Authority: Access Specification  
Owner: Manual Access Maintainer  
Last reviewed: 2026-07-22

## Purpose

현재 JW session의 canonical non-root Linux 계정으로 loopback OpenSSH에 한 번 로그인하기 위한 password를 짧은 수명의 server-side ticket에 보관합니다. password를 DB, 파일, 브라우저 저장소, URL, argv, environment, audit 또는 terminal transcript에 남기지 않습니다.

## Request and response

- `POST /api/v1/terminal/tickets`
- request: `password`, `rows`, `cols`, `riskConfirmed`
- response: opaque `ticket`, `expiresAt`, `websocketPath`, assurance와 session limits
- request는 authenticated JW session, exact Host/Origin, CSRF, 최근 PAM 재검증을 한 번에 수행합니다.
- username은 request로 받지 않고 JW session의 canonical username만 사용합니다.

`password`는 PAM 재검증용 복사와 SSH one-shot 전달용 복사 두 개만 잠시 존재합니다. 둘 다 `SecretString` 또는 `Zeroizing` owner가 소유하며 PAM 성공 또는 실패 뒤 불필요한 복사를 폐기합니다.

## Ticket

- 256-bit CSPRNG bearer, base64url, 단일 사용, TTL 30초
- JW session digest, UID, username, ingress, exact origin, purpose `terminal`에 bind
- 원문 ticket과 password는 process memory에만 존재하며 restart 시 전부 폐기
- ticket은 URL query에 넣지 않고 WebSocket subprotocol의 `ticket.<base64url>`로 한 번 전달
- consume, expiry, logout, session rotation, public disable 시 즉시 제거
- 사용자와 JW session별 동시 terminal은 1개

## SSH credential transfer

- system `/usr/bin/ssh`만 고정 인자로 실행하며 user-controlled argv와 remote command는 없음
- `SSH_ASKPASS`는 동일 설치 바이너리의 제한된 askpass mode만 사용
- password는 root가 아닌 `jw-agent` 소유 mode `0600` one-shot FIFO로 전달
- FIFO path는 `/run/jw-agent/askpass/` 하위의 server-generated name만 허용하고 type, owner, mode를 다시 검증
- helper는 FIFO를 한 번 열고 즉시 unlink한 뒤 bounded password 한 줄만 stdout으로 반환
- SSH 인증 직후 parent copy, FIFO, askpass process를 폐기

## Authorization and fail-closed rules

- UID 0, `viewer`, canonical username/UID mismatch, PAM account denial은 거부
- 추가 인증 정책이 `disabled`가 아니고 provider가 구현되지 않은 현재 단계에서는 terminal ticket을 거부
- password/key 저장, root login, product-driven sudo password 입력, SSH agent forwarding은 금지
- OpenSSH client, sshd, strict known-host authority 중 하나라도 없으면 capability와 ticket을 `UNAVAILABLE`로 유지
- sshd의 loopback `PasswordAuthentication`은 설치기가 자동 변경하지 않습니다. 비활성 서버에서는 terminal 인증이 실패하며, 향후 별도 G2 설정 operation 전까지 운영자가 loopback에만 명시적으로 활성화해야 합니다.

## Audit and redaction

저장 허용: actor UID/username, ingress, opaque session ID의 digest, start/end, close reason, byte counts, exit/disconnect class. 저장 금지: password, ticket, command, input, output, terminal title, environment, file body.

## Acceptance

- auth 실패, wrong Origin, CSRF, UID 0, viewer, 추가 인증 미지원에서 ticket 미발급
- ticket replay, wrong session/origin/purpose, 30초 만료 거부
- process restart와 logout 뒤 ticket·active session 폐기
- `/proc` argv/environment, SQLite, journal, browser storage에 password/ticket/transcript 없음
- forced askpass/FIFO/SSH failure가 기존 sshd, opsd, JW session을 변경하지 않음
- disposable VM은 public/LAN SSH 정책을 넓히지 않고 `Match LocalAddress 127.0.0.1` fixture에서만 password 인증 성공을 증명
