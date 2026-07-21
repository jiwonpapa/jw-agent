# Interface Contracts

Status: Accepted  
Authority: Contract  
Owner: API Maintainer  
Last reviewed: 2026-07-21

정확한 schema는 Rust contract type에서 생성한 OpenAPI가 소유합니다. 아래는 경계와 최소 필드입니다.

## Browser ↔ agentd

- public requests arrive only through Nginx HTTPS and dedicated UDS
- recovery requests arrive through 127.0.0.1-only HTTP over SSH tunnel and never trust proxy headers
- REST `/api/v1` for commands and snapshots
- P2부터 SSE for operation progress
- `application/problem+json` for errors
- RFC 3339 UTC timestamps
- byte counts as integer, formatted only in UI
- mutation automatic retry and optimistic success prohibited

P1 구현 endpoint:

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/session`
- `POST /api/v1/auth/reauth`
- `GET /api/v1/host`
- `GET /api/v1/capabilities`
- `GET /api/v1/services`
- `GET /api/v1/services/nginx/sites`
- `GET /api/v1/settings/access`
- `PUT /api/v1/settings/access/additional-auth`

P2 이후에만 추가할 endpoint:

- `POST /api/v1/auth/sessions/revoke-all`
- `POST /api/v1/operation-plans`
- `POST /api/v1/operation-plans/{plan_id}/approve`
- `GET /api/v1/operations`
- `GET /api/v1/operations/{operation_id}`
- `GET /api/v1/operations/{operation_id}/events`

로그인·재인증 password는 strict body limit의 HTTPS JSON body에서만 받고 request logging 전에 secret type으로 분리합니다. 인증 실패는 account 존재·잠김·비밀번호 오류를 같은 public response로 반환합니다.

예외적으로 loopback recovery listener는 SSH tunnel transport에서 같은 JSON form을 받습니다. Public과 recovery는 cookie name·session namespace·acceptance channel을 분리하며 서로의 session을 거부합니다.

## agentd ↔ authd

- systemd socket-activated root one-shot service
- request마다 새 length-bounded frame과 PAM transaction
- peer UID must equal agentd service UID
- username, password, trusted remote address, purpose `login | step_up`
- `pam_authenticate(PAM_DISALLOW_NULL_AUTHTOK)` then `pam_acct_mgmt`
- canonical PAM user를 다시 읽고 UID 0·비허용 group 거부
- response는 canonical UID·username·role·generic result만 포함
- password zeroize, no DB/log/argv/core; raw PAM text is never forwarded
- timeout or unsupported PAM conversation fails closed

## agentd ↔ opsd

- root-owned Unix domain socket
- fixed maximum frame size
- versioned length-prefixed JSON request/response for MVP
- P1 request는 request ID·deadline의 read-only capability handshake만 허용
- P2 이후에만 operation version과 typed payload 추가
- peer UID validation and socket permission
- no generic exec/path/message extension bag
- incompatible version is explicit error, not fallback

## Generated contract

REST OpenAPI와 UI TypeScript client는 Rust contract에서 생성합니다. Generated file은 직접 편집하지 않습니다. MVP에서 gRPC·protobuf·streaming IPC는 도입하지 않습니다.
