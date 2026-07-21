# ADR-0012 — One-shot Loopback TLS Verifier

Status: Accepted  
Authority: Architecture Decision  
Owner: Certificate Lifecycle Maintainer  
Last reviewed: 2026-07-21

## Context

Certbot Nginx attach의 G2 완료 증거에는 실제 `127.0.0.1:443` SNI 응답 인증서 지문이 필요합니다. 장기 실행 root `opsd`는 `PrivateNetwork=yes`와 `IPAddressDeny=any`를 유지해야 하므로 host Nginx에 직접 연결할 수 없습니다.

## Decision

- 기존 socket-activated one-shot `jw-certd`에 `verify_local_tls` typed command를 추가합니다.
- 연결 주소와 포트는 binary가 `127.0.0.1:443`으로 고정하고 caller는 validated FQDN SNI와 expected SHA-256 fingerprint만 전달합니다.
- worker는 fixed `openssl s_client`와 `openssl x509`를 shell 없이 bounded timeout·output cap으로 실행합니다.
- certificate 원문과 command output은 response·ledger·journal에 반환하지 않고 digest와 성공 여부만 반환합니다.
- `opsd`는 Nginx 교체·snapshot·rollback을 계속 소유하며 TLS probe 실패를 local rollback 원인으로 처리합니다.
- `opsd`의 network namespace와 IP deny 정책은 변경하지 않습니다.

## Rejected alternatives

- `opsd` network sandbox 완화: 장기 실행 root daemon의 host·external network attack surface가 커집니다.
- agentd의 성공 판정 뒤 별도 rollback: apply와 verification 사이 crash window가 생깁니다.
- 새 TLS crate·별도 daemon: MVP build graph와 package surface가 불필요하게 늘어납니다.

## Acceptance

- command schema가 IP·port·argv·path 입력을 받지 않음
- unit proof에서 loopback address와 SNI mapping 고정
- VM에서 실제 Nginx SNI fingerprint success와 mismatch rollback 검증
- raw peer certificate·private key·OpenSSL output이 API·ledger·journal에 없음
