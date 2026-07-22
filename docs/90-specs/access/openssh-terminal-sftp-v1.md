# ACCESS-OPENSSH-TERMINAL-SFTP-V1

Status: Accepted  
Authority: Access Specification  
Owner: Manual Access Maintainer  
Last reviewed: 2026-07-22

## User job

운영자가 JW Agent 자동화가 지원하지 않는 진단과 사용자 소유 파일 관리를 기존 OpenSSH 계정 권한으로 잠시 수행합니다. 제품은 새 SSH/SFTP server나 root command API를 만들지 않습니다.

## Routes and protocol

- `/terminal`: same-origin `WSS` terminal session
- `/files`: REST metadata/list/download와 bounded atomic upload, textarea text edit
- agentd는 loopback OpenSSH에 client로 연결하고 strict known-host fingerprint를 package/runtime authority에서 확인
- browser는 SSH protocol, host key, private key를 처리하지 않음

## Identity and authorization

- current JW session의 canonical Linux username만 SSH username으로 사용
- UID 0, locked/expired account, denied shell, role-policy mismatch는 거부
- 세션 생성은 최근 PAM reauth와 정책-required TOTP를 요구
- server-side single-use ticket은 30초 이내 만료, JW session·user·origin·purpose에 bind
- terminal/SFTP session은 별도 max lifetime·idle timeout·connection quota를 가짐
- SSH 인증 material은 server-side ephemeral boundary에서만 처리하고 browser로 반환하지 않음

초기 지원 인증은 별도 Accepted credential broker 계약 전까지 `UNSUPPORTED`로 유지합니다. Linux password를 재사용한다면 one-shot memory only, strict zeroize, SSH authentication 직후 폐기하며 저장·로그·재전송하지 않습니다. server-managed ephemeral key를 사용한다면 설치·회수·authorized_keys ownership을 별도 typed operation과 spec으로 승인해야 합니다.

## Terminal assurance and limits

- assurance `G1 MANUAL_NON_REVERSIBLE`
- command content를 opsd가 해석·승인·원복하지 않음
- UI는 자동 원복 불가, Linux 사용자 권한, sudo 가능성, session 만료를 연결 전에 표시
- root login과 product-driven sudo/password prompt automation 금지
- WSS frame, rows/cols, paste byte, output buffer, connection, idle, total lifetime 제한
- disconnect 시 PTY/process 종료 정책과 재접속 불가 여부를 명시
- transcript는 기본 저장하지 않으며 browser storage와 audit ledger에 기록하지 않음

감사 evidence는 actor, host, session ID, start/end, reason, byte counts, remote exit/disconnect class만 기록합니다. command와 output은 사용자가 명시적으로 export하지 않는 한 기록하지 않습니다.

## SFTP assurance and policy

- list/stat/read/download: `G0 READ_ONLY`
- upload/create/delete/move/chmod: `G1 MANUAL_NON_REVERSIBLE`
- SFTP server의 realpath와 Linux permission을 적용하고 path normalization·NUL·oversized component를 거부
- system-owned/protected roots와 adapter-managed config resources는 write policy로 차단
- upload는 size/quota/timeout을 적용하고 가능한 경우 same-directory temp + atomic rename을 사용하되 자동 rollback을 주장하지 않음
- text editor는 max size, UTF-8, digest-based optimistic concurrency, line ending 표시를 제공
- binary/large file은 editor 대신 explicit download/upload만 제공

SFTP의 root 전체 파일 관리자 UI를 제공하지 않습니다. 홈·서비스별 허용 root는 server policy가 소유하고 default deny에서 명시적으로 추가합니다.

## Browser and UI security

- HTTPS 또는 loopback recovery origin만 허용, exact Host/Origin와 CSRF/session 검증
- terminal ticket은 URL query에 넣지 않고 authenticated one-time exchange 후 WSS subprotocol/body로 전달
- `Cache-Control: no-store`, CSP, clipboard·paste warning, shared-device logout/revoke
- password, private key, terminal transcript, file body를 localStorage·sessionStorage·IndexedDB·service worker에 저장하지 않음
- mobile/tablet에서 위험 경고·보장등급·종료 control을 생략하지 않음

## Failure and recovery

OpenSSH unavailable, host-key mismatch, auth failure, network loss, session timeout, transfer partial failure를 구분합니다. terminal/SFTP 실패가 opsd safety kernel이나 기존 sshd를 재시작·변경하지 않습니다. management ingress가 실패해도 normal SSH client 접근은 유지됩니다.

## Dependency and build gate

Rust SSH/SFTP client, xterm, Monaco dependency는 exact pin과 최소 feature, license, advisory, clean/incremental build cost, binary size를 기록한 compatibility spike를 통과해야 합니다. 기존 Tauri 프로젝트의 source·ticket·protocol·storage를 복사하지 않습니다.

## Acceptance scenarios

- non-root terminal connect/input/resize/output/exit at desktop/tablet/mobile
- UID 0, wrong user, expired/locked account, host-key mismatch denial
- ticket replay, wrong purpose/session/origin, expired ticket denial
- idle/max lifetime, concurrent session, frame/paste/output cap
- root/sudo automation absent and opsd API has no shell/PTY/user argv
- SFTP list/read/download and bounded atomic upload in allowed root
- traversal/symlink escape/protected root/oversized file/stale digest denial
- transfer interruption leaves explicit partial/temp state and cleanup receipt
- logout/public disable/session revoke closes terminal and SFTP sessions
- browser storage and exported evidence contain no credential/transcript/file body
