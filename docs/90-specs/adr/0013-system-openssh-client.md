# ADR-0013 — System OpenSSH Client for Manual Access

Status: Accepted  
Authority: Architecture Decision  
Owner: Architecture Maintainer  
Last reviewed: 2026-07-22

## Context

웹 terminal과 SFTP는 custom SSH server 없이 `agentd → loopback OpenSSH` 경계를 지켜야 합니다. Rust SSH client 후보는 별도 crypto/TLS graph와 default feature가 크고 장기 유지·빌드 비용을 늘립니다. Ubuntu 24.04는 이미 보안 업데이트되는 OpenSSH client를 제공합니다.

Compatibility spike 기준선은 2026-07-22의 `jw-agentd` clean debug build 11.55초, binary 14,963,144 bytes, Cargo dependency 93 nodes입니다.

## Decision

- Ubuntu package의 `/usr/bin/ssh`를 exact executable로 사용하고 package dependency는 `openssh-client`로 고정합니다.
- SSH argv는 코드 소유 allowlist만 사용합니다. username은 canonical session identity, destination은 `127.0.0.1`, port는 22, remote command는 없음입니다.
- `/etc/jw-agent/ssh_known_hosts`의 `jw-agent-loopback` authority와 `StrictHostKeyChecking=yes`를 강제합니다.
- Ubuntu `setsid --ctty --wait`로 PTY를 controlling terminal로 고정해 bounded resize와 process 종료가 같은 session 경계를 따르게 합니다.
- password는 [ACCESS-OPENSSH-PASSWORD-BROKER-V1](../access/openssh-password-broker-v1.md)의 one-shot FIFO askpass 경계만 통과합니다.
- package 설치는 기존 sshd 인증 정책을 자동 변경하지 않습니다. password 인증이 꺼진 서버는 향후 별도 G2 loopback-only 설정 operation 없이는 terminal이 지원되지 않습니다.
- PTY는 existing exact-pinned `nix`의 `term` feature, process lifecycle은 existing exact-pinned Tokio의 `process` feature, WSS는 existing exact-pinned Axum의 `ws` feature만 확장합니다.
- 브라우저 terminal은 exact-pinned `@xterm/xterm`과 `@xterm/addon-fit`만 추가합니다.
- SFTP는 같은 `/usr/bin/ssh`의 fixed `-s 127.0.0.1 sftp` subsystem을 사용하고, agentd가 SFTP v3의 bounded message allowlist를 직접 encode/decode합니다.
- terminal과 SFTP의 password-only·strict host-key·loopback·forwarding 차단 argv는 `agentd::openssh` 한 모듈이 소유하며 두 세션 구현이 같은 정책을 소비합니다.
- G0 조회는 `REALPATH`, `STAT`, `OPENDIR`, `READDIR`, `OPEN(read)`, `READ`, `CLOSE`만 허용합니다. G1 원자 업로드는 같은 디렉터리 exclusive 임시파일에 한정한 `OPEN(create/write)`, `WRITE`와 서버가 광고한 `fsync@openssh.com`, `posix-rename@openssh.com`만 추가합니다. remove/mkdir/rmdir/setstat/symlink와 임의 rename API는 제공하지 않습니다.
- wire packet, request timeout, entry count, text, download, path component와 전체 path를 고정 상한으로 제한합니다.
- SFTP canonical home root와 기존 target 또는 신규 target parent의 `REALPATH` 경계를 매 요청 검사하고 symlink·비정규 target을 차단하며 TOCTOU 잔여 위험을 공개합니다.
- 새 Rust crate, crypto, native library, browser dependency는 추가하지 않습니다.
- `opsd`, authd, certd의 dependency와 privilege는 변경하지 않습니다.

## Fixed SSH policy

- `-F /dev/null`, password-only, public-key·keyboard-interactive·agent forwarding 비활성
- one prompt, strict known host, fixed alias, no global known-host fallback
- connect timeout와 keepalive 제한, `LogLevel=ERROR`, forced PTY
- environment clear 후 필요한 locale·TERM·askpass 변수만 입력
- user input은 PTY stdin bytes일 뿐 argv, shell string, remote command가 되지 않음

## Build gate

허용치는 Rust clean build 30초 이내, binary 22 MiB 이내, native/codegen dependency 0개 추가입니다. 초과 시 기능 활성화를 중단하고 ADR을 재검토합니다.

2026-07-22 isolated compatibility 결과:

- clean debug build: 15.07초, 기준선 11.55초 대비 +3.52초
- no-change incremental build: 0.34초
- `jw-agentd` debug binary: 16,941,640 bytes, 기준선 14,963,144 bytes 대비 +1,978,496 bytes
- normal dependency nodes: 117, 기준선 93 대비 +24; lockfile package +25
- 추가 native dependency와 제품 code generation: 0
- terminal route chunk: 349.42 kB, gzip 90.11 kB; route lazy-load로 기본 dashboard chunk와 분리
- `@xterm/xterm 6.0.0`, `@xterm/addon-fit 0.11.0`: exact pin, MIT, runtime dependency 0
- Rust WSS graph는 existing Axum feature가 소유하며 별도 SSH/crypto/TLS stack은 추가하지 않음

터미널 수치 gate는 PASS입니다. Ubuntu 24.04 package VM은 non-root password login, command I/O, 40×100 resize, ticket replay·wrong-origin 차단, logout revoke, metadata-only audit와 process/FIFO cleanup을 통과했습니다. SFTP G0도 같은 dependency graph에서 home list/stat/text/download와 path-digest audit를 검증했습니다. SFTP G1은 새 dependency 없이 OpenSSH가 광고한 fsync·POSIX rename extension만 사용해 create/replace, mode·size·digest read-back과 stale/symlink/type/origin/digest/replay 차단을 별도 `VM_PASS`로 검증했습니다.

## Rejected

- `russh`/별도 Rust crypto SSH stack: MVP build graph와 crypto ownership이 과도합니다.
- 브라우저 SSH: credential과 host-key 경계를 browser로 확장합니다.
- `opsd` PTY 또는 shell API: agentd 침해를 root command execution으로 확대합니다.
- private key 업로드·저장: key lifecycle과 회수 operation이 아직 승인되지 않았습니다.

## Acceptance

- build gate가 baseline 대비 수치와 license를 제시
- fixed argv와 strict host-key negative test
- password/ticket가 argv, environment, storage, logs에 남지 않음
- non-root PTY I/O, resize, disconnect, timeout을 Ubuntu 24.04 VM에서 검증
- non-root home list/stat/text/download와 traversal·symlink·size·session negative를 Ubuntu 24.04 VM에서 별도 검증
- non-root home create/replace와 mode·size·digest read-back, stale target·symlink·type·origin·digest·ticket replay 차단, 감사·임시파일 cleanup을 Ubuntu 24.04 VM에서 별도 검증
- VM의 password 인증 fixture는 `Match LocalAddress 127.0.0.1`에만 한정하고 public/LAN SSH 정책을 넓히지 않음
