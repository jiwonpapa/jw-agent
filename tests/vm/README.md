# Ubuntu 24.04 VM evidence matrix

Status: P2B VM_PASS; P2C lifecycle VM_PASS except public CA success; P2D terminal and SFTP G0/G1 VM_PASS  
Authority: Delivery  
Owner: Verification Maintainer  
Last reviewed: 2026-07-22

This directory defines real-OS evidence that cannot be claimed from macOS or
mock browser tests. The `p2-vm` xtask lane owns the repeatable OS, package,
PAM, public-edge, recovery, typed Nginx operation, forensic-lockdown, and
secret-scan decisions. Provisioning templates
create a separate `jw-agent-p1` KVM domain instead of mutating another test VM.

## Lane inputs

The password file must be a disposable fixture secret with mode `0600`. The
lane reads it locally and sends login bodies through process stdin; it never
places the password in command arguments or evidence output.

```text
JW_VM_SSH_TARGET=neojins@192.168.0.142
JW_VM_SSH_KNOWN_HOSTS=/path/to/dedicated-known-hosts
JW_VM_PUBLIC_HOST=jw-agent-p1.test
JW_VM_PUBLIC_ADDRESS=192.168.0.142
JW_VM_CA_CERT=/path/to/test-ca.crt
JW_VM_ADMIN_USER=jwvmadmin
JW_VM_PASSWORD_FILE=/path/to/mode-0600-fixture-password
JW_VM_REMOTE_PACKAGE=/home/neojins/jw-agent_0.2.0~p2.12_amd64.deb
JW_VM_EXPECTED_PACKAGE_SHA256=c1346207c97aa457bf8e371239bc81ce8a3493d7057bee52a57f37774e502a2e
JW_VM_EXPECTED_VERSION=0.2.0~p2.12
cargo xtask verify p2-vm
```

일반 UI 확인은 `https://jw-agent-p1.test/` 공개 HTTPS를 직접 사용합니다.
SSH local port forwarding은 공개 edge 장애 시나리오와 복구 검증에만 사용하며
정상 사용자 진입점으로 안내하지 않습니다. 이 private-LAN 이름은 시험 클라이언트의
DNS 또는 hosts 설정과 전용 test CA 신뢰가 별도로 필요합니다. 현재 Mac 시험
클라이언트는 mkcert local CA를 login keychain에 신뢰시키고 동일 CA의 leaf
certificate를 VM management edge에 설치합니다.

## Current VM evidence

- domain: `jw-agent-p1`, Ubuntu 24.04.4 LTS, kernel `6.8.0-136-generic`
- package: `jw-agent 0.2.0~p2.12`, SHA-256 `c1346207c97aa457bf8e371239bc81ce8a3493d7057bee52a57f37774e502a2e`, Lintian clean
- lanes: `p2-local` 22 PASS, `p2-browser` 8 PASS with 35 browser scenarios, `p2-vm` 24 PASS
- service inventory: real Nginx and JW Agent internal classification plus a disposable failed custom unit surfaced as discovered read-only
- automated VM scenarios: installed PAM fixture equality, no `pam_faillock`, `jw-authd → libpam.so.0`, `jw-agentd → libsqlite3.so.0`, repeated product-login failures followed by unchanged Linux password state and working OpenSSH key recovery
- automated P2 faults: success, verified no-op, syntax failure rollback, injected reload failure rollback, 1 MiB snapshot filesystem cancellation before apply, deleted checkpoint lockdown and restoration
- automated P2B config faults: >16 KiB active save/no-op, exact syntax/reload rollback, external drift preservation, inactive denial, private proposal cleanup, internal temp discovery exclusion and startup cleanup
- automated P2C boundary: Ubuntu Certbot 2.9.0, root-only socket, non-root denial, expired request rejection, digest-only renewal dry-run result, one-shot worker and private-config cleanup
- automated P2C inventory: sanitized SAN·expiry·fingerprint, timer state, masked path, private-key non-disclosure, escaped symlink rejection
- automated P2C renewal operation: immutable plan, PAM approval, private inventory snapshot, real Ubuntu Certbot dry-run, digest-only receipt, timer-unhealthy rejection, one-shot cleanup
- automated P2C issuance failure: exact DNS/listener/webroot preflight, staging plan, two G1 confirmations, PAM approval, real public-CA rejection, unchanged inventory, no false rollback, ephemeral email/proposal cleanup
- automated P2C attach: exact protected-vhost TLS directive replacement, Nginx syntax/reload/active, timer and loopback SNI fingerprint read-back; forced verifier failure restores exact bytes, owner and mode
- automated P2D terminal: loopback-only password policy, non-root OpenSSH command I/O, PTY resize, ticket replay and wrong-Origin denial, logout revoke, metadata-only audit, process/FIFO cleanup
- automated P2D SFTP G0: home list/stat/text/download, traversal·absolute path·external symlink·size denial, cross-session·wrong-Origin·close·logout denial, path-digest audit, process/FIFO cleanup
- automated P2D SFTP G1: PAM-planned create/replace, `0600` create and existing-mode preservation, fsync/atomic rename, size/SHA-256 read-back, stale target·symlink·directory·traversal·digest·wrong-Origin·replay denial, metadata-only audit and temp cleanup
- package runtime: opsd private network namespace, exact `CAP_NET_BIND_SERVICE`, ephemeral Nginx test logs, no listening IP socket, root-owned `0600` ledger, bounded UDS
- real browser: public HTTPS editor, 24 KiB counter, planned-only warning, G2 scope/exclusions and custom-basename protected vhost; internal temp absent and authenticated fresh-session console error 0

This is a private-LAN `.test` host with a dedicated management-edge test CA.
The Certbot runner boundary, read-only inventory, renewal dry-run, guided issue
preflight, public-CA failure handling, and protected-vhost local TLS attachment
rollback, the bounded non-root terminal, and home-scoped SFTP G0/G1 are
VM-proven. It is not evidence of public DNS, successful public-CA issuance,
signed release distribution, delete/move/chmod SFTP operations, or production operation.

## Required disposable-VM scenarios

| Scenario | Required proof |
|---|---|
| package install/remove | clean Ubuntu 24.04 install, upgrade, remove, preserved user data policy |
| PAM matrix | valid, wrong, unknown, root, locked, expired, denied-group accounts; identical public failure |
| peer boundary | only `jw-agent` UID can reach authd/opsd; malformed, oversized and timeout frames rejected |
| systemd hardening | expected identities, restart behavior, filesystem writes, no authd/opsd network sockets |
| recovery ingress | loopback-only listener, SSH tunnel access, non-loopback bind refusal, exact Host/Origin |
| public edge | exact FQDN/TLS, UDS proxy, spoofed forwarding headers cleared, internal ports absent |
| OpenSSH terminal | loopback-only password policy, fixed client, replay/origin/revoke, bounded PTY and metadata audit |
| OpenSSH SFTP G0 | fixed read-only subsystem, canonical home, traversal/symlink/size/session negatives and path-digest audit |
| OpenSSH SFTP G1 | PAM plan, atomic create/replace, mode/size/digest read-back, stale/symlink/type/origin/digest/replay denial and metadata audit |
| failure recovery | Nginx/TLS failure leaves SSH recovery available and public profile removable |
| secret scan | password/session tokens absent from journal, DB, process arguments, package logs and evidence |

## Evidence rule

Each run verifies the immutable package checksum, Ubuntu image identity,
scenario result, sanitized logs, and evidence level. A VM PASS plus a real-API
Playwright CLI inspection is required before the implemented P2 Nginx baseline
can be described as installation- or runtime-proven.
