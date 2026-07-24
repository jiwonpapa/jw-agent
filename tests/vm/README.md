# Ubuntu 24.04 VM evidence matrix

Status: P2 managed services and UFW VM_PASS; independent edge VM_PASS; P2C lifecycle VM_PASS except public CA success; P2D terminal and SFTP G0/G1 VM_PASS  
Authority: Delivery  
Owner: Verification Maintainer  
Last reviewed: 2026-07-23

This directory defines real-OS evidence that cannot be claimed from macOS or
mock browser tests. The `p2-vm` xtask lane owns the repeatable OS, package,
PAM, public-edge, recovery, typed Nginx·Apache·PHP-FPM·UFW operation, forensic-lockdown, and
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
JW_VM_REMOTE_PACKAGE=/home/neojins/jw-agent_0.2.0~p2.20_amd64.deb
JW_VM_EXPECTED_PACKAGE_SHA256=8fbca64eaa2d47ccfa49fabdfaa7c5bcff1b31de382ad3ca91693146277e170a
JW_VM_EXPECTED_VERSION=0.2.0~p2.20
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
- package: `jw-agent 0.2.0~p2.20`, SHA-256 `8fbca64eaa2d47ccfa49fabdfaa7c5bcff1b31de382ad3ca91693146277e170a`, package/runtime gate clean
- lanes: `p2-local` 23 PASS, `p2-browser` 8 PASS with 43 browser scenarios, `p2-vm` 28 PASS
- independent edge: non-root Rustls 9443, fixed live Unix readiness, edge-missing Nginx stop denial, Nginx inactive 상태의 authenticated UI·API continuity
- service inventory: real Nginx and JW Agent internal classification plus a disposable failed custom unit surfaced as discovered read-only
- automated VM scenarios: installed PAM fixture equality, no `pam_faillock`, `jw-authd → libpam.so.0`, `jw-agentd → libsqlite3.so.0`, repeated product-login failures followed by unchanged Linux password state and working OpenSSH key recovery
- automated P2 faults: success, verified no-op, syntax failure rollback, injected reload failure rollback, 1 MiB snapshot filesystem cancellation before apply, deleted checkpoint lockdown and restoration
- automated P2B config faults: Nginx·Apache·PHP-FPM valid save와 exact syntax/reload rollback, >16 KiB save/no-op, external drift preservation, inactive denial, private proposal cleanup, internal temp discovery exclusion and startup cleanup
- automated service lifecycle: Nginx reload, Apache reload·restart·stop·start, PHP-FPM restart·stop·start, typed plan·approval·receipt와 public management continuity
- automated PHP-FPM config: Ubuntu apt PHP 8.3.6 unit·extension·masked path 관찰, `php.ini`·`php-fpm.conf`·pool inventory, 73 KiB `php.ini` valid save, exit 0 syntax warning detection, reload-before-failure 차단, exact rollback과 service continuity
- automated UFW: inactive observation, temporary active ruleset 안에서 product-owned allow·delete, protected 22/tcp deny rejection, external drift cancellation, SSH·9443 continuity와 exact fixture restore
- automated P2C boundary: Ubuntu Certbot 2.9.0, root-only socket, non-root denial, expired request rejection, digest-only renewal dry-run result, one-shot worker and private-config cleanup
- automated P2C inventory: sanitized SAN·expiry·fingerprint, timer state, masked path, private-key non-disclosure, escaped symlink rejection
- automated P2C renewal operation: immutable plan, PAM approval, private inventory snapshot, real Ubuntu Certbot dry-run, digest-only receipt, timer-unhealthy rejection, one-shot cleanup
- automated P2C issuance failure: exact DNS/listener/webroot preflight, staging plan, two G1 confirmations, PAM approval, real public-CA rejection, unchanged inventory, no false rollback, ephemeral email/proposal cleanup
- automated P2C attach: exact protected-vhost TLS directive replacement, Nginx syntax/reload/active, timer and loopback SNI fingerprint read-back; forced verifier failure restores exact bytes, owner and mode
- automated P2D terminal: loopback-only password policy, non-root OpenSSH command I/O, PTY resize, ticket replay and wrong-Origin denial, logout revoke, metadata-only audit, process/FIFO cleanup
- automated P2D SFTP G0: home list/stat/text/download, traversal·absolute path·external symlink·size denial, cross-session·wrong-Origin·close·logout denial, path-digest audit, process/FIFO cleanup
- automated P2D SFTP G1: PAM-planned create/replace, `0600` create and existing-mode preservation, fsync/atomic rename, size/SHA-256 read-back, stale target·symlink·directory·traversal·digest·wrong-Origin·replay denial, metadata-only audit and temp cleanup
- automated TOTP step-up: recovery-only admin enrollment, two consecutive codes, `risky_operations`, PAM+TOTP 15분 관리 모드, 동일 time-step replay denial, one-time recovery reset, session revoke, mode-0600 wrapping key and encrypted-state cleanup
- package runtime: opsd host network namespace, exact `CAP_NET_BIND_SERVICE|CAP_NET_ADMIN`, `IPAddressDeny=any`, no listening IP socket, root-owned `0600` ledger, bounded UDS
- local console: grouped navigation, explicit non-root Linux identity, responsive resource meters and service-family cards, current-subject typed-operation history
- real browser: public HTTPS 관리 모드 시각 증거와 p2.20 public HTTPS·API를 유지하며 43개 mock browser scenario PASS

This is a private-LAN `.test` host with a dedicated management-edge test CA.
The Certbot runner boundary, read-only inventory, renewal dry-run, guided issue
preflight, public-CA failure handling, and protected-vhost local TLS attachment
rollback, allowlisted Apache/PHP-FPM configuration, product-owned UFW rule lifecycle,
the bounded non-root terminal, and home-scoped SFTP G0/G1 are
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
| public edge | exact FQDN/TLS, UDS proxy, spoofed forwarding headers cleared, internal ports absent, Nginx-down 9443 continuity |
| OpenSSH terminal | loopback-only password policy, fixed client, replay/origin/revoke, bounded PTY and metadata audit |
| OpenSSH SFTP G0 | fixed read-only subsystem, canonical home, traversal/symlink/size/session negatives and path-digest audit |
| OpenSSH SFTP G1 | PAM plan, atomic create/replace, mode/size/digest read-back, stale/symlink/type/origin/digest/replay denial and metadata audit |
| TOTP step-up | recovery-only enrollment/reset, consecutive codes, PAM+TOTP 관리 모드, replay denial, encrypted seed and recovery cleanup |
| failure recovery | Nginx/TLS failure leaves SSH recovery available and public profile removable |
| service lifecycle | Nginx reload, Apache reload·restart·stop·start, PHP-FPM restart·stop·start, final active read-back and management continuity |
| managed service config | allowlisted Nginx·Apache·PHP-FPM inventory, valid save, syntax failure before reload, exact rollback, active continuity |
| UFW rule | inactive observation, product-owned allow/delete, protected deny and stale-plan rejection, SSH·9443 continuity, fixture restore |
| secret scan | password/session tokens absent from journal, DB, process arguments, package logs and evidence |

## Evidence rule

Each run verifies the immutable package checksum, Ubuntu image identity,
scenario result, sanitized logs, and evidence level. A VM PASS plus a real-API
Playwright CLI inspection is required before the implemented P2 Nginx baseline
can be described as installation- or runtime-proven.
