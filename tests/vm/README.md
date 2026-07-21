# Ubuntu 24.04 VM evidence matrix

Status: P1 VM_PASS  
Authority: Delivery  
Owner: Verification Maintainer  
Last reviewed: 2026-07-21

This directory defines real-OS evidence that cannot be claimed from macOS or
mock browser tests. The `p1-vm` xtask lane owns the repeatable OS, package,
PAM, public-edge, recovery, and secret-scan decisions. Provisioning templates
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
JW_VM_REMOTE_PACKAGE=/home/neojins/jw-agent_0.1.0~p1.3_amd64.deb
JW_VM_EXPECTED_PACKAGE_SHA256=<lowercase sha256>
JW_VM_EXPECTED_VERSION=0.1.0~p1.3
cargo xtask verify p1-vm
```

## Current VM evidence

- domain: `jw-agent-p1`, Ubuntu 24.04.4 LTS, kernel `6.8.0-136-generic`
- package: `jw-agent 0.1.0~p1.3`, SHA-256 `7f31112a44090aebde61d4dd5498e8d1380fc1154542b7dea13f1b03d090024d`, Lintian clean
- lanes: `p1-local` 18 PASS, `p1-browser` 8 PASS with 15 browser scenarios, `p1-vm` 12 PASS
- automated VM scenarios: installed PAM fixture equality, no `pam_faillock`, `jw-authd → libpam.so.0`, `jw-agentd → libsqlite3.so.0`, repeated product-login failures followed by unchanged Linux password state and working OpenSSH key recovery
- manual VM scenarios: session rotation/logout, wrong-UID UDS denial, Nginx outage with SSH recovery, rejected invalid TLS config, package upgrade/remove/reinstall with SQLite logical-state preservation, full VM reboot and systemd recovery
- real browser: public HTTPS login, read-only Overview/catalog, assurance blockers, mobile and desktop layout, expired-session redirect recovery

This is a private-LAN `.test` host with a dedicated test CA. It is not evidence
of public DNS, Certbot issuance, signed release distribution, or production
operation.

## Required disposable-VM scenarios

| Scenario | Required proof |
|---|---|
| package install/remove | clean Ubuntu 24.04 install, upgrade, remove, preserved user data policy |
| PAM matrix | valid, wrong, unknown, root, locked, expired, denied-group accounts; identical public failure |
| peer boundary | only `jw-agent` UID can reach authd/opsd; malformed, oversized and timeout frames rejected |
| systemd hardening | expected identities, restart behavior, filesystem writes, no authd/opsd network sockets |
| recovery ingress | loopback-only listener, SSH tunnel access, non-loopback bind refusal, exact Host/Origin |
| public edge | exact FQDN/TLS, UDS proxy, spoofed forwarding headers cleared, internal ports absent |
| failure recovery | Nginx/TLS failure leaves SSH recovery available and public profile removable |
| secret scan | password/session tokens absent from journal, DB, process arguments, package logs and evidence |

## Evidence rule

Each run verifies the immutable package checksum, Ubuntu image identity,
scenario result, sanitized logs, and evidence level. A VM PASS plus a real-API
Playwright CLI inspection is required before the P1 package can be described as
installation- or runtime-proven.
