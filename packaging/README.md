# JW Agent packaging basis

This directory owns the Ubuntu 24.04 `.deb` assembly inputs. P2 package proof
is accepted only after the disposable VM lane passes; source presence alone is
not installation proof.

Development packages compile the web assets natively and the Rust binaries with
the Mac mini's Linux/amd64 GNU cross toolchain. The disposable Ubuntu VM only
installs and verifies the immutable artifact; it does not compile release source.

- `debian/`: package metadata and artifact mapping
- `systemd/`: least-privilege service and socket units
- `pam/`: product-specific local PAM policy
- `nginx/`: opt-in public HTTPS reverse-proxy template
- `default/`: fail-closed runtime configuration
- `sysusers/` and `tmpfiles/`: service identity and runtime paths

Public ingress stays disabled until an administrator supplies an exact FQDN and
installs a certificate/key under `/etc/jw-agent/edge`. The default independent
management ingress is the unprivileged Rust `jw-edge` listener on 9443; the
Nginx 443 template remains an optional compatibility path. The package must
not edit DNS, UFW, SSH, Certbot, or unrelated Nginx sites automatically.
An existing public-edge site remains administrator-owned: upgrading the package
does not replace it. Managed-config plan requests alone use a reviewed `256 KiB`
JSON envelope: Nginx content stays capped at `24 KiB`, while the fixed Ubuntu
PHP 8.3 FPM `php.ini` adapter is capped at `128 KiB`. Other API requests retain
the `64 KiB` application limit.
Both public paths still accept existing valid certificate material only.
The P2C package contains the isolated one-shot runner, sanitized read-only
certificate inventory, a planned/PAM-approved renewal dry-run, and guided
issuance with DNS/listener/webroot preflight and explicit G1 external-effect
consent. The private-LAN CA-failure path and protected-vhost G2 attachment with
loopback SNI read-back and exact rollback are VM-proven. Public-CA success
remains unverified and separately gated. P2D includes home-scoped OpenSSH SFTP
list/stat/text/download plus G1 regular-file creation and explicit replacement.
G1 writes require a short-lived PAM-approved plan, OpenSSH fsync and POSIX rename
extensions, and mode/size/SHA-256 read-back. Delete, move, chmod/chown, recursive
transfer, system paths, and root SFTP remain absent. The exact binary upload route
has an 8 MiB edge limit. The managed-config exception above does not widen PAM,
terminal, SFTP control, or other JSON endpoints.

P2.19 keeps recovery-only TOTP enrollment and reset, and uses the separate
15-minute administrative access mode for root typed operations. The mode
requires an admin-role non-root Linux account, PAM verification, and TOTP when
the configured policy requires it; it never creates a root web session. TOTP seeds are encrypted
with a database-adjacent mode-0600 key; one-time recovery material is shown
only in the enrollment response and stored as digests. Enabling a non-disabled
policy requires a ready provider, and typed-operation approval consumes the PAM
and exact-plan TOTP claims atomically. The package does not modify PAM or SSH
MFA configuration.

The public proxy socket uses the dedicated `jw-agent-proxy` group and
`/run/jw-agent-proxy`. Nginx is never added to the privileged `jw-agent` group
that owns the `opsd` boundary.
The independent edge publishes only a fixed readiness response on
`/run/jw-agent-edge/ready.sock`. `opsd` uses that live local response to reject
an Nginx stop before side effects when the independent management path is absent.
The readiness response is withheld while the agentd proxy UDS is unavailable;
agentd restarts do not stop the edge process or its 9443 listener.

The package creates empty `jw-agent-admin`, `jw-agent-operator`, and
`jw-agent-viewer` groups. It never grants a user access automatically; an
administrator must explicitly add each Linux account to exactly the intended
product role group.

Installation, PAM, systemd, Nginx, TLS, and public-port evidence must come from
the disposable Ubuntu VM scenarios in `tests/vm/`.
