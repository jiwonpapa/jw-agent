# JW Agent packaging basis

This directory owns the Ubuntu 24.04 `.deb` assembly inputs. P2 package proof
is accepted only after the disposable VM lane passes; source presence alone is
not installation proof.

- `debian/`: package metadata and artifact mapping
- `systemd/`: least-privilege service and socket units
- `pam/`: product-specific local PAM policy
- `nginx/`: opt-in public HTTPS reverse-proxy template
- `default/`: fail-closed runtime configuration
- `sysusers/` and `tmpfiles/`: service identity and runtime paths

Public ingress stays disabled until an administrator supplies an exact FQDN,
certificate paths, and explicitly installs the Nginx template. The package must
not edit DNS, UFW, SSH, Certbot, or unrelated Nginx sites automatically.
An existing public-edge site remains administrator-owned: upgrading the package
does not replace it. P2B managed-config requests require the reviewed `64k`
JSON-envelope limit from the current template while decoded configuration content
remains capped at `24 KiB`.
The current P2B package still accepts an existing valid certificate path only;
the P2C package contains the isolated one-shot runner and sanitized read-only
certificate inventory. Issuance, attachment, and renewal are not advertised until the typed operation
and its VM fault lane pass.

The public proxy socket uses the dedicated `jw-agent-proxy` group and
`/run/jw-agent-proxy`. Nginx is never added to the privileged `jw-agent` group
that owns the `opsd` boundary.

The package creates empty `jw-agent-admin`, `jw-agent-operator`, and
`jw-agent-viewer` groups. It never grants a user access automatically; an
administrator must explicitly add each Linux account to exactly the intended
product role group.

Installation, PAM, systemd, Nginx, TLS, and public-port evidence must come from
the disposable Ubuntu VM scenarios in `tests/vm/`.
