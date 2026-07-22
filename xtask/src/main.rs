#![forbid(unsafe_code)]

mod vm;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

type GateRunner = fn(&Path, Duration) -> Result<(), String>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lane {
    Governance,
    P1Local,
    P2Local,
    P1Browser,
    P2Browser,
    P1Vm,
    P2Vm,
}

impl Lane {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "governance" => Some(Self::Governance),
            "p1-local" => Some(Self::P1Local),
            "p2-local" => Some(Self::P2Local),
            "p1-browser" => Some(Self::P1Browser),
            "p2-browser" => Some(Self::P2Browser),
            "p1-vm" => Some(Self::P1Vm),
            "p2-vm" => Some(Self::P2Vm),
            _ => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Governance => "governance",
            Self::P1Local => "p1-local",
            Self::P2Local => "p2-local",
            Self::P1Browser => "p1-browser",
            Self::P2Browser => "p2-browser",
            Self::P1Vm => "p1-vm",
            Self::P2Vm => "p2-vm",
        }
    }
}

struct Gate {
    id: &'static str,
    owner: &'static str,
    scope: &'static str,
    inputs: &'static str,
    lanes: &'static [Lane],
    timeout_seconds: u64,
    evidence: &'static str,
    failure_policy: &'static str,
    run: GateRunner,
}

const GOVERNANCE_LANES: &[Lane] = &[
    Lane::Governance,
    Lane::P1Local,
    Lane::P2Local,
    Lane::P1Browser,
    Lane::P2Browser,
    Lane::P1Vm,
    Lane::P2Vm,
];
const LOCAL_LANES: &[Lane] = &[Lane::P1Local, Lane::P2Local];
const P2_LOCAL_LANES: &[Lane] = &[Lane::P2Local];
const BROWSER_LANES: &[Lane] = &[Lane::P1Browser, Lane::P2Browser];
const VM_LANES: &[Lane] = &[Lane::P1Vm, Lane::P2Vm];
const P2_VM_LANES: &[Lane] = &[Lane::P2Vm];

const REQUIRED_FOUNDATION_PATHS: &[&str] = &[
    "README.md",
    "AGENTS.md",
    "CONSTITUTION.md",
    "docs/README.md",
    "docs/00-governance/document-authority.md",
    "docs/00-governance/specification-lifecycle.md",
    "docs/00-governance/build-and-dependency-policy.md",
    "docs/00-governance/verification-harness.md",
    "docs/00-governance/evidence-levels.md",
    "docs/00-governance/clean-room-policy.md",
    "docs/10-product/product-boundary.md",
    "docs/10-product/mvp-scope.md",
    "docs/10-product/support-matrix.md",
    "docs/10-product/non-goals.md",
    "docs/20-architecture/system-context.md",
    "docs/20-architecture/workspace-layout.md",
    "docs/20-architecture/state-ownership.md",
    "docs/20-architecture/public-ingress.md",
    "docs/30-domain/domain-map.md",
    "docs/30-domain/service-adapter-contract.md",
    "docs/30-domain/safe-operation.md",
    "docs/40-contracts/operation-lifecycle.md",
    "docs/40-contracts/assurance-levels.md",
    "docs/60-ui-ux/web-stack.md",
    "docs/60-ui-ux/information-architecture.md",
    "docs/60-ui-ux/design-system-dashboard.md",
    "docs/70-security/privilege-and-auth.md",
    "docs/70-security/pam-authentication.md",
    "docs/70-security/public-access.md",
    "docs/70-security/logging-and-forensics.md",
    "docs/70-security/JW-agent-threat-model.md",
    "docs/80-delivery/roadmap.md",
    "docs/80-delivery/definition-of-done.md",
    "docs/80-delivery/test-strategy.md",
    "docs/80-delivery/decision-register.md",
    "docs/90-specs/README.md",
    "docs/90-specs/operations/nginx-site-state-set-v1.md",
    "docs/90-specs/operations/public-access-profile-v1.md",
    "docs/90-specs/operations/managed-config-file-v1.md",
    "docs/90-specs/operations/certbot-certificate-v1.md",
    "docs/90-specs/access/openssh-terminal-sftp-v1.md",
    "docs/90-specs/access/openssh-password-broker-v1.md",
    "docs/90-specs/access/openssh-sftp-readonly-v1.md",
    "docs/90-specs/access/openssh-sftp-atomic-upload-v1.md",
    "docs/90-specs/auth/pam-login-v1.md",
    "docs/90-specs/auth/totp-step-up-v1.md",
    "docs/90-specs/ui/overview-v1.md",
    "docs/90-specs/ui/login-session-v1.md",
    "docs/90-specs/ui/responsive-shell-v1.md",
    "docs/90-specs/ui/rollback-assurance-v1.md",
    "docs/90-specs/ui/integration-catalog-v1.md",
    "docs/90-specs/adr/0007-public-https-pam-boundary.md",
    "docs/90-specs/adr/0008-p1-storage-and-contract-generation.md",
    "docs/90-specs/adr/0009-p2-safety-kernel-decisions.md",
    "docs/90-specs/adr/0010-local-maintenance-surfaces.md",
    "docs/90-specs/adr/0011-certbot-network-runner.md",
    "docs/90-specs/adr/0012-loopback-tls-verifier.md",
    "docs/90-specs/adr/0013-system-openssh-client.md",
    "tests/spec-fixtures/nginx-site-state-set-v1.json",
];

const P1_REQUIRED_PATHS: &[&str] = &[
    "api/openapi.json",
    "apps/web/bun.lock",
    "apps/web/src/routeTree.gen.ts",
    "apps/web/src/features/integrations/integrations-screen.tsx",
    "apps/web/src/routes/_authenticated.integrations.tsx",
    "apps/web/src/shared/ui/assurance.tsx",
    "apps/web/src/shared/api/generated/schema.d.ts",
    "crates/ffi-pam/src/lib.rs",
    "crates/jw-agentd/src/main.rs",
    "crates/jw-agentd/src/integration_catalog.rs",
    "crates/jw-authd/src/main.rs",
    "crates/jw-certd/src/main.rs",
    "crates/jw-contracts/src/lib.rs",
    "crates/jw-opsd/src/main.rs",
    "packaging/debian/control",
    "packaging/debian/install",
    "packaging/debian/rules",
    "packaging/default/jw-agent",
    "packaging/nginx/jw-agent-management.conf.template",
    "packaging/nginx/proxy-common.conf",
    "packaging/pam/jw-agent",
    "packaging/systemd/jw-agentd.service",
    "packaging/systemd/jw-authd.socket",
    "packaging/systemd/jw-authd@.service",
    "packaging/systemd/jw-certd.socket",
    "packaging/systemd/jw-certd@.service",
    "packaging/systemd/jw-opsd.service",
    "packaging/sysusers/jw-agent.conf",
    "packaging/tmpfiles/jw-agent.conf",
    "tests/vm/README.md",
    "tests/vm/cloud-init/user-data.yaml.template",
    "tests/vm/cloud-init/meta-data.yaml",
    "tests/vm/network/99-jw-agent-lan.yaml",
    "tests/vm/playwright-cli.json.template",
    "tests/vm/tls/server.ext.template",
    "xtask/src/vm.rs",
];

const P2_REQUIRED_PATHS: &[&str] = &[
    "apps/web/src/features/files/files-screen.tsx",
    "apps/web/src/routes/_authenticated.files.tsx",
    "apps/web/src/features/terminal/terminal-screen.tsx",
    "apps/web/src/routes/_authenticated.terminal.tsx",
    "crates/jw-certd/src/lib.rs",
    "crates/jw-agentd/migrations/0002_terminal_audit.sql",
    "crates/jw-agentd/migrations/0003_file_audit.sql",
    "crates/jw-agentd/migrations/0004_file_upload_audit.sql",
    "crates/jw-agentd/src/askpass.rs",
    "crates/jw-agentd/src/file_session.rs",
    "crates/jw-agentd/src/sftp_protocol.rs",
    "crates/jw-agentd/src/terminal.rs",
    "crates/jw-agentd/src/terminal_session.rs",
    "crates/jw-contracts/src/certificate.rs",
    "crates/jw-contracts/src/files.rs",
    "crates/jw-contracts/src/operation.rs",
    "crates/jw-contracts/src/terminal.rs",
    "crates/jw-opsd/migrations/0001_initial.sql",
    "crates/jw-opsd/migrations/0002_managed_config.sql",
    "crates/jw-opsd/migrations/0005_certbot_attach.sql",
    "crates/jw-opsd/src/config.rs",
    "crates/jw-opsd/src/certificate.rs",
    "crates/jw-opsd/src/digest.rs",
    "crates/jw-opsd/src/engine.rs",
    "crates/jw-opsd/src/error.rs",
    "crates/jw-opsd/src/ledger.rs",
    "crates/jw-opsd/src/managed_config.rs",
    "crates/jw-opsd/src/nginx.rs",
    "crates/jw-opsd/src/runner.rs",
    "crates/jw-opsd/src/snapshot.rs",
    "tests/spec-fixtures/nginx-site-state-set-v1.json",
    "tests/spec-fixtures/managed-config-file-v1.json",
];

const GATES: &[Gate] = &[
    Gate {
        id: "GOV-001",
        owner: "Maintainers",
        scope: "required foundation documents",
        inputs: "REQUIRED_FOUNDATION_PATHS registry and workspace files",
        lanes: GOVERNANCE_LANES,
        timeout_seconds: 2,
        evidence: "all required paths exist",
        failure_policy: "fail lane on any missing document",
        run: gate_required_documents,
    },
    Gate {
        id: "GOV-002",
        owner: "Maintainers",
        scope: "docs/**/*.md metadata",
        inputs: "Markdown files under docs",
        lanes: GOVERNANCE_LANES,
        timeout_seconds: 2,
        evidence: "mandatory headers present",
        failure_policy: "fail lane on incomplete metadata",
        run: gate_document_headers,
    },
    Gate {
        id: "GOV-003",
        owner: "Maintainers",
        scope: "local Markdown links",
        inputs: "workspace Markdown link graph",
        lanes: GOVERNANCE_LANES,
        timeout_seconds: 3,
        evidence: "targets exist and every docs page is indexed",
        failure_policy: "fail lane on broken or unindexed documentation",
        run: gate_markdown_links_and_index,
    },
    Gate {
        id: "GOV-004",
        owner: "Verification Maintainer",
        scope: ".github/workflows",
        inputs: "workflow directory",
        lanes: GOVERNANCE_LANES,
        timeout_seconds: 1,
        evidence: "no remote Actions workflow files",
        failure_policy: "fail lane when any remote workflow exists",
        run: gate_no_remote_actions,
    },
    Gate {
        id: "GOV-005",
        owner: "Build Maintainer",
        scope: "Cargo manifests",
        inputs: "workspace Cargo.toml files",
        lanes: GOVERNANCE_LANES,
        timeout_seconds: 2,
        evidence: "no git or outside-workspace path dependency",
        failure_policy: "fail lane on forbidden dependency source",
        run: gate_dependency_sources,
    },
    Gate {
        id: "GOV-006",
        owner: "Verification Maintainer",
        scope: "shell and Make wrappers",
        inputs: "workspace shell and Make wrappers",
        lanes: GOVERNANCE_LANES,
        timeout_seconds: 2,
        evidence: "verification logic is not duplicated outside xtask",
        failure_policy: "fail lane on duplicated verification command",
        run: gate_no_duplicate_harness,
    },
    Gate {
        id: "GOV-007",
        owner: "Verification Maintainer",
        scope: "xtask gate registry",
        inputs: "GATES metadata registry",
        lanes: GOVERNANCE_LANES,
        timeout_seconds: 1,
        evidence: "GateId and metadata are unique and complete",
        failure_policy: "fail lane on duplicate or incomplete metadata",
        run: gate_registry_integrity,
    },
    Gate {
        id: "P1-STRUCTURE",
        owner: "P1 Maintainers",
        scope: "P1 source, generated contracts, packaging, VM scenarios",
        inputs: "P1_REQUIRED_PATHS registry and workspace files",
        lanes: LOCAL_LANES,
        timeout_seconds: 2,
        evidence: "P1 ownership paths exist",
        failure_policy: "fail lane on missing P1 ownership path",
        run: gate_p1_structure,
    },
    Gate {
        id: "P2-STRUCTURE",
        owner: "P2 Safety Maintainers",
        scope: "P2 typed contracts, safety kernel, migration, and normative fixture",
        inputs: "P2_REQUIRED_PATHS registry and workspace files",
        lanes: P2_LOCAL_LANES,
        timeout_seconds: 2,
        evidence: "P2 safety ownership paths exist",
        failure_policy: "fail lane on missing P2 ownership path",
        run: gate_p2_structure,
    },
    Gate {
        id: "RUST-POLICY",
        owner: "Rust Maintainer",
        scope: "workspace Rust sources",
        inputs: "workspace Rust source files",
        lanes: LOCAL_LANES,
        timeout_seconds: 3,
        evidence: "forbidden failure shortcuts and unsafe leakage absent",
        failure_policy: "fail lane on forbidden source pattern",
        run: gate_rust_source_policy,
    },
    Gate {
        id: "P2-TERMINAL-BOUNDARY",
        owner: "Manual Access Maintainer",
        scope: "system OpenSSH terminal dependency, credential, privilege, and proxy boundary",
        inputs: "Accepted access specs, Cargo/Bun locks, package policy, agentd terminal sources, and opsd sources",
        lanes: P2_LOCAL_LANES,
        timeout_seconds: 3,
        evidence: "fixed loopback OpenSSH, strict host key, one-shot askpass, exact xterm pins, bounded WSS, and no opsd shell passed",
        failure_policy: "fail lane on credential persistence, broad SSH dependency, root helper shell path, missing bound, or proxy regression",
        run: gate_p2_terminal_boundary,
    },
    Gate {
        id: "P2-SFTP-BOUNDARY",
        owner: "Manual Access Maintainer",
        scope: "home-scoped OpenSSH SFTP read and atomic G1 upload protocol, path, session, and audit boundary",
        inputs: "Accepted SFTP read/upload specs, agentd file/SFTP sources, audit migrations, package policy, and opsd sources",
        lanes: P2_LOCAL_LANES,
        timeout_seconds: 3,
        evidence: "fixed OpenSSH subsystem, bounded read allowlist, PAM-planned fsync/atomic upload, canonical home confinement, metadata-only fail-closed audit, and no opsd path passed",
        failure_policy: "fail lane on broad write primitive, user argv, path/body/token persistence, unbounded transfer, root-helper file surface, or SSH dependency drift",
        run: gate_p2_sftp_boundary,
    },
    Gate {
        id: "RUST-FMT",
        owner: "Rust Maintainer",
        scope: "workspace Rust formatting",
        inputs: "workspace Rust source files and rustfmt toolchain",
        lanes: LOCAL_LANES,
        timeout_seconds: 30,
        evidence: "cargo fmt --check passed",
        failure_policy: "fail lane on formatting drift or timeout",
        run: gate_rust_fmt,
    },
    Gate {
        id: "RUST-CLIPPY",
        owner: "Rust Maintainer",
        scope: "workspace all targets",
        inputs: "Cargo.lock, manifests, Rust sources, clippy toolchain",
        lanes: LOCAL_LANES,
        timeout_seconds: 300,
        evidence: "clippy passed with warnings denied",
        failure_policy: "fail lane on warning, compile error, or timeout",
        run: gate_rust_clippy,
    },
    Gate {
        id: "RUST-TEST",
        owner: "Rust Maintainer",
        scope: "workspace unit and contract tests",
        inputs: "Cargo.lock, Rust sources, unit and contract tests",
        lanes: LOCAL_LANES,
        timeout_seconds: 300,
        evidence: "workspace tests and normative P2 fixture drift passed",
        failure_policy: "fail lane on test failure or timeout",
        run: gate_rust_test,
    },
    Gate {
        id: "OPENAPI-DRIFT",
        owner: "Contract Maintainer",
        scope: "Rust OpenAPI and generated TypeScript",
        inputs: "ApiDoc, committed OpenAPI, local generator, generated schema",
        lanes: LOCAL_LANES,
        timeout_seconds: 180,
        evidence: "committed API artifacts match generators",
        failure_policy: "fail lane on generator error, timeout, or byte drift",
        run: gate_openapi_drift,
    },
    Gate {
        id: "WEB-TYPECHECK",
        owner: "Web Maintainer",
        scope: "React application types",
        inputs: "web TypeScript sources and generated route/API types",
        lanes: LOCAL_LANES,
        timeout_seconds: 120,
        evidence: "TypeScript typecheck passed",
        failure_policy: "fail lane on type error or timeout",
        run: gate_web_typecheck,
    },
    Gate {
        id: "WEB-POLICY",
        owner: "Web Maintainer",
        scope: "web runtime source policy",
        inputs: "TypeScript and TSX files under apps/web/src",
        lanes: LOCAL_LANES,
        timeout_seconds: 3,
        evidence: "direct fetch, browser persistence, service worker, and dynamic classes absent",
        failure_policy: "fail lane on forbidden browser source pattern",
        run: gate_web_source_policy,
    },
    Gate {
        id: "WEB-LINT",
        owner: "Web Maintainer",
        scope: "React application lint",
        inputs: "web sources and ESLint configuration",
        lanes: LOCAL_LANES,
        timeout_seconds: 120,
        evidence: "ESLint passed with warnings denied",
        failure_policy: "fail lane on lint finding or timeout",
        run: gate_web_lint,
    },
    Gate {
        id: "WEB-UNIT",
        owner: "Web Maintainer",
        scope: "React unit tests",
        inputs: "web sources and Vitest suites",
        lanes: LOCAL_LANES,
        timeout_seconds: 120,
        evidence: "Vitest suite passed",
        failure_policy: "fail lane on unit failure or timeout",
        run: gate_web_unit,
    },
    Gate {
        id: "WEB-BUILD",
        owner: "Web Maintainer",
        scope: "production web bundle",
        inputs: "web sources, lockfile, Tailwind and Vite configuration",
        lanes: LOCAL_LANES,
        timeout_seconds: 180,
        evidence: "production bundle built",
        failure_policy: "fail lane on asset generation, bundle error, or timeout",
        run: gate_web_build,
    },
    Gate {
        id: "WEB-SESSION-BROWSER",
        owner: "Web Maintainer",
        scope: "mock-backed browser flows and responsive viewports",
        inputs: "web sources, Playwright scenarios, local Chromium",
        lanes: BROWSER_LANES,
        timeout_seconds: 300,
        evidence: "Playwright session, accessibility, and viewport scenarios passed",
        failure_policy: "fail lane and preserve configured failure artifacts",
        run: gate_web_browser,
    },
    Gate {
        id: "VM-PREFLIGHT",
        owner: "Verification Maintainer",
        scope: "disposable Ubuntu VM identity and fixture",
        inputs: "JW_VM_* environment and SSH host",
        lanes: VM_LANES,
        timeout_seconds: 45,
        evidence: "Ubuntu 24.04 disposable VM and fixture accounts verified",
        failure_policy: "fail lane on wrong host, missing fixture, or unsafe secret file",
        run: vm::gate_preflight,
    },
    Gate {
        id: "VM-PACKAGE-RUNTIME",
        owner: "Release Maintainer",
        scope: "installed deb, native links, PAM fixture, systemd identities, sockets, and sandbox",
        inputs: "installed jw-agent package and remote package artifact",
        lanes: VM_LANES,
        timeout_seconds: 60,
        evidence: "package checksum, native links, PAM fixture, services, least privilege, and socket boundaries passed",
        failure_policy: "fail lane on artifact/PAM drift, missing native runtime, inactive service, or privilege widening",
        run: vm::gate_package_runtime,
    },
    Gate {
        id: "VM-PAM-MATRIX",
        owner: "Identity Maintainer",
        scope: "real Ubuntu pam_unix login, app limiter isolation, SSH recovery, and role mapping",
        inputs: "disposable PAM fixture accounts and password via stdin",
        lanes: VM_LANES,
        timeout_seconds: 90,
        evidence: "limiter preserved Linux account and SSH recovery; valid roles and generic denials passed",
        failure_policy: "fail lane on Linux account mutation, lost SSH recovery, role mismatch, enumeration, timeout, or unavailable PAM",
        run: vm::gate_pam_matrix,
    },
    Gate {
        id: "VM-PUBLIC-RECOVERY",
        owner: "Ingress Maintainer",
        scope: "TLS public edge, SPA deep links, and loopback recovery",
        inputs: "VM FQDN, address, CA certificate, Nginx, and SSH",
        lanes: VM_LANES,
        timeout_seconds: 60,
        evidence: "valid TLS, exact boundary, HTTP redirect, deep link, and recovery passed",
        failure_policy: "fail lane on public plaintext, bad headers, exposed recovery, or lost SSH path",
        run: vm::gate_public_recovery,
    },
    Gate {
        id: "VM-P2-NGINX-OPERATION",
        owner: "P2 Safety Maintainers",
        scope: "real Nginx G2 plan, approval, apply, validation, reload, and rollback",
        inputs: "installed P2 package, public TLS API, PAM fixture, Nginx, opsd ledger",
        lanes: P2_VM_LANES,
        timeout_seconds: 300,
        evidence: "success, no-op, syntax failure, reload failure, and disk guard receipts passed",
        failure_policy: "fail lane on unsafe apply, missing rollback, wrong receipt, or leaked secret",
        run: vm::gate_p2_nginx_operation,
    },
    Gate {
        id: "VM-P2-MANAGED-CONFIG",
        owner: "Managed Configuration Maintainers",
        scope: "active Nginx config G2 plan, atomic replace, validation, reload, and exact rollback",
        inputs: "installed P2 package, public TLS API, PAM fixture, active Nginx resource, opsd ledger",
        lanes: P2_VM_LANES,
        timeout_seconds: 300,
        evidence: "save, no-op, syntax/reload rollback, external drift, inactive denial, and proposal cleanup passed",
        failure_policy: "fail lane on unvalidated save, inexact rollback, inactive edit, stale overwrite, or retained proposal",
        run: vm::gate_p2_managed_config,
    },
    Gate {
        id: "VM-P2-FORENSIC-LOCKDOWN",
        owner: "Security Maintainer",
        scope: "opsd ledger checkpoint deletion and fail-closed capability",
        inputs: "completed P2 ledger, checkpoint, opsd restart, authenticated capability API",
        lanes: P2_VM_LANES,
        timeout_seconds: 120,
        evidence: "checkpoint deletion disabled mutations and restoration recovered service",
        failure_policy: "fail lane if deleted evidence leaves mutation capability available",
        run: vm::gate_p2_forensic_lockdown,
    },
    Gate {
        id: "VM-P2-CERTD-BOUNDARY",
        owner: "Certificate Lifecycle Maintainer",
        scope: "root-only one-shot Certbot runner framing, command class, and cleanup",
        inputs: "installed P2C foundation package, certbot, root-only UDS, systemd sandbox",
        lanes: P2_VM_LANES,
        timeout_seconds: 120,
        evidence: "non-root denial, expired rejection, bounded renewal dry-run evidence, and one-shot cleanup passed",
        failure_policy: "fail lane on peer widening, invalid request execution, raw output response, or persistent worker/config",
        run: vm::gate_p2_certd_boundary,
    },
    Gate {
        id: "VM-P2-CERTIFICATE-INVENTORY",
        owner: "Certificate Lifecycle Maintainer",
        scope: "sanitized Certbot lineage, SAN, expiry, fingerprint, timer, and path policy",
        inputs: "installed P2C inventory package, public API, disposable certificate lineage",
        lanes: P2_VM_LANES,
        timeout_seconds: 120,
        evidence: "valid lineage metadata, masked paths, private-key non-disclosure, and escaped-target rejection passed",
        failure_policy: "fail lane on key/path disclosure, unvalidated symlink, missing timer state, or stale inventory",
        run: vm::gate_p2_certificate_inventory,
    },
    Gate {
        id: "VM-P2-CERTBOT-RENEW-OPERATION",
        owner: "Certificate Lifecycle Maintainer",
        scope: "G1 Certbot renewal plan, PAM approval, one-shot execution, and read-back",
        inputs: "installed P2C operation package, public API, PAM fixture, certbot.timer",
        lanes: P2_VM_LANES,
        timeout_seconds: 300,
        evidence: "success and unhealthy-timer receipts, private snapshot, digest-only output, and worker cleanup passed",
        failure_policy: "fail lane on bypassed plan/reauth, raw output, false rollback, unhealthy timer success, or retained worker",
        run: vm::gate_p2_certbot_renew_operation,
    },
    Gate {
        id: "VM-P2-CERTBOT-ISSUE-FAILURE",
        owner: "Certificate Lifecycle Maintainer",
        scope: "G1 Certbot staging issue preflight, approval, CA failure, and non-rollback receipt",
        inputs: "installed P2 issuance package, public API, PAM fixture, protected Nginx webroot, private-LAN FQDN",
        lanes: P2_VM_LANES,
        timeout_seconds: 480,
        evidence: "DNS/listener/webroot preflight passed; unreachable public CA was rejected without false rollback or inventory mutation",
        failure_policy: "fail lane on bypassed preflight/reauth, false success/rollback, inventory drift, raw email persistence, or retained proposal/worker",
        run: vm::gate_p2_certbot_issue_failure,
    },
    Gate {
        id: "VM-P2-CERTBOT-ATTACH-ROLLBACK",
        owner: "Certificate Lifecycle Maintainer",
        scope: "G2 protected Nginx certificate attach, local SNI verification, and exact rollback",
        inputs: "installed P2 attach package, public API, PAM fixture, disposable lineage, protected Nginx vhost",
        lanes: P2_VM_LANES,
        timeout_seconds: 360,
        evidence: "successful SNI fingerprint read-back and forced verifier failure exact rollback passed",
        failure_policy: "fail lane on unplanned attach, wrong SNI certificate, inexact rollback, unavailable Nginx, or raw certificate persistence",
        run: vm::gate_p2_certbot_attach_operation,
    },
    Gate {
        id: "VM-P2-OPENSSH-TERMINAL",
        owner: "Manual Access Maintainer",
        scope: "same-origin WSS ticket, non-root OpenSSH PTY, resize, replay, origin, revoke, and audit",
        inputs: "installed P2D package, public TLS API, PAM fixture, loopback sshd, strict host key, and agentd audit DB",
        lanes: P2_VM_LANES,
        timeout_seconds: 180,
        evidence: "non-root command I/O and resize, ticket replay/wrong-origin denial, logout close, metadata audit, and process cleanup passed",
        failure_policy: "fail lane on root path, weak host key, credential persistence, replay, missing bounds/audit, leaked process, or lost SSH service",
        run: vm::gate_p2_openssh_terminal,
    },
    Gate {
        id: "VM-P2-OPENSSH-SFTP-READONLY",
        owner: "Manual Access Maintainer",
        scope: "same-origin REST, PAM-bound OpenSSH SFTP, home confinement, bounded read, revoke, and audit",
        inputs: "installed P2D package, public TLS API, PAM fixture, loopback sshd, home fixture, strict host key, and agentd audit DB",
        lanes: P2_VM_LANES,
        timeout_seconds: 180,
        evidence: "home list/stat/text/download, traversal/symlink/size denial, cross-session/origin/close/logout denial, metadata audit, and process cleanup passed",
        failure_policy: "fail lane on home escape, write surface, credential/path/body persistence, missing bound/audit, leaked process, or changed SSH policy",
        run: vm::gate_p2_openssh_sftp_readonly,
    },
    Gate {
        id: "VM-P2-OPENSSH-SFTP-ATOMIC-UPLOAD",
        owner: "Manual Access Maintainer",
        scope: "PAM-planned home-scoped G1 file create and replace through OpenSSH atomic extensions",
        inputs: "installed P2 package, exact bounded Nginx route, public TLS API, PAM fixture, loopback sshd, and agentd upload audit",
        lanes: P2_VM_LANES,
        timeout_seconds: 240,
        evidence: "create, replace, mode and digest read-back, stale target, symlink/type/origin/digest/replay denial, metadata audit, and cleanup passed",
        failure_policy: "fail lane on unplanned write, non-atomic fallback, stale overwrite, home escape, secret/path/body persistence, false success, or temporary-file residue",
        run: vm::gate_p2_openssh_sftp_atomic_upload,
    },
    Gate {
        id: "VM-SECRET-SCAN",
        owner: "Security Maintainer",
        scope: "journal, SQLite, snapshot, process arguments, and package logs",
        inputs: "fixture password via stdin and live VM evidence sources",
        lanes: VM_LANES,
        timeout_seconds: 60,
        evidence: "fixture password absent from persisted and process evidence",
        failure_policy: "fail lane on any plaintext fixture secret match or incomplete scan",
        run: vm::gate_secret_scan,
    },
];

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<(), String> {
    let root = workspace_root()?;
    let mut arguments = env::args().skip(1);
    match (arguments.next().as_deref(), arguments.next().as_deref()) {
        (Some("list"), None) => list_gates(),
        (Some("verify"), Some(lane)) if arguments.next().is_none() => {
            let selected = Lane::parse(lane).ok_or_else(usage)?;
            verify_lane(&root, selected)
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    String::from(
        "usage: cargo xtask list | cargo xtask verify governance|p1-local|p2-local|p1-browser|p2-browser|p1-vm|p2-vm",
    )
}

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(parent) = manifest_directory.parent() else {
        return Err(String::from("xtask manifest has no workspace parent"));
    };
    Ok(parent.to_path_buf())
}

fn list_gates() -> Result<(), String> {
    for gate in GATES {
        let lanes = gate
            .lanes
            .iter()
            .map(|lane| lane.label())
            .collect::<Vec<&str>>()
            .join(",");
        println!(
            "{} | owner={} | scope={} | inputs={} | lanes={} | timeout={}s | evidence={} | failure={}",
            gate.id,
            gate.owner,
            gate.scope,
            gate.inputs,
            lanes,
            gate.timeout_seconds,
            gate.evidence,
            gate.failure_policy
        );
    }
    Ok(())
}

fn verify_lane(root: &Path, lane: Lane) -> Result<(), String> {
    let selected: Vec<&Gate> = GATES
        .iter()
        .filter(|gate| gate.lanes.contains(&lane))
        .collect();
    if selected.is_empty() {
        return Err(format!("lane {} has no registered gates", lane.label()));
    }

    let mut failures = Vec::new();
    for gate in &selected {
        let timeout = Duration::from_secs(gate.timeout_seconds);
        match (gate.run)(root, timeout) {
            Ok(()) => println!("PASS {} — {}", gate.id, gate.evidence),
            Err(error) => {
                println!("FAIL {} — {}", gate.id, error);
                failures.push(format!("{}: {error}", gate.id));
            }
        }
    }

    if failures.is_empty() {
        println!("{}: PASS ({} unique gates)", lane.label(), selected.len());
        Ok(())
    } else {
        Err(format!(
            "{} failed with {} gate(s): {}",
            lane.label(),
            failures.len(),
            failures.join(" | ")
        ))
    }
}

fn gate_required_documents(root: &Path, _timeout: Duration) -> Result<(), String> {
    let missing: Vec<&str> = REQUIRED_FOUNDATION_PATHS
        .iter()
        .copied()
        .filter(|relative| !root.join(relative).is_file())
        .collect();

    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("missing: {}", missing.join(", ")))
    }
}

fn gate_document_headers(root: &Path, _timeout: Duration) -> Result<(), String> {
    let docs = markdown_files(&root.join("docs"))?;
    let required = ["Status:", "Authority:", "Owner:", "Last reviewed:"];
    let mut failures = Vec::new();

    for document in docs {
        let content = read_text(&document)?;
        let missing: Vec<&str> = required
            .iter()
            .copied()
            .filter(|header| !content.lines().any(|line| line.starts_with(header)))
            .collect();
        if !missing.is_empty() {
            failures.push(format!(
                "{} missing {}",
                display_relative(root, &document),
                missing.join(", ")
            ));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn gate_markdown_links_and_index(root: &Path, _timeout: Duration) -> Result<(), String> {
    let mut all_markdown = markdown_files(root)?;
    all_markdown.retain(|path| !is_ignored_path(root, path));

    let mut graph: BTreeMap<PathBuf, BTreeSet<PathBuf>> = BTreeMap::new();
    let mut broken = Vec::new();

    for document in &all_markdown {
        let content = read_text(document)?;
        let mut targets = BTreeSet::new();
        for link in markdown_link_targets(&content) {
            if is_external_or_anchor(&link) {
                continue;
            }
            let without_fragment = match link.split_once('#') {
                Some((value, _fragment)) => value,
                None => link.as_str(),
            };
            if without_fragment.is_empty() {
                continue;
            }
            let Some(parent) = document.parent() else {
                broken.push(format!(
                    "{} has no parent",
                    display_relative(root, document)
                ));
                continue;
            };
            let candidate = normalize_path(&parent.join(without_fragment));
            if !candidate.exists() {
                broken.push(format!(
                    "{} -> {}",
                    display_relative(root, document),
                    without_fragment
                ));
            } else if candidate.extension() == Some(OsStr::new("md")) {
                targets.insert(candidate);
            }
        }
        graph.insert(normalize_path(document), targets);
    }

    if !broken.is_empty() {
        return Err(format!("broken links: {}", broken.join("; ")));
    }

    let start = normalize_path(&root.join("README.md"));
    let mut reached = BTreeSet::new();
    let mut queue = VecDeque::from([start]);
    while let Some(document) = queue.pop_front() {
        if !reached.insert(document.clone()) {
            continue;
        }
        if let Some(targets) = graph.get(&document) {
            queue.extend(targets.iter().cloned());
        }
    }

    let unindexed: Vec<String> = all_markdown
        .iter()
        .filter(|path| path.starts_with(root.join("docs")))
        .map(|path| normalize_path(path))
        .filter(|path| !reached.contains(path))
        .map(|path| display_relative(root, &path))
        .collect();

    if unindexed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "not reachable from README.md: {}",
            unindexed.join(", ")
        ))
    }
}

fn gate_no_remote_actions(root: &Path, _timeout: Duration) -> Result<(), String> {
    let workflow_directory = root.join(".github/workflows");
    if !workflow_directory.exists() {
        return Ok(());
    }
    let files = regular_files(&workflow_directory)?;
    if files.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "remote workflow files found: {}",
            files
                .iter()
                .map(|path| display_relative(root, path))
                .collect::<Vec<String>>()
                .join(", ")
        ))
    }
}

fn gate_dependency_sources(root: &Path, _timeout: Duration) -> Result<(), String> {
    let manifests: Vec<PathBuf> = regular_files(root)?
        .into_iter()
        .filter(|path| path.file_name() == Some(OsStr::new("Cargo.toml")))
        .filter(|path| !is_ignored_path(root, path))
        .collect();
    let mut failures = Vec::new();

    for manifest in manifests {
        let content = read_text(&manifest)?;
        for (line_index, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            if trimmed.contains("git =") || trimmed.contains("git=") {
                failures.push(format!(
                    "{}:{} git dependency",
                    display_relative(root, &manifest),
                    line_index + 1
                ));
            }
            if let Some(relative_path) = cargo_path_value(trimmed) {
                let Some(parent) = manifest.parent() else {
                    failures.push(format!(
                        "{}:{} manifest has no parent",
                        display_relative(root, &manifest),
                        line_index + 1
                    ));
                    continue;
                };
                let candidate = normalize_path(&parent.join(relative_path));
                if !candidate.starts_with(root) {
                    failures.push(format!(
                        "{}:{} outside path dependency",
                        display_relative(root, &manifest),
                        line_index + 1
                    ));
                }
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn gate_no_duplicate_harness(root: &Path, _timeout: Duration) -> Result<(), String> {
    let verification_fragments = [
        "cargo fmt",
        "cargo clippy",
        "cargo test",
        "cargo check",
        "bun test",
        "bun run test",
        "playwright test",
    ];
    let mut failures = Vec::new();

    for file in regular_files(root)? {
        if is_ignored_path(root, &file) || file.starts_with(root.join("xtask")) {
            continue;
        }
        let is_wrapper = file.file_name() == Some(OsStr::new("Makefile"))
            || matches!(
                file.extension().and_then(OsStr::to_str),
                Some("sh" | "zsh" | "bash")
            );
        if !is_wrapper {
            continue;
        }
        let content = read_text(&file)?;
        for fragment in verification_fragments {
            if content.contains(fragment) {
                failures.push(format!(
                    "{} duplicates `{fragment}`; call cargo xtask instead",
                    display_relative(root, &file)
                ));
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn gate_registry_integrity(_root: &Path, _timeout: Duration) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    let mut failures = Vec::new();
    for gate in GATES {
        if !ids.insert(gate.id) {
            failures.push(format!("duplicate GateId {}", gate.id));
        }
        if gate.owner.trim().is_empty()
            || gate.scope.trim().is_empty()
            || gate.inputs.trim().is_empty()
            || gate.evidence.trim().is_empty()
            || gate.failure_policy.trim().is_empty()
            || gate.lanes.is_empty()
            || gate.timeout_seconds == 0
        {
            failures.push(format!("incomplete metadata for {}", gate.id));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn gate_p1_structure(root: &Path, _timeout: Duration) -> Result<(), String> {
    let missing: Vec<&str> = P1_REQUIRED_PATHS
        .iter()
        .copied()
        .filter(|relative| !root.join(relative).is_file())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("missing: {}", missing.join(", ")))
    }
}

fn gate_p2_structure(root: &Path, _timeout: Duration) -> Result<(), String> {
    let missing: Vec<&str> = P2_REQUIRED_PATHS
        .iter()
        .copied()
        .filter(|relative| !root.join(relative).is_file())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("missing: {}", missing.join(", ")))
    }
}

fn gate_rust_source_policy(root: &Path, _timeout: Duration) -> Result<(), String> {
    let forbidden = [
        concat!(".", "unwrap", "("),
        concat!(".", "unwrap", "_"),
        concat!(".", "expect", "("),
        concat!(".", "expect", "_"),
        concat!("panic", "!"),
        concat!("todo", "!"),
        concat!("unimplemented", "!"),
    ];
    let mut failures = Vec::new();
    for file in regular_files(root)? {
        if file.extension() != Some(OsStr::new("rs")) || is_ignored_path(root, &file) {
            continue;
        }
        let content = read_text(&file)?;
        for (line_index, line) in content.lines().enumerate() {
            for fragment in forbidden {
                if line.contains(fragment) {
                    failures.push(format!(
                        "{}:{} contains forbidden `{fragment}`",
                        display_relative(root, &file),
                        line_index + 1
                    ));
                }
            }
            if !file.starts_with(root.join("crates/ffi-pam"))
                && (line.contains(concat!("unsafe", " {"))
                    || line.contains(concat!("unsafe", " fn"))
                    || line.contains(concat!("unsafe", " extern"))
                    || line.contains(concat!("unsafe", " impl")))
            {
                failures.push(format!(
                    "{}:{} leaks unsafe outside ffi-pam",
                    display_relative(root, &file),
                    line_index + 1
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn gate_p2_terminal_boundary(root: &Path, _timeout: Duration) -> Result<(), String> {
    let agent_manifest = read_text(&root.join("crates/jw-agentd/Cargo.toml"))?;
    let root_manifest = read_text(&root.join("Cargo.toml"))?;
    let web_manifest = read_text(&root.join("apps/web/package.json"))?;
    let package_control = read_text(&root.join("packaging/debian/control"))?;
    let tmpfiles = read_text(&root.join("packaging/tmpfiles/jw-agent.conf"))?;
    let proxy = read_text(&root.join("packaging/nginx/proxy-common.conf"))?;
    let terminal = read_text(&root.join("crates/jw-agentd/src/terminal_session.rs"))?;
    let askpass = read_text(&root.join("crates/jw-agentd/src/askpass.rs"))?;
    let audit = read_text(&root.join("crates/jw-agentd/migrations/0002_terminal_audit.sql"))?;
    let mut failures = Vec::new();

    for (content, needle, label) in [
        (&agent_manifest, "\"ws\"", "Axum WSS feature"),
        (&agent_manifest, "\"term\"", "nix PTY feature"),
        (&agent_manifest, "\"process\"", "Tokio process feature"),
        (
            &web_manifest,
            "\"@xterm/xterm\": \"6.0.0\"",
            "exact xterm pin",
        ),
        (
            &web_manifest,
            "\"@xterm/addon-fit\": \"0.11.0\"",
            "exact fit addon pin",
        ),
        (
            &package_control,
            "openssh-client",
            "OpenSSH package dependency",
        ),
        (
            &tmpfiles,
            "/run/jw-agent/askpass 0700 jw-agent jw-agent",
            "private askpass runtime",
        ),
        (
            &proxy,
            "proxy_set_header Upgrade $http_upgrade;",
            "WebSocket upgrade proxy",
        ),
        (&terminal, "StrictHostKeyChecking=yes", "strict host key"),
        (&terminal, "EscapeChar=none", "local SSH escape denial"),
        (&terminal, ".arg(\"--ctty\")", "controlling PTY wrapper"),
        (
            &terminal,
            ".arg(LOOPBACK_HOST)",
            "fixed loopback destination",
        ),
        (&askpass, "file_type().is_fifo()", "FIFO type validation"),
        (&askpass, "fs::remove_file(&path)", "one-shot FIFO unlink"),
        (&audit, "terminal_sessions", "terminal audit table"),
    ] {
        if !content.contains(needle) {
            failures.push(format!("missing {label}"));
        }
    }
    if root_manifest.contains("russh") || agent_manifest.contains("russh") {
        failures.push(String::from(
            "Rust SSH stack is forbidden for the local MVP",
        ));
    }
    for forbidden in ["password", "ticket", "command", "input", "output"] {
        if audit.lines().any(|line| {
            line.split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .any(|word| word == forbidden)
        }) {
            failures.push(format!(
                "terminal audit schema contains forbidden {forbidden} field"
            ));
        }
    }
    let opsd = root.join("crates/jw-opsd/src");
    for file in regular_files(&opsd)? {
        if file.extension() == Some(OsStr::new("rs")) {
            let content = read_text(&file)?;
            if content.contains("Terminal")
                || content.contains("openpty")
                || content.contains("SSH_ASKPASS")
            {
                failures.push(format!(
                    "root helper gained terminal surface in {}",
                    display_relative(root, &file)
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn gate_p2_sftp_boundary(root: &Path, _timeout: Duration) -> Result<(), String> {
    let root_manifest = read_text(&root.join("Cargo.toml"))?;
    let agent_manifest = read_text(&root.join("crates/jw-agentd/Cargo.toml"))?;
    let package_control = read_text(&root.join("packaging/debian/control"))?;
    let spec = read_text(&root.join("docs/90-specs/access/openssh-sftp-readonly-v1.md"))?;
    let upload_spec =
        read_text(&root.join("docs/90-specs/access/openssh-sftp-atomic-upload-v1.md"))?;
    let session = read_text(&root.join("crates/jw-agentd/src/file_session.rs"))?;
    let protocol = read_text(&root.join("crates/jw-agentd/src/sftp_protocol.rs"))?;
    let contract = read_text(&root.join("crates/jw-contracts/src/files.rs"))?;
    let audit = read_text(&root.join("crates/jw-agentd/migrations/0003_file_audit.sql"))?;
    let upload_audit =
        read_text(&root.join("crates/jw-agentd/migrations/0004_file_upload_audit.sql"))?;
    let edge = read_text(&root.join("packaging/nginx/jw-agent-management.conf.template"))?;
    let mut failures = Vec::new();

    for (content, needle, label) in [
        (&spec, "Status: Accepted", "Accepted SFTP spec"),
        (
            &upload_spec,
            "Status: Accepted",
            "Accepted atomic upload spec",
        ),
        (
            &package_control,
            "openssh-client",
            "OpenSSH package dependency",
        ),
        (&session, ".arg(\"-s\")", "fixed SSH subsystem mode"),
        (&session, ".arg(\"sftp\")", "fixed SFTP subsystem"),
        (&session, "RequestTTY=no", "PTY denial"),
        (&session, "StrictHostKeyChecking=yes", "strict host key"),
        (
            &session,
            ".arg(LOOPBACK_HOST)",
            "fixed loopback destination",
        ),
        (&session, "FILE_IDLE_TIMEOUT_SECONDS", "idle session bound"),
        (&protocol, "SSH_FXP_REALPATH", "server canonical path check"),
        (&protocol, "FILE_MAX_LIST_ENTRIES", "directory entry bound"),
        (&protocol, "FILE_MAX_TEXT_BYTES", "text bound"),
        (&protocol, "FILE_MAX_DOWNLOAD_BYTES", "download bound"),
        (&protocol, "SSH_FXP_WRITE", "bounded SFTP write message"),
        (
            &protocol,
            "open_write_exclusive",
            "exclusive temporary create",
        ),
        (&protocol, "EXTENSION_FSYNC", "OpenSSH fsync extension"),
        (
            &protocol,
            "EXTENSION_POSIX_RENAME",
            "OpenSSH atomic rename extension",
        ),
        (&session, "plan_upload", "memory-only upload plan"),
        (&contract, "FILE_UPLOAD_PLAN_TTL_SECONDS", "upload plan TTL"),
        (&contract, "validate_file_path", "relative path validator"),
        (&audit, "path_digest BLOB", "path digest audit"),
        (&audit, "file_access_events", "file access audit table"),
        (&upload_audit, "file_uploads", "file upload audit table"),
        (
            &edge,
            "location = /api/v1/files/upload",
            "exact upload edge route",
        ),
        (&edge, "client_max_body_size 8m;", "bounded upload body"),
    ] {
        if !content.contains(needle) {
            failures.push(format!("missing {label}"));
        }
    }
    for forbidden in [
        "SSH_FXP_RENAME",
        "SSH_FXP_MKDIR",
        "SSH_FXP_RMDIR",
        "SSH_FXP_SETSTAT",
        "SSH_FXP_FSETSTAT",
        "SSH_FXP_SYMLINK",
    ] {
        if protocol.contains(forbidden) {
            failures.push(format!(
                "read-only SFTP client contains forbidden {forbidden}"
            ));
        }
    }
    if root_manifest.contains("russh") || agent_manifest.contains("russh") {
        failures.push(String::from(
            "Rust SSH stack is forbidden for the local MVP",
        ));
    }
    for forbidden in ["path TEXT", "content", "password", "token", "file_body"] {
        if audit.contains(forbidden) || upload_audit.contains(forbidden) {
            failures.push(format!(
                "file audit schema contains forbidden {forbidden} field"
            ));
        }
    }
    let opsd = root.join("crates/jw-opsd/src");
    for file in regular_files(&opsd)? {
        if file.extension() == Some(OsStr::new("rs")) {
            let content = read_text(&file)?;
            if content.contains("SftpProtocol")
                || content.contains("FilePathRequest")
                || content.contains("SSH_FXP_")
            {
                failures.push(format!(
                    "root helper gained SFTP surface in {}",
                    display_relative(root, &file)
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn gate_rust_fmt(root: &Path, timeout: Duration) -> Result<(), String> {
    run_command(root, "cargo", ["fmt", "--all", "--check"], timeout)
}

fn gate_rust_clippy(root: &Path, timeout: Duration) -> Result<(), String> {
    run_command(
        root,
        "cargo",
        [
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        timeout,
    )
}

fn gate_rust_test(root: &Path, timeout: Duration) -> Result<(), String> {
    run_command(root, "cargo", ["test", "--workspace"], timeout)
}

fn gate_openapi_drift(root: &Path, timeout: Duration) -> Result<(), String> {
    let temporary = root
        .join("target")
        .join(format!("xtask-openapi-{}", std::process::id()));
    fs::create_dir_all(root.join("target")).map_err(|error| error.to_string())?;
    fs::create_dir(&temporary).map_err(|error| {
        format!(
            "cannot create contract evidence directory {}: {error}",
            temporary.display()
        )
    })?;
    let result = generate_and_compare_contracts(root, &temporary, timeout);
    let cleanup = fs::remove_dir_all(&temporary).map_err(|error| {
        format!(
            "cannot remove contract evidence directory {}: {error}",
            temporary.display()
        )
    });
    match (result, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn generate_and_compare_contracts(
    root: &Path,
    temporary: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let generated_openapi = temporary.join("openapi.json");
    let generated_schema = temporary.join("schema.d.ts");
    run_command_os(
        root,
        OsStr::new("cargo"),
        &[
            OsString::from("run"),
            OsString::from("--quiet"),
            OsString::from("-p"),
            OsString::from("jw-agentd"),
            OsString::from("--"),
            OsString::from("openapi"),
            generated_openapi.as_os_str().to_owned(),
        ],
        timeout,
    )?;
    let generator = root.join("apps/web/node_modules/.bin/openapi-typescript");
    if !generator.is_file() {
        return Err(String::from(
            "OpenAPI generator missing; run bun install in apps/web",
        ));
    }
    run_command_os(
        root,
        generator.as_os_str(),
        &[
            generated_openapi.as_os_str().to_owned(),
            OsString::from("-o"),
            generated_schema.as_os_str().to_owned(),
        ],
        timeout,
    )?;
    compare_files(root, &generated_openapi, &root.join("api/openapi.json"))?;
    compare_files(
        root,
        &generated_schema,
        &root.join("apps/web/src/shared/api/generated/schema.d.ts"),
    )
}

fn gate_web_typecheck(root: &Path, timeout: Duration) -> Result<(), String> {
    run_command(&root.join("apps/web"), "bun", ["run", "typecheck"], timeout)
}

fn gate_web_source_policy(root: &Path, _timeout: Duration) -> Result<(), String> {
    let source = root.join("apps/web/src");
    let forbidden = [
        ("localStorage", "local browser persistence"),
        ("sessionStorage", "session browser persistence"),
        ("navigator.serviceWorker", "service worker"),
        (concat!("className=", "{`"), "dynamic Tailwind class string"),
    ];
    let mut failures = Vec::new();
    for file in regular_files(&source)? {
        if !matches!(file.extension().and_then(OsStr::to_str), Some("ts" | "tsx")) {
            continue;
        }
        let content = read_text(&file)?;
        for (line_index, line) in content.lines().enumerate() {
            if contains_standalone_call(line, "fetch") {
                failures.push(format!(
                    "{}:{} contains direct fetch",
                    display_relative(root, &file),
                    line_index + 1
                ));
            }
            for (fragment, label) in forbidden {
                if line.contains(fragment) {
                    failures.push(format!(
                        "{}:{} contains {label}",
                        display_relative(root, &file),
                        line_index + 1
                    ));
                }
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn contains_standalone_call(line: &str, name: &str) -> bool {
    let needle = format!("{name}(");
    let mut remaining = line;
    while let Some(index) = remaining.find(&needle) {
        let preceding = remaining[..index].chars().next_back();
        if preceding.is_none_or(|value| !value.is_alphanumeric() && value != '_') {
            return true;
        }
        remaining = &remaining[index + needle.len()..];
    }
    false
}

fn gate_web_lint(root: &Path, timeout: Duration) -> Result<(), String> {
    run_command(&root.join("apps/web"), "bun", ["run", "lint"], timeout)
}

fn gate_web_unit(root: &Path, timeout: Duration) -> Result<(), String> {
    run_command(&root.join("apps/web"), "bun", ["run", "test"], timeout)
}

fn gate_web_build(root: &Path, timeout: Duration) -> Result<(), String> {
    run_command(&root.join("apps/web"), "bun", ["run", "build"], timeout)
}

fn gate_web_browser(root: &Path, timeout: Duration) -> Result<(), String> {
    run_command(&root.join("apps/web"), "bun", ["run", "test:e2e"], timeout)
}

fn run_command<I, S>(
    working_directory: &Path,
    program: &str,
    arguments: I,
    timeout: Duration,
) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let converted: Vec<OsString> = arguments
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect();
    run_command_os(working_directory, OsStr::new(program), &converted, timeout)
}

fn run_command_os(
    working_directory: &Path,
    program: &OsStr,
    arguments: &[OsString],
    timeout: Duration,
) -> Result<(), String> {
    let mut child = Command::new(program)
        .args(arguments)
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("cannot start {}: {error}", program.to_string_lossy()))?;
    let started = Instant::now();
    loop {
        match child
            .try_wait()
            .map_err(|error| format!("cannot wait for {}: {error}", program.to_string_lossy()))?
        {
            Some(status) if status.success() => return Ok(()),
            Some(status) => {
                return Err(format!(
                    "{} exited with {}",
                    program.to_string_lossy(),
                    status
                ));
            }
            None if started.elapsed() >= timeout => {
                child
                    .kill()
                    .map_err(|error| format!("cannot stop timed-out process: {error}"))?;
                let _status = child
                    .wait()
                    .map_err(|error| format!("cannot reap timed-out process: {error}"))?;
                return Err(format!(
                    "{} exceeded {} seconds",
                    program.to_string_lossy(),
                    timeout.as_secs()
                ));
            }
            None => thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn compare_files(root: &Path, generated: &Path, committed: &Path) -> Result<(), String> {
    let generated_bytes = fs::read(generated)
        .map_err(|error| format!("cannot read {}: {error}", generated.display()))?;
    let committed_bytes = fs::read(committed)
        .map_err(|error| format!("cannot read {}: {error}", committed.display()))?;
    if generated_bytes == committed_bytes {
        Ok(())
    } else {
        Err(format!(
            "generated contract differs from {}; regenerate it",
            display_relative(root, committed)
        ))
    }
}

fn markdown_files(directory: &Path) -> Result<Vec<PathBuf>, String> {
    Ok(regular_files(directory)?
        .into_iter()
        .filter(|path| path.extension() == Some(OsStr::new("md")))
        .collect())
}

fn regular_files(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let mut result = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = fs::read_dir(&current)
            .map_err(|error| format!("cannot read {}: {error}", current.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("cannot read directory entry: {error}"))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
            if file_type.is_dir() {
                if entry.file_name() != OsStr::new("target")
                    && entry.file_name() != OsStr::new("node_modules")
                    && entry.file_name() != OsStr::new(".git")
                {
                    pending.push(path);
                }
            } else if file_type.is_file() {
                result.push(path);
            }
        }
    }
    result.sort();
    Ok(result)
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn markdown_link_targets(content: &str) -> Vec<String> {
    let mut targets = Vec::new();
    for line in content.lines() {
        let mut remaining = line;
        while let Some(start) = remaining.find("](") {
            let after_open = &remaining[start + 2..];
            let Some(end) = after_open.find(')') else {
                break;
            };
            targets.push(after_open[..end].trim().to_string());
            remaining = &after_open[end + 1..];
        }
    }
    targets
}

fn is_external_or_anchor(target: &str) -> bool {
    target.starts_with("http://")
        || target.starts_with("https://")
        || target.starts_with("mailto:")
        || target.starts_with('#')
}

fn cargo_path_value(line: &str) -> Option<&str> {
    let path_start = line.find("path")?;
    let after_path = &line[path_start + 4..];
    let equals = after_path.find('=')?;
    let value = after_path[equals + 1..].trim_start();
    let value = value.strip_prefix('"')?;
    let end = value.find('"')?;
    Some(&value[..end])
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let _removed = normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn is_ignored_path(root: &Path, path: &Path) -> bool {
    path.starts_with(root.join("target"))
        || path.starts_with(root.join(".git"))
        || path.starts_with(root.join("artifacts"))
        || path
            .components()
            .any(|part| part.as_os_str() == OsStr::new("node_modules"))
}

fn display_relative(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(relative) => relative,
        Err(_) => path,
    }
    .display()
    .to_string()
}
