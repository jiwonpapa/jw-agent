import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import type { OperationReceiptView } from "../../src/shared/api/types";

const session = {
  subject: { uid: 1001, username: "operator", role: "admin" },
  ingress: "recovery",
  authenticatedAt: "2026-07-21T02:00:00Z",
  idleExpiresAt: "2026-07-21T03:00:00Z",
  absoluteExpiresAt: "2026-07-21T10:00:00Z",
  csrfToken: "fixture-csrf-token",
  additionalAuthPolicy: "disabled",
};

const health = {
  status: "ok",
  version: "0.1.0",
  ingress: "recovery",
  pam: "available",
  opsd: "available",
};

const host = {
  observedAt: "2026-07-21T02:10:00Z",
  status: "observed",
  hostname: "jw-demo",
  osId: "ubuntu",
  osVersionId: "24.04",
  osPrettyName: "Ubuntu 24.04 LTS",
  architecture: "x86_64",
  kernelRelease: "6.8.0",
  uptimeSeconds: 172800,
  loadAverageOne: 0.21,
  memory: { totalBytes: 8589934592, availableBytes: 5368709120 },
  rootDisk: { totalBytes: 107374182400, availableBytes: 75161927680 },
};

const observeAssurance = {
  level: "g0_observe_only",
  rollbackSupport: "not_applicable",
  operationAvailable: false,
  scope: ["상태 관찰"],
  excludedEffects: ["설정 변경"],
  applyVerifier: [],
  rollbackVerifier: [],
  reason: "현재 P1은 읽기 전용입니다.",
};

const protectedAssurance = {
  ...observeAssurance,
  reason: "JW Agent 공개 관리 리소스는 일반 Nginx 작업에서 변경할 수 없습니다.",
};

const policyAssurance = {
  level: "g2_reversible_config",
  rollbackSupport: "automatic_bounded",
  operationAvailable: true,
  scope: ["JW Agent 추가 인증 정책 값"],
  excludedEffects: ["외부 추가 인증 provider"],
  applyVerifier: ["SQLite transaction과 canonical read-back"],
  rollbackVerifier: ["저장 실패 시 이전 정책 유지"],
  reason: null,
};

const reversibleAssurance = {
  level: "g2_reversible_config",
  rollbackSupport: "automatic_bounded",
  operationAvailable: true,
  scope: ["선택한 Nginx site의 enabled link 존재 상태"],
  excludedEffects: ["sites-available 설정 내용", "기존 연결과 process history"],
  applyVerifier: ["enabled link read-back", "nginx -t", "nginx.service active"],
  rollbackVerifier: ["이전 link 상태 복원", "nginx -t와 reload 후 active 확인"],
  reason: null,
} satisfies OperationReceiptView["assurance"];

const availableDigest = `sha256:${"1".repeat(64)}`;
const enabledStateDigest = `sha256:${"2".repeat(64)}`;
const planHash = `sha256:${"3".repeat(64)}`;
const metadataDigest = `sha256:${"5".repeat(64)}`;
const configPlanHash = `sha256:${"6".repeat(64)}`;
const configResourceId = "ngc_fixtureResource123456789";

const nginx = {
  observedAt: "2026-07-21T02:10:00Z",
  status: "observed",
  sites: [
    {
      name: "example.com",
      siteId: "ngs_tQ9Xog5xTe1fh8OsTIdiw6xr",
      available: true,
      enabled: true,
      protected: false,
      availableDigest,
      enabledStateDigest,
      operationType: "nginx.site_state.set/v1",
      operationSchemaVersion: 1,
      managedConfigResourceId: configResourceId,
      managedConfigOperationType: "service.config_file.set/v1",
      managedConfigSchemaVersion: 1,
      assurance: reversibleAssurance,
    },
    {
      name: "jw-agent-management.conf",
      siteId: null,
      available: true,
      enabled: true,
      protected: true,
      availableDigest: null,
      enabledStateDigest: null,
      operationType: null,
      operationSchemaVersion: null,
      managedConfigResourceId: null,
      managedConfigOperationType: null,
      managedConfigSchemaVersion: null,
      assurance: protectedAssurance,
    },
  ],
  truncated: false,
};

const operationPlan = {
  schemaVersion: 1,
  operationType: "nginx.site_state.set/v1",
  planId: "plan_fixture",
  planHash,
  createdAt: "2026-07-21T02:11:00Z",
  expiresAt: "2026-07-21T02:16:00Z",
  actor: session.subject,
  siteId: "ngs_tQ9Xog5xTe1fh8OsTIdiw6xr",
  displayName: "example.com",
  currentState: "enabled",
  targetState: "disabled",
  availableDigest,
  enabledStateDigest,
  impact: [
    "Nginx enabled symlink 상태가 변경됩니다.",
    "nginx -t 후 nginx.service reload를 실행합니다.",
  ],
  recoveryPath: [
    "SSH로 서버에 접속합니다.",
    "JW Agent receipt와 Nginx 설정을 확인합니다.",
    "nginx -t 성공 후 Nginx를 reload합니다.",
  ],
  assurance: reversibleAssurance,
};

const operationReceipt: OperationReceiptView = {
  schemaVersion: 1,
  operationType: "nginx.site_state.set/v1",
  operationId: "op_fixture",
  planId: "plan_fixture",
  planHash,
  actor: session.subject as OperationReceiptView["actor"],
  terminalState: "SUCCEEDED",
  beforeDigest: enabledStateDigest,
  afterDigest: `sha256:${"4".repeat(64)}`,
  stages: [
    { sequence: 1, stage: "APPROVED", recordedAt: "2026-07-21T02:12:00Z", resultCode: "approved", evidenceDigest: planHash },
    { sequence: 2, stage: "SNAPSHOTTED", recordedAt: "2026-07-21T02:12:01Z", resultCode: "snapshot_durable", evidenceDigest: availableDigest },
    { sequence: 3, stage: "APPLYING", recordedAt: "2026-07-21T02:12:02Z", resultCode: "apply_started", evidenceDigest: enabledStateDigest },
    { sequence: 4, stage: "VALIDATING", recordedAt: "2026-07-21T02:12:03Z", resultCode: "nginx_config_valid", evidenceDigest: availableDigest },
    { sequence: 5, stage: "RELOADING", recordedAt: "2026-07-21T02:12:04Z", resultCode: "nginx_reloaded", evidenceDigest: availableDigest },
    { sequence: 6, stage: "SUCCEEDED", recordedAt: "2026-07-21T02:12:05Z", resultCode: "verified", evidenceDigest: availableDigest },
  ],
  assurance: reversibleAssurance,
  rollbackResult: null,
  recoveryPath: [],
};

const operationAccepted = {
  schemaVersion: 1,
  operationType: "nginx.site_state.set/v1",
  operationId: "op_fixture",
  planId: "plan_fixture",
  planHash,
  actor: session.subject,
  currentStage: "APPROVED",
  eventStream: "/api/v1/operations/op_fixture/events",
};

const managedConfigResource = {
  schemaVersion: 1,
  adapterId: "nginx/ubuntu-standard-v1",
  resourceId: configResourceId,
  displayName: "example.com",
  maskedPath: "…/sites-available/example.com",
  content: "server {\n  listen 80;\n}\n",
  contentDigest: availableDigest,
  metadataDigest,
  maxBytes: 24576,
  allowedServiceActions: ["reload"],
  assurance: {
    ...reversibleAssurance,
    scope: ["등록된 Nginx 설정 파일 하나의 bytes·owner·mode와 검증된 reload"],
    excludedEffects: ["include된 다른 파일과 active connection", "제품 밖 root 사용자의 동시 변경"],
  },
};

const managedConfigPlan = {
  schemaVersion: 1,
  operationType: "service.config_file.set/v1",
  planId: "plan_config_fixture",
  planHash: configPlanHash,
  createdAt: "2026-07-21T02:11:00Z",
  expiresAt: "2026-07-21T02:16:00Z",
  actor: session.subject,
  adapterId: "nginx/ubuntu-standard-v1",
  resourceId: configResourceId,
  displayName: "example.com",
  maskedPath: "…/sites-available/example.com",
  currentContentDigest: availableDigest,
  proposedContentDigest: `sha256:${"7".repeat(64)}`,
  metadataDigest,
  currentBytes: 26,
  proposedBytes: 44,
  addedLines: 1,
  removedLines: 0,
  diffSummary: ["+  client_max_body_size 20m;"],
  serviceAction: "reload",
  impact: [
    "등록된 Nginx 설정 파일 하나의 bytes·owner·mode를 교체합니다.",
    "nginx -t가 성공한 경우에만 nginx.service reload를 실행합니다.",
  ],
  recoveryPath: ["SSH로 서버에 접속합니다.", "대상 Nginx 설정을 검토하고 nginx -t를 실행합니다."],
  assurance: managedConfigResource.assurance,
};

const managedConfigReceipt: OperationReceiptView = {
  ...operationReceipt,
  operationType: "service.config_file.set/v1",
  planId: "plan_config_fixture",
  planHash: configPlanHash,
  beforeDigest: availableDigest,
  afterDigest: managedConfigPlan.proposedContentDigest,
};

const managedConfigAccepted = {
  ...operationAccepted,
  operationType: "service.config_file.set/v1",
  planId: "plan_config_fixture",
  planHash: configPlanHash,
};

const access = {
  ingress: "recovery",
  publicHost: "care.example.com",
  recoveryOrigin: "http://127.0.0.1:9843",
  additionalAuthPolicy: "disabled",
  additionalAuthProvider: "not_implemented",
  mutationApprovalAvailable: false,
  assurance: policyAssurance,
};

const terminalCapability = {
  available: true,
  reason: null,
  username: "operator",
  assurance: {
    level: "g1_verified_action",
    rollbackSupport: "not_guaranteed",
    operationAvailable: true,
    scope: ["현재 로그인한 non-root Linux 계정의 제한 시간 OpenSSH 세션"],
    excludedEffects: ["터미널에서 실행한 명령과 외부 효과의 자동 원복", "root 로그인"],
    applyVerifier: ["PAM 재인증", "strict OpenSSH host key"],
    rollbackVerifier: ["자동 원복 없음"],
    reason: null,
  },
  limits: {
    ticketTtlSeconds: 30,
    idleTimeoutSeconds: 300,
    maxLifetimeSeconds: 1800,
    maxFrameBytes: 16384,
    maxOutputBufferBytes: 262144,
    maxSessionsPerUser: 1,
  },
};

const certificates = {
  schemaVersion: 1,
  observedAt: "2026-07-21T02:10:00Z",
  certbotInstalled: true,
  timerEnabled: true,
  timerActive: true,
  inventoryDigest: `sha256:${"8".repeat(64)}`,
  certificates: [
    {
      primaryDomain: "care.example.com",
      sans: ["care.example.com", "www.care.example.com"],
      notAfter: "2026-10-20 12:00:00Z",
      fingerprintSha256: `sha256:${"a".repeat(64)}`,
      certificatePath: "…/live/care.example.com/fullchain.pem",
      privateKeyPresent: true,
      renewalConfigPresent: true,
      webrootManaged: true,
    },
  ],
  problems: [],
  attachOperationType: null,
  issueOperationType: null,
  renewTestOperationType: null,
  assurance: {
    ...observeAssurance,
    scope: ["certificate SAN·만료·fingerprint와 Certbot timer 상태만 조회합니다."],
    excludedEffects: ["private key·ACME account secret·certificate 원문"],
    reason: "발급·attach 작업은 P2C operation fault gate 전까지 차단됩니다.",
  },
};

const verifiedActionAssurance = {
  level: "g1_verified_action",
  rollbackSupport: "not_guaranteed",
  operationAvailable: true,
  scope: ["고정된 certbot renew --dry-run만 one-shot network runner에서 실행합니다."],
  excludedEffects: ["CA challenge·rate-limit 기록 같은 외부 효과는 원복할 수 없습니다."],
  applyVerifier: [
    "Certbot exit와 timeout 상태를 digest-only 증거로 검증합니다.",
    "certbot.timer와 sanitized certificate inventory를 다시 읽습니다.",
  ],
  rollbackVerifier: [],
  reason: "로컬 설정을 바꾸지 않는 외부 갱신 검증이므로 자동 원복 대상이 없습니다.",
} satisfies OperationReceiptView["assurance"];

const actionableCertificates = {
  ...certificates,
  renewTestOperationType: "certbot.certificate.renew_test/v1",
};

const actionableIssueCertificates = {
  ...certificates,
  issueOperationType: "certbot.certificate.issue/v1",
  renewTestOperationType: "certbot.certificate.renew_test/v1",
};

const actionableAttachCertificates = {
  ...actionableIssueCertificates,
  attachOperationType: "certbot.certificate.attach/v1",
};

const issueNginx = {
  ...nginx,
  sites: nginx.sites.map((site) =>
    site.protected
      ? {
          ...site,
          siteId: "ngs_managementFixture123456",
          availableDigest: `sha256:${"b".repeat(64)}`,
          enabledStateDigest,
        }
      : site,
  ),
};

const certbotIssuePlan = {
  schemaVersion: 1,
  operationType: "certbot.certificate.issue/v1",
  planId: "plan_certbot_issue_fixture",
  planHash: `sha256:${"c".repeat(64)}`,
  createdAt: "2026-07-21T02:11:00Z",
  expiresAt: "2026-07-21T02:21:00Z",
  actor: session.subject,
  primaryDomain: "care.example.com",
  domains: ["care.example.com"],
  maskedAccountEmail: "o***@example.com",
  environment: "staging",
  siteId: "ngs_managementFixture123456",
  inventoryDigest: certificates.inventoryDigest,
  siteDigest: `sha256:${"b".repeat(64)}`,
  resolvedAddresses: ["192.0.2.10"],
  localPort80Reachable: true,
  localPort443Reachable: true,
  stagingEvidenceValid: false,
  impact: [
    "staging은 Let’s Encrypt 시험 CA에 실제 challenge를 요청하지만 인증서를 저장하지 않습니다.",
    "이번 작업은 인증서 발급까지만 수행하고 Nginx TLS 연결은 별도 G2 승인으로 남깁니다.",
  ],
  recoveryPath: ["SSH에서 certbot certificates와 해당 domain의 renewal 상태를 확인합니다."],
  assurance: {
    ...verifiedActionAssurance,
    scope: ["canonical domain에 대해 고정 webroot Certbot staging 또는 production 발급만 실행합니다."],
    excludedEffects: ["CA challenge·계정·발급·rate-limit 기록은 원복할 수 없습니다."],
  },
};

const certbotIssueReceipt: OperationReceiptView = {
  ...operationReceipt,
  operationType: "certbot.certificate.issue/v1",
  planId: certbotIssuePlan.planId,
  planHash: certbotIssuePlan.planHash,
  beforeDigest: certificates.inventoryDigest,
  afterDigest: certificates.inventoryDigest,
  assurance: verifiedActionAssurance,
  rollbackResult: null,
  recoveryPath: [],
  stages: [
    { sequence: 1, stage: "APPROVED", recordedAt: "2026-07-21T02:12:00Z", resultCode: "approved", evidenceDigest: certbotIssuePlan.planHash },
    { sequence: 2, stage: "SNAPSHOTTED", recordedAt: "2026-07-21T02:12:01Z", resultCode: "snapshot_durable", evidenceDigest: certificates.inventoryDigest },
    { sequence: 3, stage: "APPLYING", recordedAt: "2026-07-21T02:12:02Z", resultCode: "certbot_staging_dry_run_started", evidenceDigest: certificates.inventoryDigest },
    { sequence: 4, stage: "VALIDATING", recordedAt: "2026-07-21T02:12:03Z", resultCode: "certbot_issue_command_completed", evidenceDigest: certificates.inventoryDigest },
    { sequence: 5, stage: "SUCCEEDED", recordedAt: "2026-07-21T02:12:04Z", resultCode: "staging_challenge_verified", evidenceDigest: certificates.inventoryDigest },
  ],
};

const certbotIssueAccepted = {
  ...operationAccepted,
  operationType: "certbot.certificate.issue/v1",
  planId: certbotIssuePlan.planId,
  planHash: certbotIssuePlan.planHash,
};

const certbotAttachPlan = {
  schemaVersion: 1,
  operationType: "certbot.certificate.attach/v1",
  planId: "plan_certbot_attach_fixture",
  planHash: `sha256:${"d".repeat(64)}`,
  createdAt: "2026-07-21T02:11:00Z",
  expiresAt: "2026-07-21T02:16:00Z",
  actor: session.subject,
  primaryDomain: "care.example.com",
  siteId: "ngs_managementFixture123456",
  siteDigest: `sha256:${"b".repeat(64)}`,
  inventoryDigest: certificates.inventoryDigest,
  certificateFingerprint: `sha256:${"a".repeat(64)}`,
  sans: ["care.example.com", "www.care.example.com"],
  notAfter: "2026-10-20 12:00:00Z",
  currentCertificatePath: "…/jw-agent/tls/server.crt",
  targetCertificatePath: "…/live/care.example.com/fullchain.pem",
  timerEnabled: true,
  timerActive: true,
  impact: [
    "보호된 Nginx vhost의 ssl_certificate 지시문 두 개만 교체합니다.",
    "문법 검사 후 reload하고 loopback SNI 인증서 지문을 확인합니다.",
  ],
  recoveryPath: ["SSH에서 보호된 Nginx 설정 snapshot을 확인합니다."],
  assurance: {
    ...reversibleAssurance,
    scope: ["보호된 Nginx vhost 인증서 지시문 두 개와 검증된 reload"],
    excludedEffects: ["제품 밖 root 사용자의 동시 변경", "기존 TLS 연결"],
    applyVerifier: ["nginx -t", "reload 후 active", "loopback SNI SHA-256", "Certbot timer"],
    rollbackVerifier: ["원본 bytes·owner·mode 복원", "nginx -t와 reload 후 active"],
  },
};

const certbotAttachReceipt: OperationReceiptView = {
  ...operationReceipt,
  operationType: "certbot.certificate.attach/v1",
  planId: certbotAttachPlan.planId,
  planHash: certbotAttachPlan.planHash,
  beforeDigest: certbotAttachPlan.siteDigest,
  afterDigest: `sha256:${"e".repeat(64)}`,
  assurance: certbotAttachPlan.assurance,
  stages: [
    { sequence: 1, stage: "APPROVED", recordedAt: "2026-07-21T02:12:00Z", resultCode: "approved", evidenceDigest: certbotAttachPlan.planHash },
    { sequence: 2, stage: "SNAPSHOTTED", recordedAt: "2026-07-21T02:12:01Z", resultCode: "snapshot_durable", evidenceDigest: certbotAttachPlan.siteDigest },
    { sequence: 3, stage: "APPLYING", recordedAt: "2026-07-21T02:12:02Z", resultCode: "tls_directives_replaced", evidenceDigest: certbotAttachPlan.siteDigest },
    { sequence: 4, stage: "VALIDATING", recordedAt: "2026-07-21T02:12:03Z", resultCode: "nginx_syntax_valid", evidenceDigest: certbotAttachPlan.siteDigest },
    { sequence: 5, stage: "RELOADING", recordedAt: "2026-07-21T02:12:04Z", resultCode: "nginx_reloaded", evidenceDigest: certbotAttachPlan.siteDigest },
    { sequence: 6, stage: "VERIFYING", recordedAt: "2026-07-21T02:12:05Z", resultCode: "nginx_reloaded", evidenceDigest: certbotAttachPlan.siteDigest },
    { sequence: 7, stage: "SUCCEEDED", recordedAt: "2026-07-21T02:12:06Z", resultCode: "tls_attachment_verified", evidenceDigest: `sha256:${"e".repeat(64)}` },
  ],
};

const certbotAttachAccepted = {
  ...operationAccepted,
  operationType: "certbot.certificate.attach/v1",
  planId: certbotAttachPlan.planId,
  planHash: certbotAttachPlan.planHash,
};

const certbotRenewPlan = {
  schemaVersion: 1,
  operationType: "certbot.certificate.renew_test/v1",
  planId: "plan_certbot_fixture",
  planHash: `sha256:${"9".repeat(64)}`,
  createdAt: "2026-07-21T02:11:00Z",
  expiresAt: "2026-07-21T02:21:00Z",
  actor: session.subject,
  inventoryDigest: certificates.inventoryDigest,
  timerEnabled: true,
  timerActive: true,
  certificateCount: 1,
  impact: [
    "Certbot이 ACME staging 서버에 실제 갱신 challenge를 요청할 수 있습니다.",
    "인증서 교체를 적용하지 않는 dry-run이지만 외부 CA 통신과 challenge 요청은 되돌릴 수 없습니다.",
  ],
  recoveryPath: ["SSH로 certbot.timer와 Nginx 상태를 확인합니다."],
  assurance: verifiedActionAssurance,
};

const certbotRenewReceipt: OperationReceiptView = {
  schemaVersion: 1,
  operationType: "certbot.certificate.renew_test/v1",
  operationId: "op_fixture",
  planId: certbotRenewPlan.planId,
  planHash: certbotRenewPlan.planHash,
  actor: session.subject as OperationReceiptView["actor"],
  terminalState: "SUCCEEDED",
  beforeDigest: certificates.inventoryDigest,
  afterDigest: certificates.inventoryDigest,
  stages: [
    { sequence: 1, stage: "APPROVED", recordedAt: "2026-07-21T02:12:00Z", resultCode: "approved", evidenceDigest: certbotRenewPlan.planHash },
    { sequence: 2, stage: "SNAPSHOTTED", recordedAt: "2026-07-21T02:12:01Z", resultCode: "snapshot_durable", evidenceDigest: certificates.inventoryDigest },
    { sequence: 3, stage: "APPLYING", recordedAt: "2026-07-21T02:12:02Z", resultCode: "certbot_renew_dry_run_started", evidenceDigest: certificates.inventoryDigest },
    { sequence: 4, stage: "VALIDATING", recordedAt: "2026-07-21T02:12:03Z", resultCode: "certbot_renew_dry_run_completed", evidenceDigest: certificates.inventoryDigest },
    { sequence: 5, stage: "SUCCEEDED", recordedAt: "2026-07-21T02:12:04Z", resultCode: "renewal_test_verified", evidenceDigest: certificates.inventoryDigest },
  ],
  assurance: verifiedActionAssurance,
  rollbackResult: null,
  recoveryPath: [],
};

const certbotRenewAccepted = {
  ...operationAccepted,
  operationType: "certbot.certificate.renew_test/v1",
  planId: certbotRenewPlan.planId,
  planHash: certbotRenewPlan.planHash,
};

const integrations = {
  observedAt: "2026-07-21T02:10:00Z",
  status: "observed",
  entries: [
    {
      id: "g7_telegram_devops",
      name: "G7Telegram DevOps",
      summary: "Telegram에서 서버 상태와 장애를 확인합니다.",
      category: "notification",
      lifecycleStatus: "not_installed",
      installStatus: "blocked",
      detectedComponents: [],
      installBlockers: ["독립 Release 서명이 등록되지 않았습니다."],
      resourceClaims: ["g7tg-agent systemd 서비스", "Telegram Bot token"],
      setupSteps: ["Bot token 발급", "제품 setup에서 직접 등록"],
      sourceUrl: "https://github.com/jiwonpapa/g7Telegram-devops",
      assurance: observeAssurance,
    },
    {
      id: "g7_media_booster",
      name: "G7MediaBooster",
      summary: "Gnuboard 미디어 업로드와 가공을 처리합니다.",
      category: "media",
      lifecycleStatus: "needs_setup",
      installStatus: "blocked",
      detectedComponents: ["실행 파일 감지"],
      installBlockers: ["native dependency VM 증거가 없습니다."],
      resourceClaims: ["libvips와 FFmpeg", "loopback API"],
      setupSteps: ["스토리지 provider 준비", "doctor 실행"],
      sourceUrl: "https://github.com/jiwonpapa/g7mediabooster",
      assurance: observeAssurance,
    },
    {
      id: "g7_installer",
      name: "G7 Installer",
      summary: "신규 Ubuntu VPS 설치 환경을 구성합니다.",
      category: "provisioning",
      lifecycleStatus: "partial",
      installStatus: "blocked",
      detectedComponents: ["설정 또는 활성 release 감지"],
      installBlockers: ["G2 원복 보장 대상이 아닙니다."],
      resourceClaims: ["apt package", "Nginx·PHP·MySQL"],
      setupSteps: ["신규 VPS 확인", "VPS snapshot 준비"],
      sourceUrl: "https://github.com/jiwonpapa/g7-installer",
      assurance: observeAssurance,
    },
    {
      id: "vps_guard",
      name: "VPSGuard",
      summary: "봇과 과다 트래픽을 단계적으로 방어합니다.",
      category: "security",
      lifecycleStatus: "installed",
      installStatus: "blocked",
      detectedComponents: ["실행 파일 감지", "설정 또는 활성 release 감지"],
      installBlockers: ["80/443 cutover와 rollback 증거가 없습니다."],
      resourceClaims: ["public 80/443", "Nginx·TLS·Cloudflare"],
      setupSteps: ["충돌 검사", "shadow 검증", "별도 활성화 plan"],
      sourceUrl: "https://github.com/jiwonpapa/VPSGuard",
      assurance: observeAssurance,
    },
  ],
};

async function mockApi(
  page: Page,
  initiallyAuthenticated: boolean,
  healthFixture = health,
  operationOptions: {
    receipt?: OperationReceiptView;
    onPlan?: (body: unknown) => void;
    onApproval?: (body: unknown) => void;
    onConfigPlan?: (body: unknown) => void;
    onConfigApproval?: (body: unknown) => void;
    onEvents?: () => void;
    certificateFixture?: Record<string, unknown>;
    nginxFixture?: Record<string, unknown>;
    onCertbotPlan?: (body: unknown) => void;
    onCertbotApproval?: (body: unknown) => void;
    onCertbotIssuePlan?: (body: unknown) => void;
    onCertbotIssueApproval?: (body: unknown) => void;
    onCertbotAttachPlan?: (body: unknown) => void;
    onCertbotAttachApproval?: (body: unknown) => void;
    onTerminalTicket?: (body: unknown) => void;
    terminalFixture?: Record<string, unknown>;
  } = {},
): Promise<void> {
  let authenticated = initiallyAuthenticated;
  let activeReceipt = operationOptions.receipt ?? operationReceipt;
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/health") return route.fulfill({ json: healthFixture });
    if (path === "/api/v1/auth/login" && request.method() === "POST") {
      authenticated = true;
      return route.fulfill({ json: session });
    }
    if (path === "/api/v1/auth/session") {
      return authenticated
        ? route.fulfill({ json: session })
        : route.fulfill({
            status: 401,
            json: { type: "about:blank", title: "Authentication required", status: 401, code: "unauthorized" },
          });
    }
    if (path === "/api/v1/auth/reauth" && request.method() === "POST") {
      return route.fulfill({
        json: {
          session,
          reauthToken: "reauth_fixture_token_1234567890",
          expiresAt: "2026-07-21T02:14:00Z",
        },
      });
    }
    if (path === "/api/v1/host") return route.fulfill({ json: host });
    if (path === "/api/v1/terminal" && request.method() === "GET") {
      return route.fulfill({ json: operationOptions.terminalFixture ?? terminalCapability });
    }
    if (path === "/api/v1/terminal/tickets" && request.method() === "POST") {
      operationOptions.onTerminalTicket?.(request.postDataJSON());
      return route.fulfill({
        status: 201,
        json: {
          ticket: "A".repeat(43),
          expiresAt: "2026-07-21T02:11:30Z",
          websocketPath: "/api/v1/terminal/connect",
          assurance: terminalCapability.assurance,
          limits: terminalCapability.limits,
        },
      });
    }
    if (path === "/api/v1/certificates") {
      return route.fulfill({ json: operationOptions.certificateFixture ?? certificates });
    }
    if (path === "/api/v1/services/nginx/sites") {
      return route.fulfill({ json: operationOptions.nginxFixture ?? nginx });
    }
    if (path === `/api/v1/config-resources/${configResourceId}` && request.method() === "GET") {
      return route.fulfill({ json: managedConfigResource });
    }
    if (path === "/api/v1/operations/nginx/site-state/plans" && request.method() === "POST") {
      operationOptions.onPlan?.(request.postDataJSON());
      return route.fulfill({ json: operationPlan });
    }
    if (path === "/api/v1/operations/nginx/site-state/approvals" && request.method() === "POST") {
      operationOptions.onApproval?.(request.postDataJSON());
      activeReceipt = operationOptions.receipt ?? operationReceipt;
      return route.fulfill({ status: 202, json: operationAccepted });
    }
    if (path === "/api/v1/operations/service/config-file/plans" && request.method() === "POST") {
      operationOptions.onConfigPlan?.(request.postDataJSON());
      return route.fulfill({ json: managedConfigPlan });
    }
    if (path === "/api/v1/operations/service/config-file/approvals" && request.method() === "POST") {
      operationOptions.onConfigApproval?.(request.postDataJSON());
      activeReceipt = managedConfigReceipt;
      return route.fulfill({ status: 202, json: managedConfigAccepted });
    }
    if (path === "/api/v1/operations/certbot/renew-test/plans" && request.method() === "POST") {
      operationOptions.onCertbotPlan?.(request.postDataJSON());
      return route.fulfill({ json: certbotRenewPlan });
    }
    if (path === "/api/v1/operations/certbot/renew-test/approvals" && request.method() === "POST") {
      operationOptions.onCertbotApproval?.(request.postDataJSON());
      activeReceipt = certbotRenewReceipt;
      return route.fulfill({ status: 202, json: certbotRenewAccepted });
    }
    if (path === "/api/v1/operations/certbot/issue/plans" && request.method() === "POST") {
      operationOptions.onCertbotIssuePlan?.(request.postDataJSON());
      return route.fulfill({ json: certbotIssuePlan });
    }
    if (path === "/api/v1/operations/certbot/issue/approvals" && request.method() === "POST") {
      operationOptions.onCertbotIssueApproval?.(request.postDataJSON());
      activeReceipt = certbotIssueReceipt;
      return route.fulfill({ status: 202, json: certbotIssueAccepted });
    }
    if (path === "/api/v1/operations/certbot/attach/plans" && request.method() === "POST") {
      operationOptions.onCertbotAttachPlan?.(request.postDataJSON());
      return route.fulfill({ json: certbotAttachPlan });
    }
    if (path === "/api/v1/operations/certbot/attach/approvals" && request.method() === "POST") {
      operationOptions.onCertbotAttachApproval?.(request.postDataJSON());
      activeReceipt = certbotAttachReceipt;
      return route.fulfill({ status: 202, json: certbotAttachAccepted });
    }
    if (path === "/api/v1/operations/op_fixture/events") {
      operationOptions.onEvents?.();
      const receipt = activeReceipt;
      const stage = receipt.stages.at(-1);
      return route.fulfill({
        status: 200,
        headers: {
          "cache-control": "no-store",
          "content-type": "text/event-stream",
          "x-accel-buffering": "no",
        },
        body:
          stage === undefined
            ? ""
            : `id: ${String(stage.sequence)}\nevent: operation-stage\ndata: ${JSON.stringify(stage)}\n\n`,
      });
    }
    if (path === "/api/v1/operations/op_fixture" && request.method() === "GET") {
      return route.fulfill({ json: activeReceipt });
    }
    if (path === "/api/v1/integrations") return route.fulfill({ json: integrations });
    if (path === "/api/v1/settings/access") return route.fulfill({ json: access });
    return route.fulfill({ status: 404, json: { type: "about:blank", title: "Not found", status: 404, code: "not_found" } });
  });
}

test("PAM login keeps credentials out of URL and web storage", async ({ page }) => {
  await mockApi(page, false);
  await page.goto("/login?returnTo=%2Foverview");
  await page.getByLabel("Linux 아이디").fill("operator");
  await page.getByLabel("비밀번호", { exact: true }).fill("fixture-password");
  await page.getByRole("button", { name: "로그인" }).click();

  await expect(page).toHaveURL(/\/overview$/);
  await expect(page.getByRole("heading", { name: "서버 개요" })).toBeVisible();
  expect(page.url()).not.toContain("fixture-password");
  const stored = await page.evaluate(() => ({
    local: Object.values(localStorage),
    session: Object.values(sessionStorage),
  }));
  expect(JSON.stringify(stored)).not.toContain("fixture-password");
});

test("public HTTP keeps the password form disabled", async ({ page }) => {
  await mockApi(page, false, { ...health, ingress: "public" });
  await page.goto("/login?returnTo=%2Foverview");
  await expect(page.getByText("공개 접속에서는 유효한 HTTPS 연결이 필요합니다.")).toBeVisible();
  await expect(page.getByLabel("Linux 아이디")).toBeDisabled();
  await expect(page.getByLabel("비밀번호", { exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "로그인" })).toBeDisabled();
});

test("expired session redirects to login once without nesting returnTo", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await mockApi(page, false);

  await page.goto("/integrations");
  await expect(page.getByRole("heading", { name: "서버에 로그인" })).toBeVisible();
  let location = new URL(page.url());
  expect(location.pathname).toBe("/login");
  expect(location.searchParams.get("returnTo")).toBe("/integrations");

  await page.reload();
  await expect(page.getByRole("heading", { name: "서버에 로그인" })).toBeVisible();
  location = new URL(page.url());
  expect(location.pathname).toBe("/login");
  expect(location.searchParams.get("returnTo")).toBe("/integrations");
  expect(pageErrors).toEqual([]);
});

for (const viewport of [
  { width: 320, height: 800 },
  { width: 390, height: 844 },
  { width: 768, height: 1024 },
  { width: 1024, height: 768 },
  { width: 1440, height: 900 },
]) {
  test(
    `overview reflows at ${String(viewport.width)}x${String(viewport.height)}`,
    async ({ page }) => {
    await page.setViewportSize(viewport);
    await mockApi(page, true);
    await page.goto("/overview");
    await expect(page.getByRole("heading", { name: "서버 개요" })).toBeVisible();
    const hasOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    expect(hasOverflow).toBe(false);
    },
  );
}

test("access screen states provider limitation without false protection claim", async ({ page }) => {
  await mockApi(page, true);
  await page.goto("/settings/access");
  await expect(page.getByText("추가 인증 제공자가 아직 구현되지 않았습니다.")).toBeVisible();
  await expect(page.getByText(/보호됨으로 간주하지 마세요/)).toBeVisible();
  await expect(page.getByText("위험 작업만")).toBeVisible();
  await expect(page.getByText(/G2 · 제한된 설정 자동 원복 지원/)).toBeVisible();
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((violation) => ["critical", "serious"].includes(violation.impact ?? ""))).toEqual([]);
});

for (const viewport of [
  { width: 320, height: 800 },
  { width: 768, height: 1024 },
  { width: 1440, height: 900 },
]) {
  test(
    `terminal keeps G1 approval visible at ${String(viewport.width)}x${String(viewport.height)}`,
    async ({ page }) => {
      await page.setViewportSize(viewport);
      await mockApi(page, true);
      await page.goto("/terminal");
      await expect(page.getByRole("heading", { name: "비루트 터미널" })).toBeVisible();
      await expect(page.getByText("G1 · 자동 원복 없음")).toBeVisible();
      await expect(page.getByText(/잘못된 명령으로 서비스나 데이터가 손상될 수 있음/)).toBeVisible();
      const connect = page.getByRole("button", { name: "재인증 후 연결" });
      await page.getByLabel("Linux 비밀번호 재확인").fill("fixture-terminal-password");
      await expect(connect).toBeDisabled();
      await page.getByLabel(/터미널 명령은 자동 원복되지 않으며/).check();
      await expect(connect).toBeEnabled();
      const hasOverflow = await page.evaluate(
        () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
      );
      expect(hasOverflow).toBe(false);
    },
  );
}

test("terminal ticket keeps password out of URL and browser storage", async ({ page }) => {
  let ticketBody: unknown;
  await page.routeWebSocket("**/api/v1/terminal/connect", (socket) => {
    socket.send(JSON.stringify({
      type: "ready",
      sessionId: "0123456789abcdef0123456789abcdef",
      assurance: "g1_verified_action",
    }));
  });
  await mockApi(page, true, health, {
    onTerminalTicket: (body) => {
      ticketBody = body;
    },
  });
  await page.goto("/terminal");
  await page.getByLabel("Linux 비밀번호 재확인").fill("fixture-terminal-password");
  await page.getByLabel(/터미널 명령은 자동 원복되지 않으며/).check();
  await page.getByRole("button", { name: "재인증 후 연결" }).click();
  await expect(page.getByText(/세션 01234567/)).toBeVisible();
  expect(ticketBody).toEqual({
    password: "fixture-terminal-password",
    rows: 24,
    cols: 80,
    riskConfirmed: true,
  });
  expect(page.url()).not.toContain("fixture-terminal-password");
  const stored = await page.evaluate(() => ({
    local: Object.values(localStorage),
    session: Object.values(sessionStorage),
  }));
  expect(JSON.stringify(stored)).not.toContain("fixture-terminal-password");
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter((violation) =>
      ["critical", "serious"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
});

test("G2 Nginx change discloses rollback scope before exact-plan PAM approval", async ({ page }) => {
  let planRequests = 0;
  let approvalRequests = 0;
  const planBodies: unknown[] = [];
  const approvalBodies: unknown[] = [];
  await page.setViewportSize({ width: 320, height: 800 });
  await mockApi(page, true, health, {
    onPlan: (body) => {
      planRequests += 1;
      planBodies.push(body);
    },
    onApproval: (body) => {
      approvalRequests += 1;
      approvalBodies.push(body);
    },
  });
  await page.goto("/services/nginx");

  await expect(
    page.locator("span:visible").filter({ hasText: "G2 · 제한된 설정 자동 원복 지원" }).first(),
  ).toBeVisible();
  await page.getByRole("button", { name: "변경 계획 열기" }).first().click();
  await page.getByRole("button", { name: "비활성화 계획 만들기" }).dblclick();

  await expect(page.getByRole("heading", { name: "실행 영향" })).toBeVisible();
  await expect(page.getByText(/sites-available 설정 내용/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "원복 검증도 실패하면 수동 복구가 필요합니다" })).toBeVisible();
  const recoveryHeading = page.getByRole("heading", {
    name: "원복 검증도 실패하면 수동 복구가 필요합니다",
  });
  const approvalButton = page.getByRole("button", { name: "재인증 후 실행" });
  const disclosureComesFirst = await recoveryHeading.evaluate((heading, button) => {
    if (!(button instanceof Element)) return false;
    return Boolean(heading.compareDocumentPosition(button) & Node.DOCUMENT_POSITION_FOLLOWING);
  }, await approvalButton.elementHandle());
  expect(disclosureComesFirst).toBe(true);

  await page.getByLabel("Linux 계정 비밀번호로 이 계획 승인").fill("fixture-password");
  await approvalButton.dblclick();
  await expect(page.getByRole("heading", { name: "적용 완료" })).toBeVisible();
  await expect(page.getByText("이전 상태 저장")).toBeVisible();
  expect(planRequests).toBe(1);
  expect(approvalRequests).toBe(1);
  expect((approvalBodies[0] as Record<string, unknown>).planHash).toBe(planHash);
  expect((approvalBodies[0] as Record<string, unknown>).idempotencyKey).toBe(
    (planBodies[0] as Record<string, unknown>).idempotencyKey,
  );
  expect(JSON.stringify(approvalBodies)).not.toContain("fixture-password");
  expect(page.url()).not.toContain("fixture-password");
  const hasOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(hasOverflow).toBe(false);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter((violation) =>
      ["critical", "serious"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
});

test("managed Nginx editor requires diff, two intents, and exact-plan PAM before reload", async ({
  page,
}) => {
  const planBodies: unknown[] = [];
  const approvalBodies: unknown[] = [];
  await page.setViewportSize({ width: 390, height: 844 });
  await mockApi(page, true, health, {
    onConfigPlan: (body) => planBodies.push(body),
    onConfigApproval: (body) => approvalBodies.push(body),
  });
  await page.goto("/services/nginx");
  await page.getByRole("button", { name: "변경 계획 열기" }).first().click();
  await page.getByRole("button", { name: "설정 파일 편집" }).click();

  const editor = page.getByLabel("Nginx 설정 내용");
  await expect(editor).toHaveValue(managedConfigResource.content);
  await expect(page.getByText("저장 버튼으로 즉시 반영하지 않습니다")).toBeVisible();
  await editor.fill("server {\n  listen 80;\n  client_max_body_size 20m;\n}\n");
  await page.getByRole("button", { name: "변경 계획 만들기" }).dblclick();

  await expect(page.getByRole("heading", { name: "설정 변경 계획" })).toBeVisible();
  await expect(page.getByText("+  client_max_body_size 20m;")).toBeVisible();
  await expect(page.getByText(/include된 다른 파일과 active connection/)).toBeVisible();
  const approval = page.getByRole("button", { name: "재인증 후 설정 적용" });
  await page.getByLabel("Linux 계정 비밀번호로 exact plan 승인").fill("fixture-password");
  await expect(approval).toBeDisabled();
  await page.getByLabel(/nginx -t를 통과해야만 reload/).check();
  await expect(approval).toBeDisabled();
  await page.getByLabel(/nginx.service reload를 수행/).check();
  await approval.dblclick();

  await expect(page.getByRole("heading", { name: "적용 완료" })).toBeVisible();
  await expect(page.getByText(/설정 bytes·metadata, 문법, reload, active/)).toBeVisible();
  expect(planBodies).toHaveLength(1);
  expect(approvalBodies).toHaveLength(1);
  const approvalBody = approvalBodies[0] as Record<string, unknown>;
  expect(approvalBody.planHash).toBe(configPlanHash);
  expect(approvalBody.approvalIntent).toEqual({
    validationConfirmed: true,
    serviceActionConfirmed: true,
  });
  expect(JSON.stringify(approvalBodies)).not.toContain("fixture-password");
  expect(JSON.stringify(approvalBodies)).not.toContain("client_max_body_size");
  const hasOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(hasOverflow).toBe(false);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter((violation) =>
      ["critical", "serious"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
});

test("G0 protected Nginx resource has no mutation action", async ({ page }) => {
  await mockApi(page, true);
  await page.goto("/services/nginx");
  await page.getByRole("button", { name: "상세" }).click();
  await expect(page.getByText("JW Agent 공개 관리 리소스는 일반 Nginx 작업에서 변경할 수 없습니다.")).toBeVisible();
  await expect(page.getByRole("button", { name: /계획 만들기/ })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "설정 파일 편집" })).toHaveCount(0);
});

test("rollback failure is never shown as a successful recovery", async ({ page }) => {
  const recoveryReceipt: OperationReceiptView = {
    ...operationReceipt,
    terminalState: "RECOVERY_REQUIRED",
    rollbackResult: "rollback_verification_failed",
    recoveryPath: operationPlan.recoveryPath,
    stages: [
      ...operationReceipt.stages.slice(0, 4),
      { sequence: 5, stage: "ROLLING_BACK", recordedAt: "2026-07-21T02:12:04Z", resultCode: "rollback_started", evidenceDigest: availableDigest },
      { sequence: 6, stage: "RECOVERY_REQUIRED", recordedAt: "2026-07-21T02:12:05Z", resultCode: "rollback_verification_failed", evidenceDigest: availableDigest },
    ],
  };
  await mockApi(page, true, health, { receipt: recoveryReceipt });
  await page.goto("/services/nginx");
  await page.getByRole("button", { name: "계획 보기" }).first().click();
  await page.getByRole("button", { name: "비활성화 계획 만들기" }).click();
  await page.getByLabel("Linux 계정 비밀번호로 이 계획 승인").fill("fixture-password");
  await page.getByRole("button", { name: "재인증 후 실행" }).click();
  await expect(page.getByRole("heading", { name: "실패 · 수동 복구 필요" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "수동 복구 경로" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "적용 완료" })).toHaveCount(0);
});

test("certificate inventory stays read-only and responsive without exposing key material", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockApi(page, true);
  await page.goto("/certificates");
  await expect(page.getByRole("heading", { name: "TLS 인증서" })).toBeVisible();
  await expect(page.getByText("care.example.com", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("webroot 관리")).toBeVisible();
  await expect(page.getByText("조회 전용")).toBeVisible();
  await expect(page.getByRole("button", { name: /발급|갱신|적용/ })).toHaveCount(0);
  expect(await page.locator("body").innerText()).not.toContain("PRIVATE KEY");
  const hasOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(hasOverflow).toBe(false);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter((violation) =>
      ["critical", "serious"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
});

test("G1 Certbot renewal test requires plan, external-effect intent, and PAM approval", async ({ page }) => {
  const planBodies: unknown[] = [];
  const approvalBodies: unknown[] = [];
  await page.setViewportSize({ width: 390, height: 844 });
  await mockApi(page, true, health, {
    certificateFixture: actionableCertificates,
    onCertbotPlan: (body) => planBodies.push(body),
    onCertbotApproval: (body) => approvalBodies.push(body),
  });
  await page.goto("/certificates");

  await expect(page.getByText("G1 검증 가능")).toBeVisible();
  await page.getByRole("button", { name: "갱신 사전 검증 계획 만들기" }).dblclick();
  await expect(page.getByRole("heading", { name: "외부 갱신 사전 검증 계획" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "G1 · 자동 원복 보장 없음" })).toBeVisible();
  await expect(page.getByText(/challenge·rate-limit 기록은 되돌릴 수 없습니다/)).toBeVisible();

  const approval = page.getByRole("button", { name: "재인증 후 dry-run 실행" });
  await page.getByLabel("Linux 계정 비밀번호로 exact plan 승인").fill("fixture-password");
  await expect(approval).toBeDisabled();
  await page.getByLabel(/외부 CA 요청은 원복할 수 없다는 점/).check();
  await approval.dblclick();

  await expect(page.getByRole("heading", { name: "갱신 검증 완료" })).toBeVisible();
  await expect(page.getByText(/timer·sanitized inventory 재조회/)).toBeVisible();
  expect(planBodies).toHaveLength(1);
  expect(approvalBodies).toHaveLength(1);
  const planBody = planBodies[0] as Record<string, unknown>;
  const approvalBody = approvalBodies[0] as Record<string, unknown>;
  expect(approvalBody.planHash).toBe(certbotRenewPlan.planHash);
  expect(approvalBody.idempotencyKey).toBe(planBody.idempotencyKey);
  expect(approvalBody.externalEffectConfirmed).toBe(true);
  expect(JSON.stringify(approvalBodies)).not.toContain("fixture-password");
  expect(await page.locator("body").innerText()).not.toContain("PRIVATE KEY");
  const hasOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(hasOverflow).toBe(false);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter((violation) =>
      ["critical", "serious"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
});

test("G2 Certbot attach requires two intents and verifies responsive rollback disclosure", async ({ page }) => {
  const planBodies: unknown[] = [];
  const approvalBodies: unknown[] = [];
  await page.setViewportSize({ width: 390, height: 844 });
  await mockApi(page, true, health, {
    certificateFixture: actionableAttachCertificates,
    nginxFixture: issueNginx,
    onCertbotAttachPlan: (body) => planBodies.push(body),
    onCertbotAttachApproval: (body) => approvalBodies.push(body),
  });
  await page.goto("/certificates");

  await expect(page.getByText("G2 연결 가능")).toBeVisible();
  await page.getByRole("button", { name: "Nginx 연결 계획 만들기" }).dblclick();
  await expect(page.getByRole("heading", { name: "care.example.com TLS 연결 계획" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "G2 · 제한된 설정 자동 원복" })).toBeVisible();
  await expect(page.getByText(/jw-agent\/tls\/server\.crt.*live\/care\.example\.com\/fullchain\.pem/)).toBeVisible();
  await expect(
    page.getByLabel("Nginx TLS 인증서 연결").getByText(certbotAttachPlan.certificateFingerprint),
  ).toBeVisible();

  const approval = page.getByRole("button", { name: "재인증 후 TLS 연결" });
  await page.getByLabel("Linux 계정 비밀번호로 exact plan 승인").fill("fixture-password");
  await expect(approval).toBeDisabled();
  await page.getByLabel(/인증서 지시문 두 개가 교체됨/).check();
  await expect(approval).toBeDisabled();
  await page.getByLabel(/nginx\.service reload와 기존 연결 재수립/).check();
  await approval.dblclick();

  await expect(page.getByRole("heading", { name: "TLS 연결 검증 완료" })).toBeVisible();
  await expect(page.getByText(/SNI 인증서 지문·Certbot 갱신 상태/)).toBeVisible();
  expect(planBodies).toHaveLength(1);
  expect(approvalBodies).toHaveLength(1);
  const planBody = planBodies[0] as Record<string, unknown>;
  const approvalBody = approvalBodies[0] as Record<string, unknown>;
  expect(planBody.primaryDomain).toBe("care.example.com");
  expect(planBody.siteId).toBe(issueNginx.sites[1]?.siteId);
  expect(planBody.expectedSiteDigest).toBe(issueNginx.sites[1]?.availableDigest);
  expect(planBody.expectedInventoryDigest).toBe(certificates.inventoryDigest);
  expect(planBody.expectedCertificateFingerprint).toBe(certificates.certificates[0]?.fingerprintSha256);
  expect(approvalBody.configReplaceConfirmed).toBe(true);
  expect(approvalBody.serviceReloadConfirmed).toBe(true);
  expect(JSON.stringify(approvalBodies)).not.toContain("fixture-password");
  const hasOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(hasOverflow).toBe(false);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter((violation) =>
      ["critical", "serious"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
});

test("guided Certbot staging issue requires preflight, two intents, and PAM approval", async ({ page }) => {
  const planBodies: unknown[] = [];
  const approvalBodies: unknown[] = [];
  await page.setViewportSize({ width: 390, height: 844 });
  await mockApi(page, true, health, {
    certificateFixture: actionableIssueCertificates,
    nginxFixture: issueNginx,
    onCertbotIssuePlan: (body) => planBodies.push(body),
    onCertbotIssueApproval: (body) => approvalBodies.push(body),
  });
  await page.goto("/certificates");

  await expect(page.getByRole("heading", { name: "신규 인증서 발급" })).toBeVisible();
  await page.getByLabel("ACME 계정 이메일").fill("owner@example.com");
  await page.getByLabel(/Let’s Encrypt 이용약관/).check();
  await page.getByRole("button", { name: "발급 전 계획 만들기" }).dblclick();
  await expect(page.getByRole("heading", { name: "care.example.com 발급 계획" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "G1 · CA 외부효과는 자동 원복 불가" })).toBeVisible();
  await expect(page.getByText(/TLS 연결은 별도 G2 승인/).first()).toBeVisible();

  const approval = page.getByRole("button", { name: "staging 발급 실행" });
  await page.getByLabel("Linux 계정 비밀번호로 exact plan 승인").fill("fixture-password");
  await expect(approval).toBeDisabled();
  await page.getByLabel(/CA challenge·발급·rate-limit 외부효과/).check();
  await expect(approval).toBeDisabled();
  await page.getByLabel(/Nginx TLS 연결은 별도 G2 계획/).check();
  await approval.dblclick();

  await expect(page.getByRole("heading", { name: "인증서 발급 검증 완료" })).toBeVisible();
  await expect(page.getByText(/TLS 연결은 아직 변경하지 않았습니다/)).toBeVisible();
  expect(planBodies).toHaveLength(1);
  expect(approvalBodies).toHaveLength(1);
  const planBody = planBodies[0] as Record<string, unknown>;
  const approvalBody = approvalBodies[0] as Record<string, unknown>;
  expect(planBody.environment).toBe("staging");
  expect(planBody.primaryDomain).toBe("care.example.com");
  expect(approvalBody.externalEffectConfirmed).toBe(true);
  expect(approvalBody.localAttachDeferredConfirmed).toBe(true);
  expect(JSON.stringify(approvalBodies)).not.toContain("fixture-password");
  const hasOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(hasOverflow).toBe(false);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter((violation) =>
      ["critical", "serious"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
});

for (const viewport of [
  { width: 320, height: 800 },
  { width: 390, height: 844 },
  { width: 768, height: 1024 },
  { width: 1024, height: 768 },
  { width: 1440, height: 900 },
]) {
  test(
    `integration catalog keeps assurance and blockers at ${String(viewport.width)}x${String(viewport.height)}`,
    async ({ page }) => {
      await page.setViewportSize(viewport);
      await mockApi(page, true);
      await page.goto("/integrations");
      await expect(page.getByRole("heading", { name: "통합 카탈로그" })).toBeVisible();
      const telegram = page.locator('[data-testid="integration-g7_telegram_devops"]:visible');
      await expect(telegram.getByText("G7Telegram DevOps")).toBeVisible();
      await expect(telegram.getByText(/차단/)).toBeVisible();
      await expect(telegram.getByText(/G0 · 변경 없음/)).toBeVisible();
      const hasOverflow = await page.evaluate(
        () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
      );
      expect(hasOverflow).toBe(false);
    },
  );
}

test("integration inspector exposes resources and blockers without install action", async ({ page }) => {
  await mockApi(page, true);
  await page.goto("/integrations");
  await page.getByRole("button", { name: /조건.*보기/ }).first().click();
  await expect(page.getByRole("heading", { name: "필요한 자원과 권한" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "현재 설치 차단 사유" })).toBeVisible();
  await expect(page.getByText("독립 Release 서명이 등록되지 않았습니다.")).toBeVisible();
  await expect(page.getByText(/외부 저장소의 명령을 자동 실행하지 않습니다/)).toBeVisible();
  await expect(page.getByRole("button", { name: /^설치$/ })).toHaveCount(0);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter((violation) =>
      ["critical", "serious"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
});
