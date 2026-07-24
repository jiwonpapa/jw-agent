import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { services } from "./fixtures/service-inventory";

const resourceId = "php_EHiO24phPSLjnfU_2gJ5LpNw";
const contentDigest = `sha256:${"1".repeat(64)}`;
const metadataDigest = `sha256:${"2".repeat(64)}`;
const planHash = `sha256:${"3".repeat(64)}`;
const proposedDigest = `sha256:${"4".repeat(64)}`;
const assurance = {
  level: "g2_reversible_config",
  rollbackSupport: "automatic_bounded",
  operationAvailable: true,
  scope: ["Ubuntu PHP 8.3 FPM 표준 php.ini 한 파일과 검증된 reload"],
  excludedEffects: ["pool·CLI·Apache SAPI 설정과 extension package"],
  applyVerifier: ["php-fpm8.3 -t", "php8.3-fpm.service active", "content·owner·mode read-back"],
  rollbackVerifier: ["이전 bytes·owner·mode 복원", "문법 검사·reload·active 재확인"],
  reason: null,
};
const session = {
  subject: { uid: 1001, username: "operator", role: "admin" },
  ingress: "recovery",
  authenticatedAt: "2026-07-22T02:00:00Z",
  idleExpiresAt: "2026-07-22T03:00:00Z",
  absoluteExpiresAt: "2026-07-22T10:00:00Z",
  csrfToken: "fixture-csrf-token",
  additionalAuthPolicy: "disabled",
  administrativeAccess: "administrative",
  administrativeExpiresAt: "2026-07-22T02:25:00Z",
};
const phpFpm = {
  observedAt: "2026-07-22T02:10:00Z",
  status: "observed",
  runtimes: [{
    version: "8.3",
    unitName: "php8.3-fpm.service",
    runtimeState: "running",
    activeState: "active",
    subState: "running",
    phpIniMaskedPath: "/etc/php/8.3/fpm/php.ini",
    poolDirectoryMaskedPath: "/etc/php/8.3/fpm/pool.d",
    extensionDirectoryMaskedPath: "/etc/php/8.3/fpm/conf.d",
    extensions: ["curl", "mbstring", "opcache"],
    extensionCount: 3,
    extensionsTruncated: false,
    managedConfigResourceId: resourceId,
    managedConfigOperationType: "service.config_file.set/v1",
    managedConfigSchemaVersion: 1,
    managedConfigs: [{
      resourceId,
      displayName: "PHP 8.3 FPM php.ini",
      maskedPath: "…/php/8.3/fpm/php.ini",
      operationType: "service.config_file.set/v1",
      schemaVersion: 1,
      available: true,
      blockedReason: null,
      assurance,
    }],
    blockedReason: null,
    assurance,
  }],
};
const resource = {
  schemaVersion: 1,
  adapterId: "php-fpm/ubuntu-24.04-8.3-v1",
  resourceId,
  displayName: "PHP 8.3 FPM php.ini",
  maskedPath: "…/php/8.3/fpm/php.ini",
  content: "memory_limit = 128M\n",
  contentDigest,
  metadataDigest,
  maxBytes: 131072,
  allowedServiceActions: ["reload"],
  assurance,
};
const plan = {
  schemaVersion: 1,
  operationType: "service.config_file.set/v1",
  planId: "plan_php_fixture",
  planHash,
  createdAt: "2026-07-22T02:11:00Z",
  expiresAt: "2026-07-22T02:16:00Z",
  actor: session.subject,
  adapterId: resource.adapterId,
  resourceId,
  displayName: resource.displayName,
  maskedPath: resource.maskedPath,
  currentContentDigest: contentDigest,
  proposedContentDigest: proposedDigest,
  metadataDigest,
  currentBytes: 20,
  proposedBytes: 20,
  addedLines: 1,
  removedLines: 1,
  diffSummary: ["- memory_limit = 128M", "+ memory_limit = 256M"],
  serviceAction: "reload",
  impact: ["php.ini를 원자 교체합니다.", "php-fpm8.3 -t 성공 후 reload합니다."],
  recoveryPath: ["SSH로 접속합니다.", "php.ini를 검토하고 php-fpm8.3 -t를 실행합니다."],
  assurance,
};
const accepted = {
  schemaVersion: 1,
  operationType: "service.config_file.set/v1",
  operationId: "op_php_fixture",
  planId: plan.planId,
  planHash,
  actor: session.subject,
  currentStage: "APPROVED",
  eventStream: "/api/v1/operations/op_php_fixture/events",
};
const receipt = {
  schemaVersion: 1,
  operationType: "service.config_file.set/v1",
  operationId: accepted.operationId,
  planId: plan.planId,
  planHash,
  actor: session.subject,
  displayName: "PHP 8.3 FPM php.ini",
  recordedAt: "2026-07-22T02:12:05Z",
  terminalState: "SUCCEEDED",
  beforeDigest: contentDigest,
  afterDigest: proposedDigest,
  stages: [
    { sequence: 1, stage: "APPROVED", recordedAt: "2026-07-22T02:12:00Z", resultCode: "approved", evidenceDigest: planHash },
    { sequence: 2, stage: "SNAPSHOTTED", recordedAt: "2026-07-22T02:12:01Z", resultCode: "snapshot_durable", evidenceDigest: contentDigest },
    { sequence: 3, stage: "VALIDATING", recordedAt: "2026-07-22T02:12:02Z", resultCode: "php_fpm_config_valid", evidenceDigest: contentDigest },
    { sequence: 4, stage: "RELOADING", recordedAt: "2026-07-22T02:12:03Z", resultCode: "php_fpm_reloaded", evidenceDigest: contentDigest },
    { sequence: 5, stage: "SUCCEEDED", recordedAt: "2026-07-22T02:12:05Z", resultCode: "managed_config_verified", evidenceDigest: proposedDigest },
  ],
  assurance,
  rollbackResult: null,
  recoveryPath: [],
};

async function mockApi(page: Page, onPlan: (body: unknown) => void, onApproval: (body: unknown) => void) {
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/auth/session") return route.fulfill({ json: session });
    if (path === "/api/v1/auth/reauth") {
      return route.fulfill({ json: { session, reauthToken: "reauth_php_fixture_1234567890", expiresAt: "2026-07-22T02:14:00Z" } });
    }
    if (path === "/api/v1/health") return route.fulfill({ json: { status: "ok", version: "0.2.0", ingress: "recovery", pam: "available", opsd: "available" } });
    if (path === "/api/v1/services") return route.fulfill({ json: services });
    if (path === "/api/v1/services/php-fpm") return route.fulfill({ json: phpFpm });
    if (path === `/api/v1/config-resources/${resourceId}`) return route.fulfill({ json: resource });
    if (path === "/api/v1/activity") return route.fulfill({ json: { operations: [] } });
    if (path === "/api/v1/operations/service/config-file/plans") {
      onPlan(request.postDataJSON());
      return route.fulfill({ json: plan });
    }
    if (path === "/api/v1/operations/service/config-file/approvals") {
      onApproval(request.postDataJSON());
      return route.fulfill({ status: 202, json: accepted });
    }
    if (path === accepted.eventStream) {
      return route.fulfill({ status: 200, headers: { "content-type": "text/event-stream" }, body: "id: 5\nevent: operation-stage\ndata: {}\n\n" });
    }
    if (path === `/api/v1/operations/${accepted.operationId}`) return route.fulfill({ json: receipt });
    return route.fulfill({ status: 404, json: { status: 404, code: "not_found" } });
  });
}

test("PHP-FPM workspace exposes runtime facts and a typed G2 php.ini flow", async ({ page }) => {
  const planBodies: unknown[] = [];
  const approvalBodies: unknown[] = [];
  await page.setViewportSize({ width: 390, height: 844 });
  await mockApi(page, (body) => planBodies.push(body), (body) => approvalBodies.push(body));
  await page.goto("/services/php-fpm");

  await expect(page.getByRole("heading", { name: "PHP-FPM", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "PHP 8.3 FPM", exact: true })).toBeVisible();
  await expect(page.getByText("curl", { exact: true })).toBeVisible();
  await expect(page.getByText("원문 phpinfo는 제공하지 않습니다")).toBeVisible();
  await page.getByRole("button", { name: "PHP 8.3 FPM php.ini 편집" }).click();
  const editor = page.getByLabel("PHP 8.3 FPM php.ini 설정");
  await expect(editor).toContainText("memory_limit = 128M");
  await editor.fill("memory_limit = 256M\n");
  await page.getByRole("button", { name: "저장", exact: true }).click();

  await expect(page.getByRole("heading", { name: "저장 완료" })).toBeVisible();
  await expect(page.getByText("문법 검사, reload와 서비스 작동 확인을 마쳤습니다.")).toBeVisible();
  expect(planBodies).toHaveLength(1);
  expect(approvalBodies).toHaveLength(1);
  expect(JSON.stringify(approvalBodies)).not.toContain("password");
  const hasOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(hasOverflow).toBe(false);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((violation) => ["critical", "serious"].includes(violation.impact ?? ""))).toEqual([]);
});
