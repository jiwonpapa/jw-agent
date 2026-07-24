import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const stateDigest = `sha256:${"1".repeat(64)}`;
const planHash = `sha256:${"2".repeat(64)}`;
const afterDigest = `sha256:${"3".repeat(64)}`;
const ruleId = "ufr_0123456789abcdef01234567";
const session = {
  subject: { uid: 1001, username: "operator", role: "admin" },
  ingress: "recovery",
  authenticatedAt: "2026-07-24T02:00:00Z",
  idleExpiresAt: "2026-07-24T03:00:00Z",
  absoluteExpiresAt: "2026-07-24T10:00:00Z",
  csrfToken: "fixture-csrf-token",
  additionalAuthPolicy: "disabled",
  administrativeAccess: "administrative",
  administrativeExpiresAt: "2026-07-24T02:25:00Z",
};
const assurance = {
  level: "g2_reversible_config",
  rollbackSupport: "automatic_bounded",
  operationAvailable: true,
  scope: ["이번 작업의 JW Agent 소유 UFW 규칙 한 개와 verified status read-back"],
  excludedEffects: ["기존 사용자 규칙, default policy, cloud firewall"],
  applyVerifier: ["제품 comment와 typed rule exact read-back"],
  rollbackVerifier: ["이번 product effect의 inverse operation과 status read-back"],
  reason: null,
};
const inventory = {
  observedAt: "2026-07-24T02:10:00Z",
  status: "active",
  defaultIncoming: null,
  defaultOutgoing: null,
  rules: [{
    sequence: 1,
    ruleId: null,
    action: "allow",
    protocol: "tcp",
    port: 22,
    source: "Anywhere",
    destination: "22/tcp",
    ipv6: false,
    owned: false,
    protected: true,
    summary: "allow 22/tcp · Anywhere",
  }],
  stateDigest,
  truncated: false,
  mutationAvailable: true,
  blockedReason: null,
  assurance,
};
const plan = {
  schemaVersion: 1,
  operationType: "ufw.rule.set/v1",
  planId: "plan_ufw_fixture",
  planHash,
  createdAt: "2026-07-24T02:11:00Z",
  expiresAt: "2026-07-24T02:16:00Z",
  actor: session.subject,
  mutation: "allow",
  ruleId,
  protocol: "tcp",
  port: 18080,
  source: "203.0.113.0/24",
  expectedStateDigest: stateDigest,
  impact: ["활성 UFW에 JW Agent 소유 인바운드 규칙 하나를 추가합니다."],
  recoveryPath: ["독립 JW Agent edge 또는 SSH로 서버에 접속합니다."],
  assurance,
};
const accepted = {
  schemaVersion: 1,
  operationType: "ufw.rule.set/v1",
  operationId: "op_ufw_fixture",
  planId: plan.planId,
  planHash,
  actor: session.subject,
  currentStage: "APPROVED",
  eventStream: "/api/v1/operations/op_ufw_fixture/events",
};
const receipt = {
  schemaVersion: 1,
  operationType: "ufw.rule.set/v1",
  operationId: accepted.operationId,
  planId: plan.planId,
  planHash,
  actor: session.subject,
  displayName: "UFW allow 18080/tcp",
  recordedAt: "2026-07-24T02:12:04Z",
  terminalState: "SUCCEEDED",
  beforeDigest: stateDigest,
  afterDigest,
  stages: [
    { sequence: 1, stage: "APPROVED", recordedAt: "2026-07-24T02:12:00Z", resultCode: "approved", evidenceDigest: planHash },
    { sequence: 2, stage: "SNAPSHOTTED", recordedAt: "2026-07-24T02:12:01Z", resultCode: "snapshot_durable", evidenceDigest: stateDigest },
    { sequence: 3, stage: "APPLYING", recordedAt: "2026-07-24T02:12:02Z", resultCode: "ufw_rule_apply_started", evidenceDigest: stateDigest },
    { sequence: 4, stage: "SUCCEEDED", recordedAt: "2026-07-24T02:12:04Z", resultCode: "ufw_rule_verified", evidenceDigest: afterDigest },
  ],
  assurance,
  rollbackResult: null,
  recoveryPath: [],
  restoreAvailable: false,
};

async function mockFirewall(
  page: Page,
  onPlan: (body: unknown) => void,
  onApproval: (body: unknown) => void,
): Promise<void> {
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/auth/session") return route.fulfill({ json: session });
    if (path === "/api/v1/health") {
      return route.fulfill({ json: { status: "ok", version: "0.2.0", ingress: "recovery", pam: "available", opsd: "available" } });
    }
    if (path === "/api/v1/firewall/ufw") return route.fulfill({ json: inventory });
    if (path === "/api/v1/operations/ufw/rules/plans") {
      onPlan(request.postDataJSON());
      return route.fulfill({ json: plan });
    }
    if (path === "/api/v1/operations/ufw/rules/approvals") {
      onApproval(request.postDataJSON());
      return route.fulfill({ status: 202, json: accepted });
    }
    if (path === accepted.eventStream) {
      return route.fulfill({
        status: 200,
        headers: { "content-type": "text/event-stream" },
        body: "id: 4\nevent: operation-stage\ndata: {}\n\n",
      });
    }
    if (path === `/api/v1/operations/${accepted.operationId}`) {
      return route.fulfill({ json: receipt });
    }
    return route.fulfill({ status: 404, json: { status: 404, code: "not_found" } });
  });
}

test("UFW workspace applies one typed product rule without password repetition", async ({ page }) => {
  const planBodies: unknown[] = [];
  const approvalBodies: unknown[] = [];
  await page.setViewportSize({ width: 390, height: 844 });
  await mockFirewall(page, (body) => planBodies.push(body), (body) => approvalBodies.push(body));
  await page.goto("/firewall");

  await expect(page.getByRole("heading", { name: "UFW 방화벽" })).toBeVisible();
  await expect(page.getByText("기존 규칙", { exact: true })).toBeVisible();
  await page.getByLabel("포트").fill("18080");
  await page.getByLabel(/접속 원본/).fill("203.0.113.0/24");
  await page.getByRole("button", { name: "규칙 추가" }).click();

  await expect(page.getByText("방화벽 규칙 적용 완료")).toBeVisible();
  expect(planBodies).toHaveLength(1);
  expect(approvalBodies).toHaveLength(1);
  expect(planBodies[0]).toMatchObject({
    operationType: "ufw.rule.set/v1",
    mutation: "allow",
    protocol: "tcp",
    port: 18080,
    source: "203.0.113.0/24",
    expectedStateDigest: stateDigest,
  });
  expect(approvalBodies[0]).toMatchObject({
    planId: plan.planId,
    planHash,
    impactConfirmed: true,
  });
  expect(JSON.stringify([planBodies, approvalBodies])).not.toContain("password");
  expect(await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  )).toBe(false);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter(
    (violation) => ["critical", "serious"].includes(violation.impact ?? ""),
  )).toEqual([]);
});
