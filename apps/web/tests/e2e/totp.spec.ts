import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const subject = { uid: 1001, username: "operator", role: "admin" };
const session = {
  subject,
  ingress: "recovery",
  authenticatedAt: "2026-07-21T02:00:00Z",
  idleExpiresAt: "2026-07-21T03:00:00Z",
  absoluteExpiresAt: "2026-07-21T10:00:00Z",
  csrfToken: "fixture-csrf-token",
  additionalAuthPolicy: "disabled",
  administrativeAccess: "standard",
  administrativeExpiresAt: null,
};
const assurance = {
  level: "g2_reversible_config",
  rollbackSupport: "automatic_bounded",
  operationAvailable: true,
  scope: ["JW Agent 추가 인증 정책 값"],
  excludedEffects: ["Linux PAM·SSH MFA"],
  applyVerifier: ["SQLite transaction과 canonical read-back"],
  rollbackVerifier: ["저장 실패 시 이전 정책 유지"],
  reason: null,
};

test("TOTP enrollment shows one-time recovery material and requires two codes", async ({ page }) => {
  const starts: unknown[] = [];
  const confirmations: unknown[] = [];
  let confirmationCount = 0;
  let provider = "not_configured";
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/auth/session") return route.fulfill({ json: session });
    if (path === "/api/v1/auth/reauth") {
      return route.fulfill({ json: { session, reauthToken: "reauth_fixture_token_1234567890", expiresAt: "2026-07-21T02:14:00Z" } });
    }
    if (path === "/api/v1/settings/access") {
      return route.fulfill({ json: {
        ingress: "recovery",
        publicHost: "care.example.com",
        recoveryOrigin: "http://127.0.0.1:9843",
        additionalAuthPolicy: "disabled",
        additionalAuthProvider: provider,
        mutationApprovalAvailable: provider === "ready",
        assurance,
      } });
    }
    if (path === "/api/v1/settings/access/totp/enrollment") {
      starts.push(request.postDataJSON());
      return route.fulfill({ status: 201, json: {
        enrollmentId: "0123456789abcdef0123456789abcdef",
        providerId: "totp/v1",
        manualKey: "JBSWY3DPEHPK3PXP",
        otpauthUri: "otpauth://totp/JW%20Agent%3Aoperator%40fixture?secret=JBSWY3DPEHPK3PXP&issuer=JW%20Agent&algorithm=SHA1&digits=6&period=30",
        recoveryCodes: Array.from({ length: 10 }, (_, index) => `ABCDE-FGHIJ-KLMN${String(index)}`),
        expiresAt: "2026-07-21T02:20:00Z",
      } });
    }
    if (path === "/api/v1/settings/access/totp/enrollment/confirm") {
      confirmations.push(request.postDataJSON());
      confirmationCount += 1;
      if (confirmationCount >= 2) provider = "ready";
      return route.fulfill({ json: {
        providerId: "totp/v1",
        state: confirmationCount >= 2 ? "ready" : "awaiting_next_code",
      } });
    }
    return route.fulfill({ status: 404, json: { title: "Not found", status: 404, code: "not_found" } });
  });

  await page.goto("/settings/access");
  await page.getByRole("button", { name: "인증 앱 등록" }).click();
  await page.getByLabel("Linux 비밀번호").fill("fixture-password");
  await page.getByRole("button", { name: "재인증 후 등록 시작" }).click();
  await expect(page.getByAltText("TOTP 등록 QR 코드")).toBeVisible();
  await expect(page.getByText("ABCDE-FGHIJ-KLMN0")).toBeVisible();
  await page.getByLabel(/복구 코드를 서버 밖/).check();
  await page.getByLabel("현재 6자리 코드").fill("123456");
  await page.getByRole("button", { name: "첫 번째 코드 확인" }).click();
  await page.getByLabel("다음 30초 코드").fill("654321");
  await page.getByRole("button", { name: "두 번째 코드 확인" }).click();

  await expect(page.getByText("등록됨")).toBeVisible();
  expect(starts).toHaveLength(1);
  expect(confirmations).toHaveLength(2);
  const stored = await page.evaluate(() => JSON.stringify({ local: Object.values(localStorage), session: Object.values(sessionStorage) }));
  expect(stored).not.toContain("JBSWY3DPEHPK3PXP");
  expect(stored).not.toContain("ABCDE-FGHIJ-KLMN0");
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((violation) => ["critical", "serious"].includes(violation.impact ?? ""))).toEqual([]);
});
