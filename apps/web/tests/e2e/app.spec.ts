import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

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

const nginx = {
  observedAt: "2026-07-21T02:10:00Z",
  status: "observed",
  sites: [
    { name: "example.com", available: true, enabled: true, protected: false, assurance: observeAssurance },
    { name: "jw-agent-management", available: true, enabled: true, protected: true, assurance: observeAssurance },
  ],
  truncated: false,
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
): Promise<void> {
  let authenticated = initiallyAuthenticated;
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
    if (path === "/api/v1/host") return route.fulfill({ json: host });
    if (path === "/api/v1/services/nginx/sites") return route.fulfill({ json: nginx });
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
