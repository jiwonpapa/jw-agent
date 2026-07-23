import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { services } from "./fixtures/service-inventory";

const session = {
  subject: { uid: 1001, username: "operator", role: "admin" },
  ingress: "recovery",
  authenticatedAt: "2026-07-21T02:00:00Z",
  idleExpiresAt: "2026-07-21T03:00:00Z",
  absoluteExpiresAt: "2026-07-21T10:00:00Z",
  csrfToken: "fixture-csrf-token",
  additionalAuthPolicy: "disabled",
  administrativeAccess: "administrative",
  administrativeExpiresAt: "2026-07-21T02:25:00Z",
};

async function mockServiceApi(page: Page): Promise<void> {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/auth/session") return route.fulfill({ json: session });
    if (path === "/api/v1/health") {
      return route.fulfill({
        json: {
          status: "ok",
          version: "0.2.0",
          ingress: "recovery",
          pam: "available",
          opsd: "available",
        },
      });
    }
    if (path === "/api/v1/services") return route.fulfill({ json: services });
    return route.fulfill({ status: 404, json: { status: 404, code: "not_found" } });
  });
}

for (const viewport of [
  { width: 320, height: 800 },
  { width: 768, height: 1024 },
  { width: 1440, height: 900 },
]) {
  test(`service inventory keeps status and role visible at ${String(viewport.width)}x${String(viewport.height)}`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await mockServiceApi(page);
    await page.goto("/services");
    await expect(page.getByRole("heading", { name: "서비스", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "주요 서비스" })).toBeVisible();
    await expect(page.getByText("PHP-FPM").first()).toBeVisible();
    await expect(page.getByText("실패한 서비스 1개")).toBeVisible();
    await expect(page.getByText("고객 애플리케이션 작업 처리기")).toBeVisible();
    await expect(page.getByText("systemd-resolved.service").first()).toBeHidden();
    const hasOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
    );
    expect(hasOverflow).toBe(false);
  });
}

test("service inventory exposes system detail on demand and has no serious accessibility violation", async ({ page }) => {
  await mockServiceApi(page);
  await page.goto("/services");
  await page.getByText("시스템 서비스 1개").click();
  await expect(page.getByText("systemd-resolved.service").first()).toBeVisible();
  await page.getByText("systemd-resolved.service").first().click();
  await expect(page.getByText("시스템 내부", { exact: true })).toBeVisible();
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter((violation) =>
      ["critical", "serious"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
});

test("desktop service families use reusable brand assets and multi-column cards", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await mockServiceApi(page);
  await page.goto("/services");
  await expect(page.locator('img[src="/service-icons/php.svg"]')).toBeVisible();
  await expect(page.locator('img[src="/service-icons/nginx.svg"]')).toBeVisible();
  const cards = page.locator("#primary-services-heading + p + ul > li");
  await expect(cards.first()).toBeVisible();
  const first = await cards.nth(0).boundingBox();
  const second = await cards.nth(1).boundingBox();
  expect(first).not.toBeNull();
  expect(second).not.toBeNull();
  expect(second?.y).toBe(first?.y);
});
