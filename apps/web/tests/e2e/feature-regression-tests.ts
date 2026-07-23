import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

type FeatureRegressionHarness = {
  setupOverview: (
    page: Page,
    options?: { standardAccess?: boolean; onAdministrativeAccess?: (body: unknown) => void },
  ) => Promise<void>;
  setupSftp: (
    page: Page,
    callbacks: { onSession: () => void; onClose: () => void },
  ) => Promise<void>;
  setupManagedConfig: (
    page: Page,
    callbacks: { onPlan: (body: unknown) => void; onApproval: (body: unknown) => void },
  ) => Promise<void>;
  setupManagedConfigSyntaxFailure: (page: Page) => Promise<void>;
  configPlanHash: string;
};

export function registerFeatureRegressionTests(harness: FeatureRegressionHarness): void {
  test("overview exposes account state and opens bounded root typed management mode", async ({ page }) => {
    let submitted: unknown;
    await harness.setupOverview(page, {
      standardAccess: true,
      onAdministrativeAccess: (body) => { submitted = body; },
    });
    await page.goto("/overview");
    await expect(page.getByRole("heading", { name: "계정·현재 세션" })).toBeVisible();
    await expect(page.getByText("root 작업 잠김")).toBeVisible();
    await page.getByRole("button", { name: "관리 모드 열기" }).click();
    await expect(page.getByRole("dialog", { name: "관리 모드 열기" })).toBeVisible();
    await expect(page.getByText(/root 계정으로 로그인하지 않습니다/)).toBeVisible();
    await page.getByLabel("Linux 비밀번호").fill("fixture-management-password");
    await page.getByRole("button", { name: "재인증 후 관리 모드 열기" }).click();
    await expect(page.getByText("root opsd typed 작업 승인 가능")).toBeVisible();
    await expect(page.getByText("관리 권한 · 관리 모드").first()).toBeVisible();
    expect(submitted).toEqual({ password: "fixture-management-password", additionalAuthCode: null });
    expect(page.url()).not.toContain("fixture-management-password");
  });

  test("overview renders resource graphs, actionable attention, and expandable receipts", async ({ page }) => {
    await harness.setupOverview(page);
    await page.goto("/overview");
    await expect(page.getByRole("img", { name: "CPU 38%" })).toBeVisible();
    await expect(page.getByRole("progressbar", { name: "메모리 사용률" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "주의 및 권장 조치" })).toBeVisible();
    await expect(page.getByText("실패한 서비스 1개", { exact: true })).toBeVisible();
    await expect(page.getByRole("link", { name: /서비스 확인/ })).toBeVisible();
    await page.getByText("example.com 비활성화").click();
    await expect(page.getByText("변경 전 digest")).toBeVisible();
    await expect(page.getByText("nginx.site_state.set/v1")).toBeVisible();
  });

  for (const viewport of [{ width: 320, height: 800 }, { width: 390, height: 844 }, { width: 768, height: 1024 }, { width: 1024, height: 768 }, { width: 1440, height: 900 }]) {
    test(`overview reflows at ${String(viewport.width)}x${String(viewport.height)}`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await harness.setupOverview(page);
      await page.goto("/overview");
      await expect(page.getByRole("heading", { name: "서버 개요" })).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)).toBe(false);
    });
  }

  test("SFTP keeps the same memory-only session and directory across route navigation", async ({ page }) => {
    let sessionRequests = 0;
    let closeRequests = 0;
    await page.setViewportSize({ width: 1440, height: 900 });
    await harness.setupSftp(page, {
      onSession: () => { sessionRequests += 1; },
      onClose: () => { closeRequests += 1; },
    });
    await page.goto("/files");
    await page.getByRole("button", { name: "SFTP 연결" }).click();
    await page.getByLabel("Linux 비밀번호 재확인").fill("fixture-file-password");
    await page.getByLabel(/쓰기는 별도 계획과 재인증/).check();
    await page.getByRole("button", { name: "재인증 후 홈 열기" }).click();
    await expect(page.getByText("notes.txt")).toBeVisible();

    await page.getByRole("link", { name: "개요" }).click();
    await expect(page.getByRole("heading", { name: "서버 개요" })).toBeVisible();
    await page.getByRole("link", { name: "SFTP" }).click();
    await expect(page.getByText("notes.txt")).toBeVisible();
    await expect(page.getByRole("button", { name: "세션 종료" })).toBeVisible();
    expect(sessionRequests).toBe(1);
    expect(closeRequests).toBe(0);
  });

  test("managed Nginx editor requires diff, two intents, and exact-plan PAM before reload", async ({ page }) => {
    const planBodies: unknown[] = [];
    const approvalBodies: unknown[] = [];
    await page.setViewportSize({ width: 390, height: 844 });
    await harness.setupManagedConfig(page, {
      onPlan: (body) => planBodies.push(body),
      onApproval: (body) => approvalBodies.push(body),
    });
    await page.goto("/services/nginx");
    await page.getByRole("button", { name: "변경 계획 열기" }).first().click();
    await page.getByRole("button", { name: "설정 파일 편집" }).click();

    const editor = page.getByLabel("Nginx 설정 내용");
    await expect(editor).toContainText("listen 80;");
    await expect(page.getByText("저장 버튼으로 즉시 반영하지 않습니다")).toBeVisible();
    await editor.fill("server {\n  listen 80;\n  client_max_body_size 20m;\n}\n");
    await page.getByRole("button", { name: "변경 계획 만들기" }).dblclick();

    await expect(page.getByRole("heading", { name: "설정 변경 계획" })).toBeVisible();
    await expect(page.getByLabel("Nginx 설정 변경 diff")).toContainText("client_max_body_size 20m;");
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
    expect(approvalBody.planHash).toBe(harness.configPlanHash);
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

  test("managed Nginx syntax failure returns to the exact diagnostic line after verified rollback", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await harness.setupManagedConfigSyntaxFailure(page);
    await page.goto("/services/nginx");
    await page.getByRole("button", { name: "변경 계획 열기" }).first().click();
    await page.getByRole("button", { name: "설정 파일 편집" }).click();
    await page.getByLabel("Nginx 설정 내용").fill("server {\n  listen 80\n  broken on;\n}\n");
    await page.getByRole("button", { name: "변경 계획 만들기" }).click();
    await page.getByLabel("Linux 계정 비밀번호로 exact plan 승인").fill("fixture-password");
    await page.getByLabel(/nginx -t를 통과해야만 reload/).check();
    await page.getByLabel(/nginx.service reload를 수행/).check();
    await page.getByRole("button", { name: "재인증 후 설정 적용" }).click();

    await expect(page.getByRole("heading", { name: "선택한 설정 3번째 줄에서 문법 오류" })).toBeVisible();
    await expect(page.getByText(/서비스는 reload하지 않았고 이전 설정 복원과 재검증/)).toBeVisible();
    await page.getByRole("button", { name: "3번째 줄 수정" }).click();
    await expect(page.getByLabel("Nginx 설정 내용")).toContainText("broken on;");
    await expect(page.getByLabel("nginx -t가 선택한 설정의 3번째 줄을 지목했습니다.")).toBeVisible();
  });
}
