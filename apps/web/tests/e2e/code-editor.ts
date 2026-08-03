import { expect, type Locator, type Page } from "@playwright/test";

export function codeEditorHost(page: Page, label: string): Locator {
  return page.locator(`[data-code-editor][aria-label="${label}"]`);
}

export async function expectCodeEditorText(
  page: Page,
  label: string,
  expected: string,
): Promise<void> {
  const host = codeEditorHost(page, label);
  await expect(host.locator(".monaco-editor")).toBeVisible();
  await expect(host.locator(".view-lines")).toContainText(expected);
}

export async function fillCodeEditor(
  page: Page,
  label: string,
  value: string,
): Promise<void> {
  const host = codeEditorHost(page, label);
  await expect(host).toHaveAttribute("data-readonly", "false");
  const canvas = host.locator(".view-lines");
  await expect(canvas).toBeVisible();
  await canvas.click({ position: { x: 24, y: 18 } });
  await page.keyboard.press("ControlOrMeta+A");
  await page.keyboard.insertText(value);
}
