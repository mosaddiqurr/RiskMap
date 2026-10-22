import type { Page } from "@playwright/test";

export async function navigate(page: Page, name: string) {
  const link = page.getByRole("link", { name, exact: true });
  if (!(await link.isVisible())) {
    await page.getByRole("button", { name: "Open navigation", exact: true }).click();
  }
  await link.click();
}
