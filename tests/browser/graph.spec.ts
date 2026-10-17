import { expect, test } from "@playwright/test";

test("graph exact path edges, zoom, pan, resize and evidence remain usable", async ({
  page
}) => {
  await page.goto("/analyze");
  await page.getByRole("button", { name: "Load demo analysis" }).click();
  await expect(
    page.getByRole("heading", { name: "Your next security decision." })
  ).toBeVisible();
  await page.getByRole("link", { name: "Exposure Map", exact: true }).click();
  await page.getByLabel("Highlight a path").selectOption("path-1");
  await page.getByLabel("Only this path").check();
  await page.getByRole("button", { name: "Fit view", exact: true }).click();
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(7);
  await expect(page.locator(".react-flow__edge:visible")).toHaveCount(6);
  await expect(
    page.locator('[data-testid="rf__edge-finding-target:public-ssh:web-deploy"]')
  ).toBeVisible();
  await expect(
    page.locator('[data-testid="rf__edge-finding-target:api-access:api-db"]')
  ).toBeHidden();
  const viewport = page.locator(".react-flow__viewport");
  const before = await viewport.getAttribute("style");
  await page.getByRole("button", { name: "Zoom In", exact: true }).click();
  await expect.poll(() => viewport.getAttribute("style")).not.toBe(before);
  const zoomed = await viewport.getAttribute("style");
  await page.getByRole("button", { name: "Zoom Out", exact: true }).click();
  await expect.poll(() => viewport.getAttribute("style")).not.toBe(zoomed);
  const pane = await page.locator(".react-flow__pane").boundingBox();
  if (!pane) throw new Error("Graph pane is missing");
  const priorPan = await viewport.getAttribute("style");
  const startX = Math.max(15, pane.x + 12);
  const startY = Math.max(40, pane.y + 30);
  await page.mouse.move(startX, startY);
  await page.mouse.down();
  await page.mouse.move(startX + 58, startY + 35, { steps: 8 });
  await page.mouse.up();
  await expect.poll(() => viewport.getAttribute("style")).not.toBe(priorPan);
  const size = page.viewportSize()!;
  await page.setViewportSize({
    width: Math.max(390, size.width - 130),
    height: size.height - 100
  });
  await page.getByRole("button", { name: "Fit view", exact: true }).click();
  await expect(
    page.locator('.react-flow__node[data-id="finding:public-ssh"]')
  ).toBeVisible();
  await expect(page.locator(".graph-legend")).toContainText("Observed");
  await expect(page.locator(".graph-legend")).toContainText("Inferred");
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)
  ).toBe(true);
});
