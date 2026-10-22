import { expect, test, type Page } from "@playwright/test";
import path from "node:path";
import { navigate } from "./navigation";

async function checkAccessibility(page: Page) {
  await page.addScriptTag({
    path: path.join(process.cwd(), "node_modules", "axe-core", "axe.min.js")
  });
  const violations = await page.evaluate(async () => {
    const axe = (
      window as typeof window & {
        axe: {
          run: (
            root: Document,
            options: object
          ) => Promise<{
            violations: {
              id: string;
              nodes: { target: string[]; failureSummary: string }[];
            }[];
          }>;
        };
      }
    ).axe;
    return (
      await axe.run(document, {
        runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa"] }
      })
    ).violations;
  });
  expect(violations).toEqual([]);
}

test("hero remediation and keyboard evidence tabs remain functional", async ({
  page
}, testInfo) => {
  await page.goto("/");
  await expect(page.locator(".capability-rail")).toHaveCount(0);
  await expect(page.locator(".preview-summary strong")).toHaveText(
    "3 potential attack paths"
  );
  await expect(page.locator(".hero-visual")).toHaveCSS("opacity", "1");
  await page.screenshot({
    path: path.join(
      process.cwd(),
      "test-results",
      "screenshots",
      `home-hero-${testInfo.project.name}.png`
    ),
    fullPage: false
  });
  await page.getByRole("button", { name: "Preview fix", exact: true }).click();
  await expect(page.locator(".preview-summary strong")).toHaveText(
    "1 potential attack path"
  );
  await expect(page.locator(".preview-fix strong")).toHaveText("2 mapped paths removed");
  await page.getByRole("button", { name: "Reset", exact: true }).click();
  await expect(page.locator(".preview-summary strong")).toHaveText(
    "3 potential attack paths"
  );
  const assetsTab = page.getByRole("tab", { name: "assets 6", exact: true });
  await assetsTab.focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("tab", { name: "services 5", exact: true })).toBeFocused();
  await expect(page.getByRole("tabpanel")).toContainText(/"port":\s*22/);
  await page.keyboard.press("End");
  await expect(
    page.getByRole("tab", { name: "relationships 4", exact: true })
  ).toBeFocused();
  await expect(page.getByRole("tabpanel")).toContainText("viaFindingId");
  await page.keyboard.press("Home");
  await expect(assetsTab).toBeFocused();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.getByRole("button", { name: /theme|animations?/i })).toHaveCount(0);
  await checkAccessibility(page);
});

test("dark workspace keeps accessible evidence and report surfaces", async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto("/");
  await page.getByRole("link", { name: "Explore the demo", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Your next security decision." })
  ).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await checkAccessibility(page);
  for (const name of ["Exposure Map", "Report", "About"]) {
    await navigate(page, name);
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await checkAccessibility(page);
  }
});

test("mobile menu supports keyboard navigation", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");
  const menu = page.getByRole("button", { name: "Open navigation", exact: true });
  if (page.viewportSize()!.width <= 600) {
    await menu.click();
    await expect(page.getByRole("navigation", { name: "Main navigation" })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(menu).toBeFocused();
    await expect(menu).toHaveAttribute("aria-expanded", "false");
  }
  await navigate(page, "Analyze");
  await expect(
    page.getByRole("heading", { name: "Analyze exposure", exact: true })
  ).toBeVisible();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)
  ).toBe(true);
});

test("exposure signals and callout animate automatically without motion controls", async ({
  page
}) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");
  await expect(page.getByRole("button", { name: /animation|theme/i })).toHaveCount(0);
  const network = page.locator(".preview-network");
  await network.scrollIntoViewIfNeeded();
  const packet = page
    .locator(".normal-connection .network-signal:not(.network-signal-halo)")
    .first();
  const offset = await packet.evaluate(
    (element) => getComputedStyle(element).strokeDashoffset
  );
  await expect
    .poll(() => packet.evaluate((element) => getComputedStyle(element).strokeDashoffset))
    .not.toBe(offset);
  await expect(packet).toHaveCSS("animation-play-state", "running");
  await page.locator(".home-cta").scrollIntoViewIfNeeded();
  const orbit = page.locator(".cta-orbit > div").first();
  const position = await orbit.evaluate((element) => getComputedStyle(element).transform);
  await expect
    .poll(() => orbit.evaluate((element) => getComputedStyle(element).transform))
    .not.toBe(position);
  await expect(orbit).toHaveCSS("animation-play-state", "running");
});

test("body text and supporting labels remain readable on home and input pages", async ({
  page
}) => {
  await page.goto("/");
  for (const selector of [".hero-description", ".product-intro > p", ".home-cta > p"]) {
    expect(
      await page
        .locator(selector)
        .evaluate((element) => parseFloat(getComputedStyle(element).fontSize))
    ).toBeGreaterThanOrEqual(16);
  }
  expect(
    await page
      .locator(".preview-node strong")
      .first()
      .evaluate((element) => parseFloat(getComputedStyle(element).fontSize))
  ).toBeGreaterThanOrEqual(12);
  await navigate(page, "Analyze");
  expect(
    await page
      .locator(".demo-panel > p:not(.eyebrow):not(.help)")
      .evaluate((element) => parseFloat(getComputedStyle(element).fontSize))
  ).toBeGreaterThanOrEqual(16);
  expect(
    await page
      .locator(".ingest-panel > .help")
      .evaluate((element) => parseFloat(getComputedStyle(element).fontSize))
  ).toBeGreaterThanOrEqual(14);
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)
  ).toBe(true);
});

test("the complete desktop hero fits above the fold on short and wide screens", async ({
  page
}, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-1440");
  for (const viewport of [
    { width: 1891, height: 850 },
    { width: 1440, height: 900 },
    { width: 1366, height: 768 },
    { width: 1242, height: 668 },
    { width: 1280, height: 600 },
    { width: 1024, height: 768 },
    { width: 900, height: 668 }
  ]) {
    await page.setViewportSize(viewport);
    await page.goto("/");
    await page.evaluate(() => document.fonts.ready);
    const header = await page.locator(".site-header").boundingBox();
    for (const selector of [
      ".hero-copy",
      ".hero-actions",
      ".exposure-preview",
      ".preview-footnote"
    ]) {
      const box = await page.locator(selector).boundingBox();
      expect(
        box,
        `${selector} exists at ${viewport.width}×${viewport.height}`
      ).not.toBeNull();
      expect(box!.y).toBeGreaterThanOrEqual(header!.height - 1);
      expect(
        box!.y + box!.height,
        `${selector} fits at ${viewport.width}×${viewport.height}`
      ).toBeLessThanOrEqual(viewport.height - 8);
    }
    const preview = (await page.locator(".exposure-preview").boundingBox())!;
    const footnote = (await page.locator(".preview-footnote").boundingBox())!;
    expect(footnote.y + footnote.height).toBeLessThanOrEqual(preview.y + preview.height);
    const network = await page.locator(".preview-network").boundingBox();
    for (const node of await page.locator(".preview-node").all()) {
      const box = (await node.boundingBox())!;
      expect(box.y).toBeGreaterThanOrEqual(network!.y);
      expect(box.y + box.height).toBeLessThanOrEqual(network!.y + network!.height);
    }
    await expect(
      page.getByRole("link", { name: "Launch demo", exact: true })
    ).toBeVisible();
    expect(await page.evaluate(() => scrollY)).toBe(0);
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)
    ).toBe(true);
    if (viewport.width === 1242) {
      await page.screenshot({
        path: path.join(
          process.cwd(),
          "test-results",
          "screenshots",
          "home-compact-desktop.png"
        )
      });
    }
  }
});
