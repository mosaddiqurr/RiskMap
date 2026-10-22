import { navigate } from "./navigation";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { expect, test } from "@playwright/test";

test("branding and favicon assets load on every direct route", async ({
  page,
  request
}) => {
  for (const route of ["/", "/analyze", "/exposure-map", "/report", "/about"]) {
    await page.goto(route);
    const brand = page.getByRole("link", { name: "RiskMap home", exact: true });
    await expect(brand).toBeVisible();
    const logo = brand.locator("img");
    await expect(logo).toHaveCount(1);
    await expect
      .poll(() =>
        logo.evaluate((image: HTMLImageElement) => image.complete && image.naturalWidth > 0)
      )
      .toBe(true);
    const geometry = await logo.evaluate((image: HTMLImageElement) => {
      const box = image.getBoundingClientRect();
      return {
        width: box.width,
        height: box.height,
        ratio: image.naturalWidth / image.naturalHeight
      };
    });
    expect(geometry.width).toBeGreaterThanOrEqual(32);
    expect(geometry.width).toBeLessThanOrEqual(48);
    expect(geometry.width / geometry.height).toBeCloseTo(geometry.ratio, 2);
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)
    ).toBe(true);

    const icons = await page
      .locator('head link[rel="icon"], head link[rel="apple-touch-icon"]')
      .evaluateAll((links) =>
        links.map((link) => ({
          href: link.getAttribute("href")!,
          type: link.getAttribute("type")
        }))
      );
    expect(icons).toHaveLength(4);
    for (const icon of icons) {
      expect(icon.href).toMatch(/^\/(?:favicon|apple-touch-icon)/);
      const response = await request.get(icon.href);
      expect(response.ok()).toBe(true);
      if (icon.type) expect(response.headers()["content-type"]).toContain(icon.type);
      const filename = new URL(icon.href, page.url()).pathname.slice(1);
      expect(await response.body()).toEqual(
        await readFile(path.join(process.cwd(), "public", filename))
      );
      if (route === "/") {
        const dimensions = await page.evaluate(
          (src) =>
            new Promise<{ width: number; height: number }>((resolve, reject) => {
              const image = new Image();
              image.onload = () =>
                resolve({ width: image.naturalWidth, height: image.naturalHeight });
              image.onerror = () => reject(new Error(`Cannot decode icon: ${src}`));
              image.src = src;
            }),
          icon.href
        );
        expect(dimensions.width).toBeGreaterThan(0);
        expect(dimensions.width).toBe(dimensions.height);
      }
    }
  }
  expect((await request.get("/favicon.ico")).ok()).toBe(true);
});

test("the branded report shows one logo in print and one in the application header", async ({
  page
}) => {
  await page.goto("/analyze");
  await page.getByRole("button", { name: "Load demo analysis" }).click();
  await expect(
    page.getByRole("heading", { name: "Your next security decision." })
  ).toBeVisible();
  await navigate(page, "Report");
  await expect(page.locator(".site-header .brand-lockup")).toBeVisible();
  await expect(page.locator(".report-brand")).toBeHidden();
  await page.emulateMedia({ media: "print" });
  await expect(page.locator(".site-header")).toBeHidden();
  await expect(page.locator(".report-brand")).toBeVisible();
  await expect
    .poll(() =>
      page
        .locator(".report-brand img")
        .evaluate((image: HTMLImageElement) => image.complete && image.naturalWidth > 0)
    )
    .toBe(true);
});
