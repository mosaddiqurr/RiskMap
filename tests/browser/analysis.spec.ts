import { readFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { demoDataset } from "../../lib/analysis/demo";

const screenshots = path.join(process.cwd(), "test-results", "screenshots");
async function noOverflow(page: Page) {
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)
  ).toBe(true);
}
async function capture(page: Page, name: string, project: string) {
  await mkdir(screenshots, { recursive: true });
  await page.screenshot({
    path: path.join(screenshots, `${name}-${project}.png`),
    fullPage: true
  });
}
async function loadDemo(page: Page) {
  await page.goto("/analyze");
  await page.getByRole("button", { name: "Load demo analysis" }).click();
  await expect(
    page.getByRole("heading", { name: "Your next security decision." })
  ).toBeVisible();
}

test("core journey: ingestion, best fix, paths, finding evidence, comparison, graph and report", async ({
  page
}, testInfo) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Know what to fix first." })
  ).toBeVisible();
  await noOverflow(page);
  await capture(page, "home", testInfo.project.name);
  await page.getByRole("link", { name: "Analyze exposure", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Analyze exposure" })).toBeVisible();
  await capture(page, "analyze", testInfo.project.name);
  await noOverflow(page);
  await page.getByLabel("Upload JSON dataset").setInputFiles({
    name: "northstar.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify(demoDataset))
  });
  await expect(page.getByRole("status")).toContainText("6 assets");
  await page.getByRole("button", { name: "Analyze dataset", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Your next security decision." })
  ).toBeVisible();
  await expect(
    page.getByRole("heading", {
      name: "Restrict SSH on WEB-01 to the management network or an authenticated bastion."
    })
  ).toBeVisible();
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  await noOverflow(page);
  await capture(page, "results", testInfo.project.name);
  await page.locator(".best-fix").screenshot({
    path: path.join(screenshots, `best-fix-${testInfo.project.name}.png`)
  });
  await page.getByRole("button", { name: "Preview this fix" }).click();
  await expect(
    page.getByRole("heading", { name: "If this finding is fully remediated" })
  ).toBeVisible();
  await expect(page.locator(".comparison-notes")).toContainText(
    "not a measured risk percentage"
  );
  await capture(page, "comparison", testInfo.project.name);
  await page.getByRole("button", { name: "Close preview" }).click();
  await page.getByRole("button", { name: "Inspect finding" }).click();
  await expect(page.locator("#finding-detail")).toContainText(
    "Fictional firewall rule WEB-SSH-01"
  );
  await capture(page, "finding-detail", testInfo.project.name);
  await page.getByLabel("Finding severity").selectOption("LOW");
  await page
    .getByRole("button", { name: /Missing content security policy on DOCS-01/ })
    .click();
  await expect(page.locator("#finding-detail")).toContainText(
    "No current mapped path uses this finding"
  );
  await page.getByLabel("Finding severity").selectOption("ALL");
  await page.getByLabel("Search findings").fill("nothing-matches");
  await expect(page.getByText("No findings match these filters.")).toBeVisible();
  await page.getByLabel("Search findings").fill("");
  await page.getByRole("link", { name: "Exposure Map", exact: true }).click();
  await page.getByLabel("Highlight a path").selectOption("path-3");
  await page.getByLabel("Only this path").check();
  await expect(page.locator(".graph-path-bar")).toContainText("API-01");
  await expect(page.locator('.react-flow__node[data-id="asset:web-01"]')).toBeHidden();
  await page.getByLabel("Only this path").uncheck();
  await page.getByLabel("Graph node type").selectOption("IDENTITY");
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(1);
  await page.getByLabel("Graph node type").selectOption("ALL");
  await page.getByLabel("Search graph nodes").fill("no-matching-node");
  await expect(page.getByText("No graph nodes match these filters.")).toBeVisible();
  await page.getByLabel("Search graph nodes").fill("");
  await page.getByLabel("Relationship evidence").selectOption("INFERRED");
  await expect(page.locator(".react-flow__edge:visible")).toHaveCount(2);
  await page.getByLabel("Relationship evidence").selectOption("ALL");
  await capture(page, "graph-overview", testInfo.project.name);
  await page.getByLabel("Highlight a path").selectOption("path-1");
  await page.getByLabel("Only this path").check();
  await page.getByRole("button", { name: "Fit view", exact: true }).click();
  await expect(page.locator(".graph-path-bar")).toContainText("WEB-01");
  await page.locator('.react-flow__node[data-id="finding:public-ssh"]').click();
  await expect(page.getByLabel("Selected graph evidence")).toContainText(
    "Fictional firewall rule"
  );
  await noOverflow(page);
  await capture(page, "graph", testInfo.project.name);
  await page.locator(".graph-content").screenshot({
    path: path.join(screenshots, `graph-detail-${testInfo.project.name}.png`)
  });
  await page.getByRole("link", { name: "Report", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Executive summary" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Methodology and limitations" })
  ).toBeVisible();
  await noOverflow(page);
  const jsonPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "JSON", exact: true }).click();
  const jsonDownload = await jsonPromise;
  expect(jsonDownload.suggestedFilename()).toBe(
    "northstar-labs-fictional-demo-analysis.json"
  );
  const json = JSON.parse(await readFile((await jsonDownload.path())!, "utf8"));
  expect(json.product).toBe("RiskMap");
  expect(json.reportVersion).toBe(1);
  expect(json.summary.bestNextFix.findingId).toBe("public-ssh");
  expect(json.summary.potentialPaths).toBe(3);
  expect(json.paths).toHaveLength(3);
  expect(json.summary.modelScore).toBe(62);
  expect(Number.isFinite(Date.parse(json.analyzedAt))).toBe(true);
  expect(json.dataset).toEqual(demoDataset);
  const csvPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Findings CSV" }).click();
  const csvDownload = await csvPromise;
  expect(csvDownload.suggestedFilename()).toBe(
    "northstar-labs-fictional-demo-findings.csv"
  );
  const csv = await readFile((await csvDownload.path())!, "utf8");
  expect(csv).toContain("mapped_path_count");
  for (const finding of demoDataset.findings) {
    expect(csv).toContain(finding.id);
    expect(csv).toContain(finding.evidence);
    expect(csv).toContain(finding.remediation);
  }
  await capture(page, "report", testInfo.project.name);
  await page.evaluate(() => {
    window.print = () => document.body.setAttribute("data-print-invoked", "true");
  });
  await page.getByRole("button", { name: "Print / Save PDF" }).click();
  await expect(page.locator("body")).toHaveAttribute("data-print-invoked", "true");
  await page.emulateMedia({ media: "print" });
  const pdf = await page.pdf({
    path: path.join(screenshots, `northstar-report-${testInfo.project.name}.pdf`),
    format: "A4",
    printBackground: true
  });
  expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
  expect(pdf.length).toBeGreaterThan(10_000);
  await page.emulateMedia({ media: "screen" });
  await page.getByRole("link", { name: "About", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Best Next Fix methodology" })
  ).toBeVisible();
  await noOverflow(page);
  await capture(page, "about", testInfo.project.name);
  await page.getByRole("link", { name: "Analyze", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Your next security decision." })
  ).toBeVisible();
  await page.getByRole("button", { name: "Clear analysis" }).click();
  await expect(page.getByRole("heading", { name: "Analyze exposure" })).toBeVisible();
  const replacement = structuredClone(demoDataset);
  replacement.name = "Replacement snapshot";
  replacement.findings[0]!.evidence = "Fresh replacement evidence for export validation.";
  await page.getByLabel("Upload JSON dataset").setInputFiles({
    name: "replacement.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify(replacement))
  });
  await page.getByRole("button", { name: "Analyze dataset", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Your next security decision." })
  ).toBeVisible();
  await page.getByRole("link", { name: "Report", exact: true }).click();
  await expect(page.locator(".report-page")).toContainText(replacement.name);
  await expect(page.locator(".report-page")).toContainText(
    replacement.findings[0]!.evidence
  );
  const freshJsonPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "JSON", exact: true }).click();
  const freshJsonDownload = await freshJsonPromise;
  expect(freshJsonDownload.suggestedFilename()).toBe("replacement-snapshot-analysis.json");
  const freshJson = JSON.parse(await readFile((await freshJsonDownload.path())!, "utf8"));
  expect(freshJson.dataset).toEqual(replacement);
  expect(freshJson.analyzedAt).not.toBe(json.analyzedAt);
  const freshCsvPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Findings CSV" }).click();
  const freshCsvDownload = await freshCsvPromise;
  expect(freshCsvDownload.suggestedFilename()).toBe("replacement-snapshot-findings.csv");
  const freshCsv = await readFile((await freshCsvDownload.path())!, "utf8");
  expect(freshCsv).toContain(replacement.findings[0]!.evidence);
  expect(freshCsv).not.toContain(demoDataset.findings[0]!.evidence);
  expect(errors).toEqual([]);
});

test("empty, loading, validation, server-error and zero-finding states", async ({
  page
}, testInfo) => {
  await page.goto("/report");
  await expect(
    page.getByRole("heading", { name: "Your report starts with an analysis" })
  ).toBeVisible();
  await capture(page, "report-empty", testInfo.project.name);
  await noOverflow(page);
  await page.goto("/exposure-map");
  await expect(
    page.getByRole("heading", { name: "Build your exposure map" })
  ).toBeVisible();
  await capture(page, "graph-empty", testInfo.project.name);
  await page.goto("/analyze");
  await page.getByLabel("Upload JSON dataset").setInputFiles({
    name: "broken.json",
    mimeType: "application/json",
    buffer: Buffer.from('{"assets":')
  });
  await expect(page.locator(".error-banner")).toContainText("not valid JSON");
  await expect(
    page.getByRole("button", { name: "Analyze dataset", exact: true })
  ).toBeDisabled();
  await capture(page, "input-error", testInfo.project.name);
  await page.route("**/api/analyze", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 800));
    await route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({ error: "Analysis is at capacity. Try again in a minute." })
    });
  });
  await page.getByRole("button", { name: "Load demo analysis" }).click();
  await expect(page.getByRole("status")).toContainText("Building the exposure graph");
  await capture(page, "loading", testInfo.project.name);
  await expect(page.locator(".error-banner")).toContainText("at capacity");
  await capture(page, "server-error", testInfo.project.name);
  await page.unroute("**/api/analyze");
  const empty = { ...demoDataset, findings: [], relationships: [] };
  await page.getByLabel("Upload JSON dataset").setInputFiles({
    name: "no-findings.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify(empty))
  });
  await page.getByRole("button", { name: "Analyze dataset", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "No next fix to recommend" })
  ).toBeVisible();
  await expect(
    page.getByText("No path meets the evidence and target requirements.", { exact: false })
  ).toBeVisible();
  await noOverflow(page);
  await capture(page, "zero-findings", testInfo.project.name);
  await page.getByRole("button", { name: "New dataset", exact: true }).click();
  await page.route("**/api/analyze", (route) =>
    route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({ error: "Replacement analysis failed." })
    })
  );
  await page.getByRole("button", { name: "Load demo analysis" }).click();
  await expect(page.locator(".error-banner")).toContainText("Replacement analysis failed.");
  await expect(page.getByRole("heading", { name: "Analyze exposure" })).toBeVisible();
  await page.getByRole("button", { name: "Return to current results" }).click();
  await expect(
    page.getByRole("heading", { name: "No next fix to recommend" })
  ).toBeVisible();
  await page.unroute("**/api/analyze");
});

test("untrusted evidence is escaped and long tokens stay within the viewport", async ({
  page
}) => {
  const input = structuredClone(demoDataset);
  input.findings[0]!.title = '<img src=x onerror="window.__unsafe=true">' + "X".repeat(120);
  input.findings[0]!.evidence = "<script>window.__unsafe=true</script>" + "Y".repeat(2000);
  await page.goto("/analyze");
  await page.getByLabel("Upload JSON dataset").setInputFiles({
    name: "untrusted.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify(input))
  });
  await page.getByRole("button", { name: "Analyze dataset", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Your next security decision." })
  ).toBeVisible();
  await page.getByRole("button", { name: "Inspect finding" }).click();
  await expect(page.locator("#finding-detail")).toContainText(
    "<script>window.__unsafe=true</script>"
  );
  expect(await page.evaluate(() => "__unsafe" in window)).toBe(false);
  expect(await page.locator("#finding-detail img, #finding-detail script").count()).toBe(0);
  await noOverflow(page);
  await page.getByRole("link", { name: "Report", exact: true }).click();
  await expect(page.locator(".report-page script")).toHaveCount(0);
  // The only report image is the trusted, print-only product branding.
  await expect(page.locator(".report-page img")).toHaveCount(1);
  await expect(page.locator(".report-brand img")).toHaveAttribute("alt", "");
  await noOverflow(page);
});

test("invalid UTF-8 upload fails before analysis", async ({ page }) => {
  const source = JSON.stringify(demoDataset);
  const buffer = Buffer.from(source);
  buffer[source.indexOf("Northstar")] = 0xc3;
  await page.goto("/analyze");
  await page
    .getByLabel("Upload JSON dataset")
    .setInputFiles({ name: "invalid-utf8.json", mimeType: "application/json", buffer });
  await expect(page.locator(".error-banner")).toContainText("UTF-8");
  await expect(
    page.getByRole("button", { name: "Analyze dataset", exact: true })
  ).toBeDisabled();
});

test("API validates limits and retired account and scanning endpoints are unavailable", async ({
  request
}) => {
  const good = await request.post("/api/analyze", { data: demoDataset });
  expect(good.ok()).toBe(true);
  expect(good.headers()["cache-control"]).toBe("no-store");
  expect(
    (
      await request.post("/api/analyze", {
        data: { ...demoDataset, tenantId: "unrequested" }
      })
    ).status()
  ).toBe(422);
  expect(
    (
      await request.post("/api/analyze", {
        data: demoDataset,
        headers: { origin: "https://evil.test" }
      })
    ).status()
  ).toBe(403);
  expect(
    (
      await request.post("/api/analyze", {
        data: "x".repeat(1_048_577),
        headers: { "content-type": "application/json" }
      })
    ).status()
  ).toBe(413);
  for (const endpoint of [
    "/api/auth/login",
    "/api/scans",
    "/api/members",
    "/api/billing",
    "/api/quick-check"
  ])
    expect((await request.post(endpoint, { data: {} })).status()).toBe(404);
  const health = await request.get("/api/health");
  expect(await health.json()).toMatchObject({ status: "ok", mode: "stateless-analysis" });
});

async function checkAxe(page: Page) {
  await page.addScriptTag({
    path: path.join(process.cwd(), "node_modules", "axe-core", "axe.min.js")
  });
  const violations = await page.evaluate(async () => {
    const axe = (
      window as typeof window & {
        axe: {
          run: (
            document: Document,
            options: object
          ) => Promise<{
            violations: Array<{ id: string; impact: string | null; nodes: unknown[] }>;
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
  expect(violations.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes }))).toEqual(
    []
  );
}
test("WCAG checks and keyboard access on every active page and analysis state", async ({
  page
}) => {
  test.setTimeout(90_000);
  for (const url of ["/", "/analyze", "/exposure-map", "/report", "/about"]) {
    await page.goto(url);
    await checkAxe(page);
  }
  await loadDemo(page);
  await checkAxe(page);
  await page.getByRole("button", { name: "Preview this fix" }).click();
  await checkAxe(page);
  await page.getByRole("link", { name: "Exposure Map", exact: true }).click();
  await checkAxe(page);
  await page.getByRole("link", { name: "Report", exact: true }).click();
  await checkAxe(page);
  const tableRegion = page.getByRole("region", { name: "Asset context table" });
  await tableRegion.focus();
  await expect(tableRegion).toBeFocused();
  if (page.viewportSize()!.width < 540) {
    await page.keyboard.press("ArrowRight");
    await expect.poll(() => tableRegion.evaluate((el) => el.scrollLeft)).toBeGreaterThan(0);
  }
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
  await page.keyboard.press("Enter");
  expect(await page.evaluate(() => document.activeElement?.id)).toBe("main-content");
});
