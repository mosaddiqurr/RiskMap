import { existsSync } from "node:fs";
import path from "node:path";
import { defineConfig } from "@playwright/test";

const port = Number(process.env.PLAYWRIGHT_PORT || 3100);
if (!Number.isInteger(port) || port < 1024 || port > 65535)
  throw new Error("Invalid PLAYWRIGHT_PORT.");
const baseURL = `http://127.0.0.1:${port}`;
const edgePath = "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const executablePath =
  process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ||
  (process.platform === "win32" && existsSync(edgePath) ? edgePath : undefined);
export default defineConfig({
  testDir: "./tests/browser",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 45_000,
  expect: { timeout: 15_000 },
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
    launchOptions: {
      ...(executablePath ? { executablePath } : {}),
      downloadsPath: path.join(process.cwd(), "test-results", "downloads")
    }
  },
  webServer: {
    command: `node scripts/start-production.mjs --hostname 127.0.0.1 --port ${port}`,
    url: `${baseURL}/api/health`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    env: { NODE_ENV: "production", NEXT_TELEMETRY_DISABLED: "1" }
  },
  projects: [
    { name: "desktop-1440", use: { viewport: { width: 1440, height: 960 } } },
    { name: "desktop-1366", use: { viewport: { width: 1366, height: 900 } } },
    { name: "tablet-768", use: { viewport: { width: 768, height: 1024 } } },
    {
      name: "mobile-390",
      use: { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true }
    }
  ]
});
