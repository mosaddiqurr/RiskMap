import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

function loadProductionEnv(overrides: Record<string, string | undefined>) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_ENV: "production",
    DATABASE_URL: "file:./env-validation.db",
    APP_URL: "https://riskmap.example.test",
    SCAN_MODE: "mock",
    SESSION_SECRET: "a-strong-production-secret-value-1234567890",
    ...overrides
  };
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) delete env[key];
  }
  return spawnSync(
    process.execPath,
    ["--import", "tsx", "--input-type=module", "-e", "await import('./lib/env.ts')"],
    {
      cwd: process.cwd(),
      env,
      encoding: "utf8",
      windowsHide: true
    }
  );
}

describe("production environment validation", () => {
  it.each([
    undefined,
    "development-only-secret-change-before-production-123456",
    "replace-me-with-a-real-production-secret-123456"
  ])("rejects missing or placeholder session secret: %s", (secret) => {
    const result = loadProductionEnv({ SESSION_SECRET: secret });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/SESSION_SECRET/);
  });

  it("rejects a non-loopback HTTP application URL", () => {
    const result = loadProductionEnv({ APP_URL: "http://riskmap.example.test" });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/HTTPS/);
  });

  it("accepts a strong secret and HTTPS URL", () => {
    const result = loadProductionEnv({});
    expect(result.status, result.stderr).toBe(0);
  });

  it("allows loopback HTTP for bounded local production validation", () => {
    const result = loadProductionEnv({ APP_URL: "http://127.0.0.1:3000" });
    expect(result.status, result.stderr).toBe(0);
  });
});
