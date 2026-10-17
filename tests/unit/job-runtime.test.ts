import { describe, expect, it } from "vitest";
import { isRetryableScanError, scanRetryDelayMs } from "@/lib/scanning/job-runtime";

describe("scan job retry policy", () => {
  it.each([
    "Domain is not verified",
    "Explicit active-check authorisation is required",
    "The verified root domain is excluded from scanning",
    "FORBIDDEN",
    "NOT_FOUND"
  ])("does not retry permanent policy failure: %s", (message: string) => {
    expect(isRetryableScanError(new Error(message))).toBe(false);
  });

  it.each([
    "ECONNRESET",
    "DNS adapter timeout",
    "Worker stopped before provider completion"
  ])("retries transient operational failure: %s", (message: string) => {
    expect(isRetryableScanError(new Error(message))).toBe(true);
  });

  it("uses bounded exponential retry delays", () => {
    const first = scanRetryDelayMs(1);
    const second = scanRetryDelayMs(2);
    const third = scanRetryDelayMs(3);
    expect(first).toBeGreaterThan(0);
    expect(second).toBe(first * 2);
    expect(third).toBe(first * 4);
    expect(scanRetryDelayMs(100)).toBeLessThanOrEqual(15 * 60_000);
  });
});
