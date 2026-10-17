import { describe, expect, it } from "vitest";
import { isWithinPreferredScanWindow, parseUtcScanWindow } from "@/lib/services/schedules";

describe("preferred scan windows", () => {
  it("parses one-hour and explicit UTC windows", () => {
    expect(parseUtcScanWindow("02:00 UTC")).toEqual({ start: 120, end: 180 });
    expect(parseUtcScanWindow("Daily, 02:00–04:00 UTC")).toEqual({ start: 120, end: 240 });
  });

  it("supports windows crossing midnight", () => {
    expect(
      isWithinPreferredScanWindow("23:30–01:00 UTC", new Date("2026-07-25T00:20:00Z"))
    ).toBe(true);
    expect(
      isWithinPreferredScanWindow("23:30–01:00 UTC", new Date("2026-07-25T12:00:00Z"))
    ).toBe(false);
  });

  it("does not schedule malformed values", () => {
    expect(isWithinPreferredScanWindow("overnight", new Date())).toBe(false);
  });
});
