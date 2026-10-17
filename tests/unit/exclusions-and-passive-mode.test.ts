import { describe, expect, it } from "vitest";
import { matchesAnyExclusion, wildcardToRegExp } from "@/lib/scanning/exclusions";
import { MockScanProvider } from "@/lib/scanning/mock-provider";

describe("scan exclusions", () => {
  it("supports exact and wildcard patterns without partial accidental matches", () => {
    expect(wildcardToRegExp("dev-*.example.test").test("dev-api.example.test")).toBe(true);
    expect(matchesAnyExclusion("admin.example.test", ["admin.example.test"])).toBe(true);
    expect(matchesAnyExclusion("not-admin.example.test", ["admin.example.test"])).toBe(
      false
    );
  });
});

describe("passive mock scans", () => {
  it("omits TCP-only evidence when active checks are disabled", async () => {
    const result = await new MockScanProvider().scan("example.test", {
      activeChecks: false
    });
    expect(result.observations.some((item) => item.type === "PORT")).toBe(false);
    expect(
      result.findings.some(
        (item) => item.title === "Public administration service observed"
      )
    ).toBe(false);
    expect(result.log.some((item) => item.includes("passive checks only"))).toBe(true);
  });
});
