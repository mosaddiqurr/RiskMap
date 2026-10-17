import { describe, expect, it } from "vitest";
import { getPlanLimit } from "@/lib/services/plans";

describe("plan entitlements", () => {
  it("limits Free to one domain, three findings and no full graph", () => {
    const plan = getPlanLimit("FREE");
    expect(plan.rootDomains).toBe(1);
    expect(plan.visibleFindings).toBe(3);
    expect(plan.fullGraph).toBe(false);
    expect(plan.scheduled).toBe(false);
  });

  it("enables reports and daily scheduling for Pro", () => {
    const plan = getPlanLimit("PRO");
    expect(plan.reports).toBe(true);
    expect(plan.scheduled).toBe(true);
    expect(plan.multipleUsers).toBe(false);
  });

  it("reserves multi-user and webhook features for Business", () => {
    const plan = getPlanLimit("BUSINESS");
    expect(plan.multipleUsers).toBe(true);
    expect(plan.webhooks).toBe(true);
    expect(plan.historyDays).toBe(365);
  });
});
