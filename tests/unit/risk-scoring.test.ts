import { describe, expect, it } from "vitest";
import {
  calculateOrganisationRisk,
  estimateScoreAfterFix,
  scoreFinding
} from "@/lib/services/risk-scoring";

const now = new Date("2026-07-25T00:00:00Z");
const base = {
  id: "finding-1",
  severity: "HIGH" as const,
  status: "OPEN" as const,
  confidence: "HIGH" as const,
  firstSeen: new Date("2026-04-01T00:00:00Z"),
  isNew: false,
  externallyReachable: true,
  asset: { criticality: "CRITICAL" as const },
  relatedFindingCount: 2,
  inAttackPath: true
};

describe("risk scoring", () => {
  it("is deterministic and explains contributors", () => {
    const first = scoreFinding(base, now);
    const second = scoreFinding(base, now);
    expect(first).toEqual(second);
    expect(first.capped).toBeGreaterThan(20);
    expect(first.reasons).toContain("present in a potential attack path");
  });

  it("ignores resolved and false-positive findings", () => {
    const result = calculateOrganisationRisk([{ ...base, status: "RESOLVED" }], now);
    expect(result.score).toBe(0);
  });

  it("estimates a lower score after a material fix", () => {
    const findings = [
      base,
      {
        ...base,
        id: "finding-2",
        severity: "MEDIUM" as const,
        asset: { criticality: "MEDIUM" as const },
        inAttackPath: false
      }
    ];
    const impact = estimateScoreAfterFix(findings, base.id, now);
    expect(impact.reduction).toBeGreaterThan(0);
    expect(impact.projected).toBeLessThan(impact.current);
  });
});
