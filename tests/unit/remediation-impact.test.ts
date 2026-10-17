import { describe, expect, it } from "vitest";
import {
  calculateRemediationImpact,
  simulateBestNextFix
} from "@/lib/services/remediation-impact";
import { findPotentialAttackPaths } from "@/lib/services/attack-paths";

const nodes = [
  { id: "internet", label: "Internet", type: "INTERNET", isEntry: true },
  { id: "web-a", label: "App A", type: "WEB_APPLICATION" },
  { id: "web-b", label: "App B", type: "WEB_APPLICATION" },
  {
    id: "finding:shared",
    label: "Shared weakness",
    type: "FINDING",
    findingId: "shared",
    findingSeverity: "HIGH" as const
  },
  {
    id: "critical-a",
    label: "Admin A",
    type: "CRITICAL_ASSET",
    isTarget: true,
    critical: true,
    criticality: "CRITICAL" as const
  },
  {
    id: "critical-b",
    label: "Admin B",
    type: "CRITICAL_ASSET",
    isTarget: true,
    critical: true,
    criticality: "HIGH" as const
  }
];
const edges = [
  {
    id: "e1",
    source: "internet",
    target: "web-a",
    relationship: "Internet reachable",
    confidence: "HIGH" as const,
    state: "OBSERVED" as const,
    evidence: "public"
  },
  {
    id: "e2",
    source: "internet",
    target: "web-b",
    relationship: "Internet reachable",
    confidence: "HIGH" as const,
    state: "OBSERVED" as const,
    evidence: "public"
  },
  {
    id: "e3",
    source: "web-a",
    target: "finding:shared",
    relationship: "Contains finding",
    confidence: "HIGH" as const,
    state: "OBSERVED" as const,
    evidence: "shared config"
  },
  {
    id: "e4",
    source: "web-b",
    target: "finding:shared",
    relationship: "Contains finding",
    confidence: "HIGH" as const,
    state: "OBSERVED" as const,
    evidence: "shared config"
  },
  {
    id: "e5",
    source: "finding:shared",
    target: "critical-a",
    relationship: "Could reach",
    confidence: "MEDIUM" as const,
    state: "INFERRED" as const,
    evidence: "boundary A"
  },
  {
    id: "e6",
    source: "finding:shared",
    target: "critical-b",
    relationship: "Could reach",
    confidence: "MEDIUM" as const,
    state: "INFERRED" as const,
    evidence: "boundary B"
  }
];

describe("remediation impact", () => {
  it("prioritises the fix linked to the most current paths", () => {
    const paths = findPotentialAttackPaths(nodes, edges, 8);
    const result = calculateRemediationImpact(paths, [
      {
        findingId: "shared",
        title: "Restrict shared administration",
        assetName: "shared boundary",
        difficulty: "Low",
        estimatedRiskReduction: 18
      },
      {
        findingId: "other",
        title: "Add a low-impact header",
        assetName: "app",
        difficulty: "Low",
        estimatedRiskReduction: 3
      }
    ]);
    expect(result[0]?.findingId).toBe("shared");
    expect(result[0]?.attackPathsReduced).toBeGreaterThanOrEqual(2);
  });

  it("recalculates graph paths and organisation risk for each candidate", () => {
    const paths = findPotentialAttackPaths(nodes, edges, 8);
    const recommendations = simulateBestNextFix({
      nodes,
      edges,
      currentPaths: paths,
      findings: [
        {
          id: "shared",
          severity: "HIGH",
          status: "OPEN",
          confidence: "HIGH",
          firstSeen: new Date("2026-06-01T00:00:00Z"),
          isNew: false,
          currentlyObserved: true,
          externallyReachable: true,
          asset: { criticality: "CRITICAL" },
          relatedFindingCount: 1,
          inAttackPath: true
        },
        {
          id: "other",
          severity: "LOW",
          status: "OPEN",
          confidence: "MEDIUM",
          firstSeen: new Date("2026-07-01T00:00:00Z"),
          isNew: false,
          currentlyObserved: true,
          externallyReachable: true,
          asset: { criticality: "MEDIUM" },
          relatedFindingCount: 0,
          inAttackPath: false
        }
      ],
      candidates: [
        {
          findingId: "shared",
          title: "Restrict shared administration",
          assetName: "shared boundary",
          difficulty: "Medium",
          severity: "HIGH",
          assetCriticality: "CRITICAL",
          confidence: "HIGH"
        },
        {
          findingId: "other",
          title: "Add a low-impact header",
          assetName: "app",
          difficulty: "Low",
          severity: "LOW",
          assetCriticality: "MEDIUM",
          confidence: "MEDIUM"
        }
      ]
    });

    expect(recommendations[0]?.findingId).toBe("shared");
    expect(recommendations[0]?.attackPathsReduced).toBeGreaterThanOrEqual(2);
    expect(recommendations[0]?.estimatedRiskAfterFix).toBeLessThan(
      recommendations[0]?.currentRisk ?? 0
    );
  });
});
