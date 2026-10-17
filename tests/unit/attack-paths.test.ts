import { describe, expect, it } from "vitest";
import { createAttackPathFingerprint } from "@/lib/scanning/identity";
import {
  findPotentialAttackPaths,
  highestRiskPotentialPath,
  pathsFromPublicEntryPoints,
  pathsToCriticalAssets,
  scorePotentialPath,
  shortestPotentialPath
} from "@/lib/services/attack-paths";

const nodes = [
  {
    id: "internet",
    key: "internet",
    label: "Internet",
    type: "INTERNET",
    risk: 5,
    isEntry: true
  },
  { id: "web", key: "asset:web", label: "Public web", type: "WEB_APPLICATION", risk: 10 },
  {
    id: "service",
    key: "service:443",
    label: "HTTPS",
    type: "NETWORK_SERVICE",
    risk: 8,
    servicePort: 443,
    protocol: "https"
  },
  {
    id: "finding:a",
    key: "finding:a",
    label: "High finding",
    type: "FINDING",
    risk: 28,
    findingId: "a",
    findingSeverity: "HIGH" as const
  },
  {
    id: "critical",
    key: "asset:critical",
    label: "Admin",
    type: "CRITICAL_ASSET",
    risk: 20,
    critical: true,
    isTarget: true,
    criticality: "CRITICAL" as const,
    administrative: true
  }
];
const edges = [
  {
    id: "e1",
    key: "edge:1",
    source: "internet",
    target: "web",
    relationship: "Internet reachable",
    confidence: "HIGH" as const,
    state: "OBSERVED" as const,
    evidence: "Public DNS and HTTPS"
  },
  {
    id: "e2",
    key: "edge:2",
    source: "web",
    target: "service",
    relationship: "Exposes service",
    confidence: "HIGH" as const,
    state: "OBSERVED" as const,
    evidence: "TCP 443 observed"
  },
  {
    id: "e3",
    key: "edge:3",
    source: "service",
    target: "finding:a",
    relationship: "Contains finding",
    confidence: "HIGH" as const,
    state: "OBSERVED" as const,
    evidence: "Header evidence"
  },
  {
    id: "e4",
    key: "edge:4",
    source: "finding:a",
    target: "critical",
    relationship: "Could reach",
    confidence: "MEDIUM" as const,
    state: "INFERRED" as const,
    evidence: "Shared administrative boundary"
  },
  {
    id: "cycle",
    key: "edge:cycle",
    source: "critical",
    target: "web",
    relationship: "Related to",
    confidence: "LOW" as const,
    state: "INFERRED" as const,
    evidence: "Cycle fixture"
  }
];

describe("potential attack-path search", () => {
  it("finds a bounded meaningful path and preserves step evidence", () => {
    const paths = findPotentialAttackPaths(nodes, edges, { maxDepth: 8 });
    expect(paths).toHaveLength(1);
    expect(paths[0]?.nodeIds).toEqual([
      "internet",
      "web",
      "service",
      "finding:a",
      "critical"
    ]);
    expect(paths[0]?.evidence).toContain("Shared administrative boundary");
    expect(paths[0]?.pathType).toBe("Administrative exposure path");
  });

  it("prevents cycles and suppresses semantically duplicate paths", () => {
    const duplicateEdges = [...edges, { ...edges[3]!, id: "duplicate-e4" }];
    const paths = findPotentialAttackPaths(nodes, duplicateEdges, { maxDepth: 10 });
    expect(paths).toHaveLength(1);
    expect(new Set(paths[0]?.nodeIds).size).toBe(paths[0]?.nodeIds.length);
  });

  it("excludes inactive evidence and enforces confidence thresholds", () => {
    const inactive = nodes.map((node) =>
      node.id === "finding:a" ? { ...node, active: false } : node
    );
    expect(findPotentialAttackPaths(inactive, edges)).toHaveLength(0);
    expect(
      findPotentialAttackPaths(nodes, edges, { minimumConfidence: "HIGH" })
    ).toHaveLength(0);
  });

  it("returns shortest, highest-risk, public and critical helpers", () => {
    const paths = findPotentialAttackPaths(nodes, edges, 8);
    expect(shortestPotentialPath(paths)?.nodeIds.length).toBe(5);
    expect(highestRiskPotentialPath(paths)?.riskScore).toBe(paths[0]?.riskScore);
    expect(pathsToCriticalAssets(paths, nodes)).toHaveLength(1);
    expect(pathsFromPublicEntryPoints(paths, nodes)).toHaveLength(1);
  });

  it("scores administrative and inferred steps transparently", () => {
    const result = scorePotentialPath(nodes, edges.slice(0, 4), {
      newPath: true,
      recurrenceCount: 2
    });
    expect(result.riskScore).toBeGreaterThan(50);
    expect(result.contributors.administrativeBonus).toBeGreaterThan(0);
    expect(result.contributors.inferredPenalty).toBeGreaterThan(0);
    expect(result.contributors.newPathBonus).toBe(5);
  });

  it("produces a stable ordered path fingerprint", () => {
    const path = findPotentialAttackPaths(nodes, edges, 8)[0]!;
    const fingerprint = createAttackPathFingerprint({
      organisationId: "org-a",
      orderedNodeKeys: path.nodeIds.map(
        (id) => nodes.find((node) => node.id === id)?.key ?? id
      ),
      orderedEdgeKeys: path.edgeIds.map(
        (id) => edges.find((edge) => edge.id === id)?.key ?? id
      )
    });
    expect(fingerprint).toMatch(/^attack-path:v1:/);
  });
});
