import { describe, expect, it } from "vitest";
import { analyzeDataset, compareFix } from "@/lib/analysis/analyze";
import { parseDataset, INPUT_LIMIT_BYTES } from "@/lib/analysis/dataset";
import { demoDataset } from "@/lib/analysis/demo";
import { findingsCsv, reportJson, exportName } from "@/lib/analysis/export";
import { readAnalysisRequest } from "@/lib/analysis/request";
import {
  pathIdentity,
  searchPotentialAttackPaths,
  type GraphEdge,
  type GraphNode
} from "@/lib/services/attack-paths";

const now = new Date("2026-10-04T08:00:00Z");
function demo() {
  return structuredClone(demoDataset);
}

describe("focused exposure analysis", () => {
  it("maps the multi-step identity story and ranks a finding supported by evidence", () => {
    const result = analyzeDataset(parseDataset(JSON.stringify(demo())), now);
    expect(result.search.truncated).toBe(false);
    expect(
      result.paths.some(
        (p) =>
          p.nodeIds.includes("asset:svc-deploy") &&
          p.findingIds.includes("public-ssh") &&
          p.findingIds.includes("deploy-privilege")
      )
    ).toBe(true);
    const best = result.recommendations[0]!;
    expect(best.findingId).toBe("public-ssh");
    expect(best.evidence).toBe(demoDataset.findings[0]!.evidence);
    expect(best.action).toBe(demoDataset.findings[0]!.remediation);
    expect(best.attackPathsReduced).toBe(
      result.paths.filter((p) => p.findingIds.includes(best.findingId)).length
    );
    expect(result.graph.edges.some((e) => e.id === "relationship:web-deploy")).toBe(false);
    expect(
      result.graph.edges.find((e) => e.id === "finding-target:public-ssh:web-deploy")
        ?.relationship
    ).toBe("Uses identity");
  });
  it("requires explicit public exposure instead of inferring it from asset type", () => {
    const input = demo();
    input.assets.forEach((a) => (a.public = false));
    const result = analyzeDataset(input, now);
    expect(result.paths).toEqual([]);
    expect(result.graph.edges.some((e) => e.source === "internet")).toBe(false);
    expect(result.recommendations.length).toBe(input.findings.length);
  });
  it("does not turn an open service or a CVE alone into a path", () => {
    const input = demo();
    input.findings = [];
    input.relationships = [];
    expect(analyzeDataset(input, now).paths).toEqual([]);
    expect(analyzeDataset(input, now).recommendations).toEqual([]);
    const referenced = demo();
    referenced.findings[3]!.cve = "CVE-2026-12345";
    const result = analyzeDataset(referenced, now);
    expect(result.findings.find((f) => f.id === "docs-header")?.pathIds).toEqual([]);
  });
  it("does not invent a transition from an unrelated finding", () => {
    const input = demo();
    input.findings.push({
      ...input.findings[0]!,
      id: "unrelated-header",
      title: "Unrelated header",
      category: "HTTP headers",
      serviceId: undefined
    });
    const result = analyzeDataset(input, now);
    expect(
      result.graph.edges.some(
        (e) => e.source === "finding:unrelated-header" && e.target === "asset:svc-deploy"
      )
    ).toBe(false);
  });
  it("compares without mutation, and leaves unrelated paths and service reachability in place", () => {
    const result = analyzeDataset(demo(), now);
    const saved = JSON.stringify(result);
    const comparison = compareFix(result, "public-ssh");
    expect(JSON.stringify(result)).toBe(saved);
    expect(comparison.after.paths.every((p) => !p.findingIds.includes("public-ssh"))).toBe(
      true
    );
    expect(comparison.after.paths.some((p) => p.findingIds.includes("api-access"))).toBe(
      true
    );
    expect(comparison.after.graph.nodes.some((n) => n.id === "service:web-ssh")).toBe(true);
    expect(comparison.after.graph.edges.some((e) => e.id === "internet:web-01")).toBe(true);
    expect(comparison.removedPathIds.length).toBe(
      result.recommendations.find((r) => r.findingId === "public-ssh")!.attackPathsReduced
    );
    expect(comparison.after.risk.score).toBe(
      result.recommendations.find((r) => r.findingId === "public-ssh")!
        .estimatedRiskAfterFix
    );
    expect(comparison.after.analyzedAt).toBe(result.analyzedAt);
  });
  it("preserves general relationships when a finding is removed", () => {
    const input = demo();
    input.relationships.push({
      id: "general-web-deploy",
      from: "web-01",
      to: "svc-deploy",
      type: "Uses identity",
      state: "OBSERVED",
      confidence: "HIGH",
      evidence: "Independent inventory relationship."
    });
    const result = analyzeDataset(input, now);
    const comparison = compareFix(result, "public-ssh");
    expect(
      comparison.after.graph.edges.some((e) => e.id === "relationship:general-web-deploy")
    ).toBe(true);
    expect(
      comparison.after.paths.some((p) => p.findingIds.includes("deploy-privilege"))
    ).toBe(true);
  });
  it("is deterministic for a fixed timestamp and does not invent a newly observed bonus", () => {
    expect(analyzeDataset(demo(), now)).toEqual(analyzeDataset(demo(), now));
    expect(
      analyzeDataset(demo(), now).findings.every(
        (f) => !f.contribution.reasons.includes("newly observed")
      )
    ).toBe(true);
  });
});

describe("strict dataset parsing", () => {
  it.each(["assets", "services", "findings", "relationships"] as const)(
    "rejects duplicate IDs in %s",
    (collection) => {
      const input = demo();
      input[collection].push(input[collection][0]! as never);
      expect(() => parseDataset(JSON.stringify(input))).toThrow(/unique/);
    }
  );
  it("rejects dangling references, cross-asset services and invalid finding gates", () => {
    const input = demo();
    input.services[0]!.assetId = "missing";
    expect(() => parseDataset(JSON.stringify(input))).toThrow(
      /does not exist|Service must exist/
    );
    const crossed = demo();
    crossed.findings[0]!.serviceId = "api-https";
    expect(() => parseDataset(JSON.stringify(crossed))).toThrow(/Service must exist/);
    const gate = demo();
    gate.relationships[0]!.viaFindingId = "api-access";
    expect(() => parseDataset(JSON.stringify(gate))).toThrow(/source asset/);
  });
  it("rejects unknown fields, oversized byte input, invalid JSON and excessive records", () => {
    expect(() => parseDataset(JSON.stringify({ ...demo(), admin: true }))).toThrow(
      /Unrecognized/
    );
    expect(() => parseDataset(" ".repeat(INPUT_LIMIT_BYTES + 1))).toThrow(/1 MiB/);
    expect(() => parseDataset("not JSON")).toThrow(/not valid JSON/);
    const input = demo();
    input.assets = Array.from({ length: 101 }, (_, i) => ({
      ...input.assets[0]!,
      id: `a${i}`
    }));
    expect(() => parseDataset(JSON.stringify(input))).toThrow(/100/);
  });
});

describe("bounded path search", () => {
  const nodes: GraphNode[] = [
    { id: "internet", label: "Internet", type: "INTERNET", isEntry: true },
    { id: "web", label: "Web", type: "WEB_APPLICATION" },
    {
      id: "finding:x",
      label: "Finding",
      type: "FINDING",
      findingId: "x",
      findingSeverity: "HIGH"
    },
    { id: "target", label: "Database", type: "CRITICAL_ASSET", isTarget: true }
  ];
  const edge = (id: string, source: string, target: string): GraphEdge => ({
    id,
    source,
    target,
    relationship: "Could reach",
    confidence: "HIGH",
    state: "OBSERVED",
    evidence: id
  });
  const edges = [
    edge("a", "internet", "web"),
    edge("b", "web", "finding:x"),
    edge("c", "finding:x", "target"),
    edge("d", "finding:x", "target"),
    edge("cycle", "finding:x", "web")
  ];
  it("distinguishes parallel relationship evidence for the same nodes", () => {
    const search = searchPotentialAttackPaths(nodes, edges, { maxDepth: 8 });
    expect(search.paths.length).toBe(2);
    expect(new Set(search.paths.map(pathIdentity)).size).toBe(2);
    expect(search.paths.every((p) => new Set(p.nodeIds).size === p.nodeIds.length)).toBe(
      true
    );
  });
  it("reports incomplete search when path or exploration budgets are reached", () => {
    expect(searchPotentialAttackPaths(nodes, edges, { maxPaths: 1 }).truncated).toBe(true);
    const search = searchPotentialAttackPaths(nodes, edges, { maxExpansions: 2 });
    expect(search.truncated).toBe(true);
    expect(search.exploredStates).toBe(2);
  });
});

describe("stateless request and export security", () => {
  const request = (body: string, headers: Record<string, string> = {}) =>
    new Request("http://localhost:3000/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body
    });
  it("checks origin, media type and both declared and actual body sizes", async () => {
    await expect(
      readAnalysisRequest(request("{}", { origin: "https://evil.test" }))
    ).rejects.toMatchObject({ status: 403 });
    await expect(
      readAnalysisRequest(request("{}", { "sec-fetch-site": "cross-site" }))
    ).rejects.toMatchObject({ status: 403 });
    await expect(
      readAnalysisRequest(request("{}", { "content-type": "text/plain" }))
    ).rejects.toMatchObject({ status: 415 });
    await expect(
      readAnalysisRequest(
        request("{}", { "content-length": String(INPUT_LIMIT_BYTES + 1) })
      )
    ).rejects.toMatchObject({ status: 413 });
    await expect(
      readAnalysisRequest(request("x".repeat(INPUT_LIMIT_BYTES + 1)))
    ).rejects.toMatchObject({ status: 413 });
    expect(
      await readAnalysisRequest(request("{}", { origin: "http://localhost:3000" }))
    ).toBe("{}");
  });
  it("exports complete machine-readable results and neutralises whitespace-prefixed formulas", () => {
    const input = demo();
    input.findings[0]!.title = '  =HYPERLINK("https://evil.test")';
    const result = analyzeDataset(input, now);
    const csv = findingsCsv(result);
    expect(csv).toContain("'  =HYPERLINK");
    expect(csv).toContain("mapped_path_count");
    expect(JSON.parse(reportJson(result)).dataset).toEqual(input);
    expect(JSON.parse(reportJson(result)).limitations).toEqual(result.limitations);
    expect(exportName("../../Northstar / Labs")).toBe("northstar-labs");
    expect(exportName("x".repeat(100))).toHaveLength(64);
  });
  it("accepts the browser Host authority when Next uses a different loopback hostname", async () => {
    expect(
      await readAnalysisRequest(
        request("{}", { host: "127.0.0.1:3000", origin: "http://127.0.0.1:3000" })
      )
    ).toBe("{}");
  });
});
