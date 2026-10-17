import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { analyzeDataset, compareFix, pathSeverity } from "@/lib/analysis/analyze";
import { parseDataset, parseDatasetBytes } from "@/lib/analysis/dataset";
import { demoDataset } from "@/lib/analysis/demo";
import { analysisApiUrl } from "@/lib/analysis/api-url";
import { analysisOriginAllowed, readAnalysisRequest } from "@/lib/analysis/request";
import { OPTIONS, POST } from "@/app/api/analyze/route";
import { resetRateLimits } from "@/lib/services/rate-limit";
import { pathIdentity, searchPotentialAttackPaths } from "@/lib/services/attack-paths";

const now = new Date("2026-10-05T00:00:00Z");
afterEach(() => {
  vi.unstubAllEnvs();
  resetRateLimits();
});
const demo = () => structuredClone(demoDataset);
function request(origin?: string, body = JSON.stringify(demoDataset), headers = {}) {
  return new Request("http://internal:3000/api/analyze", {
    method: "POST",
    body,
    headers: {
      "Content-Type": "application/json",
      ...(origin ? { origin } : {}),
      ...headers
    }
  });
}

describe("publication path and recommendation cases", () => {
  it("rejects malformed upload bytes before JSON replaces them silently", () => {
    const bytes = new TextEncoder().encode(JSON.stringify(demoDataset));
    expect(parseDatasetBytes(bytes)).toEqual(demoDataset);
    bytes[JSON.stringify(demoDataset).indexOf("Northstar")] = 0xc3;
    expect(() => parseDatasetBytes(bytes)).toThrow(/UTF-8/);
  });
  it("ships the same downloadable and built-in demo with three paths and two critical paths", () => {
    expect(parseDataset(readFileSync("public/demo-dataset.json", "utf8"))).toEqual(
      demoDataset
    );
    const result = analyzeDataset(demo(), now);
    expect(result.paths).toHaveLength(3);
    expect(result.paths.filter((p) => p.severity === "CRITICAL")).toHaveLength(2);
    expect(result.paths.map((p) => p.riskScore)).toEqual(
      [...result.paths.map((p) => p.riskScore)].sort((a, b) => b - a)
    );
    const edges = new Map(result.graph.edges.map((e) => [e.id, e]));
    for (const p of result.paths)
      for (const [i, id] of p.edgeIds.entries()) {
        expect(edges.get(id)?.source).toBe(p.nodeIds[i]);
        expect(edges.get(id)?.target).toBe(p.nodeIds[i + 1]);
      }
  });
  it("reversing a relationship removes its original direction", () => {
    const input = demo();
    const r = input.relationships[0]!;
    [r.from, r.to] = [r.to, r.from];
    delete r.viaFindingId;
    const result = analyzeDataset(parseDataset(JSON.stringify(input)), now);
    expect(result.paths.every((p) => !p.findingIds.includes("public-ssh"))).toBe(true);
    expect(result.paths.some((p) => p.findingIds.includes("api-access"))).toBe(true);
  });
  it("cycles remain finite, simple and directional", () => {
    const input = demo();
    input.relationships.push({
      id: "cycle",
      from: "db-01",
      to: "web-01",
      type: "Connects to",
      state: "OBSERVED",
      confidence: "HIGH",
      evidence: "Fictional reverse dependency"
    });
    const result = analyzeDataset(input, now);
    expect(result.search.truncated).toBe(false);
    expect(result.paths.every((p) => new Set(p.nodeIds).size === p.nodeIds.length)).toBe(
      true
    );
  });
  it("rejects repeated evidence even when a duplicate relationship has a fresh ID", () => {
    const input = demo();
    input.relationships.push({ ...input.relationships[0]!, id: "duplicate" });
    expect(() => parseDataset(JSON.stringify(input))).toThrow(
      /Duplicate relationship evidence/
    );
    input.relationships.at(-1)!.evidence = "Independent observation";
    expect(() => parseDataset(JSON.stringify(input))).not.toThrow();
  });
  it.each(["missing", "web-01"])(
    "rejects missing or self-linked relationship target %s",
    (to) => {
      const input = demo();
      input.relationships[0]!.to = to;
      expect(() => parseDataset(JSON.stringify(input))).toThrow(/existing asset IDs/);
    }
  );
  it("handles no sensitive targets without inventing critical paths", () => {
    const input = demo();
    input.assets.forEach((a) => {
      a.criticality = "LOW";
      if (a.type === "CRITICAL_ASSET") a.type = "IP_ADDRESS";
    });
    const result = analyzeDataset(input, now);
    expect(result.paths).toEqual([]);
    expect(result.recommendations.length).toBeGreaterThan(0);
    expect(result.recommendations.every((r) => r.highRiskPathsTotal === 0)).toBe(true);
  });
  it("retains comparable alternatives and stable ties", () => {
    const input = demo();
    input.services = [];
    input.relationships = [];
    input.findings = [0, 1].map((i) => ({ ...demoDataset.findings[3]!, id: `equal-${i}` }));
    const result = analyzeDataset(input, now);
    expect(result.recommendations.map((r) => r.findingId)).toEqual(["equal-0", "equal-1"]);
    expect(result.recommendations[0]?.priorityScore).toBe(
      result.recommendations[1]?.priorityScore
    );
  });
  it("does not recommend a fix with no modeled score or path benefit", () => {
    const input = demo();
    input.services = [];
    input.relationships = [];
    input.findings = Array.from({ length: 200 }, (_, i) => ({
      ...demoDataset.findings[3]!,
      id: `info-${i}`,
      severity: "INFORMATIONAL",
      confidence: "LOW"
    }));
    expect(analyzeDataset(input, now).recommendations).toEqual([]);
    input.findings = [];
    expect(analyzeDataset(input, now).recommendations).toEqual([]);
  });
  it("prioritizes finding severity independently of imported record order", () => {
    const input = demo();
    input.findings.reverse();
    const result = analyzeDataset(input, now);
    expect(result.findings.at(-1)?.severity).toBe("LOW");
    expect(result.findings[0]?.severity).toBe("HIGH");
  });
  it("comparison matches the recommendation and preserves remaining finding evidence", () => {
    const before = analyzeDataset(demo(), now);
    const best = before.recommendations[0]!;
    const comparison = compareFix(before, best.findingId);
    expect(comparison.before.paths).toHaveLength(3);
    expect(comparison.removedPathIds).toHaveLength(2);
    expect(comparison.after.paths).toHaveLength(1);
    expect(comparison.after.findings).toHaveLength(3);
    expect(comparison.after.risk.score).toBe(best.estimatedRiskAfterFix);
    expect(comparison.after.dataset.findings).toEqual(
      before.dataset.findings.filter((f) => f.id !== best.findingId)
    );
    expect(() => compareFix(before, "missing")).toThrow(/does not exist/);
  });
  it("filters confidence and inactive graph records without dangling paths", () => {
    const result = analyzeDataset(demo(), now);
    const filtered = searchPotentialAttackPaths(result.graph.nodes, result.graph.edges, {
      maxDepth: 8,
      minimumConfidence: "HIGH"
    });
    expect(filtered.paths.every((p) => p.confidence === "HIGH")).toBe(true);
    const originalKeys = new Set(result.paths.map(pathIdentity));
    expect(filtered.paths.every((p) => originalKeys.has(pathIdentity(p)))).toBe(true);
    const edges = result.graph.edges.map((e) => ({ ...e, active: false }));
    expect(searchPotentialAttackPaths(result.graph.nodes, edges).paths).toEqual([]);
  });
  it.each([
    [80, "CRITICAL"],
    [79, "HIGH"],
    [60, "HIGH"],
    [59, "MEDIUM"],
    [35, "MEDIUM"],
    [34, "LOW"]
  ] as const)("maps path score %s to %s", (score, severity) =>
    expect(pathSeverity(score)).toBe(severity)
  );
});

describe("production origin and API boundaries", () => {
  it("allows explicit HTTPS origins behind an HTTP internal proxy without trusting forwarded hosts", () => {
    expect(
      analysisOriginAllowed(request("https://riskmap.example"), "https://riskmap.example")
    ).toBe(true);
    expect(
      analysisOriginAllowed(
        request("https://evil.example", undefined, { "x-forwarded-host": "evil.example" }),
        "https://riskmap.example"
      )
    ).toBe(false);
    expect(analysisOriginAllowed(request("https://riskmap.example"), "")).toBe(false);
  });
  it("does not broaden default access to cross-site or same-site requests", () => {
    expect(
      analysisOriginAllowed(
        request(undefined, undefined, { "sec-fetch-site": "cross-site" }),
        ""
      )
    ).toBe(false);
    expect(
      analysisOriginAllowed(
        request("http://internal:3000", undefined, { "sec-fetch-site": "same-site" }),
        ""
      )
    ).toBe(false);
  });
  it("answers allowlisted preflight and includes CORS on success and parser errors", async () => {
    vi.stubEnv("ANALYSIS_ALLOWED_ORIGINS", "https://front.example");
    const preflight = await OPTIONS(request("https://front.example"));
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("Access-Control-Allow-Origin")).toBe(
      "https://front.example"
    );
    expect(preflight.headers.get("Access-Control-Allow-Credentials")).toBeNull();
    expect((await OPTIONS(request("https://evil.example"))).status).toBe(403);
    const good = await POST(request("https://front.example"));
    expect(good.status).toBe(200);
    expect(good.headers.get("Access-Control-Allow-Origin")).toBe("https://front.example");
    const bad = await POST(request("https://front.example", "{}"));
    expect(bad.status).toBe(422);
    expect(bad.headers.get("Access-Control-Allow-Origin")).toBe("https://front.example");
    const denied = await POST(request("https://evil.example"));
    expect(denied.status).toBe(403);
    expect(denied.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });
  it.each([
    "*",
    "http://public.example",
    "https://front.example/path",
    "https://front.example/",
    "https://user:pass@front.example"
  ])("fails closed for invalid allowlist %s", async (origin) => {
    vi.stubEnv("ANALYSIS_ALLOWED_ORIGINS", origin);
    expect((await POST(request("https://front.example"))).status).toBe(500);
  });
  it("enforces a per-process budget including spoofed forwarded IPs", async () => {
    vi.stubEnv("ANALYSIS_ALLOWED_ORIGINS", "");
    resetRateLimits();
    for (let i = 0; i < 60; i++)
      expect(
        (await POST(request(undefined, "{}", { "x-forwarded-for": String(i) }))).status
      ).toBe(422);
    const limited = await POST(request());
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBe("60");
  });
  it("rejects invalid UTF-8 bytes", async () => {
    const req = new Request("http://internal:3000/api/analyze", {
      method: "POST",
      body: new Uint8Array([0xc3, 0x28]),
      headers: { "Content-Type": "application/json" }
    });
    await expect(readAnalysisRequest(req)).rejects.toMatchObject({ status: 400 });
  });
  it("configures a relative API by default and an explicit secure remote origin", () => {
    expect(analysisApiUrl("")).toBe("/api/analyze");
    expect(analysisApiUrl("https://api.example")).toBe("https://api.example/api/analyze");
    expect(analysisApiUrl("http://127.0.0.1:3200")).toBe(
      "http://127.0.0.1:3200/api/analyze"
    );
    for (const base of [
      "http://public.example",
      "https://api.example/path",
      "//api.example",
      "https://api.example/"
    ])
      expect(() => analysisApiUrl(base)).toThrow();
  });
});
