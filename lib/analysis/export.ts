import type { AnalysisResult } from "@/lib/analysis/analyze";
import { toCsv } from "@/lib/services/csv";

export function exportName(name: string) {
  return (
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 64) || "riskmap"
  );
}
export function findingsCsv(result: AnalysisResult) {
  return toCsv(
    result.findings.map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      asset: f.assetName,
      confidence: f.confidence,
      evidence: f.evidence,
      why_it_matters: f.description,
      remediation: f.remediation,
      mapped_path_count: f.pathIds.length,
      cve_reference: f.cve ?? "",
      best_next_fix: result.recommendations[0]?.findingId === f.id ? "Yes" : "",
      analysis_scope: result.search.truncated
        ? "Bounded subset"
        : "Within documented search bounds"
    }))
  );
}
export function reportJson(result: AnalysisResult) {
  return JSON.stringify(
    {
      product: "RiskMap",
      reportVersion: 1,
      summary: {
        dataset: result.dataset.name,
        assets: result.dataset.assets.length,
        findings: result.findings.length,
        potentialPaths: result.paths.length,
        criticalPaths: result.paths.filter((p) => p.severity === "CRITICAL").length,
        modelScore: result.risk.score,
        bestNextFix: result.recommendations[0] ?? null
      },
      ...result
    },
    null,
    2
  );
}
