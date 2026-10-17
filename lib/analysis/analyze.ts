import type { Dataset } from "@/lib/analysis/dataset";
import { constructExposureGraph } from "@/lib/services/exposure-model";
import {
  searchPotentialAttackPaths,
  type PotentialPath
} from "@/lib/services/attack-paths";
import {
  calculateOrganisationRisk,
  scoreFinding,
  type ScorableFinding
} from "@/lib/services/risk-scoring";
import { simulateBestNextFix } from "@/lib/services/remediation-impact";

export const ANALYSIS_LIMITATIONS = [
  "Attack paths describe potential exposure from supplied evidence. They are not proof of exploitation or a complete threat model.",
  "Public exposure is explicitly supplied. An open service or a CVE reference alone does not establish a vulnerability or exploitability.",
  "Finding-dependent relationships must specify viaFindingId. General dependencies can connect paths but do not imply compromise.",
  "Remediation previews assume the selected finding and its dependent graph transitions are fully removed. They do not change assets or verify a real fix.",
  "Scores are deterministic prioritisation aids, not probabilities, financial loss estimates or measured real-world risk reduction.",
  "Search is bounded to 8 nodes, 400 paths and 30,000 explored states. Large or dense datasets may have additional paths."
];

export type AnalysisPath = PotentialPath & {
  id: string;
  name: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  findingIds: string[];
  assetIds: string[];
};
export function pathSeverity(score: number): AnalysisPath["severity"] {
  return score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 35 ? "MEDIUM" : "LOW";
}

export function analyzeDataset(dataset: Dataset, now = new Date()) {
  const assetMap = new Map(dataset.assets.map((a) => [a.id, a]));
  const gates = new Map<string, Set<string>>();
  for (const r of dataset.relationships)
    if (r.viaFindingId)
      gates.set(r.viaFindingId, new Set([...(gates.get(r.viaFindingId) ?? []), r.id]));
  const assets = dataset.assets.map((a) => ({ ...a, fingerprint: `asset:${a.id}` }));
  const byId = new Map(assets.map((a) => [a.id, a]));
  const graph = constructExposureGraph({
    assets,
    services: dataset.services.map((s) => ({
      ...s,
      fingerprint: `service:${s.id}`,
      serviceIdentifier: s.protocol,
      active: true,
      evidenceSource: "Supplied service evidence"
    })),
    findings: dataset.findings.map((f) => ({
      ...f,
      fingerprint: `finding:${f.id}`,
      serviceId: f.serviceId ?? null,
      currentlyObserved: true,
      evidenceSummary: f.evidence,
      source: "Supplied finding evidence"
    })),
    relationships: dataset.relationships.map((r) => ({
      id: r.id,
      fingerprint: `relationship:${r.id}`,
      fromAssetId: r.from,
      toAssetId: r.to,
      type: r.type,
      state: r.state,
      confidence: r.confidence,
      evidence: r.evidence,
      source: "Supplied relationship evidence",
      active: true,
      fromAsset: byId.get(r.from)!,
      toAsset: byId.get(r.to)!
    })),
    publicAssetIds: new Set(dataset.assets.filter((a) => a.public).map((a) => a.id)),
    sensitiveAssetIds: new Set(
      dataset.assets
        .filter((a) => a.type === "CRITICAL_ASSET" || a.criticality === "CRITICAL")
        .map((a) => a.id)
    ),
    findingRelationshipIds: gates
  });
  const search = searchPotentialAttackPaths(graph.nodes, graph.edges, { maxDepth: 8 });
  const nodeMap = new Map(graph.nodes.map((n) => [n.id, n]));
  const paths: AnalysisPath[] = search.paths.map((p, i) => {
    const entry = p.nodeIds.map((id) => nodeMap.get(id)).find((n) => n?.assetId);
    const target = [...p.nodeIds]
      .reverse()
      .map((id) => nodeMap.get(id))
      .find((n) => n?.isTarget);
    return {
      ...p,
      id: `path-${i + 1}`,
      name: `${entry?.label ?? "Internet"} → ${target?.label.replace(" · critical target", "") ?? "Sensitive target"}`,
      severity: pathSeverity(p.riskScore),
      findingIds: [...new Set(p.nodeIds.flatMap((id) => nodeMap.get(id)?.findingId ?? []))],
      assetIds: [...new Set(p.nodeIds.flatMap((id) => nodeMap.get(id)?.assetId ?? []))]
    };
  });
  const pathFindings = new Set(paths.flatMap((p) => p.findingIds));
  const scorable: ScorableFinding[] = dataset.findings.map((f) => ({
    id: f.id,
    severity: f.severity,
    status: "OPEN",
    confidence: f.confidence,
    firstSeen: f.firstSeen ? new Date(f.firstSeen) : now,
    isNew: false,
    currentlyObserved: true,
    externallyReachable: assetMap.get(f.assetId)!.public,
    asset: { criticality: assetMap.get(f.assetId)!.criticality },
    // The number of imported records is not evidence of correlated weaknesses.
    relatedFindingCount: 0,
    inAttackPath: pathFindings.has(f.id)
  }));
  const risk = calculateOrganisationRisk(scorable, now);
  const recommendations = simulateBestNextFix({
    nodes: graph.nodes,
    edges: graph.edges,
    currentPaths: paths,
    findings: scorable,
    now,
    candidates: dataset.findings.map((f) => ({
      findingId: f.id,
      title: f.title,
      assetName: assetMap.get(f.assetId)!.name,
      difficulty: /header|certificate|dmarc|spf/i.test(f.category)
        ? ("Low" as const)
        : ("Medium" as const),
      severity: f.severity,
      assetCriticality: assetMap.get(f.assetId)!.criticality,
      confidence: f.confidence
    }))
  })
    .filter((r) => r.attackPathsReduced > 0 || r.estimatedRiskReduction > 0)
    .map((r) => {
      const finding = dataset.findings.find((f) => f.id === r.findingId)!;
      const affected = paths.filter((p) => p.findingIds.includes(r.findingId));
      const highRisk = paths.filter((p) => p.riskScore >= 60);
      const highAffected = affected.filter((p) => p.riskScore >= 60);
      return {
        ...r,
        action: finding.remediation,
        evidence: finding.evidence,
        affectedPathIds: affected.map((p) => p.id),
        highRiskPathsAffected: highAffected.length,
        highRiskPathsTotal: highRisk.length,
        riskReduction:
          highAffected.length >= 2 || r.estimatedRiskReduction >= 12
            ? "High"
            : affected.length || r.estimatedRiskReduction >= 5
              ? "Moderate"
              : "Limited",
        reasons: [
          finding.description,
          affected.length
            ? `Removes ${affected.length} of ${paths.length} mapped potential paths in the finding-removal model.`
            : "Addresses a finding outside the current mapped paths.",
          highAffected.length
            ? `Affects ${highAffected.length} of ${highRisk.length} high or critical paths.`
            : "No high or critical mapped path depends on this finding.",
          `Supported by ${finding.confidence.toLowerCase()} confidence evidence on ${r.assetName}.`
        ],
        searchTruncated: r.searchTruncated || search.truncated
      };
    });
  return {
    version: 1 as const,
    dataset,
    analyzedAt: now.toISOString(),
    graph: { nodes: graph.nodes, edges: graph.edges },
    paths,
    risk,
    findings: dataset.findings
      .map((f) => ({
        ...f,
        assetName: assetMap.get(f.assetId)!.name,
        contribution: scoreFinding(scorable.find((s) => s.id === f.id)!, now),
        pathIds: paths.filter((p) => p.findingIds.includes(f.id)).map((p) => p.id)
      }))
      .sort((a, b) => {
        const severity = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFORMATIONAL: 0 };
        return (
          severity[b.severity] - severity[a.severity] ||
          b.contribution.capped - a.contribution.capped
        );
      }),
    recommendations,
    search: {
      truncated: search.truncated,
      exploredStates: search.exploredStates,
      maxDepth: 8,
      maxPaths: 400
    },
    limitations: ANALYSIS_LIMITATIONS
  };
}
export type AnalysisResult = ReturnType<typeof analyzeDataset>;
export type Recommendation = AnalysisResult["recommendations"][number];

export function compareFix(result: AnalysisResult, findingId: string) {
  const selected = result.dataset.findings.find((f) => f.id === findingId);
  if (!selected) throw new Error("Finding does not exist in this analysis.");
  const afterDataset = {
    ...result.dataset,
    findings: result.dataset.findings.filter((f) => f.id !== findingId),
    relationships: result.dataset.relationships.filter((r) => r.viaFindingId !== findingId)
  };
  const after = analyzeDataset(afterDataset, new Date(result.analyzedAt));
  return {
    findingId,
    before: result,
    after,
    removedPathIds: result.paths
      .filter((p) => p.findingIds.includes(findingId))
      .map((p) => p.id)
  };
}
