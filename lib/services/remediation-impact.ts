import type { Criticality, FindingSeverity } from "@prisma/client";
import {
  searchPotentialAttackPaths,
  pathIdentity,
  type GraphEdge,
  type GraphNode,
  type PotentialPath
} from "@/lib/services/attack-paths";
import {
  calculateOrganisationRisk,
  type ScorableFinding
} from "@/lib/services/risk-scoring";

export type CandidateFix = {
  findingId: string;
  title: string;
  assetName: string;
  difficulty: "Low" | "Medium" | "High";
  estimatedRiskReduction?: number;
  severity?: FindingSeverity;
  assetCriticality?: Criticality;
  confidence?: "LOW" | "MEDIUM" | "HIGH";
};

export function calculateRemediationImpact(
  paths: PotentialPath[],
  candidates: CandidateFix[]
) {
  return candidates
    .map((candidate) => {
      const affected = paths.filter((path) =>
        path.nodeIds.includes(`finding:${candidate.findingId}`)
      );
      const pathRisk = affected.reduce((sum, path) => sum + path.riskScore, 0);
      const estimatedRiskReduction = candidate.estimatedRiskReduction ?? 0;
      const difficultyWeight =
        candidate.difficulty === "Low" ? 1.2 : candidate.difficulty === "Medium" ? 1 : 0.75;
      const priorityScore = Math.round(
        (affected.length * 15 + pathRisk * 0.25 + estimatedRiskReduction * 5) *
          difficultyWeight
      );
      return {
        ...candidate,
        estimatedRiskReduction,
        attackPathsReduced: affected.length,
        priorityScore,
        reason:
          affected.length > 0
            ? `This action weakens ${affected.length} potential attack path${affected.length === 1 ? "" : "s"} and addresses a material score contributor.`
            : "This action reduces direct exposure even though it is not currently part of a mapped potential attack path."
      };
    })
    .sort((a, b) => b.priorityScore - a.priorityScore);
}

export type RemediationSimulationInput = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  currentPaths: PotentialPath[];
  findings: ScorableFinding[];
  candidates: CandidateFix[];
  now?: Date;
};

export function simulateBestNextFix(input: RemediationSimulationInput) {
  const now = input.now ?? new Date();
  const currentRisk = calculateOrganisationRisk(input.findings, now).score;
  return input.candidates
    .map((candidate) => {
      const findingNodeId = `finding:${candidate.findingId}`;
      const reducedNodes = input.nodes.filter((node) => node.id !== findingNodeId);
      const reducedEdges = input.edges.filter(
        (edge) => edge.source !== findingNodeId && edge.target !== findingNodeId
      );
      const search = searchPotentialAttackPaths(reducedNodes, reducedEdges, {
        maxDepth: 8,
        minimumConfidence: "LOW",
        requireFinding: true,
        requireTarget: true
      });
      const recalculatedPaths = search.paths;
      const findingIdsInRemainingPaths = new Set(
        recalculatedPaths.flatMap((path) =>
          path.nodeIds
            .filter((nodeId) => nodeId.startsWith("finding:"))
            .map((nodeId) => nodeId.replace("finding:", ""))
        )
      );
      const projectedFindings = input.findings
        .filter((finding) => finding.id !== candidate.findingId)
        .map((finding) => ({
          ...finding,
          inAttackPath: findingIdsInRemainingPaths.has(finding.id)
        }));
      const projectedRisk = calculateOrganisationRisk(projectedFindings, now).score;
      const currentAffected = input.currentPaths.filter((path) =>
        path.nodeIds.includes(findingNodeId)
      );
      // Only paths containing the removed finding are provably broken by this model.
      // A bounded re-search can omit other paths without those paths being removed.
      const pathsRemoved = new Set(currentAffected.map(pathIdentity)).size;
      const aggregatePathRiskBefore = currentAffected.reduce(
        (sum, path) => sum + path.riskScore,
        0
      );
      const difficultyWeight =
        candidate.difficulty === "Low" ? 1.2 : candidate.difficulty === "Medium" ? 1 : 0.75;
      const severityWeight =
        candidate.severity === "CRITICAL"
          ? 20
          : candidate.severity === "HIGH"
            ? 14
            : candidate.severity === "MEDIUM"
              ? 8
              : 3;
      const criticalityWeight =
        candidate.assetCriticality === "CRITICAL"
          ? 12
          : candidate.assetCriticality === "HIGH"
            ? 8
            : 3;
      const confidenceWeight =
        candidate.confidence === "HIGH"
          ? 1
          : candidate.confidence === "MEDIUM"
            ? 0.82
            : 0.62;
      const estimatedReduction = Math.max(0, currentRisk - projectedRisk);
      const priorityScore = Math.round(
        (estimatedReduction * 12 +
          pathsRemoved * 20 +
          aggregatePathRiskBefore * 0.15 +
          severityWeight +
          criticalityWeight) *
          difficultyWeight *
          confidenceWeight
      );
      return {
        ...candidate,
        currentRisk,
        estimatedRiskAfterFix: projectedRisk,
        estimatedRiskReduction: estimatedReduction,
        attackPathsReduced: pathsRemoved,
        affectedPathCount: currentAffected.length,
        pathsBefore: input.currentPaths.length,
        pathsAfter: recalculatedPaths.length,
        searchTruncated: search.truncated,
        priorityScore,
        explanation:
          pathsRemoved > 0
            ? `Simulated removal of this finding removed or changed ${pathsRemoved} mapped path${pathsRemoved === 1 ? "" : "s"} and reduced the deterministic organisation score by ${estimatedReduction} point${estimatedReduction === 1 ? "" : "s"}.`
            : `The simulated fix reduces the direct organisation score by ${estimatedReduction} point${estimatedReduction === 1 ? "" : "s"}, but no current path is fully removed.`
      };
    })
    .sort(
      (a, b) =>
        b.priorityScore - a.priorityScore ||
        b.estimatedRiskReduction - a.estimatedRiskReduction
    );
}
