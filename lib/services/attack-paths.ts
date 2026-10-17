import type {
  Confidence,
  Criticality,
  FindingSeverity,
  RelationshipState
} from "@prisma/client";

export type GraphNode = {
  id: string;
  key?: string;
  label: string;
  type: string;
  risk?: number;
  active?: boolean;
  isEntry?: boolean;
  isTarget?: boolean;
  critical?: boolean;
  criticality?: Criticality;
  findingId?: string;
  findingSeverity?: FindingSeverity;
  assetId?: string;
  serviceId?: string;
  servicePort?: number;
  protocol?: string;
  administrative?: boolean;
  database?: boolean;
  api?: boolean;
  email?: boolean;
};

export type GraphEdge = {
  id: string;
  key?: string;
  source: string;
  target: string;
  relationship: string;
  confidence: Confidence;
  state: RelationshipState;
  evidence: string;
  sourceName?: string;
  relationshipId?: string;
  active?: boolean;
};

export type PathScoreContributors = {
  entryExposure: number;
  findingSeverity: number;
  assetCriticality: number;
  serviceSensitivity: number;
  stepContribution: number;
  administrativeBonus: number;
  dataOrApiBonus: number;
  newPathBonus: number;
  recurrenceBonus: number;
  inferredPenalty: number;
  confidenceMultiplier: number;
  rawScore: number;
};

export type PotentialPath = {
  nodeIds: string[];
  edgeIds: string[];
  riskScore: number;
  confidence: Confidence;
  evidence: string[];
  contributors: PathScoreContributors;
  inferredRelationshipCount: number;
  recommendedBreakNodeId?: string;
  pathType: string;
};

export type PathSearchOptions = {
  maxDepth?: number;
  minimumConfidence?: Confidence;
  requireFinding?: boolean;
  requireTarget?: boolean;
  newPath?: boolean;
  recurrenceCount?: number;
  maxPaths?: number;
  maxExpansions?: number;
};

const confidenceValue: Record<Confidence, number> = {
  HIGH: 1,
  MEDIUM: 0.75,
  LOW: 0.5
};

const severityValue: Record<FindingSeverity, number> = {
  CRITICAL: 30,
  HIGH: 22,
  MEDIUM: 12,
  LOW: 5,
  INFORMATIONAL: 1
};

const criticalityValue: Record<Criticality, number> = {
  CRITICAL: 18,
  HIGH: 12,
  MEDIUM: 6,
  LOW: 2
};

function pathConfidence(edges: GraphEdge[]): Confidence {
  if (!edges.length) return "LOW";
  const average =
    edges.reduce((sum, edge) => sum + confidenceValue[edge.confidence], 0) / edges.length;
  const weakest = Math.min(...edges.map((edge) => confidenceValue[edge.confidence]));
  const combined = average * 0.7 + weakest * 0.3;
  return combined >= 0.86 ? "HIGH" : combined >= 0.66 ? "MEDIUM" : "LOW";
}

function confidenceAtLeast(value: Confidence, minimum: Confidence) {
  return confidenceValue[value] >= confidenceValue[minimum];
}

export function scorePotentialPath(
  nodes: GraphNode[],
  edges: GraphEdge[],
  options?: { newPath?: boolean; recurrenceCount?: number }
) {
  const entryExposure = nodes.some((node) => node.isEntry || node.type === "INTERNET")
    ? 10
    : 0;
  const findingSeverity = Math.min(
    42,
    nodes.reduce(
      (sum, node) => sum + (node.findingSeverity ? severityValue[node.findingSeverity] : 0),
      0
    )
  );
  const assetCriticality = Math.min(
    24,
    Math.max(
      0,
      ...nodes.map((node) =>
        node.criticality
          ? criticalityValue[node.criticality]
          : node.critical || node.isTarget
            ? 18
            : 0
      )
    )
  );
  const serviceSensitivity = Math.min(
    20,
    nodes.reduce((sum, node) => {
      if (node.database) return sum + 14;
      if (node.administrative) return sum + 12;
      if (node.api) return sum + 8;
      if (node.email) return sum + 6;
      if (node.servicePort) return sum + 3;
      return sum;
    }, 0)
  );
  const stepContribution = Math.min(8, Math.max(0, nodes.length - 2) * 2);
  const administrativeBonus = nodes.some((node) => node.administrative) ? 10 : 0;
  const dataOrApiBonus = nodes.some((node) => node.database)
    ? 12
    : nodes.some((node) => node.api)
      ? 8
      : 0;
  const newPathBonus = options?.newPath ? 5 : 0;
  const recurrenceBonus = Math.min(6, Math.max(0, options?.recurrenceCount ?? 0) * 2);
  const inferredCount = edges.filter((edge) => edge.state === "INFERRED").length;
  const inferredPenalty = inferredCount * 6;
  const confidenceMultiplier = edges.length
    ? edges.reduce((sum, edge) => sum + confidenceValue[edge.confidence], 0) / edges.length
    : 0.5;

  const rawScore =
    entryExposure +
    findingSeverity +
    assetCriticality +
    serviceSensitivity +
    stepContribution +
    administrativeBonus +
    dataOrApiBonus +
    newPathBonus +
    recurrenceBonus -
    inferredPenalty;
  const riskScore = Math.max(0, Math.min(100, Math.round(rawScore * confidenceMultiplier)));

  return {
    riskScore,
    contributors: {
      entryExposure,
      findingSeverity,
      assetCriticality,
      serviceSensitivity,
      stepContribution,
      administrativeBonus,
      dataOrApiBonus,
      newPathBonus,
      recurrenceBonus,
      inferredPenalty,
      confidenceMultiplier: Number(confidenceMultiplier.toFixed(2)),
      rawScore
    } satisfies PathScoreContributors
  };
}

function pathType(nodes: GraphNode[]) {
  if (nodes.some((node) => node.email)) return "Impersonation path";
  if (nodes.some((node) => node.administrative)) return "Administrative exposure path";
  if (nodes.some((node) => node.database)) return "Public service risk path";
  if (nodes.some((node) => node.api)) return "Exposure chain";
  return "Potential attack path";
}

function recommendedBreakNode(nodes: GraphNode[]) {
  const findings = nodes
    .filter((node) => node.findingId)
    .sort(
      (a, b) =>
        severityValue[b.findingSeverity ?? "INFORMATIONAL"] -
        severityValue[a.findingSeverity ?? "INFORMATIONAL"]
    );
  return findings[0]?.id;
}

function isMeaningfulPath(
  nodes: GraphNode[],
  options: Required<Pick<PathSearchOptions, "requireFinding" | "requireTarget">>
) {
  if (nodes.length < 4) return false;
  if (
    options.requireFinding &&
    !nodes.some((node) => node.findingId || node.type === "FINDING")
  ) {
    return false;
  }
  if (options.requireTarget && !nodes.some((node) => node.isTarget || node.critical))
    return false;
  return nodes.some(
    (node) =>
      node.serviceId ||
      node.type === "NETWORK_SERVICE" ||
      node.type === "WEB_APPLICATION" ||
      node.type === "API_ENDPOINT" ||
      node.type === "POTENTIAL_ENTRY_POINT" ||
      node.administrative ||
      node.database ||
      node.api ||
      node.email
  );
}

export function searchPotentialAttackPaths(
  nodes: GraphNode[],
  edges: GraphEdge[],
  maxDepthOrOptions: number | PathSearchOptions = 7
): { paths: PotentialPath[]; truncated: boolean; exploredStates: number } {
  const options: PathSearchOptions =
    typeof maxDepthOrOptions === "number"
      ? { maxDepth: maxDepthOrOptions }
      : maxDepthOrOptions;
  const maxDepth = Math.max(4, Math.min(10, options.maxDepth ?? 7));
  const minimumConfidence = options.minimumConfidence ?? "LOW";
  const requireFinding = options.requireFinding ?? true;
  const requireTarget = options.requireTarget ?? true;
  const activeNodes = nodes.filter((node) => node.active !== false);
  const activeNodeIds = new Set(activeNodes.map((node) => node.id));
  const activeEdges = edges.filter(
    (edge) =>
      edge.active !== false &&
      activeNodeIds.has(edge.source) &&
      activeNodeIds.has(edge.target) &&
      confidenceAtLeast(edge.confidence, minimumConfidence)
  );
  const nodeMap = new Map(activeNodes.map((node) => [node.id, node]));
  const edgeMap = new Map(activeEdges.map((edge) => [edge.id, edge]));
  const adjacency = new Map<string, GraphEdge[]>();
  for (const edge of activeEdges) {
    adjacency.set(edge.source, [...(adjacency.get(edge.source) ?? []), edge]);
  }
  const entries = activeNodes.filter((node) => node.isEntry || node.type === "INTERNET");
  const paths: PotentialPath[] = [];
  const maxPaths = Math.max(1, Math.min(1000, options.maxPaths ?? 400));
  const maxExpansions = Math.max(1, Math.min(100_000, options.maxExpansions ?? 30_000));
  let exploredStates = 0;
  let truncated = false;

  function record(nodeIds: string[], edgeIds: string[]) {
    const pathNodes = nodeIds.map((id) => nodeMap.get(id)).filter(Boolean) as GraphNode[];
    if (!isMeaningfulPath(pathNodes, { requireFinding, requireTarget })) return;
    const pathEdges = edgeIds.map((id) => edgeMap.get(id)).filter(Boolean) as GraphEdge[];
    const confidence = pathConfidence(pathEdges);
    if (!confidenceAtLeast(confidence, minimumConfidence)) return;
    const scored = scorePotentialPath(pathNodes, pathEdges, {
      newPath: options.newPath,
      recurrenceCount: options.recurrenceCount
    });
    paths.push({
      nodeIds: [...nodeIds],
      edgeIds: [...edgeIds],
      riskScore: scored.riskScore,
      confidence,
      evidence: pathEdges.map((edge) => edge.evidence),
      contributors: scored.contributors,
      inferredRelationshipCount: pathEdges.filter((edge) => edge.state === "INFERRED")
        .length,
      recommendedBreakNodeId: recommendedBreakNode(pathNodes),
      pathType: pathType(pathNodes)
    });
  }

  function dfs(
    currentId: string,
    visited: Set<string>,
    nodeIds: string[],
    edgeIds: string[]
  ) {
    if (exploredStates >= maxExpansions || paths.length >= maxPaths) {
      truncated = true;
      return;
    }
    exploredStates += 1;
    const current = nodeMap.get(currentId);
    if (!current) return;
    if (nodeIds.length > 1 && (current.isTarget || current.critical))
      record(nodeIds, edgeIds);
    if (nodeIds.length >= maxDepth) return;
    for (const edge of adjacency.get(currentId) ?? []) {
      if (truncated) break;
      if (visited.has(edge.target)) continue;
      visited.add(edge.target);
      dfs(edge.target, visited, [...nodeIds, edge.target], [...edgeIds, edge.id]);
      visited.delete(edge.target);
    }
  }

  for (const entry of entries) {
    if (truncated) break;
    dfs(entry.id, new Set([entry.id]), [entry.id], []);
  }

  const unique = new Map<string, PotentialPath>();
  for (const path of paths) {
    const semanticNodeKey = path.nodeIds.map((id) => nodeMap.get(id)?.key ?? id).join(">");
    const semanticEdgeKey = path.edgeIds.map((id) => edgeMap.get(id)?.key ?? id).join(">");
    const key = `${semanticNodeKey}||${semanticEdgeKey}`;
    const previous = unique.get(key);
    if (!previous || previous.riskScore < path.riskScore) unique.set(key, path);
  }
  return {
    paths: [...unique.values()].sort(
      (a, b) => b.riskScore - a.riskScore || a.nodeIds.length - b.nodeIds.length
    ),
    truncated,
    exploredStates
  };
}

export function findPotentialAttackPaths(
  nodes: GraphNode[],
  edges: GraphEdge[],
  options: number | PathSearchOptions = 7
): PotentialPath[] {
  return searchPotentialAttackPaths(nodes, edges, options).paths;
}

export function pathIdentity(path: Pick<PotentialPath, "nodeIds" | "edgeIds">) {
  return JSON.stringify([path.nodeIds, path.edgeIds]);
}

export function shortestPotentialPath(paths: PotentialPath[]) {
  return (
    [...paths].sort(
      (a, b) => a.nodeIds.length - b.nodeIds.length || b.riskScore - a.riskScore
    )[0] ?? null
  );
}

export function highestRiskPotentialPath(paths: PotentialPath[]) {
  return [...paths].sort((a, b) => b.riskScore - a.riskScore)[0] ?? null;
}

export function pathsToCriticalAssets(paths: PotentialPath[], nodes: GraphNode[]) {
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  return paths.filter((path) =>
    path.nodeIds.some((id) => nodeMap.get(id)?.critical || nodeMap.get(id)?.isTarget)
  );
}

export function pathsFromPublicEntryPoints(paths: PotentialPath[], nodes: GraphNode[]) {
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  return paths.filter((path) => {
    const first = nodeMap.get(path.nodeIds[0] ?? "");
    return Boolean(first?.isEntry || first?.type === "INTERNET");
  });
}
