import { Confidence, RelationshipState } from "@prisma/client";
import { prisma } from "@/lib/db";
import { createAttackPathFingerprint } from "@/lib/scanning/identity";
import { findPotentialAttackPaths, type PotentialPath } from "@/lib/services/attack-paths";
import {
  constructExposureGraph,
  type ExposureGraphSnapshot
} from "@/lib/services/exposure-model";
export {
  constructExposureGraph,
  type GraphRelationshipRecord,
  type ExposureGraphSnapshot
} from "@/lib/services/exposure-model";

export async function buildExposureGraphSnapshot(
  organisationId: string,
  scanId: string
): Promise<ExposureGraphSnapshot> {
  const [assetPresences, servicePresences, findingObservations, relationships] =
    await Promise.all([
      prisma.assetPresence.findMany({
        where: { scanId, observed: true, asset: { organisationId } },
        include: { asset: true }
      }),
      prisma.servicePresence.findMany({
        where: { scanId, observed: true, service: { organisationId } },
        include: { service: { include: { asset: true } } }
      }),
      prisma.findingObservation.findMany({
        where: { scanId, observed: true, finding: { organisationId } },
        include: { finding: { include: { asset: true, service: true } } }
      }),
      prisma.assetRelationship.findMany({
        where: { organisationId, active: true, lastScanId: scanId },
        include: { fromAsset: true, toAsset: true }
      })
    ]);

  const assets = assetPresences.map((presence) => presence.asset);
  const services = servicePresences.map((presence) => presence.service);
  const findings = findingObservations.map((observation) => observation.finding);
  return constructExposureGraph({ assets, services, findings, relationships });
}

function labelPath(path: PotentialPath, graph: ExposureGraphSnapshot) {
  const nodeMap = new Map(graph.nodes.map((node) => [node.id, node]));
  const entry = path.nodeIds.map((id) => nodeMap.get(id)).find((node) => node?.assetId);
  const target = [...path.nodeIds]
    .reverse()
    .map((id) => nodeMap.get(id))
    .find((node) => node?.isTarget || node?.critical);
  if (path.pathType === "Impersonation path") return "Potential mail impersonation path";
  if (path.pathType === "Administrative exposure path") {
    return `Administrative exposure path${entry?.label ? ` via ${entry.label}` : ""}`;
  }
  if (target?.label)
    return `${path.pathType} to ${target.label.replace(" · critical target", "")}`;
  return path.pathType;
}

export type PersistedPathResult = {
  current: Array<{ id: string; fingerprint: string; isNew: boolean; riskScore: number }>;
  created: string[];
  recurred: string[];
  broken: string[];
  graph: ExposureGraphSnapshot;
  potentialPaths: PotentialPath[];
};

export async function calculateAndPersistAttackPaths(
  organisationId: string,
  scanId: string
): Promise<PersistedPathResult> {
  const graph = await buildExposureGraphSnapshot(organisationId, scanId);
  const potentialPaths = findPotentialAttackPaths(graph.nodes, graph.edges, {
    maxDepth: 8,
    minimumConfidence: "LOW",
    requireFinding: true,
    requireTarget: true
  }).slice(0, 25);
  const nodeMap = new Map(graph.nodes.map((node) => [node.id, node]));
  const edgeMap = new Map(graph.edges.map((edge) => [edge.id, edge]));
  const seenFingerprints = new Set<string>();
  const current: PersistedPathResult["current"] = [];
  const created: string[] = [];
  const recurred: string[] = [];

  for (const path of potentialPaths) {
    const orderedNodeKeys = path.nodeIds.map((id) => nodeMap.get(id)?.key ?? id);
    const orderedEdgeKeys = path.edgeIds.map((id) => edgeMap.get(id)?.key ?? id);
    const fingerprint = createAttackPathFingerprint({
      organisationId,
      orderedNodeKeys,
      orderedEdgeKeys
    });
    if (seenFingerprints.has(fingerprint)) continue;
    seenFingerprints.add(fingerprint);

    const existing = await prisma.attackPath.findUnique({
      where: { organisationId_fingerprint: { organisationId, fingerprint } }
    });
    const wasBroken = Boolean(existing && !existing.active);
    const recurrenceCount = existing?.occurrenceCount ?? 0;
    const recurrenceBonus = wasBroken ? Math.min(6, recurrenceCount * 2) : 0;
    const riskScore = Math.min(100, path.riskScore + recurrenceBonus);
    const breakNode = path.recommendedBreakNodeId
      ? nodeMap.get(path.recommendedBreakNodeId)
      : undefined;
    const finding = breakNode?.findingId
      ? graph.findings.find((item) => item.id === breakNode.findingId)
      : undefined;
    const entryAsset = path.nodeIds
      .map((id) => nodeMap.get(id))
      .find((node) => node?.assetId && node.id.startsWith("asset:"));
    const targetAsset = [...path.nodeIds]
      .reverse()
      .map((id) => nodeMap.get(id))
      .find((node) => node?.assetId && (node.isTarget || node.critical));
    const scoreContributors = {
      ...path.contributors,
      recurrenceBonus,
      observedSteps: path.edgeIds.length - path.inferredRelationshipCount,
      inferredSteps: path.inferredRelationshipCount
    };

    const persisted = existing
      ? await prisma.attackPath.update({
          where: { id: existing.id },
          data: {
            scanId,
            pathType: path.pathType,
            name: labelPath(path, graph),
            riskScore,
            confidence: path.confidence,
            entryAssetId: entryAsset?.assetId ?? null,
            targetAssetId: targetAsset?.assetId ?? null,
            evidence: path.evidence.join(" "),
            weakestLink: finding?.title ?? "Publicly reachable relationship",
            recommendedFix:
              finding?.remediation ??
              "Reduce unnecessary public reachability and validate inferred dependencies.",
            recommendedBreakPoint: breakNode?.label ?? null,
            riskReduction: Math.min(30, Math.max(4, Math.round(riskScore * 0.3))),
            scoreContributorsJson: JSON.stringify(scoreContributors),
            active: true,
            isNew: false,
            lastSeen: new Date(),
            lastScanId: scanId,
            occurrenceCount: { increment: 1 },
            brokenAt: null
          }
        })
      : await prisma.attackPath.create({
          data: {
            organisationId,
            scanId,
            fingerprint,
            pathType: path.pathType,
            name: labelPath(path, graph),
            riskScore,
            confidence: path.confidence,
            entryAssetId: entryAsset?.assetId ?? null,
            targetAssetId: targetAsset?.assetId ?? null,
            evidence: path.evidence.join(" "),
            weakestLink: finding?.title ?? "Publicly reachable relationship",
            recommendedFix:
              finding?.remediation ??
              "Reduce unnecessary public reachability and validate inferred dependencies.",
            recommendedBreakPoint: breakNode?.label ?? null,
            riskReduction: Math.min(30, Math.max(4, Math.round(riskScore * 0.3))),
            scoreContributorsJson: JSON.stringify(scoreContributors),
            active: true,
            isNew: true,
            firstSeen: new Date(),
            lastSeen: new Date(),
            lastScanId: scanId
          }
        });

    if (!existing) created.push(persisted.id);
    if (wasBroken) recurred.push(persisted.id);
    await prisma.attackPathStep.deleteMany({ where: { attackPathId: persisted.id } });
    for (const [stepOrder, nodeId] of path.nodeIds.entries()) {
      const node = nodeMap.get(nodeId);
      if (!node) continue;
      const edgeId = path.edgeIds[stepOrder - 1];
      const edge = edgeId ? edgeMap.get(edgeId) : undefined;
      await prisma.attackPathStep.create({
        data: {
          attackPathId: persisted.id,
          stepOrder,
          nodeKey: node.key ?? node.id,
          edgeKey: edge?.key ?? null,
          nodeType: node.type,
          label: node.label,
          assetId: node.assetId ?? null,
          findingId: node.findingId ?? null,
          relationshipId: edge?.relationshipId ?? null,
          evidence: edge?.evidence ?? "Public entry point",
          observedState: edge?.state ?? RelationshipState.OBSERVED,
          confidence: edge?.confidence ?? Confidence.HIGH
        }
      });
    }
    await prisma.attackPathObservation.upsert({
      where: { attackPathId_scanId: { attackPathId: persisted.id, scanId } },
      create: {
        attackPathId: persisted.id,
        scanId,
        active: true,
        riskScore,
        confidence: path.confidence,
        scoreContributorsJson: JSON.stringify(scoreContributors)
      },
      update: {
        active: true,
        riskScore,
        confidence: path.confidence,
        scoreContributorsJson: JSON.stringify(scoreContributors)
      }
    });
    current.push({
      id: persisted.id,
      fingerprint,
      isNew: !existing,
      riskScore
    });
  }

  const previouslyActive = await prisma.attackPath.findMany({
    where: {
      organisationId,
      active: true,
      fingerprint: { notIn: [...seenFingerprints] }
    }
  });
  const broken: string[] = [];
  for (const path of previouslyActive) {
    await prisma.attackPath.update({
      where: { id: path.id },
      data: { active: false, isNew: false, brokenAt: new Date(), lastScanId: scanId }
    });
    await prisma.attackPathObservation.upsert({
      where: { attackPathId_scanId: { attackPathId: path.id, scanId } },
      create: {
        attackPathId: path.id,
        scanId,
        active: false,
        riskScore: path.riskScore,
        confidence: path.confidence,
        scoreContributorsJson: path.scoreContributorsJson
      },
      update: { active: false }
    });
    broken.push(path.id);
  }

  return { current, created, recurred, broken, graph, potentialPaths };
}

export async function latestExposureGraph(organisationId: string) {
  const latest = await prisma.scan.findFirst({
    where: { organisationId, status: "COMPLETED" },
    orderBy: { completedAt: "desc" }
  });
  if (!latest) return null;
  return buildExposureGraphSnapshot(organisationId, latest.id);
}
