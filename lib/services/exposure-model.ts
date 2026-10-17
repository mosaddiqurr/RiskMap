import {
  type FindingSeverity,
  type Asset,
  type AssetRelationship,
  type Finding,
  type Service
} from "@prisma/client";
import type { GraphNode, GraphEdge } from "@/lib/services/attack-paths";

export type GraphAssetRecord = Pick<
  Asset,
  "id" | "fingerprint" | "name" | "criticality"
> & { type: Asset["type"] | "IDENTITY"; evidence?: string };
export type GraphServiceRecord = Pick<
  Service,
  | "id"
  | "fingerprint"
  | "assetId"
  | "port"
  | "protocol"
  | "serviceIdentifier"
  | "active"
  | "confidence"
  | "evidence"
  | "evidenceSource"
>;
export type GraphFindingRecord = Pick<
  Finding,
  | "id"
  | "fingerprint"
  | "assetId"
  | "serviceId"
  | "title"
  | "severity"
  | "currentlyObserved"
  | "category"
  | "confidence"
  | "evidenceSummary"
  | "source"
  | "remediation"
>;
export type GraphRelationshipInput = Pick<
  AssetRelationship,
  | "id"
  | "fingerprint"
  | "fromAssetId"
  | "toAssetId"
  | "type"
  | "source"
  | "confidence"
  | "evidence"
  | "state"
  | "active"
> & { fromAsset: GraphAssetRecord; toAsset: GraphAssetRecord };
const PUBLIC_ASSET_TYPES = new Set([
  "ROOT_DOMAIN",
  "SUBDOMAIN",
  "IP_ADDRESS",
  "WEB_APPLICATION",
  "API_ENDPOINT",
  "EMAIL_SERVICE",
  "DNS_SERVICE",
  "POTENTIAL_ENTRY_POINT"
]);

const SENSITIVE_PORTS = {
  administrative: new Set([22, 3389, 8443]),
  database: new Set([3306, 5432, 6379, 9200, 27017])
};

function assetRisk(asset: GraphAssetRecord) {
  return asset.criticality === "CRITICAL"
    ? 18
    : asset.criticality === "HIGH"
      ? 12
      : asset.criticality === "MEDIUM"
        ? 6
        : 2;
}

function findingRisk(severity: FindingSeverity) {
  return severity === "CRITICAL"
    ? 30
    : severity === "HIGH"
      ? 22
      : severity === "MEDIUM"
        ? 12
        : severity === "LOW"
          ? 5
          : 1;
}

function serviceRisk(service: GraphServiceRecord) {
  if (SENSITIVE_PORTS.database.has(service.port)) return 18;
  if (SENSITIVE_PORTS.administrative.has(service.port)) return 15;
  if (service.protocol.includes("api")) return 11;
  if ([25, 465, 587, 993, 995].includes(service.port)) return 8;
  return 5;
}

function isCriticalTarget(asset: GraphAssetRecord) {
  return (
    asset.type === "CRITICAL_ASSET" ||
    asset.criticality === "CRITICAL" ||
    (asset.type === "API_ENDPOINT" && asset.criticality === "HIGH") ||
    (asset.type === "EMAIL_SERVICE" && ["HIGH", "CRITICAL"].includes(asset.criticality))
  );
}

function serviceFlags(service: GraphServiceRecord) {
  return {
    administrative:
      SENSITIVE_PORTS.administrative.has(service.port) ||
      /admin|management|rdp|ssh/i.test(
        `${service.protocol} ${service.serviceIdentifier ?? ""}`
      ),
    database: SENSITIVE_PORTS.database.has(service.port),
    api: /api/i.test(`${service.protocol} ${service.serviceIdentifier ?? ""}`),
    email: [25, 110, 143, 465, 587, 993, 995].includes(service.port)
  };
}

export type ExposureGraphSnapshot = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  assets: GraphAssetRecord[];
  services: GraphServiceRecord[];
  findings: GraphFindingRecord[];
  relationships: GraphRelationshipInput[];
};

export type GraphRelationshipRecord = AssetRelationship & {
  fromAsset: Asset;
  toAsset: Asset;
};

export function constructExposureGraph(input: {
  assets: GraphAssetRecord[];
  services: GraphServiceRecord[];
  findings: GraphFindingRecord[];
  relationships: GraphRelationshipInput[];
  publicAssetIds?: Set<string>;
  sensitiveAssetIds?: Set<string>;
  findingRelationshipIds?: Map<string, Set<string>>;
}): ExposureGraphSnapshot {
  const { assets, services, findings, relationships } = input;
  const targetAsset = (asset: GraphAssetRecord) =>
    input.sensitiveAssetIds
      ? input.sensitiveAssetIds.has(asset.id)
      : isCriticalTarget(asset);
  const assetIds = new Set(assets.map((asset) => asset.id));
  const nodes: GraphNode[] = [
    {
      id: "internet",
      key: "internet",
      label: "Internet",
      type: "INTERNET",
      risk: 10,
      active: true,
      isEntry: true
    }
  ];
  const edges: GraphEdge[] = [];

  for (const asset of assets) {
    nodes.push({
      id: `asset:${asset.id}`,
      key: asset.fingerprint,
      label: asset.name,
      type: asset.type,
      risk: assetRisk(asset),
      active: true,
      assetId: asset.id,
      critical: targetAsset(asset),
      isTarget: targetAsset(asset),
      criticality: asset.criticality,
      api: asset.type === "API_ENDPOINT",
      email: asset.type === "EMAIL_SERVICE"
    });
    if (
      input.publicAssetIds
        ? input.publicAssetIds.has(asset.id)
        : PUBLIC_ASSET_TYPES.has(asset.type)
    ) {
      edges.push({
        id: `internet:${asset.id}`,
        key: `internet-reachable:${asset.fingerprint}`,
        source: "internet",
        target: `asset:${asset.id}`,
        relationship: "Internet reachable",
        confidence: "HIGH",
        state: "OBSERVED",
        evidence:
          asset.evidence ??
          "The asset was observed in the verified public scope during this scan.",
        sourceName: input.publicAssetIds ? "Supplied inventory" : "RiskMap verified scope",
        active: true
      });
    }
  }

  for (const relationship of relationships) {
    if (!assetIds.has(relationship.fromAssetId) || !assetIds.has(relationship.toAssetId)) {
      continue;
    }
    // An explicitly finding-dependent transition cannot also create a bypass edge.
    if (
      input.findingRelationshipIds &&
      [...input.findingRelationshipIds.values()].some((ids) => ids.has(relationship.id))
    )
      continue;
    edges.push({
      id: `relationship:${relationship.id}`,
      key: relationship.fingerprint,
      source: `asset:${relationship.fromAssetId}`,
      target: `asset:${relationship.toAssetId}`,
      relationship: relationship.type,
      confidence: relationship.confidence,
      state: relationship.state,
      evidence: relationship.evidence,
      sourceName: relationship.source,
      relationshipId: relationship.id,
      active: relationship.active
    });
  }

  for (const service of services) {
    const flags = serviceFlags(service);
    nodes.push({
      id: `service:${service.id}`,
      key: service.fingerprint,
      label: `${service.protocol.toUpperCase()} · ${service.port}`,
      type: "NETWORK_SERVICE",
      risk: serviceRisk(service),
      active: service.active,
      assetId: service.assetId,
      serviceId: service.id,
      servicePort: service.port,
      protocol: service.protocol,
      ...flags
    });
    edges.push({
      id: `asset-service:${service.id}`,
      key: `exposes-service:${service.fingerprint}`,
      source: `asset:${service.assetId}`,
      target: `service:${service.id}`,
      relationship: "Exposes service",
      confidence: service.confidence,
      state: "OBSERVED",
      evidence: service.evidence,
      sourceName: service.evidenceSource,
      active: service.active
    });
  }

  const relationshipsByFrom = new Map<string, GraphRelationshipInput[]>();
  for (const relationship of relationships) {
    relationshipsByFrom.set(relationship.fromAssetId, [
      ...(relationshipsByFrom.get(relationship.fromAssetId) ?? []),
      relationship
    ]);
  }

  for (const finding of findings) {
    nodes.push({
      id: `finding:${finding.id}`,
      key: finding.fingerprint,
      label: finding.title,
      type: "FINDING",
      risk: findingRisk(finding.severity),
      active: finding.currentlyObserved,
      findingId: finding.id,
      findingSeverity: finding.severity,
      assetId: finding.assetId,
      serviceId: finding.serviceId ?? undefined,
      administrative: /administration|remote administration/i.test(finding.title),
      database: /database|data-service/i.test(finding.title),
      api: /api/i.test(`${finding.title} ${finding.category}`),
      email: /dmarc|spf|mail|impersonation/i.test(`${finding.title} ${finding.category}`)
    });
    const sourceNode = finding.serviceId
      ? `service:${finding.serviceId}`
      : `asset:${finding.assetId}`;
    edges.push({
      id: `finding:${finding.id}:contains`,
      key: `contains-finding:${finding.fingerprint}`,
      source: sourceNode,
      target: `finding:${finding.id}`,
      relationship: "Contains finding",
      confidence: finding.confidence,
      state: "OBSERVED",
      evidence: finding.evidenceSummary,
      sourceName: finding.source,
      active: finding.currentlyObserved
    });

    const candidateTargets = (relationshipsByFrom.get(finding.assetId) ?? []).filter(
      (relationship) =>
        input.findingRelationshipIds
          ? relationship.active &&
            Boolean(input.findingRelationshipIds.get(finding.id)?.has(relationship.id))
          : [
              "Could reach",
              "Depends on",
              "Protects",
              "Uses mail provider",
              "Hosted on",
              "Inferred dependency"
            ].includes(relationship.type) ||
            (/mail|dmarc|spf/i.test(`${finding.title} ${finding.category}`) &&
              relationship.toAsset.type === "EMAIL_SERVICE")
    );

    for (const relationship of candidateTargets) {
      if (!assetIds.has(relationship.toAssetId)) continue;
      edges.push({
        id: `finding-target:${finding.id}:${relationship.id}`,
        key: `finding-target:${finding.fingerprint}:${relationship.fingerprint}`,
        source: `finding:${finding.id}`,
        target: `asset:${relationship.toAssetId}`,
        relationship: input.findingRelationshipIds
          ? relationship.type
          : relationship.type === "Could reach"
            ? "Could reach"
            : "Inferred dependency",
        confidence: relationship.confidence,
        state: relationship.state,
        evidence: `${finding.evidenceSummary} ${relationship.evidence}`,
        sourceName: relationship.source,
        relationshipId: relationship.id,
        active: true
      });
    }

    const affectedAsset = assets.find((asset) => asset.id === finding.assetId);
    if (affectedAsset && targetAsset(affectedAsset)) {
      const targetId = `target:${affectedAsset.id}`;
      if (!nodes.some((node) => node.id === targetId)) {
        nodes.push({
          id: targetId,
          key: `critical-target:${affectedAsset.fingerprint}`,
          label: `${affectedAsset.name} · critical target`,
          type: "CRITICAL_ASSET",
          risk: assetRisk(affectedAsset),
          active: true,
          assetId: affectedAsset.id,
          critical: true,
          isTarget: true,
          criticality: affectedAsset.criticality,
          api: affectedAsset.type === "API_ENDPOINT",
          email: affectedAsset.type === "EMAIL_SERVICE"
        });
      }
      edges.push({
        id: `finding-affected-target:${finding.id}`,
        key: `affects-critical:${finding.fingerprint}:${affectedAsset.fingerprint}`,
        source: `finding:${finding.id}`,
        target: targetId,
        relationship: "Related to critical asset",
        confidence: finding.confidence,
        state: "OBSERVED",
        evidence: `The finding is directly associated with critical asset ${affectedAsset.name}.`,
        sourceName: finding.source,
        active: true
      });
    }
  }

  return { nodes, edges, assets, services, findings, relationships };
}
