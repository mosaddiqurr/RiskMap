import { describe, expect, it } from "vitest";
import type { Asset, AssetRelationship, Finding, Service } from "@prisma/client";
import {
  constructExposureGraph,
  type GraphRelationshipRecord
} from "@/lib/services/graph-construction";
import { findPotentialAttackPaths } from "@/lib/services/attack-paths";

function asset(
  id: string,
  type: Asset["type"],
  criticality: Asset["criticality"] = "MEDIUM"
): Asset {
  return {
    id,
    organisationId: "org-fixture",
    rootDomainId: "root-fixture",
    fingerprint: `asset:${id}`,
    name: `${id}.example.test`,
    type,
    hostname: `${id}.example.test`,
    normalizedHostname: `${id}.example.test`,
    ipAddress: null,
    normalizedIpAddress: null,
    port: null,
    protocol: null,
    serviceIdentifier: null,
    status: "ACTIVE",
    active: true,
    verificationStatus: "VERIFIED",
    criticality,
    source: "fixture",
    ownerName: null,
    notes: null,
    tagsJson: "[]",
    firstSeen: new Date("2026-01-01T00:00:00Z"),
    lastSeen: new Date("2026-01-01T00:00:00Z"),
    lastScanId: "scan-fixture",
    consecutivePresenceCount: 1,
    consecutiveAbsenceCount: 0,
    reappearedAt: null,
    deletedAt: null,
    createdAt: new Date("2026-01-01T00:00:00Z"),
    updatedAt: new Date("2026-01-01T00:00:00Z")
  };
}

function service(
  id: string,
  assetId: string,
  port: number,
  protocol: string,
  identifier: string
): Service {
  return {
    id,
    organisationId: "org-fixture",
    assetId,
    fingerprint: `service:${id}`,
    port,
    protocol,
    transport: "tcp",
    serviceIdentifier: identifier,
    observedState: "OPEN",
    active: true,
    confidence: "HIGH",
    evidenceSource: "fixture observation",
    evidence: `${protocol}/${port} was observed in the authorised fixture.`,
    metadataJson: "{}",
    sourceModule: "PORT_CHECKS",
    firstSeen: new Date("2026-01-01T00:00:00Z"),
    lastSeen: new Date("2026-01-01T00:00:00Z"),
    lastScanId: "scan-fixture",
    consecutivePresenceCount: 1,
    consecutiveAbsenceCount: 0,
    reappearedAt: null,
    createdAt: new Date("2026-01-01T00:00:00Z"),
    updatedAt: new Date("2026-01-01T00:00:00Z")
  };
}

function finding(input: {
  id: string;
  assetId: string;
  serviceId?: string;
  title: string;
  category: string;
  severity?: Finding["severity"];
  currentlyObserved?: boolean;
}): Finding {
  const currentlyObserved = input.currentlyObserved ?? true;
  return {
    id: input.id,
    organisationId: "org-fixture",
    scanId: "scan-fixture",
    assetId: input.assetId,
    serviceId: input.serviceId ?? null,
    fingerprint: `finding:${input.id}`,
    ruleId: `fixture.${input.id}`,
    module: "PORT_CHECKS",
    title: input.title,
    severity: input.severity ?? "HIGH",
    status: currentlyObserved ? "OPEN" : "RESOLVED",
    category: input.category,
    description: "Conservative fixture description.",
    evidenceSummary: `${input.title} evidence collected from an authorised fixture.`,
    evidenceIdentity: input.id,
    firstSeen: new Date("2026-01-01T00:00:00Z"),
    lastSeen: new Date("2026-01-01T00:00:00Z"),
    lastScanId: "scan-fixture",
    currentlyObserved,
    observationCount: 1,
    consecutiveMisses: currentlyObserved ? 0 : 1,
    recurrenceCount: 0,
    resolvedAt: currentlyObserved ? null : new Date("2026-01-02T00:00:00Z"),
    resolutionScanId: currentlyObserved ? null : "scan-fixture",
    reopenedAt: null,
    confidence: "HIGH",
    source: "fixture",
    remediation: "Restrict or harden the observed exposure after validation.",
    technicalDetail: "No exploitation was performed.",
    businessImpact: "The exposure may increase attack surface.",
    referencesJson: "[]",
    isNew: false,
    externallyReachable: true,
    falsePositive: false,
    assignedUserId: null,
    dueDate: null,
    notes: null,
    deletedAt: null,
    createdAt: new Date("2026-01-01T00:00:00Z"),
    updatedAt: new Date("2026-01-01T00:00:00Z")
  };
}

function relationship(
  id: string,
  fromAsset: Asset,
  toAsset: Asset,
  type: string,
  state: AssetRelationship["state"] = "INFERRED",
  active = true
): GraphRelationshipRecord {
  return {
    id,
    organisationId: "org-fixture",
    fingerprint: `relationship:${id}`,
    fromAssetId: fromAsset.id,
    toAssetId: toAsset.id,
    type,
    source: "fixture inventory",
    confidence: "MEDIUM",
    evidence: `${fromAsset.name} ${type.toLowerCase()} ${toAsset.name}.`,
    state,
    firstSeen: new Date("2026-01-01T00:00:00Z"),
    lastSeen: new Date("2026-01-01T00:00:00Z"),
    lastScanId: "scan-fixture",
    active,
    createdAt: new Date("2026-01-01T00:00:00Z"),
    updatedAt: new Date("2026-01-01T00:00:00Z"),
    fromAsset,
    toAsset
  };
}

function paths(input: {
  assets: Asset[];
  services: Service[];
  findings: Finding[];
  relationships?: GraphRelationshipRecord[];
}) {
  const graph = constructExposureGraph({
    ...input,
    relationships: input.relationships ?? []
  });
  return {
    graph,
    paths: findPotentialAttackPaths(graph.nodes, graph.edges, {
      maxDepth: 8,
      minimumConfidence: "LOW",
      requireFinding: true,
      requireTarget: true
    })
  };
}

describe("production exposure-graph fixtures", () => {
  it("builds an administrative exposure path through a real service node", () => {
    const publicAdmin = asset("admin-public", "SUBDOMAIN", "HIGH");
    const criticalAdmin = asset("admin-core", "CRITICAL_ASSET", "CRITICAL");
    const adminService = service(
      "admin-8443",
      publicAdmin.id,
      8443,
      "https-admin",
      "administration-console"
    );
    const result = paths({
      assets: [publicAdmin, criticalAdmin],
      services: [adminService],
      findings: [
        finding({
          id: "public-admin",
          assetId: publicAdmin.id,
          serviceId: adminService.id,
          title: "Public administration service observed",
          category: "Network exposure"
        })
      ],
      relationships: [
        relationship("admin-dependency", publicAdmin, criticalAdmin, "Could reach")
      ]
    });

    expect(
      result.paths.some((path) => path.pathType === "Administrative exposure path")
    ).toBe(true);
    expect(result.paths[0]?.nodeIds).toContain(`service:${adminService.id}`);
    expect(result.paths[0]?.evidence.every(Boolean)).toBe(true);
  });

  it("builds a public database exposure path", () => {
    const database = asset("customer-database", "IP_ADDRESS", "CRITICAL");
    const databaseService = service(
      "postgres-5432",
      database.id,
      5432,
      "postgresql",
      "customer-data"
    );
    const result = paths({
      assets: [database],
      services: [databaseService],
      findings: [
        finding({
          id: "public-database",
          assetId: database.id,
          serviceId: databaseService.id,
          title: "Public database port observed",
          category: "Network exposure",
          severity: "CRITICAL"
        })
      ]
    });

    expect(result.paths).toHaveLength(1);
    expect(result.paths[0]?.pathType).toBe("Public service risk path");
    expect(result.paths[0]?.nodeIds.length).toBeGreaterThanOrEqual(5);
  });

  it("builds a weak email impersonation path", () => {
    const domain = asset("mail-domain", "ROOT_DOMAIN", "HIGH");
    const mail = asset("business-mail", "EMAIL_SERVICE", "CRITICAL");
    const result = paths({
      assets: [domain, mail],
      services: [],
      findings: [
        finding({
          id: "weak-dmarc",
          assetId: domain.id,
          title: "DMARC policy is monitoring only",
          category: "Email impersonation protection",
          severity: "MEDIUM"
        })
      ],
      relationships: [
        relationship("mail-provider", domain, mail, "Uses mail provider", "OBSERVED")
      ]
    });

    expect(result.paths.some((path) => path.pathType === "Impersonation path")).toBe(true);
  });

  it("builds a public API exposure path", () => {
    const api = asset("customer-api", "API_ENDPOINT", "CRITICAL");
    const apiService = service("api-443", api.id, 443, "https-api", "public-api");
    const result = paths({
      assets: [api],
      services: [apiService],
      findings: [
        finding({
          id: "api-validation",
          assetId: api.id,
          serviceId: apiService.id,
          title: "Public API access-control validation required",
          category: "API exposure",
          severity: "HIGH"
        })
      ]
    });

    expect(result.paths.some((path) => path.pathType === "Exposure chain")).toBe(true);
    expect(result.paths[0]?.contributors.dataOrApiBonus).toBeGreaterThan(0);
  });

  it("breaks the path after the production graph excludes a resolved finding", () => {
    const api = asset("remediated-api", "API_ENDPOINT", "CRITICAL");
    const apiService = service(
      "remediated-api-443",
      api.id,
      443,
      "https-api",
      "public-api"
    );
    const open = paths({
      assets: [api],
      services: [apiService],
      findings: [
        finding({
          id: "remediated-api-finding",
          assetId: api.id,
          serviceId: apiService.id,
          title: "Public API access-control validation required",
          category: "API exposure"
        })
      ]
    });
    const remediated = paths({
      assets: [api],
      services: [apiService],
      findings: [
        finding({
          id: "remediated-api-finding",
          assetId: api.id,
          serviceId: apiService.id,
          title: "Public API access-control validation required",
          category: "API exposure",
          currentlyObserved: false
        })
      ]
    });

    expect(open.paths.length).toBeGreaterThan(0);
    expect(remediated.paths).toHaveLength(0);
  });
});
