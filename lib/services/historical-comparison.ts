import { prisma } from "@/lib/db";
import { parseJson } from "@/lib/utils";

export type ChangeCategory =
  | "ASSET"
  | "SERVICE"
  | "FINDING"
  | "CERTIFICATE"
  | "DNS"
  | "ATTACK_PATH"
  | "RISK";

export type ScanChange = {
  category: ChangeCategory;
  type: string;
  entityId?: string;
  title: string;
  detail: string;
  before?: unknown;
  after?: unknown;
};

export type ScanComparison = {
  currentScanId: string;
  previousScanId: string;
  changes: ScanChange[];
  counts: Record<ChangeCategory, number>;
};

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJson);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, sortJson(nested)])
    );
  }
  return value;
}

function canonicalJson(value: string) {
  return JSON.stringify(sortJson(parseJson<unknown>(value, null)));
}

export async function compareCompletedScans(
  organisationId: string,
  currentScanId: string,
  previousScanId?: string | null
): Promise<ScanComparison | null> {
  const current = await prisma.scan.findFirst({
    where: { id: currentScanId, organisationId, status: "COMPLETED" }
  });
  if (!current) return null;
  const previous = previousScanId
    ? await prisma.scan.findFirst({
        where: { id: previousScanId, organisationId, status: "COMPLETED" }
      })
    : await prisma.scan.findFirst({
        where: {
          organisationId,
          status: "COMPLETED",
          id: { not: currentScanId },
          completedAt: { lt: current.completedAt ?? current.createdAt }
        },
        orderBy: { completedAt: "desc" }
      });
  if (!previous) return null;

  const [
    currentAssets,
    previousAssets,
    currentServices,
    previousServices,
    currentFindings,
    previousFindings,
    currentPaths,
    previousPaths,
    currentObservations,
    previousObservations
  ] = await Promise.all([
    prisma.assetPresence.findMany({
      where: { scanId: current.id, asset: { organisationId } },
      include: { asset: true }
    }),
    prisma.assetPresence.findMany({
      where: { scanId: previous.id, asset: { organisationId } },
      include: { asset: true }
    }),
    prisma.servicePresence.findMany({
      where: { scanId: current.id, service: { organisationId } },
      include: { service: { include: { asset: true } } }
    }),
    prisma.servicePresence.findMany({
      where: { scanId: previous.id, service: { organisationId } },
      include: { service: { include: { asset: true } } }
    }),
    prisma.findingObservation.findMany({
      where: { scanId: current.id, finding: { organisationId } },
      include: { finding: { include: { asset: true } } }
    }),
    prisma.findingObservation.findMany({
      where: { scanId: previous.id, finding: { organisationId } },
      include: { finding: { include: { asset: true } } }
    }),
    prisma.attackPathObservation.findMany({
      where: { scanId: current.id, attackPath: { organisationId } },
      include: { attackPath: true }
    }),
    prisma.attackPathObservation.findMany({
      where: { scanId: previous.id, attackPath: { organisationId } },
      include: { attackPath: true }
    }),
    prisma.scanObservation.findMany({
      where: { scanId: current.id, organisationId, type: { in: ["DNS", "TLS"] } }
    }),
    prisma.scanObservation.findMany({
      where: { scanId: previous.id, organisationId, type: { in: ["DNS", "TLS"] } }
    })
  ]);

  const changes: ScanChange[] = [];
  const previousAssetMap = new Map(
    previousAssets.map((item) => [item.asset.fingerprint, item])
  );
  for (const item of currentAssets) {
    const before = previousAssetMap.get(item.asset.fingerprint);
    if (item.observed && !before?.observed) {
      const reappeared = item.transition === "REAPPEARED";
      changes.push({
        category: "ASSET",
        type: reappeared ? "ASSET_REAPPEARED" : "ASSET_DISCOVERED",
        entityId: item.asset.id,
        title: reappeared ? "Asset reappeared" : "Asset discovered",
        detail: `${item.asset.name} · ${item.asset.type.replaceAll("_", " ")}`
      });
    }
  }
  for (const item of currentAssets) {
    if (!item.observed && item.transition === "INACTIVE") {
      changes.push({
        category: "ASSET",
        type: "ASSET_INACTIVE",
        entityId: item.asset.id,
        title: "Asset marked inactive",
        detail: `${item.asset.name} crossed the configured absence threshold.`
      });
    }
  }

  const previousServiceMap = new Map(
    previousServices.map((item) => [item.service.fingerprint, item])
  );
  const currentServiceMap = new Map(
    currentServices.map((item) => [item.service.fingerprint, item])
  );
  const pairedChangedServices = new Set<string>();
  const serviceContinuityKey = (item: (typeof currentServices)[number]) =>
    [
      item.service.asset.fingerprint,
      item.service.port,
      item.service.transport,
      item.service.serviceIdentifier ?? ""
    ].join(":");
  const previousServicesByContinuity = new Map(
    previousServices
      .filter((item) => item.observed)
      .map((item) => [serviceContinuityKey(item), item])
  );

  for (const item of currentServices) {
    const before = previousServiceMap.get(item.service.fingerprint);
    if (item.observed && !before?.observed) {
      const changedIdentity = previousServicesByContinuity.get(serviceContinuityKey(item));
      if (
        changedIdentity &&
        changedIdentity.service.fingerprint !== item.service.fingerprint
      ) {
        pairedChangedServices.add(changedIdentity.service.fingerprint);
        changes.push({
          category: "SERVICE",
          type: "SERVICE_CHANGED",
          entityId: item.service.assetId,
          title: "Service identity changed",
          detail: `${item.service.asset.name}:${item.service.port} changed from ${changedIdentity.service.protocol} to ${item.service.protocol}.`,
          before: {
            protocol: changedIdentity.service.protocol,
            metadata: parseJson(changedIdentity.metadataJson, {})
          },
          after: {
            protocol: item.service.protocol,
            metadata: parseJson(item.metadataJson, {})
          }
        });
      } else {
        changes.push({
          category: "SERVICE",
          type: item.transition === "REOPENED" ? "SERVICE_REOPENED" : "SERVICE_OPENED",
          entityId: item.service.assetId,
          title: item.transition === "REOPENED" ? "Service reopened" : "Service opened",
          detail: `${item.service.asset.name}:${item.service.port}/${item.service.protocol}`
        });
      }
    } else if (
      item.observed &&
      before?.observed &&
      canonicalJson(item.metadataJson) !== canonicalJson(before.metadataJson)
    ) {
      changes.push({
        category: "SERVICE",
        type: "SERVICE_CHANGED",
        entityId: item.service.assetId,
        title: "Service metadata changed",
        detail: `${item.service.asset.name}:${item.service.port}/${item.service.protocol}`,
        before: parseJson(before.metadataJson, {}),
        after: parseJson(item.metadataJson, {})
      });
    }
  }
  for (const item of previousServices) {
    if (pairedChangedServices.has(item.service.fingerprint)) continue;
    const after = currentServiceMap.get(item.service.fingerprint);
    if (item.observed && after && !after.observed) {
      changes.push({
        category: "SERVICE",
        type: "SERVICE_CLOSED",
        entityId: item.service.assetId,
        title: "Service closed",
        detail: `${item.service.asset.name}:${item.service.port}/${item.service.protocol}`
      });
    }
  }

  const previousFindingMap = new Map(
    previousFindings.map((item) => [item.finding.fingerprint, item])
  );
  const currentFindingMap = new Map(
    currentFindings.map((item) => [item.finding.fingerprint, item])
  );
  for (const item of currentFindings) {
    const before = previousFindingMap.get(item.finding.fingerprint);
    if (item.observed && !before?.observed) {
      const reopened = item.statusAfter === "REOPENED";
      changes.push({
        category: "FINDING",
        type: reopened ? "FINDING_REOPENED" : "FINDING_CREATED",
        entityId: item.finding.id,
        title: reopened ? "Finding reopened" : "Finding created",
        detail: `${item.finding.title} · ${item.finding.asset.name}`
      });
    } else if (item.observed && before?.observed) {
      changes.push({
        category: "FINDING",
        type: "FINDING_STILL_OPEN",
        entityId: item.finding.id,
        title: "Finding still observed",
        detail: `${item.finding.title} · ${item.finding.asset.name}`
      });
      if (item.severity !== before.severity) {
        changes.push({
          category: "FINDING",
          type: "FINDING_SEVERITY_CHANGED",
          entityId: item.finding.id,
          title: "Finding severity changed",
          detail: `${item.finding.title}: ${before.severity} → ${item.severity}`,
          before: before.severity,
          after: item.severity
        });
      }
    }
  }
  for (const item of previousFindings) {
    const after = currentFindingMap.get(item.finding.fingerprint);
    if (item.observed && after && !after.observed && after.statusAfter === "RESOLVED") {
      changes.push({
        category: "FINDING",
        type: "FINDING_RESOLVED",
        entityId: item.finding.id,
        title: "Finding resolved",
        detail: `${item.finding.title} · ${item.finding.asset.name}`
      });
    }
  }

  const previousPathMap = new Map(
    previousPaths.map((item) => [item.attackPath.fingerprint, item])
  );
  const currentPathMap = new Map(
    currentPaths.map((item) => [item.attackPath.fingerprint, item])
  );
  for (const item of currentPaths) {
    const before = previousPathMap.get(item.attackPath.fingerprint);
    if (item.active && !before?.active) {
      changes.push({
        category: "ATTACK_PATH",
        type: "ATTACK_PATH_CREATED",
        entityId: item.attackPath.id,
        title: before ? "Potential attack path recurred" : "Potential attack path created",
        detail: `${item.attackPath.name} · risk ${item.riskScore}`
      });
    } else if (item.active && before?.active && item.riskScore !== before.riskScore) {
      changes.push({
        category: "ATTACK_PATH",
        type: "ATTACK_PATH_RISK_CHANGED",
        entityId: item.attackPath.id,
        title: "Potential attack-path risk changed",
        detail: `${item.attackPath.name}: ${before.riskScore} → ${item.riskScore}`,
        before: before.riskScore,
        after: item.riskScore
      });
    }
  }
  for (const item of previousPaths) {
    const after = currentPathMap.get(item.attackPath.fingerprint);
    if (item.active && (!after || !after.active)) {
      changes.push({
        category: "ATTACK_PATH",
        type: "ATTACK_PATH_REMOVED",
        entityId: item.attackPath.id,
        title: "Potential attack path broken",
        detail: item.attackPath.name
      });
    }
  }

  const previousObservationMap = new Map(
    previousObservations.map((item) => [`${item.type}:${item.fingerprint}`, item])
  );
  for (const observation of currentObservations) {
    const before = previousObservationMap.get(
      `${observation.type}:${observation.fingerprint}`
    );
    if (!before || canonicalJson(before.dataJson) === canonicalJson(observation.dataJson))
      continue;
    changes.push({
      category: observation.type === "TLS" ? "CERTIFICATE" : "DNS",
      type: observation.type === "TLS" ? "CERTIFICATE_CHANGED" : "DNS_RECORD_CHANGED",
      entityId: observation.assetId ?? undefined,
      title: observation.type === "TLS" ? "Certificate changed" : "DNS records changed",
      detail: `Observed ${observation.type} evidence changed between completed scans.`,
      before: parseJson(before.dataJson, {}),
      after: parseJson(observation.dataJson, {})
    });
  }

  if ((current.riskScore ?? 0) !== (previous.riskScore ?? 0)) {
    changes.push({
      category: "RISK",
      type: "RISK_SCORE_CHANGED",
      title: "Risk score changed",
      detail: `${previous.riskScore ?? 0} → ${current.riskScore ?? 0}`,
      before: previous.riskScore,
      after: current.riskScore
    });
  }

  const counts = {
    ASSET: 0,
    SERVICE: 0,
    FINDING: 0,
    CERTIFICATE: 0,
    DNS: 0,
    ATTACK_PATH: 0,
    RISK: 0
  } satisfies Record<ChangeCategory, number>;
  for (const change of changes) counts[change.category] += 1;

  return {
    currentScanId: current.id,
    previousScanId: previous.id,
    changes,
    counts
  };
}
