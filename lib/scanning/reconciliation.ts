import {
  AssetStatus,
  AssetType,
  Confidence,
  Criticality,
  FindingSeverity,
  FindingStatus,
  RelationshipState,
  ScanModule,
  ScanModuleStatus,
  ServiceObservedState,
  VerificationStatus,
  type Asset,
  type Finding,
  type Service
} from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import {
  createAssetFingerprint,
  createFindingFingerprint,
  createObservationFingerprint,
  createRelationshipFingerprint,
  createServiceFingerprint,
  createTechnologyFingerprint,
  normalizeHostname,
  normalizeIpAddress,
  normalizeProtocol,
  normalizeServiceIdentifier,
  normalizeTransport
} from "@/lib/scanning/identity";
import {
  applyFindingLifecycle,
  applyPresenceLifecycle,
  serviceStateTransition
} from "@/lib/scanning/lifecycle";
import type {
  ScanFindingInput,
  ScanProviderResult,
  ScanTechnologyInput
} from "@/lib/scanning/types";
import { localFictionalVulnerabilityProvider } from "@/lib/vulnerabilities/local-catalog";

function enumValue<T extends Record<string, string>>(
  enumObject: T,
  value: string,
  fallback: T[keyof T]
) {
  return Object.values(enumObject).includes(value) ? (value as T[keyof T]) : fallback;
}

function serviceLookupKey(input: {
  assetName: string;
  port: number;
  protocol: string;
  transport?: string;
  serviceIdentifier?: string;
}) {
  return [
    input.assetName,
    Number(input.port),
    normalizeProtocol(input.protocol),
    normalizeTransport(input.transport),
    normalizeServiceIdentifier(input.serviceIdentifier)
  ].join("|");
}

async function addVersionCorrelationFindings(
  technologies: ScanTechnologyInput[],
  existingFindings: ScanFindingInput[]
) {
  const additions: ScanFindingInput[] = [];
  for (const technology of technologies) {
    const matches = await localFictionalVulnerabilityProvider.correlate({
      productName: technology.productName,
      version: technology.version,
      confidence: enumValue(Confidence, technology.confidence, Confidence.LOW),
      evidence: technology.evidence
    });
    for (const match of matches) {
      additions.push({
        assetName: technology.assetName,
        service: technology.service,
        ruleId: `version.${match.catalogueId.toLowerCase()}`,
        module: "TECHNOLOGY",
        evidenceIdentity: `${match.catalogueId}:${match.productName}:${match.matchedVersion}`,
        title: `Potential version-related exposure: ${match.catalogueId}`,
        severity: match.severity,
        category: "Technology correlation",
        description: `${match.summary} This is a conservative catalogue correlation, not proof that the condition is exploitable or reachable.`,
        evidence: `${technology.evidence} Exact fictional catalogue version match: ${match.matchedVersion}.`,
        confidence: match.confidence,
        remediation: match.remediation,
        technicalDetail:
          "RiskMap matched an observed product and version against a local fictional catalogue. No exploitation or intrusive validation was performed.",
        businessImpact:
          "Version-related exposure may increase risk when the affected feature is enabled and reachable. Configuration validation is required.",
        references: match.references,
        externallyReachable: true
      });
    }
  }
  return [...existingFindings, ...additions];
}

export type ReconciliationSummary = {
  newAssetIds: string[];
  reappearedAssetIds: string[];
  inactiveAssetIds: string[];
  openedServiceIds: string[];
  reopenedServiceIds: string[];
  closedServiceIds: string[];
  changedServiceIds: string[];
  newFindingIds: string[];
  reopenedFindingIds: string[];
  resolvedFindingIds: string[];
  observedFindingIds: string[];
  moduleStatus: Partial<Record<ScanModule, ScanModuleStatus>>;
};

export async function reconcileScanResult(input: {
  organisationId: string;
  rootDomainId: string;
  scanId: string;
  result: ScanProviderResult;
}) {
  const findingsWithCorrelation = await addVersionCorrelationFindings(
    input.result.technologies,
    input.result.findings
  );

  return prisma.$transaction(
    async (tx) => {
      const now = new Date();
      const summary: ReconciliationSummary = {
        newAssetIds: [],
        reappearedAssetIds: [],
        inactiveAssetIds: [],
        openedServiceIds: [],
        reopenedServiceIds: [],
        closedServiceIds: [],
        changedServiceIds: [],
        newFindingIds: [],
        reopenedFindingIds: [],
        resolvedFindingIds: [],
        observedFindingIds: [],
        moduleStatus: {}
      };

      for (const moduleResult of input.result.modules) {
        const scanModule = enumValue(
          ScanModule,
          moduleResult.module,
          ScanModule.PASSIVE_DISCOVERY
        );
        const status = enumValue(
          ScanModuleStatus,
          moduleResult.status,
          ScanModuleStatus.FAILED
        );
        summary.moduleStatus[scanModule] = status;
        await tx.scanModuleResult.upsert({
          where: { scanId_module: { scanId: input.scanId, module: scanModule } },
          create: {
            scanId: input.scanId,
            module: scanModule,
            status,
            recordCount: moduleResult.recordCount ?? 0,
            error: moduleResult.error,
            completedAt: now
          },
          update: {
            status,
            recordCount: moduleResult.recordCount ?? 0,
            error: moduleResult.error,
            completedAt: now
          }
        });
      }

      const existingAssets = await tx.asset.findMany({
        where: {
          organisationId: input.organisationId,
          rootDomainId: input.rootDomainId,
          deletedAt: null
        }
      });
      const existingAssetMap = new Map(
        existingAssets.map((asset) => [asset.fingerprint, asset])
      );
      const assetByName = new Map<string, Asset>();
      const observedAssetFingerprints = new Set<string>();

      for (const candidate of input.result.assets) {
        const type = enumValue(AssetType, candidate.type, AssetType.NETWORK_SERVICE);
        const fingerprint = createAssetFingerprint({
          organisationId: input.organisationId,
          type,
          hostname: candidate.hostname,
          ipAddress: candidate.ipAddress,
          port: candidate.port,
          protocol: candidate.protocol,
          serviceIdentifier: candidate.serviceIdentifier,
          name: candidate.name
        });
        observedAssetFingerprints.add(fingerprint);
        const existing = existingAssetMap.get(fingerprint) ?? null;
        const lifecycle = applyPresenceLifecycle(
          existing
            ? {
                active: existing.active,
                consecutivePresenceCount: existing.consecutivePresenceCount,
                consecutiveAbsenceCount: existing.consecutiveAbsenceCount
              }
            : null,
          true,
          env.ASSET_ABSENCE_THRESHOLD
        );
        const asset = existing
          ? await tx.asset.update({
              where: { id: existing.id },
              data: {
                name: candidate.name,
                type,
                hostname: candidate.hostname ?? existing.hostname,
                normalizedHostname:
                  normalizeHostname(candidate.hostname) ?? existing.normalizedHostname,
                ipAddress: candidate.ipAddress ?? existing.ipAddress,
                normalizedIpAddress:
                  normalizeIpAddress(candidate.ipAddress) ?? existing.normalizedIpAddress,
                port: candidate.port ?? existing.port,
                protocol: normalizeProtocol(candidate.protocol) ?? existing.protocol,
                serviceIdentifier:
                  normalizeServiceIdentifier(candidate.serviceIdentifier) ??
                  existing.serviceIdentifier,
                criticality: enumValue(
                  Criticality,
                  candidate.criticality,
                  existing.criticality
                ),
                source: candidate.source,
                tagsJson: JSON.stringify(candidate.tags),
                status: AssetStatus.ACTIVE,
                active: true,
                lastSeen: now,
                lastScanId: input.scanId,
                consecutivePresenceCount: lifecycle.consecutivePresenceCount,
                consecutiveAbsenceCount: 0,
                reappearedAt:
                  lifecycle.transition === "REAPPEARED" ? now : existing.reappearedAt
              }
            })
          : await tx.asset.create({
              data: {
                organisationId: input.organisationId,
                rootDomainId: input.rootDomainId,
                fingerprint,
                name: candidate.name,
                type,
                hostname: candidate.hostname,
                normalizedHostname: normalizeHostname(candidate.hostname),
                ipAddress: candidate.ipAddress,
                normalizedIpAddress: normalizeIpAddress(candidate.ipAddress),
                port: candidate.port,
                protocol: normalizeProtocol(candidate.protocol),
                serviceIdentifier: normalizeServiceIdentifier(candidate.serviceIdentifier),
                status: AssetStatus.ACTIVE,
                active: true,
                verificationStatus: VerificationStatus.VERIFIED,
                criticality: enumValue(
                  Criticality,
                  candidate.criticality,
                  Criticality.MEDIUM
                ),
                source: candidate.source,
                tagsJson: JSON.stringify(candidate.tags),
                firstSeen: now,
                lastSeen: now,
                lastScanId: input.scanId,
                consecutivePresenceCount: 1,
                consecutiveAbsenceCount: 0
              }
            });
        await tx.assetPresence.upsert({
          where: { assetId_scanId: { assetId: asset.id, scanId: input.scanId } },
          create: {
            assetId: asset.id,
            scanId: input.scanId,
            observed: true,
            transition: lifecycle.transition
          },
          update: { observed: true, transition: lifecycle.transition }
        });
        if (!existing) summary.newAssetIds.push(asset.id);
        if (lifecycle.transition === "REAPPEARED")
          summary.reappearedAssetIds.push(asset.id);
        existingAssetMap.set(fingerprint, asset);
        assetByName.set(candidate.name, asset);
      }

      const discoveryCompleted =
        summary.moduleStatus.PASSIVE_DISCOVERY === ScanModuleStatus.COMPLETED;
      for (const asset of existingAssets) {
        if (observedAssetFingerprints.has(asset.fingerprint)) continue;
        if (/manual|user-confirmed/i.test(asset.source)) {
          await tx.assetPresence.upsert({
            where: { assetId_scanId: { assetId: asset.id, scanId: input.scanId } },
            create: {
              assetId: asset.id,
              scanId: input.scanId,
              observed: false,
              transition: "PRESERVED_MANUAL"
            },
            update: { observed: false, transition: "PRESERVED_MANUAL" }
          });
          continue;
        }
        if (!discoveryCompleted) {
          await tx.assetPresence.upsert({
            where: { assetId_scanId: { assetId: asset.id, scanId: input.scanId } },
            create: {
              assetId: asset.id,
              scanId: input.scanId,
              observed: false,
              transition: "PRESERVED_INCOMPLETE_MODULE"
            },
            update: { observed: false, transition: "PRESERVED_INCOMPLETE_MODULE" }
          });
          continue;
        }
        const lifecycle = applyPresenceLifecycle(
          {
            active: asset.active,
            consecutivePresenceCount: asset.consecutivePresenceCount,
            consecutiveAbsenceCount: asset.consecutiveAbsenceCount
          },
          false,
          env.ASSET_ABSENCE_THRESHOLD
        );
        await tx.asset.update({
          where: { id: asset.id },
          data: {
            active: lifecycle.active,
            status: lifecycle.active ? AssetStatus.ACTIVE : AssetStatus.INACTIVE,
            lastScanId: input.scanId,
            consecutivePresenceCount: lifecycle.consecutivePresenceCount,
            consecutiveAbsenceCount: lifecycle.consecutiveAbsenceCount
          }
        });
        await tx.assetPresence.upsert({
          where: { assetId_scanId: { assetId: asset.id, scanId: input.scanId } },
          create: {
            assetId: asset.id,
            scanId: input.scanId,
            observed: false,
            transition: lifecycle.transition
          },
          update: { observed: false, transition: lifecycle.transition }
        });
        if (lifecycle.transition === "INACTIVE") summary.inactiveAssetIds.push(asset.id);
      }

      const existingServices = await tx.service.findMany({
        where: {
          organisationId: input.organisationId,
          asset: { rootDomainId: input.rootDomainId }
        }
      });
      const existingServiceMap = new Map(
        existingServices.map((service) => [service.fingerprint, service])
      );
      const observedServiceFingerprints = new Set<string>();
      const serviceByLookupKey = new Map<string, Service>();

      for (const candidate of input.result.services) {
        const asset = assetByName.get(candidate.assetName);
        if (!asset) continue;
        const fingerprint = createServiceFingerprint({
          organisationId: input.organisationId,
          assetFingerprint: asset.fingerprint,
          port: candidate.port,
          protocol: candidate.protocol,
          transport: candidate.transport,
          serviceIdentifier: candidate.serviceIdentifier
        });
        observedServiceFingerprints.add(fingerprint);
        const existing = existingServiceMap.get(fingerprint) ?? null;
        const lifecycle = applyPresenceLifecycle(
          existing
            ? {
                active: existing.active,
                consecutivePresenceCount: existing.consecutivePresenceCount,
                consecutiveAbsenceCount: existing.consecutiveAbsenceCount
              }
            : null,
          true,
          env.SERVICE_ABSENCE_THRESHOLD
        );
        const observedState = enumValue(
          ServiceObservedState,
          candidate.observedState,
          ServiceObservedState.UNKNOWN
        );
        const transition = existing
          ? serviceStateTransition(
              existing.active,
              existing.observedState,
              true,
              observedState,
              lifecycle.transition === "REAPPEARED"
            )
          : "OPENED";
        const metadataJson = JSON.stringify(candidate.metadata ?? {});
        const service = existing
          ? await tx.service.update({
              where: { id: existing.id },
              data: {
                port: Number(candidate.port),
                protocol: normalizeProtocol(candidate.protocol) ?? "unknown",
                transport: normalizeTransport(candidate.transport),
                serviceIdentifier: normalizeServiceIdentifier(candidate.serviceIdentifier),
                observedState,
                active: true,
                confidence: enumValue(Confidence, candidate.confidence, Confidence.MEDIUM),
                evidenceSource: candidate.evidenceSource,
                evidence: candidate.evidence,
                metadataJson,
                sourceModule: enumValue(
                  ScanModule,
                  candidate.sourceModule,
                  ScanModule.PORT_CHECKS
                ),
                lastSeen: now,
                lastScanId: input.scanId,
                consecutivePresenceCount: lifecycle.consecutivePresenceCount,
                consecutiveAbsenceCount: 0,
                reappearedAt:
                  lifecycle.transition === "REAPPEARED" ? now : existing.reappearedAt
              }
            })
          : await tx.service.create({
              data: {
                organisationId: input.organisationId,
                assetId: asset.id,
                fingerprint,
                port: Number(candidate.port),
                protocol: normalizeProtocol(candidate.protocol) ?? "unknown",
                transport: normalizeTransport(candidate.transport),
                serviceIdentifier: normalizeServiceIdentifier(candidate.serviceIdentifier),
                observedState,
                active: true,
                confidence: enumValue(Confidence, candidate.confidence, Confidence.MEDIUM),
                evidenceSource: candidate.evidenceSource,
                evidence: candidate.evidence,
                metadataJson,
                sourceModule: enumValue(
                  ScanModule,
                  candidate.sourceModule,
                  ScanModule.PORT_CHECKS
                ),
                firstSeen: now,
                lastSeen: now,
                lastScanId: input.scanId,
                consecutivePresenceCount: 1,
                consecutiveAbsenceCount: 0
              }
            });
        await tx.servicePresence.upsert({
          where: { serviceId_scanId: { serviceId: service.id, scanId: input.scanId } },
          create: {
            serviceId: service.id,
            scanId: input.scanId,
            observed: true,
            state: observedState,
            transition,
            metadataJson
          },
          update: {
            observed: true,
            state: observedState,
            transition,
            metadataJson
          }
        });
        if (transition === "OPENED") summary.openedServiceIds.push(service.id);
        if (transition === "REOPENED") summary.reopenedServiceIds.push(service.id);
        if (transition === "CHANGED") summary.changedServiceIds.push(service.id);
        existingServiceMap.set(fingerprint, service);
        serviceByLookupKey.set(serviceLookupKey(candidate), service);
      }

      for (const service of existingServices) {
        if (observedServiceFingerprints.has(service.fingerprint)) continue;
        const moduleStatus = summary.moduleStatus[service.sourceModule];
        if (moduleStatus !== ScanModuleStatus.COMPLETED) {
          await tx.servicePresence.upsert({
            where: { serviceId_scanId: { serviceId: service.id, scanId: input.scanId } },
            create: {
              serviceId: service.id,
              scanId: input.scanId,
              observed: false,
              state: service.observedState,
              transition: "PRESERVED_INCOMPLETE_MODULE",
              metadataJson: service.metadataJson
            },
            update: {
              observed: false,
              state: service.observedState,
              transition: "PRESERVED_INCOMPLETE_MODULE",
              metadataJson: service.metadataJson
            }
          });
          continue;
        }
        const lifecycle = applyPresenceLifecycle(
          {
            active: service.active,
            consecutivePresenceCount: service.consecutivePresenceCount,
            consecutiveAbsenceCount: service.consecutiveAbsenceCount
          },
          false,
          env.SERVICE_ABSENCE_THRESHOLD
        );
        const transition = serviceStateTransition(
          service.active,
          service.observedState,
          lifecycle.active,
          ServiceObservedState.CLOSED,
          false
        );
        await tx.service.update({
          where: { id: service.id },
          data: {
            observedState: ServiceObservedState.CLOSED,
            active: lifecycle.active,
            lastScanId: input.scanId,
            consecutivePresenceCount: lifecycle.consecutivePresenceCount,
            consecutiveAbsenceCount: lifecycle.consecutiveAbsenceCount
          }
        });
        await tx.servicePresence.upsert({
          where: { serviceId_scanId: { serviceId: service.id, scanId: input.scanId } },
          create: {
            serviceId: service.id,
            scanId: input.scanId,
            observed: false,
            state: ServiceObservedState.CLOSED,
            transition,
            metadataJson: service.metadataJson
          },
          update: {
            observed: false,
            state: ServiceObservedState.CLOSED,
            transition,
            metadataJson: service.metadataJson
          }
        });
        if (transition === "CLOSED") summary.closedServiceIds.push(service.id);
      }

      const seenRelationshipFingerprints = new Set<string>();
      for (const candidate of input.result.relationships) {
        const from = assetByName.get(candidate.from);
        const to = assetByName.get(candidate.to);
        if (!from || !to) continue;
        const fingerprint = createRelationshipFingerprint({
          organisationId: input.organisationId,
          fromFingerprint: from.fingerprint,
          toFingerprint: to.fingerprint,
          type: candidate.type
        });
        seenRelationshipFingerprints.add(fingerprint);
        await tx.assetRelationship.upsert({
          where: {
            organisationId_fingerprint: {
              organisationId: input.organisationId,
              fingerprint
            }
          },
          create: {
            organisationId: input.organisationId,
            fingerprint,
            fromAssetId: from.id,
            toAssetId: to.id,
            type: candidate.type,
            source: candidate.source,
            confidence: enumValue(Confidence, candidate.confidence, Confidence.MEDIUM),
            evidence: candidate.evidence,
            state: enumValue(
              RelationshipState,
              candidate.state,
              RelationshipState.INFERRED
            ),
            firstSeen: now,
            lastSeen: now,
            lastScanId: input.scanId,
            active: true
          },
          update: {
            source: candidate.source,
            confidence: enumValue(Confidence, candidate.confidence, Confidence.MEDIUM),
            evidence: candidate.evidence,
            state: enumValue(
              RelationshipState,
              candidate.state,
              RelationshipState.INFERRED
            ),
            lastSeen: now,
            lastScanId: input.scanId,
            active: true
          }
        });
      }
      if (summary.moduleStatus.GRAPH === ScanModuleStatus.COMPLETED) {
        const staleRelationships = await tx.assetRelationship.findMany({
          where: {
            organisationId: input.organisationId,
            active: true,
            fingerprint: { notIn: [...seenRelationshipFingerprints] },
            OR: [
              { fromAsset: { rootDomainId: input.rootDomainId } },
              { toAsset: { rootDomainId: input.rootDomainId } }
            ]
          },
          select: { id: true }
        });
        if (staleRelationships.length) {
          await tx.assetRelationship.updateMany({
            where: { id: { in: staleRelationships.map((item) => item.id) } },
            data: { active: false, lastScanId: input.scanId }
          });
        }
      }

      for (const observation of input.result.observations) {
        const asset = observation.assetName
          ? assetByName.get(observation.assetName)
          : undefined;
        const service = observation.service
          ? serviceByLookupKey.get(
              serviceLookupKey({
                assetName: observation.assetName ?? "",
                ...observation.service
              })
            )
          : undefined;
        const scanModule = enumValue(
          ScanModule,
          observation.module,
          ScanModule.PASSIVE_DISCOVERY
        );
        const fingerprint = createObservationFingerprint({
          module: scanModule,
          type: observation.type,
          assetFingerprint: asset?.fingerprint,
          serviceFingerprint: service?.fingerprint,
          identity: observation.identity
        });
        await tx.scanObservation.upsert({
          where: {
            scanId_fingerprint: { scanId: input.scanId, fingerprint }
          },
          create: {
            organisationId: input.organisationId,
            scanId: input.scanId,
            assetId: asset?.id,
            serviceId: service?.id,
            fingerprint,
            module: scanModule,
            type: observation.type,
            success: observation.success ?? true,
            dataJson: JSON.stringify(observation.data),
            observedAt: now
          },
          update: {
            assetId: asset?.id,
            serviceId: service?.id,
            success: observation.success ?? true,
            dataJson: JSON.stringify(observation.data),
            observedAt: now
          }
        });
      }

      const seenTechnologyFingerprints = new Set<string>();
      for (const technology of input.result.technologies) {
        const asset = assetByName.get(technology.assetName);
        if (!asset) continue;
        const service = technology.service
          ? serviceByLookupKey.get(
              serviceLookupKey({ assetName: technology.assetName, ...technology.service })
            )
          : undefined;
        const fingerprint = createTechnologyFingerprint({
          organisationId: input.organisationId,
          assetFingerprint: asset.fingerprint,
          serviceFingerprint: service?.fingerprint,
          productName: technology.productName,
          version: technology.version
        });
        seenTechnologyFingerprints.add(fingerprint);
        await tx.technologyObservation.upsert({
          where: {
            organisationId_fingerprint: {
              organisationId: input.organisationId,
              fingerprint
            }
          },
          create: {
            organisationId: input.organisationId,
            scanId: input.scanId,
            assetId: asset.id,
            serviceId: service?.id,
            fingerprint,
            productName: technology.productName,
            version: technology.version,
            confidence: enumValue(Confidence, technology.confidence, Confidence.LOW),
            evidence: technology.evidence,
            source: technology.source,
            firstSeen: now,
            lastSeen: now,
            active: true
          },
          update: {
            scanId: input.scanId,
            assetId: asset.id,
            serviceId: service?.id,
            confidence: enumValue(Confidence, technology.confidence, Confidence.LOW),
            evidence: technology.evidence,
            source: technology.source,
            lastSeen: now,
            active: true
          }
        });
      }
      if (summary.moduleStatus.TECHNOLOGY === ScanModuleStatus.COMPLETED) {
        const staleTechnologies = await tx.technologyObservation.findMany({
          where: {
            organisationId: input.organisationId,
            active: true,
            fingerprint: { notIn: [...seenTechnologyFingerprints] },
            asset: { rootDomainId: input.rootDomainId }
          },
          select: { id: true }
        });
        if (staleTechnologies.length) {
          await tx.technologyObservation.updateMany({
            where: { id: { in: staleTechnologies.map((item) => item.id) } },
            data: { active: false }
          });
        }
      }

      const existingFindings = await tx.finding.findMany({
        where: {
          organisationId: input.organisationId,
          deletedAt: null,
          asset: { rootDomainId: input.rootDomainId }
        },
        include: { asset: true, service: true }
      });
      const existingFindingMap = new Map(
        existingFindings.map((finding) => [finding.fingerprint, finding])
      );
      const observedFindingFingerprints = new Set<string>();

      for (const candidate of findingsWithCorrelation) {
        const asset = assetByName.get(candidate.assetName);
        if (!asset) continue;
        const service = candidate.service
          ? serviceByLookupKey.get(
              serviceLookupKey({ assetName: candidate.assetName, ...candidate.service })
            )
          : undefined;
        const fingerprint = createFindingFingerprint({
          organisationId: input.organisationId,
          assetFingerprint: asset.fingerprint,
          serviceFingerprint: service?.fingerprint,
          ruleId: candidate.ruleId,
          evidenceIdentity: candidate.evidenceIdentity,
          port: candidate.service?.port,
          protocol: candidate.service?.protocol
        });
        observedFindingFingerprints.add(fingerprint);
        const existing = existingFindingMap.get(fingerprint) ?? null;
        const lifecycle = applyFindingLifecycle(
          existing
            ? {
                status: existing.status,
                currentlyObserved: existing.currentlyObserved,
                observationCount: existing.observationCount,
                consecutiveMisses: existing.consecutiveMisses,
                recurrenceCount: existing.recurrenceCount
              }
            : null,
          true,
          true,
          env.FINDING_RESOLUTION_ABSENCE_THRESHOLD
        );
        const severity = enumValue(
          FindingSeverity,
          candidate.severity,
          FindingSeverity.INFORMATIONAL
        );
        const confidence = enumValue(Confidence, candidate.confidence, Confidence.MEDIUM);
        const scanModule = enumValue(
          ScanModule,
          candidate.module,
          ScanModule.PASSIVE_DISCOVERY
        );
        const finding = existing
          ? await tx.finding.update({
              where: { id: existing.id },
              data: {
                scanId: input.scanId,
                assetId: asset.id,
                serviceId: service?.id,
                ruleId: candidate.ruleId,
                module: scanModule,
                title: candidate.title,
                severity,
                status: lifecycle.status,
                category: candidate.category,
                description: candidate.description,
                evidenceSummary: candidate.evidence,
                evidenceIdentity: candidate.evidenceIdentity,
                lastSeen: now,
                lastScanId: input.scanId,
                currentlyObserved: true,
                observationCount: lifecycle.observationCount,
                consecutiveMisses: 0,
                recurrenceCount: lifecycle.recurrenceCount,
                resolvedAt: lifecycle.reopenedNow ? null : existing.resolvedAt,
                resolutionScanId: lifecycle.reopenedNow ? null : existing.resolutionScanId,
                reopenedAt: lifecycle.reopenedNow ? now : existing.reopenedAt,
                confidence,
                source: input.result.provider,
                remediation: candidate.remediation,
                technicalDetail: candidate.technicalDetail,
                businessImpact: candidate.businessImpact,
                referencesJson: JSON.stringify(candidate.references),
                isNew: false,
                externallyReachable: candidate.externallyReachable
              }
            })
          : await tx.finding.create({
              data: {
                organisationId: input.organisationId,
                scanId: input.scanId,
                assetId: asset.id,
                serviceId: service?.id,
                fingerprint,
                ruleId: candidate.ruleId,
                module: scanModule,
                title: candidate.title,
                severity,
                status: FindingStatus.OPEN,
                category: candidate.category,
                description: candidate.description,
                evidenceSummary: candidate.evidence,
                evidenceIdentity: candidate.evidenceIdentity,
                firstSeen: now,
                lastSeen: now,
                lastScanId: input.scanId,
                currentlyObserved: true,
                observationCount: 1,
                consecutiveMisses: 0,
                recurrenceCount: 0,
                confidence,
                source: input.result.provider,
                remediation: candidate.remediation,
                technicalDetail: candidate.technicalDetail,
                businessImpact: candidate.businessImpact,
                referencesJson: JSON.stringify(candidate.references),
                isNew: true,
                externallyReachable: candidate.externallyReachable
              }
            });
        await tx.findingObservation.upsert({
          where: { findingId_scanId: { findingId: finding.id, scanId: input.scanId } },
          create: {
            findingId: finding.id,
            scanId: input.scanId,
            observed: true,
            severity,
            confidence,
            statusAfter: lifecycle.status,
            evidenceSummary: candidate.evidence
          },
          update: {
            observed: true,
            severity,
            confidence,
            statusAfter: lifecycle.status,
            evidenceSummary: candidate.evidence
          }
        });
        await tx.findingEvidence.deleteMany({
          where: { findingId: finding.id, scanId: input.scanId }
        });
        await tx.findingEvidence.create({
          data: {
            findingId: finding.id,
            scanId: input.scanId,
            kind: "scan-observation",
            value: candidate.evidence,
            collectedAt: now
          }
        });
        if (!existing) summary.newFindingIds.push(finding.id);
        if (lifecycle.reopenedNow) summary.reopenedFindingIds.push(finding.id);
        summary.observedFindingIds.push(finding.id);
        existingFindingMap.set(
          fingerprint,
          finding as Finding & {
            asset: Asset;
            service: Service | null;
          }
        );
      }

      for (const finding of existingFindings) {
        if (observedFindingFingerprints.has(finding.fingerprint)) continue;
        const moduleCompleted =
          summary.moduleStatus[finding.module] === ScanModuleStatus.COMPLETED;
        const lifecycle = applyFindingLifecycle(
          {
            status: finding.status,
            currentlyObserved: finding.currentlyObserved,
            observationCount: finding.observationCount,
            consecutiveMisses: finding.consecutiveMisses,
            recurrenceCount: finding.recurrenceCount
          },
          false,
          moduleCompleted,
          env.FINDING_RESOLUTION_ABSENCE_THRESHOLD
        );
        await tx.finding.update({
          where: { id: finding.id },
          data: {
            status: lifecycle.status,
            currentlyObserved: lifecycle.currentlyObserved,
            consecutiveMisses: lifecycle.consecutiveMisses,
            lastScanId: input.scanId,
            resolvedAt: lifecycle.resolvedNow ? now : finding.resolvedAt,
            resolutionScanId: lifecycle.resolvedNow
              ? input.scanId
              : finding.resolutionScanId,
            isNew: false
          }
        });
        await tx.findingObservation.upsert({
          where: { findingId_scanId: { findingId: finding.id, scanId: input.scanId } },
          create: {
            findingId: finding.id,
            scanId: input.scanId,
            observed: false,
            severity: finding.severity,
            confidence: finding.confidence,
            statusAfter: lifecycle.status,
            evidenceSummary: moduleCompleted
              ? "The relevant scan module completed and this finding was not observed."
              : "The relevant scan module did not complete successfully; lifecycle state was preserved."
          },
          update: {
            observed: false,
            statusAfter: lifecycle.status,
            evidenceSummary: moduleCompleted
              ? "The relevant scan module completed and this finding was not observed."
              : "The relevant scan module did not complete successfully; lifecycle state was preserved."
          }
        });
        if (lifecycle.resolvedNow) summary.resolvedFindingIds.push(finding.id);
      }

      return summary;
    },
    { timeout: 30_000 }
  );
}
