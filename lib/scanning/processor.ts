import {
  AlertSeverity,
  AlertType,
  FindingSeverity,
  JobStatus,
  ScanStatus,
  VerificationStatus
} from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { matchesAnyExclusion } from "@/lib/scanning/exclusions";
import { MockScanProvider } from "@/lib/scanning/mock-provider";
import { isRetryableScanError, scheduleScanJobRetry } from "@/lib/scanning/job-runtime";
import { reconcileScanResult } from "@/lib/scanning/reconciliation";
import { SafeLiveScanProvider } from "@/lib/scanning/safe-live-provider";
import type { ScanProvider, ScanProviderResult } from "@/lib/scanning/types";
import { calculateAndPersistAttackPaths } from "@/lib/services/graph-construction";
import { compareCompletedScans } from "@/lib/services/historical-comparison";
import { createAlertAndSimulate } from "@/lib/services/notifications";
import { calculateOrganisationRisk } from "@/lib/services/risk-scoring";

const provider: ScanProvider =
  env.SCAN_MODE === "safe-live" ? new SafeLiveScanProvider() : new MockScanProvider();

export async function claimNextScanJob() {
  const job = await prisma.scanJob.findFirst({
    where: { status: JobStatus.QUEUED, availableAt: { lte: new Date() } },
    orderBy: { createdAt: "asc" }
  });
  if (!job) return null;
  const claimed = await prisma.scanJob.updateMany({
    where: { id: job.id, status: JobStatus.QUEUED },
    data: {
      status: JobStatus.RUNNING,
      lockedAt: new Date(),
      lastError: null,
      attempts: { increment: 1 }
    }
  });
  return claimed.count === 1 ? prisma.scanJob.findUnique({ where: { id: job.id } }) : null;
}

function filterExcludedResult(result: ScanProviderResult, patterns: string[]) {
  const excludedNames = new Set(
    result.assets
      .filter(
        (asset) =>
          matchesAnyExclusion(asset.name, patterns) ||
          Boolean(asset.hostname && matchesAnyExclusion(asset.hostname, patterns))
      )
      .map((asset) => asset.name)
  );
  return {
    ...result,
    assets: result.assets.filter((asset) => !excludedNames.has(asset.name)),
    services: result.services.filter((service) => !excludedNames.has(service.assetName)),
    technologies: result.technologies.filter(
      (technology) => !excludedNames.has(technology.assetName)
    ),
    findings: result.findings.filter((finding) => !excludedNames.has(finding.assetName)),
    relationships: result.relationships.filter(
      (relationship) =>
        !excludedNames.has(relationship.from) && !excludedNames.has(relationship.to)
    ),
    observations: result.observations.filter(
      (observation) => !observation.assetName || !excludedNames.has(observation.assetName)
    ),
    log: [
      ...result.log,
      `${excludedNames.size} asset candidate(s) were skipped by customer exclusions.`
    ]
  };
}

function scanIsFullySuccessful(result: ScanProviderResult) {
  return result.modules.every(
    (module) => module.status === "COMPLETED" || module.status === "SKIPPED"
  );
}

async function calculateCurrentRisk(organisationId: string) {
  const [findings, activePathSteps] = await Promise.all([
    prisma.finding.findMany({
      where: {
        organisationId,
        deletedAt: null,
        currentlyObserved: true,
        status: { notIn: ["RESOLVED", "FALSE_POSITIVE"] }
      },
      include: { asset: true }
    }),
    prisma.attackPathStep.findMany({
      where: {
        attackPath: { organisationId, active: true },
        findingId: { not: null }
      },
      select: { findingId: true }
    })
  ]);
  const pathFindingIds = new Set(
    activePathSteps.map((step) => step.findingId).filter(Boolean) as string[]
  );
  const findingsByAsset = new Map<string, number>();
  for (const finding of findings) {
    findingsByAsset.set(finding.assetId, (findingsByAsset.get(finding.assetId) ?? 0) + 1);
  }
  return calculateOrganisationRisk(
    findings.map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      status: finding.status,
      confidence: finding.confidence,
      firstSeen: finding.firstSeen,
      isNew: finding.isNew,
      currentlyObserved: finding.currentlyObserved,
      externallyReachable: finding.externallyReachable,
      asset: { criticality: finding.asset.criticality },
      relatedFindingCount: Math.max(0, (findingsByAsset.get(finding.assetId) ?? 1) - 1),
      inAttackPath: pathFindingIds.has(finding.id)
    }))
  );
}

async function emitLifecycleAlerts(input: {
  organisationId: string;
  scanId: string;
  newAssetIds: string[];
  newFindingIds: string[];
  reopenedFindingIds: string[];
  newPathIds: string[];
  recurredPathIds: string[];
  riskScore: number;
  previousRiskScore: number | null;
}) {
  const [criticalAssets, findings] = await Promise.all([
    prisma.asset.findMany({
      where: {
        organisationId: input.organisationId,
        id: { in: input.newAssetIds },
        criticality: "CRITICAL"
      }
    }),
    prisma.finding.findMany({
      where: {
        organisationId: input.organisationId,
        id: { in: [...input.newFindingIds, ...input.reopenedFindingIds] }
      },
      include: { asset: true }
    })
  ]);

  for (const asset of criticalAssets) {
    await createAlertAndSimulate({
      organisationId: input.organisationId,
      type: AlertType.NEW_CRITICAL_ASSET,
      severity: AlertSeverity.HIGH,
      title: "New critical asset observed",
      body: `${asset.name} was added to the verified external inventory. Confirm ownership, purpose and expected exposure.`,
      relatedAssetId: asset.id,
      relatedScanId: input.scanId
    });
  }

  for (const finding of findings) {
    const reopened = input.reopenedFindingIds.includes(finding.id);
    const interesting =
      new Set<FindingSeverity>([FindingSeverity.CRITICAL, FindingSeverity.HIGH]).has(
        finding.severity
      ) || /expires soon|port observed/i.test(finding.title);
    if (!interesting) continue;
    const type = /expires soon|expired/i.test(finding.title)
      ? AlertType.EXPIRING_CERTIFICATE
      : /port observed/i.test(finding.title)
        ? AlertType.NEW_RISKY_PORT
        : AlertType.NEW_HIGH_FINDING;
    await createAlertAndSimulate({
      organisationId: input.organisationId,
      type,
      severity:
        finding.severity === FindingSeverity.CRITICAL
          ? AlertSeverity.CRITICAL
          : finding.severity === FindingSeverity.HIGH
            ? AlertSeverity.HIGH
            : AlertSeverity.MEDIUM,
      title: reopened ? `Reopened: ${finding.title}` : finding.title,
      body: `${reopened ? "A previously resolved" : "A new"} ${finding.severity.toLowerCase()} finding is currently observed on ${finding.asset.name}. Validation and prioritisation are required.`,
      relatedAssetId: finding.assetId,
      relatedFindingId: finding.id,
      relatedScanId: input.scanId
    });
  }

  if (input.newPathIds.length || input.recurredPathIds.length) {
    await createAlertAndSimulate({
      organisationId: input.organisationId,
      type: AlertType.NEW_ATTACK_PATH,
      severity: AlertSeverity.HIGH,
      title: input.newPathIds.length
        ? "New potential attack path mapped"
        : "Potential attack path recurred",
      body: "RiskMap connected observed exposure evidence and labelled inferred relationships into a potential path. This is not confirmation of exploitation.",
      relatedScanId: input.scanId,
      relatedPathId: input.newPathIds[0] ?? input.recurredPathIds[0]
    });
  }

  if (input.previousRiskScore !== null) {
    const thresholds = await prisma.notificationSetting.findMany({
      where: { organisationId: input.organisationId },
      select: { largeIncreaseFrom: true }
    });
    const threshold = Math.min(...thresholds.map((item) => item.largeIncreaseFrom), 15);
    const increase = input.riskScore - input.previousRiskScore;
    if (increase >= threshold) {
      await createAlertAndSimulate({
        organisationId: input.organisationId,
        type: AlertType.RISK_SCORE_INCREASE,
        severity: increase >= 25 ? AlertSeverity.HIGH : AlertSeverity.MEDIUM,
        title: "Risk score increased materially",
        body: `The prioritisation score increased by ${increase} points compared with the previous successful scan. Review the contributors before acting.`,
        relatedScanId: input.scanId
      });
    }
  }
}

export async function processScanJob(jobId: string) {
  const job = await prisma.scanJob.findUnique({
    where: { id: jobId },
    include: { scan: { include: { rootDomain: true } } }
  });
  if (!job || job.status !== JobStatus.RUNNING) return;
  const { scan } = job;
  let reconciled = false;

  try {
    if (scan.rootDomain.verificationStatus !== VerificationStatus.VERIFIED) {
      throw new Error("Domain is not verified");
    }
    if (
      env.SCAN_MODE === "safe-live" &&
      !scan.rootDomain.activeChecksAuthorized &&
      scan.rootDomain.scanPermission === "SAFE_ACTIVE"
    ) {
      throw new Error("Explicit active-check authorisation is required");
    }

    const exclusions = await prisma.scanExclusion.findMany({
      where: {
        organisationId: scan.organisationId,
        rootDomainId: scan.rootDomainId,
        enabled: true
      },
      select: { pattern: true }
    });
    const exclusionPatterns = exclusions.map((item) => item.pattern);
    if (matchesAnyExclusion(scan.rootDomain.domain, exclusionPatterns)) {
      throw new Error("The verified root domain is excluded from scanning");
    }

    const previous = await prisma.scan.findFirst({
      where: {
        organisationId: scan.organisationId,
        rootDomainId: scan.rootDomainId,
        id: { not: scan.id },
        status: ScanStatus.COMPLETED,
        completedAt: { not: null }
      },
      orderBy: { completedAt: "desc" }
    });
    const successfulScanCount = await prisma.scan.count({
      where: {
        organisationId: scan.organisationId,
        rootDomainId: scan.rootDomainId,
        id: { not: scan.id },
        status: ScanStatus.COMPLETED
      }
    });

    await prisma.scan.update({
      where: { id: scan.id },
      data: {
        status: ScanStatus.RUNNING,
        startedAt: new Date(),
        progress: 8,
        previousScanId: previous?.id ?? null,
        previousRiskScore: previous?.riskScore ?? null
      }
    });

    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), env.SCAN_JOB_TIMEOUT_MS);
    let providerResult: ScanProviderResult;
    try {
      providerResult = await provider.scan(scan.rootDomain.domain, {
        activeChecks:
          scan.rootDomain.scanPermission === "SAFE_ACTIVE" &&
          scan.rootDomain.activeChecksAuthorized,
        scanSequence: successfulScanCount + 1,
        signal: abortController.signal
      });
      if (abortController.signal.aborted) {
        throw new Error(`Scan job exceeded the ${env.SCAN_JOB_TIMEOUT_MS} ms timeout.`);
      }
    } finally {
      clearTimeout(timeout);
    }
    const result = filterExcludedResult(providerResult, exclusionPatterns);
    await prisma.scan.update({
      where: { id: scan.id },
      data: {
        progress: 38,
        logJson: JSON.stringify(result.log)
      }
    });

    const lifecycle = await reconcileScanResult({
      organisationId: scan.organisationId,
      rootDomainId: scan.rootDomainId,
      scanId: scan.id,
      result
    });
    reconciled = true;
    await prisma.scan.update({ where: { id: scan.id }, data: { progress: 72 } });

    const fullySuccessful = scanIsFullySuccessful(result);
    const pathResult = fullySuccessful
      ? await calculateAndPersistAttackPaths(scan.organisationId, scan.id)
      : {
          current: [],
          created: [],
          recurred: [],
          broken: [],
          potentialPaths: []
        };
    const risk = await calculateCurrentRisk(scan.organisationId);
    const finalStatus = fullySuccessful
      ? ScanStatus.COMPLETED
      : ScanStatus.PARTIALLY_COMPLETED;
    const summary = {
      provider: result.provider,
      fictionalDemoData: env.SCAN_MODE === "mock",
      modules: result.modules,
      assetsObserved: result.assets.length,
      assetsDiscovered: lifecycle.newAssetIds.length,
      assetsReappeared: lifecycle.reappearedAssetIds.length,
      assetsMarkedInactive: lifecycle.inactiveAssetIds.length,
      servicesObserved: result.services.length,
      servicesOpened: lifecycle.openedServiceIds.length,
      servicesReopened: lifecycle.reopenedServiceIds.length,
      servicesClosed: lifecycle.closedServiceIds.length,
      findingsObserved: lifecycle.observedFindingIds.length,
      findingsCreated: lifecycle.newFindingIds.length,
      findingsResolved: lifecycle.resolvedFindingIds.length,
      findingsReopened: lifecycle.reopenedFindingIds.length,
      potentialAttackPaths: pathResult.current.length,
      attackPathsCreated: pathResult.created.length,
      attackPathsBroken: pathResult.broken.length,
      observations: result.observations.length
    };

    await prisma.$transaction([
      prisma.scan.update({
        where: { id: scan.id },
        data: {
          status: finalStatus,
          progress: 100,
          completedAt: new Date(),
          riskScore: risk.score,
          summaryJson: JSON.stringify(summary),
          logJson: JSON.stringify([
            ...result.log,
            `Risk score calculated using formula ${risk.formulaVersion}.`,
            fullySuccessful
              ? "All enabled scan modules completed successfully."
              : "One or more modules were partial or failed; lifecycle changes were limited to successfully completed modules.",
            "Scan completed without exploitation, authentication attempts or destructive checks."
          ])
        }
      }),
      prisma.scanJob.update({
        where: { id: job.id },
        data: { status: JobStatus.COMPLETED, lockedAt: null, lastError: null }
      })
    ]);

    if (finalStatus === ScanStatus.COMPLETED && previous) {
      const comparison = await compareCompletedScans(
        scan.organisationId,
        scan.id,
        previous.id
      );
      if (comparison) {
        await prisma.scan.update({
          where: { id: scan.id },
          data: { comparisonJson: JSON.stringify(comparison) }
        });
      }
    }

    await emitLifecycleAlerts({
      organisationId: scan.organisationId,
      scanId: scan.id,
      newAssetIds: lifecycle.newAssetIds,
      newFindingIds: lifecycle.newFindingIds,
      reopenedFindingIds: lifecycle.reopenedFindingIds,
      newPathIds: pathResult.created,
      recurredPathIds: pathResult.recurred,
      riskScore: risk.score,
      previousRiskScore: previous?.riskScore ?? null
    });

    return {
      scanId: scan.id,
      status: finalStatus,
      riskScore: risk.score,
      summary
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown scan failure";
    if (reconciled) {
      await prisma.$transaction([
        prisma.scan.update({
          where: { id: scan.id },
          data: {
            status: ScanStatus.PARTIALLY_COMPLETED,
            completedAt: new Date(),
            error: message,
            progress: 100
          }
        }),
        prisma.scanJob.update({
          where: { id: job.id },
          data: { status: JobStatus.COMPLETED, lastError: message, lockedAt: null }
        })
      ]);
      await createAlertAndSimulate({
        organisationId: scan.organisationId,
        type: AlertType.FAILED_SCAN,
        severity: AlertSeverity.MEDIUM,
        title: "Scan partially completed",
        body: `${message}. Successfully completed modules were retained; incomplete modules did not resolve findings or deactivate inventory.`,
        relatedScanId: scan.id
      }).catch(() => undefined);
      return { scanId: scan.id, status: ScanStatus.PARTIALLY_COMPLETED, error: message };
    }

    if (isRetryableScanError(error) && job.attempts < env.SCAN_JOB_MAX_ATTEMPTS) {
      const availableAt = await scheduleScanJobRetry({
        jobId: job.id,
        scanId: scan.id,
        attempt: job.attempts,
        error: message
      });
      return {
        scanId: scan.id,
        status: ScanStatus.QUEUED,
        retryScheduledAt: availableAt,
        error: message
      };
    }

    await prisma.$transaction([
      prisma.scan.update({
        where: { id: scan.id },
        data: {
          status: ScanStatus.FAILED,
          completedAt: new Date(),
          error: message,
          progress: 100
        }
      }),
      prisma.scanJob.update({
        where: { id: job.id },
        data: { status: JobStatus.FAILED, lastError: message, lockedAt: null }
      })
    ]);
    await createAlertAndSimulate({
      organisationId: scan.organisationId,
      type: AlertType.FAILED_SCAN,
      severity: AlertSeverity.MEDIUM,
      title: "Scan failed",
      body: message,
      relatedScanId: scan.id
    }).catch(() => undefined);
    throw error;
  }
}
