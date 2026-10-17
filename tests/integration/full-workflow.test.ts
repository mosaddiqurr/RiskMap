import { createHash, randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  JobStatus,
  Plan,
  Role,
  ScanPermission,
  ScanStatus,
  VerificationStatus
} from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { createAssetFingerprint } from "@/lib/scanning/identity";
import { recoverStaleScanJobs } from "@/lib/scanning/job-runtime";
import { claimNextScanJob, processScanJob } from "@/lib/scanning/processor";
import { reconcileScanResult } from "@/lib/scanning/reconciliation";
import { hashPassword, verifyPassword } from "@/lib/services/auth";
import { compareCompletedScans } from "@/lib/services/historical-comparison";
import { acceptInvitation } from "@/lib/services/invitations";
import { buildReportData, reportToCsv } from "@/lib/services/reporting";
import { cancelQueuedScan, retryScan } from "@/lib/services/scans";

const run = process.env.RUN_INTEGRATION_TESTS === "1";
const suite = run ? describe : describe.skip;
const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
let organisationId = "";
let otherOrganisationId = "";
let ownerId = "";
let outsiderId = "";
let rootDomainId = "";
const scanIds: string[] = [];

async function runMockSnapshot() {
  const scan = await prisma.scan.create({
    data: {
      organisationId,
      rootDomainId,
      status: ScanStatus.RUNNING,
      trigger: "integration",
      startedAt: new Date(),
      job: {
        create: {
          status: JobStatus.RUNNING,
          lockedAt: new Date(),
          attempts: 1
        }
      }
    },
    include: { job: true }
  });
  if (!scan.job) throw new Error("Integration scan job was not created");
  await processScanJob(scan.job.id);
  const completed = await prisma.scan.findUniqueOrThrow({ where: { id: scan.id } });
  expect(completed.status).toBe("COMPLETED");
  scanIds.push(completed.id);
  return completed;
}

suite("database-backed RiskMap Phase 2 workflow", () => {
  beforeAll(async () => {
    const passwordHash = await hashPassword("Workflow123!");
    const [owner, outsider] = await Promise.all([
      prisma.user.create({
        data: {
          email: `workflow-${suffix}@riskmap.local`,
          name: "Workflow Owner",
          passwordHash
        }
      }),
      prisma.user.create({
        data: {
          email: `outsider-${suffix}@riskmap.local`,
          name: "Isolation Owner",
          passwordHash
        }
      })
    ]);
    ownerId = owner.id;
    outsiderId = outsider.id;

    const [organisation, otherOrganisation] = await Promise.all([
      prisma.organisation.create({
        data: {
          name: "Workflow Test Organisation",
          slug: `workflow-${suffix}`,
          memberships: { create: { userId: ownerId, role: Role.OWNER } },
          subscription: { create: { plan: Plan.BUSINESS } }
        }
      }),
      prisma.organisation.create({
        data: {
          name: "Isolation Test Organisation",
          slug: `isolation-${suffix}`,
          memberships: { create: { userId: outsiderId, role: Role.OWNER } },
          subscription: { create: { plan: Plan.PRO } }
        }
      })
    ]);
    organisationId = organisation.id;
    otherOrganisationId = otherOrganisation.id;

    const rootDomain = await prisma.rootDomain.create({
      data: {
        organisationId,
        domain: `workflow-${suffix}.test`,
        verificationStatus: VerificationStatus.VERIFIED,
        verifiedAt: new Date(),
        scanPermission: ScanPermission.SAFE_ACTIVE,
        activeChecksAuthorized: true
      }
    });
    rootDomainId = rootDomain.id;
  });

  afterAll(async () => {
    if (organisationId) {
      await prisma.organisation
        .delete({ where: { id: organisationId } })
        .catch(() => undefined);
    }
    if (otherOrganisationId) {
      await prisma.organisation
        .delete({ where: { id: otherOrganisationId } })
        .catch(() => undefined);
    }
    if (ownerId)
      await prisma.user.delete({ where: { id: ownerId } }).catch(() => undefined);
    if (outsiderId) {
      await prisma.user.delete({ where: { id: outsiderId } }).catch(() => undefined);
    }
    await prisma.$disconnect();
  });

  it("hashes credentials and keeps verification state scoped", async () => {
    const owner = await prisma.user.findUniqueOrThrow({ where: { id: ownerId } });
    expect(owner.passwordHash).not.toContain("Workflow123!");
    expect(await verifyPassword("Workflow123!", owner.passwordHash)).toBe(true);

    const rootDomain = await prisma.rootDomain.findFirstOrThrow({
      where: { id: rootDomainId, organisationId }
    });
    expect(rootDomain.verificationStatus).toBe("VERIFIED");
    expect(
      await prisma.rootDomain.findFirst({
        where: { id: rootDomainId, organisationId: otherOrganisationId }
      })
    ).toBeNull();
  });

  it("processes four scans without duplicating stable identities", async () => {
    const first = await runMockSnapshot();
    const firstCounts = await Promise.all([
      prisma.asset.count({ where: { organisationId } }),
      prisma.service.count({ where: { organisationId } }),
      prisma.finding.count({ where: { organisationId } })
    ]);
    const firstPaths = await prisma.attackPath.findMany({
      where: { organisationId, active: true },
      select: { id: true, fingerprint: true }
    });
    expect(firstPaths.length).toBeGreaterThan(0);

    const firstAsset = await prisma.asset.findFirstOrThrow({
      where: { organisationId, type: "ROOT_DOMAIN" }
    });
    const firstService = await prisma.service.findFirstOrThrow({
      where: { organisationId, active: true }
    });
    const firstFinding = await prisma.finding.findFirstOrThrow({
      where: { organisationId, ruleId: "http.csp.missing" }
    });

    const second = await runMockSnapshot();
    const secondCounts = await Promise.all([
      prisma.asset.count({ where: { organisationId } }),
      prisma.service.count({ where: { organisationId } }),
      prisma.finding.count({ where: { organisationId } })
    ]);
    expect(secondCounts[0]).toBeGreaterThanOrEqual(firstCounts[0]);
    expect(secondCounts[1]).toBeGreaterThanOrEqual(firstCounts[1]);
    expect(secondCounts[2]).toBeGreaterThanOrEqual(firstCounts[2]);

    const [secondAsset, secondService, secondFinding] = await Promise.all([
      prisma.asset.findUniqueOrThrow({ where: { id: firstAsset.id } }),
      prisma.service.findUniqueOrThrow({ where: { id: firstService.id } }),
      prisma.finding.findUniqueOrThrow({ where: { id: firstFinding.id } })
    ]);
    expect(secondAsset.fingerprint).toBe(firstAsset.fingerprint);
    expect(secondService.fingerprint).toBe(firstService.fingerprint);
    expect(secondFinding.fingerprint).toBe(firstFinding.fingerprint);
    expect(secondAsset.firstSeen.getTime()).toBe(firstAsset.firstSeen.getTime());
    expect(secondService.firstSeen.getTime()).toBe(firstService.firstSeen.getTime());
    expect(secondFinding.firstSeen.getTime()).toBe(firstFinding.firstSeen.getTime());
    expect(secondAsset.lastSeen.getTime()).toBeGreaterThanOrEqual(
      firstAsset.lastSeen.getTime()
    );
    expect(secondService.lastSeen.getTime()).toBeGreaterThanOrEqual(
      firstService.lastSeen.getTime()
    );
    expect(secondFinding.lastSeen.getTime()).toBeGreaterThanOrEqual(
      firstFinding.lastSeen.getTime()
    );
    expect(
      await prisma.findingObservation.findUnique({
        where: {
          findingId_scanId: { findingId: firstFinding.id, scanId: second.id }
        }
      })
    ).toMatchObject({ observed: true });

    const [assetFingerprints, serviceFingerprints, findingFingerprints] = await Promise.all(
      [
        prisma.asset.findMany({
          where: { organisationId },
          select: { fingerprint: true }
        }),
        prisma.service.findMany({
          where: { organisationId },
          select: { fingerprint: true }
        }),
        prisma.finding.findMany({
          where: { organisationId },
          select: { fingerprint: true }
        })
      ]
    );
    for (const records of [assetFingerprints, serviceFingerprints, findingFingerprints]) {
      const fingerprints = records.map((record) => record.fingerprint);
      expect(new Set(fingerprints).size).toBe(fingerprints.length);
    }

    const persistentPath = await prisma.attackPath.findFirst({
      where: {
        organisationId,
        fingerprint: { in: firstPaths.map((path) => path.fingerprint) },
        observations: {
          some: { scanId: first.id, active: true }
        }
      },
      include: { observations: true }
    });
    expect(persistentPath?.observations.some((item) => item.scanId === second.id)).toBe(
      true
    );

    const third = await runMockSnapshot();
    const resolved = await prisma.finding.findFirst({
      where: {
        organisationId,
        ruleId: "http.csp.missing",
        status: "RESOLVED",
        resolutionScanId: third.id
      }
    });
    expect(resolved).not.toBeNull();
    expect(
      await prisma.servicePresence.findFirst({
        where: {
          scanId: third.id,
          transition: "CLOSED"
        }
      })
    ).not.toBeNull();
    expect(
      await prisma.attackPathObservation.count({
        where: { scanId: third.id, active: false }
      })
    ).toBeGreaterThan(0);

    const fourth = await runMockSnapshot();
    const reopened = await prisma.finding.findFirstOrThrow({
      where: { organisationId, ruleId: "http.csp.missing" }
    });
    expect(reopened.status).toBe("REOPENED");
    expect(reopened.recurrenceCount).toBeGreaterThan(0);
    expect(reopened.reopenedAt).not.toBeNull();

    const reappearedAsset = await prisma.asset.findFirst({
      where: {
        organisationId,
        name: { startsWith: "legacy." },
        active: true,
        reappearedAt: { not: null }
      },
      include: { presences: true }
    });
    expect(reappearedAsset).not.toBeNull();
    expect(
      reappearedAsset?.presences.some(
        (presence) => presence.scanId === fourth.id && presence.transition === "REAPPEARED"
      )
    ).toBe(true);

    const inactiveCertificate = await prisma.asset.findFirst({
      where: {
        organisationId,
        type: "CERTIFICATE",
        serviceIdentifier: "serial-a1",
        active: false,
        consecutiveAbsenceCount: { gte: 2 }
      }
    });
    expect(inactiveCertificate).not.toBeNull();

    const reopenedService = await prisma.servicePresence.findFirst({
      where: { scanId: fourth.id, transition: "REOPENED" }
    });
    expect(reopenedService).not.toBeNull();

    const comparison = await compareCompletedScans(organisationId, fourth.id, third.id);
    expect(comparison?.changes.some((change) => change.type === "FINDING_REOPENED")).toBe(
      true
    );
    expect(comparison?.changes.some((change) => change.type === "ASSET_REAPPEARED")).toBe(
      true
    );
    expect(comparison?.changes.some((change) => change.type === "SERVICE_REOPENED")).toBe(
      true
    );

    const countsBeforeIdempotentRerun = await Promise.all([
      prisma.asset.count({ where: { organisationId } }),
      prisma.service.count({ where: { organisationId } }),
      prisma.finding.count({ where: { organisationId } }),
      prisma.attackPath.count({ where: { organisationId } })
    ]);
    const activePathBeforeRerun = await prisma.attackPath.findFirstOrThrow({
      where: { organisationId, active: true, steps: { some: { findingId: reopened.id } } }
    });
    const fifth = await runMockSnapshot();
    expect(
      await Promise.all([
        prisma.asset.count({ where: { organisationId } }),
        prisma.service.count({ where: { organisationId } }),
        prisma.finding.count({ where: { organisationId } }),
        prisma.attackPath.count({ where: { organisationId } })
      ])
    ).toEqual(countsBeforeIdempotentRerun);
    const recurringPath = await prisma.attackPath.findUniqueOrThrow({
      where: { id: activePathBeforeRerun.id },
      include: { observations: true }
    });
    expect(recurringPath.fingerprint).toBe(activePathBeforeRerun.fingerprint);
    expect(
      recurringPath.observations.some((item) => item.scanId === fifth.id && item.active)
    ).toBe(true);
  });

  it("preserves lifecycle state when responsible scan modules fail", async () => {
    const [assetBefore, serviceBefore, findingBefore] = await Promise.all([
      prisma.asset.findFirstOrThrow({ where: { organisationId, active: true } }),
      prisma.service.findFirstOrThrow({ where: { organisationId, active: true } }),
      prisma.finding.findFirstOrThrow({
        where: {
          organisationId,
          currentlyObserved: true,
          status: { not: "FALSE_POSITIVE" }
        }
      })
    ]);
    const partialScan = await prisma.scan.create({
      data: {
        organisationId,
        rootDomainId,
        status: ScanStatus.RUNNING,
        trigger: "integration-partial",
        startedAt: new Date()
      }
    });

    const result = await reconcileScanResult({
      organisationId,
      rootDomainId,
      scanId: partialScan.id,
      result: {
        provider: "integration-failed-modules",
        assets: [],
        services: [],
        technologies: [],
        findings: [],
        relationships: [],
        observations: [],
        modules: [
          "PASSIVE_DISCOVERY",
          "DNS",
          "HTTP",
          "TLS",
          "EMAIL_SECURITY",
          "PORT_CHECKS",
          "TECHNOLOGY",
          "GRAPH"
        ].map((module) => ({
          module: module as
            | "PASSIVE_DISCOVERY"
            | "DNS"
            | "HTTP"
            | "TLS"
            | "EMAIL_SECURITY"
            | "PORT_CHECKS"
            | "TECHNOLOGY"
            | "GRAPH",
          status: "FAILED" as const,
          error: "Synthetic adapter failure"
        })),
        log: ["All modules failed before producing authoritative absence evidence."]
      }
    });

    expect(result.inactiveAssetIds).toHaveLength(0);
    expect(result.closedServiceIds).toHaveLength(0);
    expect(result.resolvedFindingIds).toHaveLength(0);

    const [assetAfter, serviceAfter, findingAfter] = await Promise.all([
      prisma.asset.findUniqueOrThrow({ where: { id: assetBefore.id } }),
      prisma.service.findUniqueOrThrow({ where: { id: serviceBefore.id } }),
      prisma.finding.findUniqueOrThrow({ where: { id: findingBefore.id } })
    ]);
    expect(assetAfter.active).toBe(assetBefore.active);
    expect(assetAfter.consecutiveAbsenceCount).toBe(assetBefore.consecutiveAbsenceCount);
    expect(serviceAfter.active).toBe(serviceBefore.active);
    expect(serviceAfter.consecutiveAbsenceCount).toBe(
      serviceBefore.consecutiveAbsenceCount
    );
    expect(findingAfter.status).toBe(findingBefore.status);
    expect(findingAfter.currentlyObserved).toBe(findingBefore.currentlyObserved);
    expect(findingAfter.consecutiveMisses).toBe(findingBefore.consecutiveMisses);
    expect(
      await prisma.findingObservation.findUnique({
        where: {
          findingId_scanId: { findingId: findingBefore.id, scanId: partialScan.id }
        }
      })
    ).toMatchObject({ observed: false, statusAfter: findingBefore.status });
  });

  it("claims a queued job exactly once across competing workers", async () => {
    const scan = await prisma.scan.create({
      data: {
        organisationId,
        rootDomainId,
        status: ScanStatus.QUEUED,
        trigger: "integration-atomic-claim",
        job: {
          create: { status: JobStatus.QUEUED, availableAt: new Date(Date.now() - 1_000) }
        }
      },
      include: { job: true }
    });
    const claims = await Promise.all([claimNextScanJob(), claimNextScanJob()]);
    const claimed = claims.filter((item): item is NonNullable<typeof item> =>
      Boolean(item)
    );
    expect(claimed).toHaveLength(1);
    expect(claimed[0]?.scanId).toBe(scan.id);

    await processScanJob(claimed[0]!.id);
    const [completedScan, completedJob] = await Promise.all([
      prisma.scan.findUniqueOrThrow({ where: { id: scan.id } }),
      prisma.scanJob.findUniqueOrThrow({ where: { scanId: scan.id } })
    ]);
    expect(completedScan.status).toBe(ScanStatus.COMPLETED);
    expect(completedJob).toMatchObject({
      status: JobStatus.COMPLETED,
      attempts: 1,
      lockedAt: null
    });
  });

  it("cancels safely and recovers queued, stale and exhausted jobs", async () => {
    const cancelled = await prisma.scan.create({
      data: {
        organisationId,
        rootDomainId,
        status: ScanStatus.QUEUED,
        trigger: "integration-cancel",
        job: {
          create: {
            status: JobStatus.QUEUED,
            availableAt: new Date(Date.now() + 60_000)
          }
        }
      }
    });
    await expect(cancelQueuedScan(otherOrganisationId, cancelled.id)).rejects.toThrow(
      "NOT_FOUND"
    );
    await cancelQueuedScan(organisationId, cancelled.id);
    expect(
      await prisma.scan.findUniqueOrThrow({ where: { id: cancelled.id } })
    ).toMatchObject({ status: ScanStatus.CANCELLED, progress: 100 });

    await retryScan(organisationId, cancelled.id);
    const retryClaim = await claimNextScanJob();
    expect(retryClaim?.scanId).toBe(cancelled.id);
    await processScanJob(retryClaim!.id);
    expect(
      await prisma.scan.findUniqueOrThrow({ where: { id: cancelled.id } })
    ).toMatchObject({ status: ScanStatus.COMPLETED, progress: 100 });

    const staleBefore = new Date(Date.now() - env.SCAN_JOB_TIMEOUT_MS - 1_000);
    const stale = await prisma.scan.create({
      data: {
        organisationId,
        rootDomainId,
        status: ScanStatus.RUNNING,
        trigger: "integration-stale-restart",
        startedAt: staleBefore,
        job: {
          create: {
            status: JobStatus.RUNNING,
            lockedAt: staleBefore,
            attempts: 1
          }
        }
      }
    });
    expect(await recoverStaleScanJobs()).toMatchObject({ retried: 1, failed: 0 });
    expect(await prisma.scan.findUniqueOrThrow({ where: { id: stale.id } })).toMatchObject({
      status: ScanStatus.QUEUED,
      progress: 0,
      startedAt: null
    });

    const exhausted = await prisma.scan.create({
      data: {
        organisationId,
        rootDomainId,
        status: ScanStatus.RUNNING,
        trigger: "integration-exhausted-restart",
        startedAt: staleBefore,
        job: {
          create: {
            status: JobStatus.RUNNING,
            lockedAt: staleBefore,
            attempts: env.SCAN_JOB_MAX_ATTEMPTS
          }
        }
      }
    });
    expect(await recoverStaleScanJobs()).toMatchObject({ retried: 0, failed: 1 });
    expect(
      await prisma.scan.findUniqueOrThrow({ where: { id: exhausted.id } })
    ).toMatchObject({ status: ScanStatus.FAILED, progress: 100 });
  });

  it("generates alerts and safe reports from the current organisation only", async () => {
    expect(await prisma.alert.count({ where: { organisationId } })).toBeGreaterThan(0);

    const otherAssetName = `private-${suffix}.test`;
    await prisma.asset.create({
      data: {
        organisationId: otherOrganisationId,
        fingerprint: createAssetFingerprint({
          organisationId: otherOrganisationId,
          type: "ROOT_DOMAIN",
          hostname: otherAssetName
        }),
        name: otherAssetName,
        type: "ROOT_DOMAIN",
        hostname: otherAssetName,
        normalizedHostname: otherAssetName,
        source: "integration-test"
      }
    });

    const visibleAssets = await prisma.asset.findMany({ where: { organisationId } });
    expect(visibleAssets.some((asset) => asset.name === otherAssetName)).toBe(false);

    const report = await buildReportData(organisationId, "TECHNICAL");
    const csv = reportToCsv(report);
    expect(report.organisation).toBe("Workflow Test Organisation");
    expect(csv).toContain("Title,Severity,Status,Observed,Asset,Confidence,Remediation");
    expect(csv).not.toContain(otherAssetName);
  });

  it("rejects invitation acceptance by the wrong account", async () => {
    const rawToken = randomBytes(24).toString("hex");
    const invitation = await prisma.invitation.create({
      data: {
        organisationId,
        email: `invited-${suffix}@riskmap.local`,
        role: Role.ANALYST,
        tokenHash: createHash("sha256").update(rawToken).digest("hex"),
        invitedById: ownerId,
        expiresAt: new Date(Date.now() + 86_400_000)
      }
    });

    await expect(
      acceptInvitation({
        userId: outsiderId,
        userEmail: `outsider-${suffix}@riskmap.local`,
        token: rawToken
      })
    ).rejects.toThrow("FORBIDDEN");

    expect(
      (await prisma.invitation.findUniqueOrThrow({ where: { id: invitation.id } })).status
    ).toBe("PENDING");
  });
});
