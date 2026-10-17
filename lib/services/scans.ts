import { JobStatus, Plan, ScanStatus, VerificationStatus } from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { getPlanLimit } from "@/lib/services/plans";
import { isWithinPreferredScanWindow } from "@/lib/services/schedules";

export async function queueScan(input: {
  organisationId: string;
  rootDomainId: string;
  userId: string;
  plan: Plan;
  trigger?: string;
}) {
  const rootDomain = await prisma.rootDomain.findFirst({
    where: {
      id: input.rootDomainId,
      organisationId: input.organisationId,
      deletedAt: null
    }
  });
  if (!rootDomain) throw new Error("NOT_FOUND");
  if (rootDomain.verificationStatus !== VerificationStatus.VERIFIED) {
    throw new Error("DOMAIN_NOT_VERIFIED");
  }

  const [organisationActive, globalActive] = await Promise.all([
    prisma.scan.count({
      where: {
        organisationId: input.organisationId,
        status: { in: [ScanStatus.QUEUED, ScanStatus.RUNNING] }
      }
    }),
    prisma.scan.count({
      where: { status: { in: [ScanStatus.QUEUED, ScanStatus.RUNNING] } }
    })
  ]);
  if (organisationActive >= env.SCAN_MAX_CONCURRENCY) throw new Error("RATE_LIMITED");
  if (globalActive >= env.SCAN_GLOBAL_RATE_LIMIT) throw new Error("GLOBAL_RATE_LIMITED");

  const windowStart = new Date(Date.now() - env.SCAN_RATE_LIMIT_WINDOW_MS);
  const [organisationRecent, globalRecent] = await Promise.all([
    prisma.scan.count({
      where: { organisationId: input.organisationId, createdAt: { gte: windowStart } }
    }),
    prisma.scan.count({ where: { createdAt: { gte: windowStart } } })
  ]);
  if (organisationRecent >= env.SCAN_ORGANISATION_RATE_LIMIT) {
    throw new Error("RATE_LIMITED");
  }
  if (globalRecent >= env.SCAN_GLOBAL_RATE_LIMIT) throw new Error("GLOBAL_RATE_LIMITED");

  const startOfWeek = new Date();
  startOfWeek.setUTCDate(startOfWeek.getUTCDate() - startOfWeek.getUTCDay());
  startOfWeek.setUTCHours(0, 0, 0, 0);
  const weekly = await prisma.scan.count({
    where: {
      organisationId: input.organisationId,
      trigger: "manual",
      createdAt: { gte: startOfWeek }
    }
  });
  if (weekly >= getPlanLimit(input.plan).manualScansPerWeek) {
    throw new Error("PLAN_LIMIT");
  }

  return prisma.scan.create({
    data: {
      organisationId: input.organisationId,
      rootDomainId: input.rootDomainId,
      status: ScanStatus.QUEUED,
      trigger: input.trigger ?? "manual",
      job: { create: { status: JobStatus.QUEUED } }
    },
    include: { job: true }
  });
}

export async function cancelQueuedScan(organisationId: string, scanId: string) {
  const scan = await prisma.scan.findFirst({ where: { id: scanId, organisationId } });
  if (!scan) throw new Error("NOT_FOUND");
  if (scan.status !== ScanStatus.QUEUED) {
    throw new Error("Only queued scans can be cancelled");
  }
  return prisma.$transaction([
    prisma.scan.update({
      where: { id: scan.id },
      data: { status: ScanStatus.CANCELLED, completedAt: new Date(), progress: 100 }
    }),
    prisma.scanJob.update({
      where: { scanId: scan.id },
      data: { status: JobStatus.CANCELLED }
    })
  ]);
}

export async function retryScan(organisationId: string, scanId: string) {
  const scan = await prisma.scan.findFirst({
    where: { id: scanId, organisationId },
    include: { job: true }
  });
  if (!scan) throw new Error("NOT_FOUND");
  if (!new Set<ScanStatus>([ScanStatus.FAILED, ScanStatus.CANCELLED]).has(scan.status)) {
    throw new Error("Only failed or cancelled scans can be retried");
  }
  return prisma.$transaction([
    prisma.scan.update({
      where: { id: scan.id },
      data: {
        status: ScanStatus.QUEUED,
        error: null,
        progress: 0,
        startedAt: null,
        completedAt: null
      }
    }),
    prisma.scanJob.upsert({
      where: { scanId: scan.id },
      create: { scanId: scan.id, status: JobStatus.QUEUED },
      update: {
        status: JobStatus.QUEUED,
        availableAt: new Date(),
        lockedAt: null,
        lastError: null
      }
    })
  ]);
}

export async function queueDueScheduledScans(now = new Date()) {
  const cutoff = new Date(now.getTime() - 23 * 60 * 60 * 1000);
  const domains = await prisma.rootDomain.findMany({
    where: {
      deletedAt: null,
      verificationStatus: VerificationStatus.VERIFIED,
      preferredScanWindow: { not: null },
      organisation: {
        deletedAt: null,
        subscription: { is: { plan: { in: [Plan.PRO, Plan.BUSINESS] } } }
      }
    },
    select: { id: true, organisationId: true, preferredScanWindow: true }
  });

  let queued = 0;
  for (const domain of domains) {
    if (!isWithinPreferredScanWindow(domain.preferredScanWindow, now)) continue;
    const existing = await prisma.scan.findFirst({
      where: {
        rootDomainId: domain.id,
        OR: [
          { status: { in: [ScanStatus.QUEUED, ScanStatus.RUNNING] } },
          { trigger: "scheduled", createdAt: { gte: cutoff } }
        ]
      }
    });
    if (existing) continue;

    const scan = await prisma.scan.create({
      data: {
        organisationId: domain.organisationId,
        rootDomainId: domain.id,
        status: ScanStatus.QUEUED,
        trigger: "scheduled",
        job: { create: { status: JobStatus.QUEUED } }
      }
    });
    await prisma.auditLog.create({
      data: {
        organisationId: domain.organisationId,
        action: "SCHEDULED_SCAN_QUEUED",
        entityType: "Scan",
        entityId: scan.id,
        detailsJson: JSON.stringify({
          preferredScanWindow: domain.preferredScanWindow,
          scheduler: "local-worker"
        })
      }
    });
    queued += 1;
  }
  return queued;
}
