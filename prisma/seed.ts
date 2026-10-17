import {
  InvitationStatus,
  JobStatus,
  Plan,
  ReportStatus,
  ReportType,
  Role,
  ScanPermission,
  ScanStatus,
  SubscriptionStatus,
  VerificationMethod,
  VerificationStatus
} from "@prisma/client";
import bcrypt from "bcryptjs";
import { createHash, randomBytes } from "node:crypto";
import { prisma } from "../lib/db";
import { processScanJob } from "../lib/scanning/processor";
import {
  createAssetFingerprint,
  createAttackPathFingerprint,
  createFindingFingerprint,
  createServiceFingerprint
} from "../lib/scanning/identity";
import { buildReportData } from "../lib/services/reporting";

const DAY = 86_400_000;
const daysAgo = (days: number) => new Date(Date.now() - days * DAY);
const daysFromNow = (days: number) => new Date(Date.now() + days * DAY);

async function clearDemoData() {
  const organisationSlugs = ["northstar-labs", "harbor-systems"];
  const userEmails = [
    "demo@riskmap.local",
    "admin@riskmap.local",
    "analyst@riskmap.local",
    "viewer@riskmap.local",
    "outsider@riskmap.local"
  ];

  await prisma.organisation.deleteMany({
    where: { slug: { in: organisationSlugs } }
  });
  await prisma.user.deleteMany({
    where: { email: { in: userEmails } }
  });
}

async function createCompletedDemoScan(input: {
  organisationId: string;
  rootDomainId: string;
  days: number;
  trigger: "manual" | "scheduled";
}) {
  const createdAt = daysAgo(input.days);
  const scan = await prisma.scan.create({
    data: {
      organisationId: input.organisationId,
      rootDomainId: input.rootDomainId,
      status: ScanStatus.RUNNING,
      trigger: input.trigger,
      progress: 0,
      createdAt,
      startedAt: new Date(createdAt.getTime() + 60_000),
      job: {
        create: {
          status: JobStatus.RUNNING,
          lockedAt: new Date(createdAt.getTime() + 60_000),
          attempts: 1,
          createdAt
        }
      }
    },
    include: { job: true }
  });
  if (!scan.job) throw new Error("Seed scan job was not created");
  await processScanJob(scan.job.id);
  const completedAt = new Date(createdAt.getTime() + 6 * 60_000);
  await prisma.scan.update({
    where: { id: scan.id },
    data: { createdAt, startedAt: new Date(createdAt.getTime() + 60_000), completedAt }
  });
  return prisma.scan.findUniqueOrThrow({ where: { id: scan.id } });
}

async function alignHistoricalTimestamps() {
  const scans = await prisma.scan.findMany({ orderBy: { completedAt: "asc" } });
  const scanDates = new Map(
    scans.map((scan) => [scan.id, scan.completedAt ?? scan.createdAt])
  );

  const assets = await prisma.asset.findMany({ include: { presences: true } });
  for (const asset of assets) {
    const observedDates = asset.presences
      .filter((presence) => presence.observed)
      .map((presence) => scanDates.get(presence.scanId))
      .filter((date): date is Date => Boolean(date))
      .sort((left, right) => left.getTime() - right.getTime());
    if (!observedDates.length) continue;
    await prisma.asset.update({
      where: { id: asset.id },
      data: { firstSeen: observedDates[0], lastSeen: observedDates.at(-1) }
    });
  }

  const services = await prisma.service.findMany({ include: { presences: true } });
  for (const service of services) {
    const observedDates = service.presences
      .filter((presence) => presence.observed)
      .map((presence) => scanDates.get(presence.scanId))
      .filter((date): date is Date => Boolean(date))
      .sort((left, right) => left.getTime() - right.getTime());
    if (!observedDates.length) continue;
    await prisma.service.update({
      where: { id: service.id },
      data: { firstSeen: observedDates[0], lastSeen: observedDates.at(-1) }
    });
  }

  const findings = await prisma.finding.findMany({ include: { observations: true } });
  for (const finding of findings) {
    const observedDates = finding.observations
      .filter((observation) => observation.observed)
      .map((observation) => scanDates.get(observation.scanId))
      .filter((date): date is Date => Boolean(date))
      .sort((left, right) => left.getTime() - right.getTime());
    const resolvedObservation = finding.observations
      .filter(
        (observation) => !observation.observed && observation.statusAfter === "RESOLVED"
      )
      .map((observation) => ({ observation, date: scanDates.get(observation.scanId) }))
      .find((entry) => entry.date);
    if (!observedDates.length) continue;
    await prisma.finding.update({
      where: { id: finding.id },
      data: {
        firstSeen: observedDates[0],
        lastSeen: observedDates.at(-1),
        resolvedAt:
          finding.status === "RESOLVED"
            ? (resolvedObservation?.date ?? finding.resolvedAt)
            : null,
        reopenedAt: finding.recurrenceCount > 0 ? observedDates.at(-1) : null
      }
    });
  }

  const paths = await prisma.attackPath.findMany({ include: { observations: true } });
  for (const path of paths) {
    const activeDates = path.observations
      .filter((observation) => observation.active)
      .map((observation) => scanDates.get(observation.scanId))
      .filter((date): date is Date => Boolean(date))
      .sort((left, right) => left.getTime() - right.getTime());
    const brokenDate = path.observations
      .filter((observation) => !observation.active)
      .map((observation) => scanDates.get(observation.scanId))
      .find((date): date is Date => Boolean(date));
    if (!activeDates.length) continue;
    await prisma.attackPath.update({
      where: { id: path.id },
      data: {
        firstSeen: activeDates[0],
        lastSeen: activeDates.at(-1),
        brokenAt: path.active ? null : (brokenDate ?? path.brokenAt)
      }
    });
  }
}

async function main() {
  await clearDemoData();
  const passwordHash = await bcrypt.hash("Demo123!", 12);
  const [demo, admin, analyst, viewer, outsider] = await Promise.all([
    prisma.user.create({
      data: { email: "demo@riskmap.local", name: "Avery Morgan", passwordHash }
    }),
    prisma.user.create({
      data: { email: "admin@riskmap.local", name: "Jordan Lee", passwordHash }
    }),
    prisma.user.create({
      data: { email: "analyst@riskmap.local", name: "Sam Rivera", passwordHash }
    }),
    prisma.user.create({
      data: { email: "viewer@riskmap.local", name: "Taylor Chen", passwordHash }
    }),
    prisma.user.create({
      data: { email: "outsider@riskmap.local", name: "Morgan Park", passwordHash }
    })
  ]);

  const organisation = await prisma.organisation.create({
    data: {
      name: "Northstar Labs",
      slug: "northstar-labs",
      memberships: {
        create: [
          { userId: demo.id, role: Role.OWNER },
          { userId: admin.id, role: Role.ADMIN },
          { userId: analyst.id, role: Role.ANALYST },
          { userId: viewer.id, role: Role.VIEWER }
        ]
      },
      subscription: {
        create: {
          plan: Plan.BUSINESS,
          status: SubscriptionStatus.ACTIVE,
          currentPeriodEnd: daysFromNow(24)
        }
      }
    }
  });

  const harbor = await prisma.organisation.create({
    data: {
      name: "Harbor Systems",
      slug: "harbor-systems",
      memberships: { create: { userId: outsider.id, role: Role.OWNER } },
      subscription: { create: { plan: Plan.PRO, status: SubscriptionStatus.ACTIVE } }
    }
  });

  const domain = await prisma.rootDomain.create({
    data: {
      organisationId: organisation.id,
      domain: "northstar.test",
      verificationStatus: VerificationStatus.VERIFIED,
      verifiedAt: daysAgo(60),
      scanPermission: ScanPermission.SAFE_ACTIVE,
      activeChecksAuthorized: true,
      preferredScanWindow: "02:00-04:00 UTC",
      challenges: {
        create: {
          method: VerificationMethod.DNS_TXT,
          token: "riskmap-verification=northstar-demo-token",
          status: VerificationStatus.VERIFIED,
          verifiedAt: daysAgo(60),
          expiresAt: daysFromNow(300)
        }
      }
    }
  });

  await prisma.notificationSetting.create({
    data: {
      organisationId: organisation.id,
      userId: demo.id,
      minSeverity: "MEDIUM",
      inAppEnabled: true,
      emailEnabled: true,
      slackEnabled: true,
      teamsEnabled: false,
      webhookEnabled: true,
      webhookUrl: "https://alerts.example.test/riskmap",
      largeIncreaseFrom: 10
    }
  });

  const scans = [];
  for (const input of [
    { days: 28, trigger: "manual" as const },
    { days: 14, trigger: "manual" as const },
    { days: 7, trigger: "scheduled" as const },
    { days: 1, trigger: "scheduled" as const }
  ]) {
    scans.push(
      await createCompletedDemoScan({
        organisationId: organisation.id,
        rootDomainId: domain.id,
        ...input
      })
    );
  }

  await alignHistoricalTimestamps();

  const harborDomain = await prisma.rootDomain.create({
    data: {
      organisationId: harbor.id,
      domain: "harbor.test",
      verificationStatus: VerificationStatus.VERIFIED,
      verifiedAt: daysAgo(30),
      scanPermission: ScanPermission.PASSIVE,
      activeChecksAuthorized: false
    }
  });
  const harborScan = await prisma.scan.create({
    data: {
      organisationId: harbor.id,
      rootDomainId: harborDomain.id,
      status: ScanStatus.COMPLETED,
      trigger: "manual",
      progress: 100,
      startedAt: daysAgo(2),
      completedAt: daysAgo(2),
      riskScore: 12,
      summaryJson: JSON.stringify({ tenantIsolationFixture: true })
    }
  });
  const harborAssetFingerprint = createAssetFingerprint({
    organisationId: harbor.id,
    type: "ROOT_DOMAIN",
    hostname: harborDomain.domain
  });
  const harborAsset = await prisma.asset.create({
    data: {
      organisationId: harbor.id,
      rootDomainId: harborDomain.id,
      fingerprint: harborAssetFingerprint,
      name: harborDomain.domain,
      type: "ROOT_DOMAIN",
      hostname: harborDomain.domain,
      normalizedHostname: harborDomain.domain,
      criticality: "HIGH",
      source: "Tenant-isolation fixture",
      lastScanId: harborScan.id
    }
  });
  const harborServiceFingerprint = createServiceFingerprint({
    organisationId: harbor.id,
    assetFingerprint: harborAssetFingerprint,
    port: 443,
    protocol: "https",
    transport: "tcp",
    serviceIdentifier: "root-https"
  });
  const harborService = await prisma.service.create({
    data: {
      organisationId: harbor.id,
      assetId: harborAsset.id,
      fingerprint: harborServiceFingerprint,
      port: 443,
      protocol: "https",
      transport: "tcp",
      serviceIdentifier: "root-https",
      observedState: "OPEN",
      confidence: "HIGH",
      evidenceSource: "Tenant-isolation fixture",
      evidence: "Fictional HTTPS service for cross-tenant denial tests.",
      sourceModule: "HTTP",
      lastScanId: harborScan.id
    }
  });
  const harborFindingFingerprint = createFindingFingerprint({
    organisationId: harbor.id,
    assetFingerprint: harborAssetFingerprint,
    serviceFingerprint: harborServiceFingerprint,
    ruleId: "fixture.harbor.header",
    evidenceIdentity: "tenant-isolation",
    port: 443,
    protocol: "https"
  });
  const harborFinding = await prisma.finding.create({
    data: {
      organisationId: harbor.id,
      scanId: harborScan.id,
      assetId: harborAsset.id,
      serviceId: harborService.id,
      fingerprint: harborFindingFingerprint,
      ruleId: "fixture.harbor.header",
      module: "HTTP",
      title: "Harbor tenant-isolation finding",
      severity: "LOW",
      status: "OPEN",
      category: "Tenant fixture",
      description: "Fictional record used only to prove organisation scoping.",
      evidenceSummary: "Tenant-specific fictional evidence.",
      evidenceIdentity: "tenant-isolation",
      confidence: "HIGH",
      source: "Seed fixture",
      remediation: "No action required outside the tenant-isolation test.",
      technicalDetail: "This is not a real security observation.",
      businessImpact: "None; test fixture only.",
      lastScanId: harborScan.id
    }
  });
  const harborPathFingerprint = createAttackPathFingerprint({
    organisationId: harbor.id,
    orderedNodeKeys: ["internet", harborAssetFingerprint, harborFindingFingerprint],
    orderedEdgeKeys: ["tenant-entry", "tenant-finding"]
  });
  const harborPath = await prisma.attackPath.create({
    data: {
      organisationId: harbor.id,
      scanId: harborScan.id,
      fingerprint: harborPathFingerprint,
      pathType: "Potential attack path",
      name: "Harbor tenant-isolation path",
      riskScore: 12,
      confidence: "MEDIUM",
      entryAssetId: harborAsset.id,
      targetAssetId: harborAsset.id,
      evidence: "Fictional tenant-specific path evidence.",
      weakestLink: harborFinding.title,
      recommendedFix: harborFinding.remediation,
      recommendedBreakPoint: harborFinding.title,
      riskReduction: 2,
      lastScanId: harborScan.id
    }
  });
  await prisma.alert.create({
    data: {
      organisationId: harbor.id,
      type: "NEW_HIGH_FINDING",
      severity: "LOW",
      title: "Harbor tenant-isolation alert",
      body: "Fictional tenant-specific alert.",
      relatedAssetId: harborAsset.id,
      relatedFindingId: harborFinding.id,
      relatedScanId: harborScan.id,
      relatedPathId: harborPath.id
    }
  });
  await prisma.report.create({
    data: {
      organisationId: harbor.id,
      type: ReportType.TECHNICAL,
      name: "Harbor tenant-isolation report",
      periodStart: daysAgo(7),
      periodEnd: new Date(),
      status: ReportStatus.READY,
      dataJson: JSON.stringify({ organisation: harbor.name, fixture: true }),
      createdById: outsider.id
    }
  });
  await prisma.auditLog.create({
    data: {
      organisationId: harbor.id,
      userId: outsider.id,
      action: "TENANT_ISOLATION_FIXTURE_CREATED",
      entityType: "Organisation",
      entityId: harbor.id
    }
  });

  const invitationToken = randomBytes(24).toString("hex");
  await prisma.invitation.create({
    data: {
      organisationId: organisation.id,
      email: "consultant@riskmap.local",
      role: Role.ANALYST,
      status: InvitationStatus.PENDING,
      tokenHash: createHash("sha256").update(invitationToken).digest("hex"),
      invitedById: demo.id,
      expiresAt: daysFromNow(7)
    }
  });

  await prisma.scanExclusion.create({
    data: {
      organisationId: organisation.id,
      rootDomainId: domain.id,
      pattern: "dev-*.northstar.test",
      reason: "Fictional development hosts are excluded from authorised active checks."
    }
  });

  for (const type of [ReportType.EXECUTIVE, ReportType.TECHNICAL, ReportType.ATTACK_PATH]) {
    const data = await buildReportData(organisation.id, type);
    await prisma.report.create({
      data: {
        organisationId: organisation.id,
        type,
        name: `${type.replaceAll("_", " ").toLowerCase()} · Northstar Labs`,
        periodStart: daysAgo(30),
        periodEnd: new Date(),
        status: ReportStatus.READY,
        dataJson: JSON.stringify(data),
        createdById: demo.id
      }
    });
  }

  await prisma.auditLog.createMany({
    data: [
      {
        organisationId: organisation.id,
        userId: demo.id,
        action: "DEMO_DATA_SEEDED",
        entityType: "Organisation",
        entityId: organisation.id,
        detailsJson: JSON.stringify({ fictional: true, scanCount: scans.length })
      },
      {
        organisationId: organisation.id,
        userId: demo.id,
        action: "DOMAIN_VERIFIED",
        entityType: "RootDomain",
        entityId: domain.id,
        detailsJson: JSON.stringify({ method: "DNS_TXT", fictional: true })
      }
    ]
  });

  console.log("RiskMap Phase 4 release-candidate fictional demo data seeded.");
  console.log("Demo login: demo@riskmap.local / Demo123!");
  console.log(`Four completed snapshots: ${scans.map((scan) => scan.id).join(", ")}`);
  console.log(`Invitation fixture token (development only): ${invitationToken}`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
