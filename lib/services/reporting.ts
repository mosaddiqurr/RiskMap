import { ReportType } from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { toCsv } from "@/lib/services/csv";
import { parseJson } from "@/lib/utils";

const severityRank = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFORMATIONAL: 1
} as const;

export async function buildReportData(organisationId: string, type: ReportType) {
  const [organisation, latestScan, findings, assets, paths] = await Promise.all([
    prisma.organisation.findUnique({ where: { id: organisationId } }),
    prisma.scan.findFirst({
      where: { organisationId, status: "COMPLETED" },
      orderBy: { completedAt: "desc" }
    }),
    prisma.finding.findMany({
      where: { organisationId, deletedAt: null },
      include: { asset: true },
      orderBy: { lastSeen: "desc" }
    }),
    prisma.asset.findMany({
      where: { organisationId, deletedAt: null },
      orderBy: { lastSeen: "desc" }
    }),
    prisma.attackPath.findMany({
      where: { organisationId },
      include: {
        steps: { orderBy: { stepOrder: "asc" } }
      },
      orderBy: [{ active: "desc" }, { riskScore: "desc" }]
    })
  ]);

  if (!organisation) throw new Error("NOT_FOUND");

  findings.sort(
    (left, right) =>
      Number(right.currentlyObserved) - Number(left.currentlyObserved) ||
      severityRank[right.severity] - severityRank[left.severity] ||
      right.lastSeen.getTime() - left.lastSeen.getTime()
  );

  const now = new Date();
  return {
    organisation: organisation.name,
    type,
    generatedAt: now.toISOString(),
    reportingPeriod: {
      start: new Date(now.getTime() - 30 * 86_400_000).toISOString(),
      end: now.toISOString()
    },
    riskScore: latestScan?.riskScore ?? 0,
    previousRiskScore: latestScan?.previousRiskScore ?? null,
    summary:
      "RiskMap summarises observed external exposure and clearly labelled inferred relationships. Potential attack paths require validation.",
    topFindings: findings.slice(0, 10).map((finding) => ({
      title: finding.title,
      severity: finding.severity,
      status: finding.status,
      currentlyObserved: finding.currentlyObserved,
      recurrenceCount: finding.recurrenceCount,
      asset: finding.asset.name,
      confidence: finding.confidence,
      remediation: finding.remediation
    })),
    assets: assets.map((asset) => ({
      name: asset.name,
      type: asset.type,
      status: asset.status,
      active: asset.active,
      criticality: asset.criticality,
      source: asset.source,
      firstSeen: asset.firstSeen.toISOString(),
      lastSeen: asset.lastSeen.toISOString()
    })),
    potentialAttackPaths: paths.map((path) => ({
      name: path.name,
      pathType: path.pathType,
      riskScore: path.riskScore,
      confidence: path.confidence,
      active: path.active,
      weakestLink: path.weakestLink,
      recommendedFix: path.recommendedFix,
      contributors: parseJson(path.scoreContributorsJson, {}),
      steps: path.steps.map((step) => ({
        label: step.label,
        evidence: step.evidence,
        confidence: step.confidence,
        state: step.observedState
      }))
    })),
    methodology:
      "Verified-domain scope, module-aware evidence reconciliation, stable identities, deterministic risk scoring and bounded graph search over observed and inferred relationships.",
    limitations:
      "No exploitation, authentication attempts, brute force, destructive testing or scanning of private and reserved addresses. Results are point-in-time observations and inferred paths require validation.",
    authorisedUse:
      "Only assess domains and assets you own or are explicitly authorised to test.",
    fictionalDemoData: env.SCAN_MODE === "mock"
  };
}

export function safeExportFilename(value: string) {
  const normalised = value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalised || "riskmap-report";
}

export type ReportData = Awaited<ReturnType<typeof buildReportData>>;

export function reportToCsv(data: ReportData) {
  return toCsv(
    data.topFindings.map((finding) => ({
      Title: finding.title,
      Severity: finding.severity,
      Status: finding.status,
      Observed: finding.currentlyObserved ? "Yes" : "No",
      Asset: finding.asset,
      Confidence: finding.confidence,
      Remediation: finding.remediation
    }))
  );
}

function escapeHtml(value: unknown) {
  return String(value).replace(/[&<>'"]/g, (character) => {
    const entities: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "'": "&#39;",
      '"': "&quot;"
    };
    return entities[character] ?? character;
  });
}

function renderFindingRows(data: ReportData) {
  return data.topFindings
    .map(
      (finding) => `
        <tr>
          <td>${escapeHtml(finding.title)}</td>
          <td>${escapeHtml(finding.severity)}</td>
          <td>${escapeHtml(finding.asset)}</td>
          <td>${escapeHtml(finding.status)}</td>
        </tr>`
    )
    .join("");
}

function renderPathSections(data: ReportData) {
  if (!data.potentialAttackPaths.length) {
    return "<p>No potential paths were mapped for the reporting snapshot.</p>";
  }
  return data.potentialAttackPaths
    .map(
      (path) => `
        <section>
          <h3>${escapeHtml(path.name)}</h3>
          <p>${escapeHtml(path.steps.map((step) => step.label).join(" → "))}</p>
          <p><strong>Recommended fix:</strong> ${escapeHtml(path.recommendedFix)}</p>
        </section>`
    )
    .join("");
}

export function reportToHtml(data: ReportData) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width">
  <title>${escapeHtml(data.organisation)} RiskMap report</title>
  <style>
    body{font-family:Arial,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#111827}
    h1,h2{letter-spacing:-.02em}table{width:100%;border-collapse:collapse;font-size:13px}
    th,td{border-bottom:1px solid #e5e7eb;padding:10px;text-align:left;vertical-align:top}
    .note{background:#f8fafc;border:1px solid #e5e7eb;padding:14px;border-radius:10px;color:#475569}
    .score{font-size:40px;font-weight:700}
  </style>
</head>
<body>
  <p>RiskMap · ${escapeHtml(data.type.replaceAll("_", " "))}</p>
  <h1>${escapeHtml(data.organisation)}</h1>
  <p class="score">${data.riskScore}/100</p>
  <p>${escapeHtml(data.summary)}</p>
  <h2>Top findings</h2>
  <table>
    <thead><tr><th>Finding</th><th>Severity</th><th>Asset</th><th>Status</th></tr></thead>
    <tbody>${renderFindingRows(data)}</tbody>
  </table>
  <h2>Potential attack paths</h2>
  ${renderPathSections(data)}
  <h2>Methodology and limitations</h2>
  <p class="note">${escapeHtml(data.methodology)} ${escapeHtml(data.limitations)} ${escapeHtml(data.authorisedUse)}</p>
</body>
</html>`;
}

export function parseStoredReport(value: string): ReportData {
  const data = parseJson<ReportData | null>(value, null);
  if (
    !data ||
    typeof data.organisation !== "string" ||
    typeof data.riskScore !== "number" ||
    !Array.isArray(data.topFindings) ||
    !Array.isArray(data.assets) ||
    !Array.isArray(data.potentialAttackPaths)
  ) {
    throw new Error("INVALID_REPORT_SNAPSHOT");
  }
  return data;
}
