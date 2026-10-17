import type {
  Confidence,
  Criticality,
  FindingSeverity,
  FindingStatus
} from "@prisma/client";
import { clamp } from "@/lib/utils";

export type ScorableFinding = {
  id: string;
  severity: FindingSeverity;
  status: FindingStatus;
  confidence: Confidence;
  firstSeen: Date;
  isNew: boolean;
  currentlyObserved?: boolean;
  externallyReachable: boolean;
  asset: { criticality: Criticality };
  relatedFindingCount?: number;
  inAttackPath?: boolean;
};

const severityWeight: Record<FindingSeverity, number> = {
  CRITICAL: 28,
  HIGH: 18,
  MEDIUM: 10,
  LOW: 4,
  INFORMATIONAL: 1
};

const criticalityMultiplier: Record<Criticality, number> = {
  CRITICAL: 1.35,
  HIGH: 1.2,
  MEDIUM: 1,
  LOW: 0.8
};

const confidenceMultiplier: Record<Confidence, number> = {
  HIGH: 1,
  MEDIUM: 0.82,
  LOW: 0.62
};

const statusMultiplier: Record<FindingStatus, number> = {
  OPEN: 1,
  REOPENED: 1.05,
  IN_PROGRESS: 0.8,
  ACCEPTED_RISK: 0.7,
  RESOLVED: 0,
  FALSE_POSITIVE: 0
};

export type FindingContribution = {
  findingId: string;
  raw: number;
  capped: number;
  reasons: string[];
};

export function scoreFinding(
  finding: ScorableFinding,
  now = new Date()
): FindingContribution {
  const reasons: string[] = [];
  if (finding.currentlyObserved === false) {
    return {
      findingId: finding.id,
      raw: 0,
      capped: 0,
      reasons: ["not currently observed"]
    };
  }

  let raw = severityWeight[finding.severity] ?? 0;
  reasons.push(`${finding.severity.toLowerCase()} severity`);
  raw *= criticalityMultiplier[finding.asset.criticality] ?? 1;
  if (["CRITICAL", "HIGH"].includes(finding.asset.criticality)) {
    reasons.push("important asset");
  }
  raw *= confidenceMultiplier[finding.confidence] ?? 1;
  if (finding.externallyReachable) {
    raw *= 1.15;
    reasons.push("externally reachable");
  }
  if (finding.isNew) {
    raw += 3;
    reasons.push("newly observed");
  }
  if (finding.status === "REOPENED") {
    raw += 3;
    reasons.push("reopened after prior resolution");
  }
  const ageDays = Math.max(
    0,
    Math.floor((now.getTime() - finding.firstSeen.getTime()) / 86_400_000)
  );
  if (ageDays > 90) {
    raw += 4;
    reasons.push("open more than 90 days");
  } else if (ageDays > 30) {
    raw += 2;
    reasons.push("open more than 30 days");
  }
  if ((finding.relatedFindingCount ?? 0) >= 2) {
    raw += Math.min(4, finding.relatedFindingCount ?? 0);
    reasons.push("multiple related observations");
  }
  if (finding.inAttackPath) {
    raw += 6;
    reasons.push("present in a potential attack path");
  }
  raw *= statusMultiplier[finding.status] ?? 1;
  if (["RESOLVED", "FALSE_POSITIVE"].includes(finding.status)) {
    reasons.push("excluded by finding status");
  } else if (!["OPEN", "REOPENED"].includes(finding.status)) {
    reasons.push(`${finding.status.toLowerCase().replaceAll("_", " ")} status adjustment`);
  }
  return {
    findingId: finding.id,
    raw,
    capped: Math.min(35, Number(raw.toFixed(2))),
    reasons
  };
}

export function calculateOrganisationRisk(findings: ScorableFinding[], now = new Date()) {
  const contributions = findings
    .map((finding) => scoreFinding(finding, now))
    .filter((item) => item.capped > 0);
  const sorted = [...contributions].sort((a, b) => b.capped - a.capped);
  const weightedTotal = sorted.reduce((total, contribution, index) => {
    const decay = Math.pow(0.82, index);
    return total + contribution.capped * decay;
  }, 0);
  const score = Math.round(clamp(100 * (1 - Math.exp(-weightedTotal / 70))));
  return {
    score,
    contributors: sorted.slice(0, 5),
    formulaVersion: "2.0",
    disclaimer:
      "RiskMap is a prioritisation aid based on observed exposure and inferred relationships, not an absolute measurement of security."
  };
}

export function estimateScoreAfterFix(
  findings: ScorableFinding[],
  findingId: string,
  now = new Date()
) {
  const current = calculateOrganisationRisk(findings, now).score;
  const projected = calculateOrganisationRisk(
    findings.filter((finding) => finding.id !== findingId),
    now
  ).score;
  return { current, projected, reduction: Math.max(0, current - projected) };
}
