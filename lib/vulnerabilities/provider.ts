import type { Confidence, FindingSeverity } from "@prisma/client";

export type TechnologyEvidence = {
  productName: string;
  version?: string | null;
  confidence: Confidence;
  evidence: string;
};

export type VulnerabilityMatch = {
  catalogueId: string;
  title: string;
  severity: FindingSeverity;
  productName: string;
  matchedVersion: string;
  confidence: Confidence;
  summary: string;
  remediation: string;
  references: string[];
  fictional: boolean;
};

export interface VulnerabilityProvider {
  name: string;
  correlate(technology: TechnologyEvidence): Promise<VulnerabilityMatch[]>;
}
