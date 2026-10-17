import type {
  VulnerabilityProvider,
  TechnologyEvidence,
  VulnerabilityMatch
} from "@/lib/vulnerabilities/provider";

const fictionalCatalogue = [
  {
    catalogueId: "RM-DEMO-2026-0001",
    productName: "Northstar API Gateway",
    exactVersion: "4.2.0-demo",
    title: "Fictional API gateway version requires configuration review",
    severity: "HIGH" as const,
    summary:
      "The fictional demo catalogue associates this exact demo version with a potentially unsafe default administration configuration.",
    remediation:
      "Review the fictional gateway configuration, restrict management access and apply the vendor’s fictional fixed configuration profile.",
    references: ["RiskMap fictional vulnerability catalogue"]
  }
];

export class LocalFictionalVulnerabilityProvider implements VulnerabilityProvider {
  name = "local-fictional-catalogue";

  async correlate(technology: TechnologyEvidence): Promise<VulnerabilityMatch[]> {
    if (!technology.version || technology.confidence === "LOW") return [];
    return fictionalCatalogue
      .filter(
        (entry) =>
          entry.productName.toLowerCase() === technology.productName.toLowerCase() &&
          entry.exactVersion.toLowerCase() === technology.version?.toLowerCase()
      )
      .map((entry) => ({
        catalogueId: entry.catalogueId,
        title: entry.title,
        severity: entry.severity,
        productName: entry.productName,
        matchedVersion: entry.exactVersion,
        confidence: technology.confidence === "HIGH" ? "HIGH" : "MEDIUM",
        summary: entry.summary,
        remediation: entry.remediation,
        references: entry.references,
        fictional: true
      }));
  }
}

export const localFictionalVulnerabilityProvider =
  new LocalFictionalVulnerabilityProvider();
