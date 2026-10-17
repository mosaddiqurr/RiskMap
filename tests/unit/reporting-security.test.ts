import { describe, expect, it } from "vitest";
import {
  parseStoredReport,
  reportToHtml,
  safeExportFilename
} from "@/lib/services/reporting";
import { sanitizeCsvCell, toCsv } from "@/lib/services/csv";

describe("report export safety", () => {
  it("neutralises spreadsheet formulas and quotes CSV delimiters", () => {
    expect(sanitizeCsvCell("=SUM(A1:A2)")).toBe("'=SUM(A1:A2)");
    expect(sanitizeCsvCell("+cmd|' /C calc'!A0")).toBe("'+cmd|' /C calc'!A0");
    expect(toCsv([{ title: '=HYPERLINK("https://example.test")', note: "one,two" }])).toBe(
      'title,note\r\n"\'=HYPERLINK(""https://example.test"")","one,two"'
    );
  });

  it("creates bounded safe filenames", () => {
    expect(safeExportFilename("  Northstar / Technical: Q3  ")).toBe(
      "northstar-technical-q3"
    );
    expect(safeExportFilename("../../")).toBe("riskmap-report");
    expect(safeExportFilename("x".repeat(200))).toHaveLength(80);
  });

  it("escapes report-controlled HTML fields", () => {
    const html = reportToHtml({
      organisation: '<script>alert("x")</script>',
      type: "TECHNICAL",
      generatedAt: new Date().toISOString(),
      reportingPeriod: {
        start: new Date().toISOString(),
        end: new Date().toISOString()
      },
      riskScore: 10,
      previousRiskScore: 8,
      summary: "Observed evidence only.",
      topFindings: [
        {
          title: '<img src=x onerror="alert(1)">',
          severity: "LOW",
          status: "OPEN",
          currentlyObserved: true,
          recurrenceCount: 0,
          asset: "example.test",
          confidence: "HIGH",
          remediation: "Remove unsafe markup."
        }
      ],
      assets: [],
      potentialAttackPaths: [],
      methodology: "Methodology",
      limitations: "Limitations",
      authorisedUse: "Authorised use",
      fictionalDemoData: true
    });
    expect(html).not.toContain("<script>alert");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("&lt;img src=x");
  });

  it("uses immutable stored report snapshots", () => {
    const snapshot = {
      organisation: "Northstar Labs",
      type: "TECHNICAL" as const,
      generatedAt: "2026-07-26T00:00:00.000Z",
      reportingPeriod: {
        start: "2026-06-26T00:00:00.000Z",
        end: "2026-07-26T00:00:00.000Z"
      },
      riskScore: 42,
      previousRiskScore: 36,
      summary: "Observed evidence only.",
      topFindings: [],
      assets: [],
      potentialAttackPaths: [],
      methodology: "Deterministic methodology.",
      limitations: "Point-in-time evidence.",
      authorisedUse: "Authorised use only.",
      fictionalDemoData: true
    };

    expect(parseStoredReport(JSON.stringify(snapshot))).toEqual(snapshot);
    expect(() => parseStoredReport("{}")).toThrow("INVALID_REPORT_SNAPSHOT");
  });
});
