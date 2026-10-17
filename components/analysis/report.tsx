"use client";
import { Download, Printer } from "lucide-react";
import { useAnalysis } from "@/components/analysis/analysis-provider";
import { BestNextFix, Summary, WorkspaceEmpty } from "@/components/analysis/workspace";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/badge";
import { BrandLogo } from "@/components/marketing/brand-logo";
import { exportName, findingsCsv, reportJson } from "@/lib/analysis/export";

function download(content: string, type: string, filename: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function AnalysisReport() {
  const { result } = useAnalysis();
  if (!result)
    return (
      <WorkspaceEmpty
        title="Your report starts with an analysis"
        description="Upload a dataset or load the demo to create a report with priorities, paths and supporting evidence."
      />
    );
  const best = result.recommendations[0];
  const high = result.findings.filter((f) => ["CRITICAL", "HIGH"].includes(f.severity));
  const nodes = new Map(result.graph.nodes.map((n) => [n.id, n]));
  const name = exportName(result.dataset.name);
  return (
    <div className="page-container page-space report-page">
      <div className="report-brand">
        <BrandLogo />
      </div>
      <div className="page-heading heading-with-actions">
        <div>
          <p className="eyebrow">DECISION REPORT</p>
          <h1>Exposure priorities</h1>
          <p>{result.dataset.name}</p>
          <p className="help">
            Analyzed{" "}
            {new Date(result.analyzedAt).toLocaleString("en-SG", {
              timeZone: "Asia/Singapore"
            })}{" "}
            SGT
          </p>
        </div>
        <div className="page-actions no-print">
          <Button
            variant="secondary"
            onClick={() =>
              download(reportJson(result), "application/json", `${name}-analysis.json`)
            }
          >
            <Download size={15} />
            JSON
          </Button>
          <Button
            variant="secondary"
            disabled={!result.findings.length}
            onClick={() =>
              download(
                findingsCsv(result),
                "text/csv;charset=utf-8",
                `${name}-findings.csv`
              )
            }
          >
            <Download size={15} />
            Findings CSV
          </Button>
          <Button onClick={() => window.print()}>
            <Printer size={15} />
            Print / Save PDF
          </Button>
        </div>
      </div>
      <Summary result={result} />
      <section className="report-section">
        <h2>Executive summary</h2>
        <p>
          RiskMap mapped {result.paths.length} potential attack paths from{" "}
          {result.dataset.assets.length} assets, {result.dataset.services.length} services
          and {result.findings.length} findings. {high.length} findings have high or
          critical supplied severity.{" "}
          {best
            ? `The recommended next action is: ${best.action}`
            : "No candidate changes the mapped paths or rounded model score."}
        </p>
        <p>
          The model’s prioritisation score is {result.risk.score}/100. It reflects supplied
          evidence and inferred relationships; it does not measure the probability of
          compromise.
        </p>
        {result.search.truncated && (
          <p className="warning-banner">
            Search reached a bound. Counts and recommendations describe a subset of possible
            paths.
          </p>
        )}
      </section>
      {best && <BestNextFix recommendation={best} result={result} showEvidence />}
      <section className="report-section">
        <h2>Asset context</h2>
        <div
          className="report-table-wrap"
          tabIndex={0}
          role="region"
          aria-label="Asset context table"
        >
          <table>
            <thead>
              <tr>
                <th>Asset</th>
                <th>Type</th>
                <th>Criticality</th>
                <th>Exposure</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {result.dataset.assets.map((a) => (
                <tr key={a.id}>
                  <td>{a.name}</td>
                  <td>{a.type.replaceAll("_", " ").toLowerCase()}</td>
                  <td>{a.criticality.toLowerCase()}</td>
                  <td>{a.public ? "Public" : "Internal / non-public"}</td>
                  <td>{a.evidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="report-section">
        <h2>Critical and high findings</h2>
        {high.length ? (
          high.map((f) => (
            <article className="report-finding" key={f.id}>
              <div className="flex flex-wrap items-center gap-3">
                <SeverityBadge severity={f.severity} />
                <h3>{f.title}</h3>
              </div>
              <p className="help">
                {f.assetName} · {f.confidence.toLowerCase()} confidence · {f.pathIds.length}{" "}
                mapped paths
              </p>
              <p>
                <strong>Evidence:</strong> {f.evidence}
              </p>
              <p>
                <strong>Why it matters:</strong> {f.description}
              </p>
              <p>
                <strong>Remediation:</strong> {f.remediation}
              </p>
              {f.cve && (
                <p>
                  Supplied CVE reference: {f.cve}. Exploitability has not been independently
                  verified.
                </p>
              )}
            </article>
          ))
        ) : (
          <p>
            No high or critical findings were supplied. Lower-severity findings may still
            matter in context.
          </p>
        )}
      </section>
      <section className="report-section">
        <h2>Potential attack paths</h2>
        {result.paths.length ? (
          result.paths.map((p) => (
            <article key={p.id} className="report-path">
              <div className="flex flex-wrap items-center gap-3">
                <SeverityBadge severity={p.severity} />
                <h3>{p.name}</h3>
                <span className="help">
                  Score {p.riskScore}/100 · {p.confidence.toLowerCase()} confidence
                </span>
              </div>
              <p className="report-chain">
                {p.nodeIds.map((id) => nodes.get(id)!.label).join(" → ")}
              </p>
              <p>
                {p.pathType}. {p.inferredRelationshipCount} inferred steps require
                validation.
              </p>
              <ol>
                {p.edgeIds.map((id) => {
                  const e = result.graph.edges.find((edge) => edge.id === id)!;
                  return (
                    <li key={id}>
                      <strong>{e.relationship}</strong> · {e.state.toLowerCase()} ·{" "}
                      {e.confidence.toLowerCase()} confidence. {e.evidence}
                    </li>
                  );
                })}
              </ol>
              <p>
                <strong>Remediation opportunities:</strong>{" "}
                {p.findingIds
                  .map((id) => result.findings.find((f) => f.id === id)!.remediation)
                  .join(" ")}
              </p>
            </article>
          ))
        ) : (
          <p>No paths meet the evidence and target requirements in the supplied graph.</p>
        )}
      </section>
      <section className="report-section">
        <h2>Remediation and remaining risk</h2>
        {best ? (
          <>
            <p>
              In the finding-removal model, the recommended action removes{" "}
              {best.attackPathsReduced} mapped paths and leaves {best.pathsAfter}. This
              assumes the finding and dependent transitions are fully remediated. Other
              findings and general relationships remain.
            </p>
            <p>
              Projected model score: {best.currentRisk} → {best.estimatedRiskAfterFix}. The
              qualitative benefit is {best.riskReduction.toLowerCase()}; score points are
              not measured risk percentages.
            </p>
          </>
        ) : (
          <p>No candidate was available for comparison.</p>
        )}
        <p>
          Validate inferred access boundaries and reanalyze an updated dataset after
          implementing a fix. Review findings outside mapped paths separately.
        </p>
        <h3>All supplied findings</h3>
        {result.findings.map((f) => (
          <div key={f.id} className="report-all-finding">
            <strong>
              {f.assetName}: {f.title}
            </strong>
            <p>
              {f.severity.toLowerCase()} · {f.evidence}
            </p>
            <p>Next action: {f.remediation}</p>
          </div>
        ))}
      </section>
      <section className="report-section">
        <h2>Methodology and limitations</h2>
        <p>
          Directed, cycle-safe path search requires a finding and a sensitive target.
          Scoring weights exposure, severity, asset importance, service sensitivity and
          confidence, with a penalty for inferred steps. Best Next Fix recalculates each
          candidate in memory and compares modeled paths and scores.
        </p>
        <ul>
          {result.limitations.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
        <p>
          The JSON export contains the complete input and machine-readable analysis. CSV
          includes all findings and evidence. The browser print dialog can save this report
          as PDF.
        </p>
      </section>
    </div>
  );
}
