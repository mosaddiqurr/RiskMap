"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowRight,
  Check,
  Download,
  FileJson,
  GitBranch,
  LoaderCircle,
  RotateCcw,
  Search,
  Upload,
  Wrench
} from "lucide-react";
import { useAnalysis } from "@/components/analysis/analysis-provider";
import { ExposureGraph } from "@/components/graph/exposure-graph";
import { Button, buttonClass } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/badge";
import { parseDatasetBytes, INPUT_LIMIT_BYTES, type Dataset } from "@/lib/analysis/dataset";
import {
  compareFix,
  type AnalysisPath,
  type AnalysisResult,
  type Recommendation
} from "@/lib/analysis/analyze";

export function WorkspaceEmpty({
  title,
  description
}: {
  title: string;
  description: string;
}) {
  const { loadDemo, busy, error } = useAnalysis();
  return (
    <div className="page-container page-space">
      <div className="empty-analysis">
        <GitBranch size={30} />
        <h1>{title}</h1>
        <p>{description}</p>
        <div className="flex flex-wrap justify-center gap-3">
          <Link href="/analyze" className={buttonClass()}>
            Upload a dataset <ArrowRight size={16} />
          </Link>
          <Button variant="secondary" disabled={busy} onClick={() => void loadDemo()}>
            {busy ? "Analyzing…" : "Load demo"}
          </Button>
        </div>
        {error && (
          <p role="alert" className="error-text">
            {error}
          </p>
        )}
        <p className="help">Results stay in this tab until refresh or Clear analysis.</p>
      </div>
    </div>
  );
}

export function AnalyzeWorkspace() {
  const { result, busy, error, analyze, loadDemo, clear } = useAnalysis();
  const [dataset, setDataset] = useState<Dataset | null>(null);
  const [filename, setFilename] = useState("");
  const [inputError, setInputError] = useState("");
  const [reading, setReading] = useState(false);
  const [editing, setEditing] = useState(false);
  const readVersion = useRef(0);
  const demoStarted = useRef(false);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (
      new URLSearchParams(window.location.search).get("demo") === "1" &&
      !demoStarted.current
    ) {
      demoStarted.current = true;
      window.history.replaceState(null, "", "/analyze");
      void loadDemo();
    }
  }, [loadDemo]);
  async function chooseFile(file?: File) {
    const version = ++readVersion.current;
    setDataset(null);
    setInputError("");
    setFilename("");
    if (!file) return;
    if (!/\.json$/i.test(file.name)) {
      setInputError("Choose a .json dataset. CSV is available for report export.");
      return;
    }
    if (file.size > INPUT_LIMIT_BYTES) {
      setInputError("Dataset exceeds the 1 MiB limit.");
      return;
    }
    setReading(true);
    try {
      const parsed = parseDatasetBytes(new Uint8Array(await file.arrayBuffer()));
      if (readVersion.current === version) {
        setDataset(parsed);
        setFilename(file.name);
      }
    } catch (caught) {
      if (readVersion.current === version)
        setInputError(caught instanceof Error ? caught.message : "File could not be read.");
    } finally {
      if (readVersion.current === version) setReading(false);
    }
  }
  if (result && !editing)
    return (
      <Results
        key={result.analyzedAt}
        result={result}
        onNew={() => setEditing(true)}
        onClear={() => {
          clear();
          setDataset(null);
          setFilename("");
        }}
      />
    );
  return (
    <div className="page-container page-space">
      <div className="page-heading">
        <p className="eyebrow">START WITH YOUR EVIDENCE</p>
        <h1>Analyze exposure</h1>
        <p>
          Bring assets, findings and relationships together. Get potential attack paths and
          a recommended next fix.
        </p>
      </div>
      <div className="ingest-grid">
        <section className="panel ingest-panel" aria-labelledby="upload-heading">
          <div className="panel-heading">
            <div>
              <h2 id="upload-heading">Upload a dataset</h2>
              <p>One UTF-8 JSON file · up to 1 MiB</p>
            </div>
            <FileJson size={21} className="text-muted" />
          </div>
          <div
            className="upload-zone"
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              if (!busy) void chooseFile(e.dataTransfer.files[0]);
            }}
          >
            <Upload size={26} />
            <strong>{filename || "Drop your JSON dataset here"}</strong>
            <p>
              {reading
                ? "Validating references and input…"
                : "or choose a file from your computer"}
            </p>
            <input
              ref={input}
              type="file"
              accept=".json,application/json"
              className="sr-only"
              aria-label="Upload JSON dataset"
              onChange={(e) => void chooseFile(e.target.files?.[0])}
              disabled={busy}
            />
            <Button
              variant="secondary"
              disabled={busy || reading}
              onClick={() => input.current?.click()}
            >
              Choose file
            </Button>
          </div>
          {dataset && (
            <div className="input-ready" role="status">
              <Check size={16} />
              <span>
                {dataset.assets.length} assets · {dataset.services.length} services ·{" "}
                {dataset.findings.length} findings · {dataset.relationships.length}{" "}
                relationships
              </span>
            </div>
          )}
          {(inputError || error) && (
            <div className="error-banner" role="alert">
              {inputError || error}
            </div>
          )}
          <div className="ingest-actions">
            <Button
              disabled={!dataset || busy || reading}
              onClick={async () => {
                if (dataset) {
                  if (await analyze(dataset)) setEditing(false);
                }
              }}
            >
              {busy ? (
                <LoaderCircle size={16} className="animate-spin" />
              ) : (
                <ArrowRight size={16} />
              )}
              {busy ? "Analyzing evidence…" : "Analyze dataset"}
            </Button>
            <a href="/demo-dataset.json" download className="text-link">
              <Download size={15} /> Sample JSON
            </a>
          </div>
          <p className="help">
            Uploaded evidence is processed by this server without database retention. This
            tab keeps the result until refresh or Clear analysis.
          </p>
        </section>
        <section className="panel demo-panel" aria-labelledby="demo-heading">
          <p className="eyebrow">A READY-TO-EXPLORE SCENARIO</p>
          <h2 id="demo-heading">Meet Northstar Labs.</h2>
          <p>
            A fictional web server exposes an administrative service. Its deployment account
            connects to customer data and backups. Which weakness matters most?
          </p>
          <div className="demo-chain">
            <span>WEB-01</span>
            <ArrowRight size={14} />
            <span>SVC-DEPLOY</span>
            <ArrowRight size={14} />
            <span>DB-01</span>
          </div>
          <dl className="demo-counts">
            <div>
              <dt>Assets</dt>
              <dd>6</dd>
            </div>
            <div>
              <dt>Findings</dt>
              <dd>4</dd>
            </div>
            <div>
              <dt>Services</dt>
              <dd>5</dd>
            </div>
          </dl>
          <Button
            variant="secondary"
            disabled={busy}
            onClick={async () => {
              setInputError("");
              if (await loadDemo()) setEditing(false);
            }}
          >
            {busy ? (
              <LoaderCircle size={16} className="animate-spin" />
            ) : (
              <GitBranch size={16} />
            )}
            Load demo analysis
          </Button>
          <p className="help">
            Fictional evidence and reserved documentation addresses. No network activity.
          </p>
        </section>
      </div>
      {busy && (
        <div className="status-banner" role="status">
          <LoaderCircle size={18} className="animate-spin" />
          Building the exposure graph, finding paths and comparing fixes…
        </div>
      )}
      {result && (
        <Button className="mt-4" variant="ghost" onClick={() => setEditing(false)}>
          Return to current results
        </Button>
      )}
      <section className="input-guide" aria-labelledby="input-guide-title">
        <div className="section-heading">
          <div>
            <h2 id="input-guide-title">What goes into the dataset?</h2>
            <p>
              IDs link your records. Evidence explains every asset, service, finding and
              relationship.
            </p>
          </div>
          <a href="/demo-dataset.json" download className="text-link">
            Download the full example <ArrowRight size={15} />
          </a>
        </div>
        <div className="input-guide-grid">
          {[
            [
              "Assets",
              "Names, types, criticality and explicit public exposure. Include identities and sensitive targets."
            ],
            [
              "Services",
              "Ports and protocols on known assets, with confidence and evidence. Open does not mean vulnerable."
            ],
            [
              "Findings",
              "Severity, evidence, explanation and remediation. Optionally include a service, CVE or first-seen date."
            ],
            [
              "Relationships",
              "Directed links with observed or inferred state. Use viaFindingId for a link dependent on a weakness."
            ]
          ].map(([title, text]) => (
            <article key={title}>
              <h3>{title}</h3>
              <p>{text}</p>
            </article>
          ))}
        </div>
        <p className="help">
          Limits: 100 assets, 200 services, 200 findings and 300 relationships. Unknown
          fields, duplicate IDs and broken references are rejected.
        </p>
      </section>
    </div>
  );
}

export function BestNextFix({
  recommendation,
  result,
  onPreview,
  onFinding,
  showEvidence = false
}: {
  recommendation: Recommendation;
  result: AnalysisResult;
  onPreview?: () => void;
  onFinding?: () => void;
  showEvidence?: boolean;
}) {
  return (
    <section className="best-fix" aria-labelledby="best-fix-title">
      <div className="best-fix-main">
        <p className="eyebrow">
          <Wrench size={15} /> BEST NEXT FIX
        </p>
        <h2 id="best-fix-title">{recommendation.action}</h2>
        <div className="fix-context">
          <SeverityBadge severity={recommendation.severity ?? "INFORMATIONAL"} />
          <span>{recommendation.assetName}</span>
          <span>{recommendation.confidence?.toLowerCase()} confidence</span>
        </div>
        <h3>Why this matters</h3>
        <ul>
          {recommendation.reasons.map((reason) => (
            <li key={reason}>
              <Check size={15} />
              {reason}
            </li>
          ))}
        </ul>
        {showEvidence ? (
          <div className="best-fix-evidence">
            <h3>Supporting evidence</h3>
            <p>{recommendation.evidence}</p>
            <p className="help">Finding: {recommendation.title}</p>
          </div>
        ) : (
          <details>
            <summary>Supporting evidence</summary>
            <p>{recommendation.evidence}</p>
            <p className="help">Finding: {recommendation.title}</p>
          </details>
        )}
      </div>
      <div className="best-fix-impact">
        <span className="eyebrow">EXPECTED BENEFIT</span>
        <strong>{recommendation.riskReduction}</strong>
        <p>
          Qualitative reduction
          <br />
          in modeled exposure
        </p>
        <div className="impact-paths">
          <strong>{recommendation.attackPathsReduced}</strong>
          <span>
            of {result.paths.length} mapped paths
            <br />
            removed in the model
          </span>
        </div>
        {onPreview && (
          <Button onClick={onPreview}>
            <GitBranch size={15} />
            Preview this fix
          </Button>
        )}
        {onFinding && (
          <Button variant="ghost" onClick={onFinding}>
            Inspect finding <ArrowRight size={14} />
          </Button>
        )}
        <p className="help">
          Assumes full remediation.
          <br /> Validate against real access controls.
        </p>
      </div>
    </section>
  );
}

function Results({
  result,
  onNew,
  onClear
}: {
  result: AnalysisResult;
  onNew: () => void;
  onClear: () => void;
}) {
  const [selectedPathId, setSelectedPathId] = useState(result.paths[0]?.id ?? "");
  const [findingId, setFindingId] = useState(
    result.recommendations[0]?.findingId ?? result.findings[0]?.id ?? ""
  );
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [previewId, setPreviewId] = useState("");
  const preview = useMemo(
    () => (previewId ? compareFix(result, previewId) : null),
    [result, previewId]
  );
  const best = result.recommendations[0];
  const selectedPath = result.paths.find((p) => p.id === selectedPathId);
  const selectedFinding = result.findings.find((f) => f.id === findingId);
  const visibleFindings = result.findings.filter(
    (f) =>
      (severity === "ALL" || f.severity === severity) &&
      `${f.title} ${f.assetName} ${f.cve ?? ""}`.toLowerCase().includes(query.toLowerCase())
  );
  return (
    <div className="page-container page-space results-page">
      <div className="page-heading heading-with-actions">
        <div>
          <p className="eyebrow">ANALYSIS RESULTS</p>
          <h1>Your next security decision.</h1>
          <p>{result.dataset.name}</p>
        </div>
        <div className="page-actions">
          <Link href="/report" className={buttonClass("secondary")}>
            <Download size={16} />
            Export report
          </Link>
          <Button variant="ghost" onClick={onNew}>
            New dataset
          </Button>
          <Button variant="ghost" onClick={onClear}>
            <RotateCcw size={14} />
            Clear analysis
          </Button>
        </div>
      </div>
      <Summary result={result} />
      {result.search.truncated && (
        <p className="warning-banner" role="status">
          Search reached a safety limit. Path counts and recommendations cover the mapped
          subset; additional paths may exist.
        </p>
      )}
      {best ? (
        <BestNextFix
          recommendation={best}
          result={result}
          onPreview={() => setPreviewId(previewId === best.findingId ? "" : best.findingId)}
          onFinding={() => {
            setFindingId(best.findingId);
            document
              .getElementById("finding-detail")
              ?.scrollIntoView({ behavior: "smooth", block: "start" });
          }}
        />
      ) : (
        <div className="panel p-6">
          <h2>No next fix to recommend</h2>
          <p className="mt-2 text-sm text-muted">
            {result.findings.length
              ? "No candidate changes the mapped paths or rounded model score. Review the supplied findings individually."
              : "This dataset contains no findings."}{" "}
            Review the data coverage before concluding that exposure is absent.
          </p>
        </div>
      )}
      {preview && <Comparison preview={preview} onClose={() => setPreviewId("")} />}
      {result.recommendations.length > 1 && (
        <details className="alternatives">
          <summary>
            Other remediation opportunities{" "}
            <span>({Math.min(2, result.recommendations.length - 1)})</span>
          </summary>
          <div className="alternative-grid">
            {result.recommendations.slice(1, 3).map((r) => (
              <div key={r.findingId}>
                <h3>{r.action}</h3>
                <p>
                  {r.assetName} · {r.attackPathsReduced} mapped paths affected ·{" "}
                  {r.riskReduction.toLowerCase()} benefit
                </p>
                <Button variant="ghost" size="sm" onClick={() => setPreviewId(r.findingId)}>
                  Preview comparison <ArrowRight size={14} />
                </Button>
              </div>
            ))}
          </div>
        </details>
      )}
      <section className="results-graph-grid">
        <div className="panel paths-panel">
          <div className="panel-heading">
            <div>
              <h2>Potential attack paths</h2>
              <p>Ranked by modeled exposure</p>
            </div>
            <GitBranch size={20} className="text-muted" />
          </div>
          <div className="path-list">
            {result.paths.length ? (
              result.paths.map((path) => (
                <button
                  key={path.id}
                  className={`path-list-item ${selectedPathId === path.id ? "is-selected" : ""}`}
                  onClick={() =>
                    setSelectedPathId(selectedPathId === path.id ? "" : path.id)
                  }
                  aria-pressed={selectedPathId === path.id}
                >
                  <div>
                    <SeverityBadge severity={path.severity} />
                    <span className="path-score">
                      {path.riskScore}
                      <small>/100</small>
                    </span>
                  </div>
                  <strong>{path.name}</strong>
                  <span>
                    {path.findingIds.length} findings · {path.nodeIds.length} steps ·{" "}
                    {path.confidence.toLowerCase()} confidence
                  </span>
                </button>
              ))
            ) : (
              <div className="panel-empty">
                No path meets the evidence and target requirements. Findings outside mapped
                paths still need review.
              </div>
            )}
          </div>
        </div>
        <div className="panel graph-panel">
          <div className="panel-heading">
            <div>
              <h2>Exposure graph</h2>
              <p>Select a path, node or relationship to inspect its evidence.</p>
            </div>
            <Link href="/exposure-map" className="text-link">
              Expand <ArrowRight size={15} />
            </Link>
          </div>
          <ExposureGraph
            result={result}
            selectedPathId={selectedPathId}
            selectedFindingId={findingId}
            onFinding={setFindingId}
          />
        </div>
      </section>
      {selectedPath && (
        <PathDetail
          path={selectedPath}
          result={result}
          onFinding={setFindingId}
          onPreview={setPreviewId}
        />
      )}
      <section className="findings-grid" aria-label="Findings and evidence">
        <div className="panel">
          <div className="panel-heading">
            <div>
              <h2>Findings</h2>
              <p>Severity with exposure context</p>
            </div>
            <span className="text-sm text-muted">
              {visibleFindings.length} of {result.findings.length}
            </span>
          </div>
          <div className="finding-filters">
            <div className="search-field">
              <Search size={16} />
              <input
                className="field"
                placeholder="Search findings or assets"
                aria-label="Search findings"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
            <select
              className="field"
              aria-label="Finding severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="ALL">All severities</option>
              {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </div>
          <div className="finding-list">
            {visibleFindings.length ? (
              visibleFindings.map((f) => (
                <button
                  key={f.id}
                  className={`finding-row ${findingId === f.id ? "is-selected" : ""}`}
                  onClick={() => setFindingId(f.id)}
                  aria-pressed={findingId === f.id}
                >
                  <SeverityBadge severity={f.severity} />
                  <div>
                    <strong>{f.title}</strong>
                    <span>
                      {f.assetName} · {f.pathIds.length} mapped paths
                    </span>
                  </div>
                  <ArrowRight size={15} />
                </button>
              ))
            ) : (
              <p className="panel-empty">No findings match these filters.</p>
            )}
          </div>
        </div>
        {selectedFinding ? (
          <FindingDetail
            finding={selectedFinding}
            result={result}
            onPath={setSelectedPathId}
            onPreview={() => setPreviewId(selectedFinding.id)}
          />
        ) : (
          <div className="panel panel-empty">
            Select a finding to inspect its evidence and remediation.
          </div>
        )}
      </section>
      <p className="analysis-note">
        Potential paths and scores are prioritisation aids, not proof of exploitation.{" "}
        <Link href="/about#limitations">Review the methodology and limitations.</Link>
      </p>
    </div>
  );
}

export function Summary({ result }: { result: AnalysisResult }) {
  const stats = [
    [result.dataset.assets.length, "Assets"],
    [result.findings.length, "Findings"],
    [result.paths.filter((p) => p.severity === "CRITICAL").length, "Critical paths"],
    [result.recommendations.length ? 1 : 0, "Recommended next fix"]
  ];
  return (
    <dl className="analysis-summary">
      {stats.map(([value, label]) => (
        <div key={label}>
          <dd>{value}</dd>
          <dt>{label}</dt>
        </div>
      ))}
    </dl>
  );
}

export function PathDetail({
  path,
  result,
  onFinding,
  onPreview
}: {
  path: AnalysisPath;
  result: AnalysisResult;
  onFinding?: (id: string) => void;
  onPreview?: (id: string) => void;
}) {
  const nodes = new Map(result.graph.nodes.map((n) => [n.id, n]));
  const edges = new Map(result.graph.edges.map((e) => [e.id, e]));
  return (
    <section className="panel path-detail">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">SELECTED PATH</p>
          <h2>{path.name}</h2>
        </div>
        <div className="flex items-center gap-3">
          <SeverityBadge severity={path.severity} />
          <span className="text-sm text-muted">Score {path.riskScore}/100</span>
        </div>
      </div>
      <p className="path-description">
        {path.pathType} with {path.inferredRelationshipCount} inferred step
        {path.inferredRelationshipCount === 1 ? "" : "s"}. It connects public exposure to a
        sensitive target; validate every access boundary.
      </p>
      <ol className="path-step-list">
        {path.nodeIds.map((id, i) => {
          const node = nodes.get(id)!;
          const edge = edges.get(path.edgeIds[i - 1] ?? "");
          return (
            <li key={id}>
              <span className="step-number">{i + 1}</span>
              <div>
                <span className="step-kind">
                  {node.type === "IDENTITY"
                    ? "Identity"
                    : node.type.replaceAll("_", " ").toLowerCase()}
                </span>
                {node.findingId && onFinding ? (
                  <button
                    className="text-link step-label"
                    onClick={() => onFinding(node.findingId!)}
                  >
                    {node.label}
                  </button>
                ) : (
                  <strong>{node.label}</strong>
                )}
                {edge && (
                  <details>
                    <summary>
                      {edge.relationship} · {edge.state.toLowerCase()} ·{" "}
                      {edge.confidence.toLowerCase()} confidence
                    </summary>
                    <p>{edge.evidence}</p>
                  </details>
                )}
              </div>
            </li>
          );
        })}
      </ol>
      <div className="path-detail-footer">
        <details>
          <summary>How this score is calculated</summary>
          <dl className="score-contributors">
            {Object.entries(path.contributors)
              .filter(([, value]) => value !== 0)
              .map(([key, value]) => (
                <div key={key}>
                  <dt>{key.replace(/([A-Z])/g, " $1").toLowerCase()}</dt>
                  <dd>{value}</dd>
                </div>
              ))}
          </dl>
          <p className="help">
            Sum the contributions, subtract the inferred penalty, multiply by confidence and
            clamp to 0–100. This is not an exploitation probability.
          </p>
        </details>
        {onPreview &&
          path.recommendedBreakNodeId &&
          nodes.get(path.recommendedBreakNodeId)?.findingId && (
            <Button
              variant="secondary"
              onClick={() => onPreview(nodes.get(path.recommendedBreakNodeId!)!.findingId!)}
            >
              Preview a break point <Wrench size={14} />
            </Button>
          )}
      </div>
    </section>
  );
}

function FindingDetail({
  finding,
  result,
  onPath,
  onPreview
}: {
  finding: AnalysisResult["findings"][number];
  result: AnalysisResult;
  onPath: (id: string) => void;
  onPreview: () => void;
}) {
  return (
    <article className="panel finding-detail" id="finding-detail">
      <div className="flex items-center gap-3">
        <p className="eyebrow">FINDING DETAILS</p>
        <SeverityBadge severity={finding.severity} />
      </div>
      <h2>{finding.title}</h2>
      <p className="finding-meta">
        {finding.assetName} · {finding.confidence.toLowerCase()} confidence
        {finding.serviceId
          ? ` · ${result.dataset.services.find((s) => s.id === finding.serviceId)?.protocol.toUpperCase()}/${result.dataset.services.find((s) => s.id === finding.serviceId)?.port}`
          : ""}
      </p>
      <h3>Evidence</h3>
      <p className="evidence-block">{finding.evidence}</p>
      <h3>Why it matters</h3>
      <p>{finding.description}</p>
      {finding.cve && (
        <p>
          <strong>{finding.cve}</strong> is a supplied reference. Version matching and
          exploitability have not been independently verified.
        </p>
      )}
      <h3>Recommended remediation</h3>
      <p>{finding.remediation}</p>
      <h3>Attack paths involving this finding</h3>
      {finding.pathIds.length ? (
        <div className="finding-path-links">
          {finding.pathIds.map((id) => (
            <button
              className="text-link"
              key={id}
              onClick={() => {
                onPath(id);
                document
                  .querySelector(".results-graph-grid")
                  ?.scrollIntoView({ behavior: "smooth" });
              }}
            >
              {result.paths.find((p) => p.id === id)?.name}
              <ArrowRight size={14} />
            </button>
          ))}
        </div>
      ) : (
        <p>
          No current mapped path uses this finding. Review the weakness on its own merits.
        </p>
      )}
      <details className="mt-4">
        <summary>Finding score explanation</summary>
        <p>
          {finding.contribution.reasons.join(" · ")}. Capped contribution:{" "}
          {finding.contribution.capped}. Confidence and asset importance adjust this
          relative score.
        </p>
      </details>
      <Button variant="secondary" className="mt-5" onClick={onPreview}>
        Preview remediation <GitBranch size={15} />
      </Button>
    </article>
  );
}

export function Comparison({
  preview,
  onClose
}: {
  preview: ReturnType<typeof compareFix>;
  onClose: () => void;
}) {
  const finding = preview.before.findings.find((f) => f.id === preview.findingId)!;
  return (
    <section className="panel comparison-panel" aria-labelledby="comparison-title">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">REMEDIATION PREVIEW · MODEL ASSUMPTION</p>
          <h2 id="comparison-title">If this finding is fully remediated</h2>
          <p>{finding.title}</p>
        </div>
        <Button variant="ghost" size="sm" onClick={onClose}>
          Close preview
        </Button>
      </div>
      <div className="comparison-stats">
        <div>
          <span>Before fix</span>
          <strong>{preview.before.paths.length}</strong>
          <p>
            Mapped paths ·{" "}
            {preview.before.paths.filter((p) => p.severity === "CRITICAL").length} critical
          </p>
        </div>
        <ArrowRight size={20} className="comparison-arrow" />
        <div>
          <span>After fix</span>
          <strong>{preview.after.paths.length}</strong>
          <p>
            Mapped paths ·{" "}
            {preview.after.paths.filter((p) => p.severity === "CRITICAL").length} critical
          </p>
        </div>
        <div>
          <span>Paths removed</span>
          <strong>{preview.removedPathIds.length}</strong>
          <p>Finding-dependent paths only</p>
        </div>
      </div>
      <div className="comparison-notes">
        <p>
          <strong>Remaining exposure:</strong> {preview.after.findings.length} findings
          remain.{" "}
          {preview.after.paths.length
            ? `The highest remaining path score is ${preview.after.paths[0]!.riskScore}/100.`
            : "No remaining path meets the current model requirements; this does not prove the environment is secure."}
        </p>
        <p>
          Model score: {preview.before.risk.score} → {preview.after.risk.score}. These are
          analytical score points, not a measured risk percentage. Asset reachability and
          general relationships remain unchanged.
        </p>
        {(preview.before.search.truncated || preview.after.search.truncated) && (
          <p className="warning-banner">
            Both counts cover bounded search results and may omit additional paths.
          </p>
        )}
      </div>
    </section>
  );
}

export function MapWorkspace() {
  const { result } = useAnalysis();
  const [selectedPathId, setSelectedPathId] = useState("");
  const [findingId, setFindingId] = useState("");
  if (!result)
    return (
      <WorkspaceEmpty
        title="Build your exposure map"
        description="Analyze a dataset or load the demo to explore assets, findings and potential attack paths."
      />
    );
  const path = result.paths.find((p) => p.id === selectedPathId);
  return (
    <div className="page-container page-space">
      <div className="page-heading heading-with-actions">
        <div>
          <p className="eyebrow">FOLLOW THE EVIDENCE</p>
          <h1>Exposure Map</h1>
          <p>{result.dataset.name}</p>
        </div>
        <Link href="/analyze" className={buttonClass("secondary")}>
          Back to results <ArrowRight size={16} />
        </Link>
      </div>
      <div className="map-path-selector">
        <label htmlFor="map-path">Highlight a path</label>
        <select
          className="field"
          id="map-path"
          value={selectedPathId}
          onChange={(e) => setSelectedPathId(e.target.value)}
        >
          <option value="">All evidence</option>
          {result.paths.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} · {p.riskScore}/100
            </option>
          ))}
        </select>
      </div>
      <div className="panel graph-panel full-map">
        <ExposureGraph
          key={result.analyzedAt}
          result={result}
          selectedPathId={selectedPathId}
          selectedFindingId={findingId}
          onFinding={setFindingId}
          expanded
        />
      </div>
      {path && <PathDetail path={path} result={result} onFinding={setFindingId} />}
      <p className="analysis-note">
        Solid relationships are observed; dashed relationships are inferred. Click an edge
        for its evidence. Use zoom, pan and Fit view to explore.
      </p>
    </div>
  );
}
