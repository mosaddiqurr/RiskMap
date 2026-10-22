"use client";

import { useState, type CSSProperties } from "react";
import {
  ArrowRight,
  Check,
  Database,
  Globe,
  KeyRound,
  Layers3,
  LockKeyhole,
  Server,
  ShieldCheck,
  Wrench
} from "lucide-react";
import { compareFix, type AnalysisResult } from "@/lib/analysis/analyze";

const positions = [
  {
    id: "internet",
    label: "Internet",
    detail: "Public entry point",
    icon: Globe,
    x: 48,
    y: 11
  },
  { id: "web-01", label: "WEB-01", detail: "Public SSH · :22", icon: Server, x: 23, y: 34 },
  {
    id: "api-01",
    label: "API-01",
    detail: "Public API · :443",
    icon: Layers3,
    x: 77,
    y: 34
  },
  {
    id: "svc-deploy",
    label: "SVC-DEPLOY",
    detail: "Deployment identity",
    icon: KeyRound,
    x: 38,
    y: 60
  },
  {
    id: "backup-01",
    label: "BACKUP-01",
    detail: "Sensitive backups",
    icon: Database,
    x: 23,
    y: 87
  },
  { id: "db-01", label: "DB-01", detail: "Customer database", icon: Database, x: 75, y: 87 }
];
const connections = [
  { from: "internet", to: "web-01", gated: true },
  { from: "internet", to: "api-01", gated: false },
  { from: "web-01", to: "svc-deploy", gated: true },
  { from: "svc-deploy", to: "backup-01", gated: true },
  { from: "svc-deploy", to: "db-01", gated: true },
  { from: "api-01", to: "db-01", gated: false }
];

export function ExposurePreview({ result }: { result: AnalysisResult }) {
  const [fixed, setFixed] = useState(false);
  const best = result.recommendations[0]!;
  const [comparison] = useState(() => compareFix(result, best.findingId));
  const displayed = fixed ? comparison.after : result;

  return (
    <div className={`exposure-preview ${fixed ? "is-remediated" : ""}`} data-ambient>
      <div className="preview-topbar">
        <span>
          <Layers3 size={15} /> Exposure preview
        </span>
        <div className="preview-controls">
          <span className="scenario-label">Fictional demo</span>
        </div>
      </div>
      <div className="preview-summary">
        <div>
          <span>Northstar Labs</span>
          <strong>
            {displayed.paths.length} potential attack{" "}
            {displayed.paths.length === 1 ? "path" : "paths"}
          </strong>
        </div>
        <span className={`preview-status ${fixed ? "is-fixed" : ""}`}>
          {fixed ? <ShieldCheck size={13} /> : <span className="status-beacon" />}
          {fixed ? "Fix preview" : "Exposure mapped"}
        </span>
      </div>
      <div
        className="preview-network"
        role="img"
        aria-label={
          fixed
            ? "Remediation model: public SSH entry removed; the API path remains."
            : "Fictional exposure map: Internet connects through WEB-01 and a deployment identity to a database and backups. A separate API path reaches the database."
        }
      >
        <div className="network-orbit orbit-one" />
        <div className="network-orbit orbit-two" />
        <div className="network-topology">
          <svg
            className="network-connections"
            viewBox="0 0 600 390"
            preserveAspectRatio="none"
            aria-hidden="true"
          >
            {connections.map((connection, i) => {
              const from = positions.find((p) => p.id === connection.from)!;
              const to = positions.find((p) => p.id === connection.to)!;
              const x1 = from.x * 6;
              const y1 = from.y * 3.9;
              const x2 = to.x * 6;
              const y2 = to.y * 3.9;
              const d = `M${x1},${y1} C${x1},${(y1 + y2) / 2} ${x2},${(y1 + y2) / 2} ${x2},${y2}`;
              return (
                <g
                  key={`${connection.from}-${connection.to}`}
                  className={`${connection.gated ? "critical-connection" : "normal-connection"} ${fixed && connection.gated ? "removed-connection" : ""}`}
                >
                  <path d={d} className="network-wire" />
                  <path
                    d={d}
                    pathLength="1"
                    className="network-signal network-signal-halo"
                    style={{ animationDelay: `${i * -0.65}s` }}
                  />
                  <path
                    d={d}
                    pathLength="1"
                    className="network-signal"
                    style={{ animationDelay: `${i * -0.65}s` }}
                  />
                </g>
              );
            })}
          </svg>
          {positions.map(({ id, label, detail, icon: Icon, x, y }, index) => (
            <div
              className={`preview-node node-${id} ${fixed && id === "web-01" ? "secured-node" : ""}`}
              key={id}
              style={
                {
                  left: `${x}%`,
                  top: `${y}%`,
                  "--node-delay": `${index * -0.55}s`
                } as CSSProperties
              }
            >
              <div className="preview-node-icon">
                <Icon size={19} strokeWidth={1.5} />
              </div>
              <div>
                <strong>{label}</strong>
                <span>{fixed && id === "web-01" ? "SSH entry removed" : detail}</span>
              </div>
              {id === "web-01" &&
                (fixed ? (
                  <Check size={13} className="node-check" />
                ) : (
                  <span className="node-alert" />
                ))}
              {(id === "db-01" || id === "backup-01") && (
                <LockKeyhole size={11} className="node-lock" />
              )}
            </div>
          ))}
        </div>
      </div>
      <div className="preview-legend">
        <span>
          <i className="legend-critical" /> Finding-dependent path
        </span>
        <span>
          <i /> Other exposure
        </span>
      </div>
      <div className="preview-fix">
        <div className="preview-fix-icon">
          {fixed ? <ShieldCheck size={19} /> : <Wrench size={19} />}
        </div>
        <div>
          <span>{fixed ? "REMEDIATION PREVIEW" : "BEST NEXT FIX"}</span>
          <strong>
            {fixed
              ? `${comparison.removedPathIds.length} mapped paths removed`
              : "Restrict public SSH on WEB-01"}
          </strong>
        </div>
        <button
          type="button"
          onClick={() => setFixed(!fixed)}
          aria-pressed={fixed}
          className="preview-fix-button"
        >
          {fixed ? "Reset" : "Preview fix"}
          <ArrowRight size={14} />
        </button>
      </div>
      <p className="preview-footnote" aria-live="polite">
        {fixed
          ? "Assumes full remediation. One API path remains in the model."
          : "Illustrative asset view. Open the demo to inspect all evidence."}
      </p>
    </div>
  );
}
