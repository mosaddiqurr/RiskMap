"use client";

import { useState } from "react";
import { Braces, Check, ChevronRight } from "lucide-react";
import { demoDataset } from "@/lib/analysis/demo";

const collections = ["assets", "services", "findings", "relationships"] as const;
export function EvidenceExplorer() {
  const [collection, setCollection] = useState<(typeof collections)[number]>("assets");
  const examples = {
    assets: {
      name: demoDataset.assets[0]!.name,
      type: demoDataset.assets[0]!.type,
      public: demoDataset.assets[0]!.public,
      criticality: demoDataset.assets[0]!.criticality
    },
    services: {
      assetId: demoDataset.services[0]!.assetId,
      port: demoDataset.services[0]!.port,
      protocol: demoDataset.services[0]!.protocol,
      confidence: demoDataset.services[0]!.confidence
    },
    findings: {
      assetId: demoDataset.findings[0]!.assetId,
      severity: demoDataset.findings[0]!.severity,
      category: demoDataset.findings[0]!.category,
      confidence: demoDataset.findings[0]!.confidence
    },
    relationships: {
      from: demoDataset.relationships[0]!.from,
      to: demoDataset.relationships[0]!.to,
      state: demoDataset.relationships[0]!.state,
      viaFindingId: demoDataset.relationships[0]!.viaFindingId
    }
  };
  return (
    <div className="evidence-explorer">
      <div
        className="evidence-tabs"
        role="tablist"
        aria-label="Example dataset collections"
      >
        {collections.map((name) => (
          <button
            type="button"
            role="tab"
            id={`tab-${name}`}
            aria-controls="example-evidence-panel"
            aria-selected={collection === name}
            tabIndex={collection === name ? 0 : -1}
            key={name}
            onClick={() => setCollection(name)}
            onKeyDown={(event) => {
              const index = collections.indexOf(name);
              const next =
                event.key === "ArrowRight"
                  ? collections[(index + 1) % collections.length]
                  : event.key === "ArrowLeft"
                    ? collections[(index + collections.length - 1) % collections.length]
                    : event.key === "Home"
                      ? collections[0]
                      : event.key === "End"
                        ? collections[collections.length - 1]
                        : undefined;
              if (next) {
                event.preventDefault();
                setCollection(next);
                document.getElementById(`tab-${next}`)?.focus();
              }
            }}
          >
            {name}
            <span>{demoDataset[name].length}</span>
          </button>
        ))}
      </div>
      <div
        id="example-evidence-panel"
        role="tabpanel"
        aria-labelledby={`tab-${collection}`}
        tabIndex={0}
        className="evidence-code"
        key={collection}
      >
        <div className="code-file">
          <Braces size={13} />
          <span>northstar-demo.json</span>
          <span>Fictional data</span>
        </div>
        <pre>
          <span className="code-brace">{"{"}</span>
          {"\n"}
          {Object.entries(examples[collection]).map(([key, value], index, entries) => (
            <span className="code-line" key={key}>
              <span className="line-number">{index + 1}</span>
              <span className="code-key">{`  "${key}"`}</span>:{" "}
              <span className={typeof value === "string" ? "code-string" : "code-value"}>
                {JSON.stringify(value)}
              </span>
              {index < entries.length - 1 ? "," : ""}
              {"\n"}
            </span>
          ))}
          <span className="code-brace">{"}"}</span>
        </pre>
      </div>
      <div className="evidence-code-footer">
        <span>
          <Check size={12} /> Evidence attached to every connection
        </span>
        <ChevronRight size={13} />
      </div>
    </div>
  );
}
