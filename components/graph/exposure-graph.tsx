"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Node,
  type NodeProps,
  type ReactFlowInstance
} from "@xyflow/react";
import {
  Database,
  FileWarning,
  Focus,
  Globe,
  KeyRound,
  Search,
  Server,
  X
} from "lucide-react";
import { Button } from "@/components/ui/button";
import type { AnalysisResult } from "@/lib/analysis/analyze";
import type { GraphEdge, GraphNode } from "@/lib/services/attack-paths";

type NodeData = {
  label: string;
  kind: string;
  critical: boolean;
  inPath: boolean;
  selectedFinding: boolean;
  severity?: string;
};
function EvidenceNode({ data, selected }: NodeProps<Node<NodeData>>) {
  const Icon =
    data.kind === "INTERNET"
      ? Globe
      : data.kind === "IDENTITY"
        ? KeyRound
        : data.kind === "FINDING"
          ? FileWarning
          : data.critical
            ? Database
            : Server;
  return (
    <div
      className={`evidence-node ${data.kind === "INTERNET" ? "entry-node" : ""} ${data.critical ? "target-node" : ""} ${data.kind === "FINDING" ? "finding-node" : ""} ${data.inPath ? "path-node" : ""} ${selected || data.selectedFinding ? "selected-node" : ""}`}
    >
      <Handle type="target" position={Position.Top} />
      <div className="node-kind">
        <Icon size={13} />
        <span>
          {data.kind === "FINDING"
            ? data.severity?.toLowerCase() + " finding"
            : data.kind === "NETWORK_SERVICE"
              ? "service"
              : data.kind === "INTERNET"
                ? "entry point"
                : data.kind === "IDENTITY"
                  ? "identity"
                  : data.critical
                    ? "sensitive target"
                    : "asset"}
        </span>
      </div>
      <strong title={data.label}>{data.label}</strong>
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}
const nodeTypes = { evidence: EvidenceNode };

// Rank nodes by their deepest occurrence in mapped paths, then place each rank in a row.
// Unmapped inventory sits in its own compact row. Cycles cannot loop this layout.
export function layoutGraph(
  nodes: GraphNode[],
  edges: GraphEdge[],
  paths: AnalysisResult["paths"]
) {
  const rank = new Map<string, number>();
  rank.set("internet", 0);
  for (const path of paths)
    path.nodeIds.forEach((id, i) => rank.set(id, Math.max(rank.get(id) ?? 0, i)));
  const queue = nodes.filter((n) => rank.has(n.id)).map((n) => n.id);
  for (let i = 0; i < queue.length; i++) {
    const id = queue[i]!;
    for (const edge of edges.filter((e) => e.source === id))
      if (!rank.has(edge.target)) {
        rank.set(edge.target, Math.min(8, (rank.get(id) ?? 0) + 1));
        queue.push(edge.target);
      }
  }
  const rows = new Map<number, GraphNode[]>();
  for (const node of nodes) {
    const r = rank.get(node.id) ?? 1;
    rows.set(r, [...(rows.get(r) ?? []), node]);
  }
  const positions = new Map<string, { x: number; y: number }>();
  for (const [r, row] of [...rows].sort(([a], [b]) => a - b))
    row
      .sort((a, b) => a.id.localeCompare(b.id))
      .forEach((n, i) =>
        positions.set(n.id, { x: (i - (row.length - 1) / 2) * 252, y: r * 108 })
      );
  return positions;
}

export function ExposureGraph({
  result,
  selectedPathId = "",
  selectedFindingId = "",
  onFinding,
  expanded = false
}: {
  result: AnalysisResult;
  selectedPathId?: string;
  selectedFindingId?: string;
  onFinding?: (id: string) => void;
  expanded?: boolean;
}) {
  const [query, setQuery] = useState("");
  const [showOnlyPath, setShowOnlyPath] = useState(Boolean(selectedPathId));
  const [evidenceState, setEvidenceState] = useState("ALL");
  const [detail, setDetail] = useState<{ node?: GraphNode; edge?: GraphEdge } | null>(null);
  const [instance, setInstance] = useState<ReactFlowInstance<Node<NodeData>> | null>(null);
  const [type, setType] = useState("ALL");
  const selectedPath = result.paths.find((p) => p.id === selectedPathId);
  const pathNodeIds = useMemo(() => new Set(selectedPath?.nodeIds ?? []), [selectedPath]);
  const pathEdgeIds = useMemo(() => new Set(selectedPath?.edgeIds ?? []), [selectedPath]);
  const positions = useMemo(
    () =>
      showOnlyPath && selectedPath
        ? layoutGraph(
            result.graph.nodes.filter((n) => pathNodeIds.has(n.id)),
            result.graph.edges.filter((e) => pathEdgeIds.has(e.id)),
            [selectedPath]
          )
        : layoutGraph(result.graph.nodes, result.graph.edges, result.paths),
    [result, showOnlyPath, selectedPath, pathNodeIds, pathEdgeIds]
  );
  const visibleIds = useMemo(
    () =>
      new Set(
        result.graph.nodes
          .filter(
            (n) =>
              (!query || n.label.toLowerCase().includes(query.toLowerCase())) &&
              (type === "ALL" ||
                (type === "TARGET"
                  ? n.isTarget
                  : type === "ASSET"
                    ? !["INTERNET", "FINDING", "NETWORK_SERVICE", "IDENTITY"].includes(
                        n.type
                      )
                    : n.type === type)) &&
              (!showOnlyPath || !selectedPath || pathNodeIds.has(n.id))
          )
          .map((n) => n.id)
      ),
    [result, query, type, showOnlyPath, selectedPath, pathNodeIds]
  );
  const nodes: Node<NodeData>[] = result.graph.nodes.map((n) => ({
    id: n.id,
    type: "evidence",
    position: positions.get(n.id) ?? { x: 0, y: 0 },
    hidden: !visibleIds.has(n.id),
    ariaLabel: `${n.label}, ${n.type.toLowerCase().replaceAll("_", " ")}`,
    data: {
      label: n.label,
      kind: n.type,
      critical: Boolean(n.isTarget),
      inPath: pathNodeIds.has(n.id),
      severity: n.findingSeverity,
      selectedFinding: n.findingId === selectedFindingId
    }
  }));
  const edges = result.graph.edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    type: "smoothstep",
    // The highlighted chain gets labels; other edges remain inspectable without overlap.
    label: pathEdgeIds.has(e.id) ? e.relationship : undefined,
    hidden:
      !visibleIds.has(e.source) ||
      !visibleIds.has(e.target) ||
      (showOnlyPath && Boolean(selectedPath) && !pathEdgeIds.has(e.id)) ||
      (evidenceState !== "ALL" && e.state !== evidenceState),
    markerEnd: {
      type: MarkerType.ArrowClosed,
      width: 14,
      height: 14,
      color: pathEdgeIds.has(e.id) ? "#3157d5" : "#8695a7"
    },
    style: {
      stroke: pathEdgeIds.has(e.id) ? "#3157d5" : "#8695a7",
      strokeWidth: pathEdgeIds.has(e.id) ? 2.3 : 1.2,
      strokeDasharray: e.state === "INFERRED" ? "5 4" : undefined
    },
    labelStyle: { fontSize: 11, fill: "#46556c" },
    labelBgPadding: [5, 3] as [number, number],
    labelBgBorderRadius: 3,
    labelBgStyle: { fill: "#f9fafc" },
    ariaLabel: `${e.relationship}, ${e.state.toLowerCase()} relationship`
  }));
  const fit = useCallback(() => {
    void instance?.fitView({
      padding: 0.08,
      duration: 200,
      maxZoom: 1,
      nodes:
        selectedPath && !query && type === "ALL"
          ? selectedPath.nodeIds.map((id) => ({ id }))
          : undefined
    });
  }, [instance, selectedPath, query, type]);
  useEffect(() => {
    if (instance) void instance.fitView({ padding: 0.08, maxZoom: 1, duration: 180 });
  }, [instance, showOnlyPath, selectedPathId, query, type]);
  function reset() {
    setQuery("");
    setType("ALL");
    setEvidenceState("ALL");
    setShowOnlyPath(false);
    setDetail(null);
    void instance?.fitView({ padding: 0.16, duration: 200, maxZoom: 1 });
  }
  const finding = detail?.node?.findingId
    ? result.findings.find((f) => f.id === detail.node!.findingId)
    : null;
  const asset = detail?.node?.assetId
    ? result.dataset.assets.find((a) => a.id === detail.node!.assetId)
    : null;
  const service = detail?.node?.serviceId
    ? result.dataset.services.find((s) => s.id === detail.node!.serviceId)
    : null;
  return (
    <div className="graph-content">
      <div className="graph-toolbar">
        <div className="search-field">
          <Search size={15} />
          <input
            aria-label="Search graph nodes"
            placeholder="Search nodes"
            className="field"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <select
          className="field"
          aria-label="Graph node type"
          value={type}
          onChange={(e) => setType(e.target.value)}
        >
          <option value="ALL">All node types</option>
          <option value="ASSET">Assets</option>
          <option value="NETWORK_SERVICE">Services</option>
          <option value="IDENTITY">Identities</option>
          <option value="FINDING">Findings</option>
          <option value="TARGET">Sensitive targets</option>
        </select>
        <select
          className="field"
          aria-label="Relationship evidence"
          value={evidenceState}
          onChange={(e) => setEvidenceState(e.target.value)}
        >
          <option value="ALL">All evidence</option>
          <option value="OBSERVED">Observed</option>
          <option value="INFERRED">Inferred</option>
        </select>
        <Button variant="ghost" size="sm" onClick={fit}>
          <Focus size={14} />
          Fit view
        </Button>
      </div>
      {selectedPath && (
        <div className="graph-path-bar">
          <span>Highlighted: {selectedPath.name}</span>
          <label>
            <input
              type="checkbox"
              checked={showOnlyPath}
              onChange={(e) => setShowOnlyPath(e.target.checked)}
            />
            Only this path
          </label>
        </div>
      )}
      <div
        className={`graph-canvas ${expanded ? "expanded-canvas" : ""}`}
        aria-label="Interactive exposure graph"
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onInit={setInstance}
          fitView
          fitViewOptions={{ padding: 0.08, maxZoom: 1 }}
          minZoom={0.15}
          maxZoom={2}
          nodesDraggable={false}
          onNodeClick={(_, n) => {
            const node = result.graph.nodes.find((item) => item.id === n.id)!;
            setDetail({ node });
            if (node.findingId) onFinding?.(node.findingId);
          }}
          onEdgeClick={(_, e) =>
            setDetail({ edge: result.graph.edges.find((item) => item.id === e.id)! })
          }
          onPaneClick={() => setDetail(null)}
          proOptions={{ hideAttribution: true }}
        >
          <Background gap={22} size={1} color="#d8dee7" />
          <Controls showInteractive={false} />
        </ReactFlow>
        {!visibleIds.size && (
          <div className="graph-no-match" role="status">
            No graph nodes match these filters.
            <Button variant="secondary" size="sm" onClick={reset}>
              Reset filters
            </Button>
          </div>
        )}
      </div>
      <div className="graph-legend">
        <span>
          <i className="legend-line" />
          Observed
        </span>
        <span>
          <i className="legend-line inferred" />
          Inferred
        </span>
        <span>◆ Sensitive target</span>
        <span>! Finding</span>
        <button className="text-link" onClick={reset}>
          Reset filters
        </button>
      </div>
      {detail && (
        <div className="graph-evidence" aria-label="Selected graph evidence">
          <button
            className="close-detail"
            aria-label="Close graph evidence"
            onClick={() => setDetail(null)}
          >
            <X size={17} />
          </button>
          <p className="eyebrow">
            {detail.edge ? `${detail.edge.state} RELATIONSHIP` : "NODE EVIDENCE"}
          </p>
          <h3>{detail.edge?.relationship ?? detail.node?.label}</h3>
          {detail.edge ? (
            <>
              <p>{detail.edge.evidence}</p>
              <span className="help">
                {detail.edge.confidence.toLowerCase()} confidence · {detail.edge.sourceName}
              </span>
            </>
          ) : (
            <>
              <p>
                {finding?.evidence ??
                  service?.evidence ??
                  asset?.evidence ??
                  "The Internet is the external entry point in the supplied exposure model."}
              </p>
              {finding && (
                <p className="mt-2">
                  <strong>Remediation:</strong> {finding.remediation}
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
