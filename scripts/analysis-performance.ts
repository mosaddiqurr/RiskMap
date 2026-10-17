import { mkdir, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { analyzeDataset } from "../lib/analysis/analyze";
import { demoDataset } from "../lib/analysis/demo";
import { parseDataset, type Dataset } from "../lib/analysis/dataset";

const results: Array<{
  scenario: string;
  assets: number;
  findings: number;
  paths: number;
  truncated: boolean;
  milliseconds: number;
}> = [];
function measure(scenario: string, dataset: Dataset) {
  const start = performance.now();
  const result = analyzeDataset(
    parseDataset(JSON.stringify(dataset)),
    new Date("2026-10-04T08:00:00Z")
  );
  const milliseconds = Number((performance.now() - start).toFixed(2));
  results.push({
    scenario,
    assets: dataset.assets.length,
    findings: dataset.findings.length,
    paths: result.paths.length,
    truncated: result.search.truncated,
    milliseconds
  });
  if (milliseconds > 10_000)
    throw new Error(`${scenario} exceeded the 10 second local analysis budget.`);
  return result;
}
measure("Fictional demo", demoDataset);
const large: Dataset = {
  version: 1,
  name: "Bounded synthetic input",
  assets: [],
  services: [],
  findings: [],
  relationships: []
};
for (let i = 0; i < 100; i++) {
  const id = `asset-${i}`;
  large.assets.push({
    id,
    name: `ASSET-${i}`,
    type: i % 10 === 9 ? "CRITICAL_ASSET" : "WEB_APPLICATION",
    criticality: i % 10 === 9 ? "CRITICAL" : "HIGH",
    public: i % 10 === 0,
    evidence: "Synthetic performance inventory."
  });
  for (let j = 0; j < 2; j++) {
    const serviceId = `service-${i}-${j}`;
    large.services.push({
      id: serviceId,
      assetId: id,
      port: j ? 443 : 22,
      protocol: j ? "https" : "ssh",
      confidence: "HIGH",
      evidence: "Synthetic performance service."
    });
    large.findings.push({
      id: `finding-${i}-${j}`,
      assetId: id,
      serviceId,
      title: `Synthetic weakness ${i}-${j}`,
      severity: "HIGH",
      confidence: "HIGH",
      category: "Network exposure",
      description: "Performance fixture only.",
      evidence: "Synthetic finding evidence.",
      remediation: "Restrict the synthetic exposure."
    });
  }
  if (i % 10 !== 9)
    for (let j = 0; j < 3; j++)
      large.relationships.push({
        id: `relationship-${i}-${j}`,
        from: id,
        to: `asset-${Math.min(i + 1 + j, Math.floor(i / 10) * 10 + 9)}`,
        type: "Could reach",
        state: "INFERRED",
        confidence: "MEDIUM",
        evidence: "Synthetic dependency.",
        viaFindingId: j < 2 ? `finding-${i}-${j % 2}` : undefined
      });
}
const bounded = measure("Maximum inventory / dense relationships", large);
if (!bounded.search.truncated) console.log("This fixture completed within search bounds.");
async function saveResults() {
  await mkdir(".runtime", { recursive: true });
  await writeFile(
    ".runtime/analysis-performance.json",
    JSON.stringify({ measuredAt: new Date().toISOString(), results }, null, 2)
  );
  console.table(results);
}
void saveResults().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
