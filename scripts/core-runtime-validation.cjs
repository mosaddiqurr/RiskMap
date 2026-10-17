#!/usr/bin/env node
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const ts = require("typescript");

const root = path.resolve(__dirname, "..");
const cache = new Map();
const prismaStub = {};
const envStub = {
  env: {
    SCAN_RESPONSE_LIMIT_BYTES: 65536,
    SCAN_TIMEOUT_MS: 5000,
    SCAN_MODE: "mock",
    SCAN_JOB_RETRY_BASE_MS: 10000,
    SCAN_JOB_TIMEOUT_MS: 300000,
    SCAN_JOB_MAX_ATTEMPTS: 3
  }
};
const utilsStub = {
  clamp(value, minimum = 0, maximum = 100) {
    return Math.min(maximum, Math.max(minimum, value));
  },
  parseJson(value, fallback) {
    try {
      return JSON.parse(value);
    } catch {
      return fallback;
    }
  }
};

function resolveLocal(specifier, parent) {
  if (specifier.startsWith("@/")) return path.join(root, specifier.slice(2));
  if (specifier.startsWith(".")) return path.resolve(path.dirname(parent), specifier);
  return null;
}

function withExtension(candidate) {
  for (const value of [
    candidate,
    `${candidate}.ts`,
    `${candidate}.tsx`,
    path.join(candidate, "index.ts")
  ]) {
    if (fs.existsSync(value) && fs.statSync(value).isFile()) return value;
  }
  throw new Error(`Unable to resolve local module ${candidate}`);
}

function loadModule(fileInput) {
  const file = withExtension(fileInput);
  if (cache.has(file)) return cache.get(file).exports;
  const module = { exports: {} };
  cache.set(file, module);
  const source = fs.readFileSync(file, "utf8");
  const compiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
      moduleResolution: ts.ModuleResolutionKind.Node10
    },
    fileName: file,
    reportDiagnostics: true
  });
  const diagnostics = compiled.diagnostics ?? [];
  const parseErrors = diagnostics.filter(
    (diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error
  );
  if (parseErrors.length) {
    throw new Error(
      parseErrors
        .map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"))
        .join("\n")
    );
  }

  function localRequire(specifier) {
    if (specifier === "@prisma/client") return prismaStub;
    if (specifier === "@/lib/db") return { prisma: prismaStub };
    if (specifier === "@/lib/env") return envStub;
    if (specifier === "@/lib/utils") return utilsStub;
    const local = resolveLocal(specifier, file);
    if (local) return loadModule(local);
    return require(specifier);
  }

  const wrapper = vm.runInThisContext(
    `(function(exports, require, module, __filename, __dirname){${compiled.outputText}\n})`,
    { filename: file }
  );
  wrapper(module.exports, localRequire, module, file, path.dirname(file));
  return module.exports;
}

let assertions = 0;
function check(condition, message) {
  assert.ok(condition, message);
  assertions += 1;
}
function equal(actual, expected, message) {
  assert.equal(actual, expected, message);
  assertions += 1;
}
function notEqual(actual, expected, message) {
  assert.notEqual(actual, expected, message);
  assertions += 1;
}

const identity = loadModule(path.join(root, "lib/scanning/identity.ts"));
const lifecycle = loadModule(path.join(root, "lib/scanning/lifecycle.ts"));
const attackPaths = loadModule(path.join(root, "lib/services/attack-paths.ts"));
const remediation = loadModule(path.join(root, "lib/services/remediation-impact.ts"));
const risk = loadModule(path.join(root, "lib/services/risk-scoring.ts"));
const safety = loadModule(path.join(root, "lib/scanning/network-safety.ts"));
const csv = loadModule(path.join(root, "lib/services/csv.ts"));
const verification = loadModule(path.join(root, "lib/services/domain-verification.ts"));
const reporting = loadModule(path.join(root, "lib/services/reporting.ts"));
const jobRuntime = loadModule(path.join(root, "lib/scanning/job-runtime.ts"));

// Stable identity and normalization.
equal(
  identity.normalizeHostname("BÜCHER.Example."),
  "xn--bcher-kva.example",
  "IDN normalization"
);
equal(
  identity.normalizeHostname("APP.EXAMPLE.TEST..."),
  "app.example.test",
  "hostname case and dots"
);
equal(identity.normalizeIpAddress("001.002.003.004"), "1.2.3.4", "IPv4 normalization");
const assetA = identity.createAssetFingerprint({
  organisationId: "org",
  type: "SUBDOMAIN",
  hostname: "APP.Example.test."
});
const assetB = identity.createAssetFingerprint({
  organisationId: "org",
  type: "SUBDOMAIN",
  hostname: "app.example.test"
});
equal(assetA, assetB, "equivalent assets share a fingerprint");
const serviceA = identity.createServiceFingerprint({
  organisationId: "org",
  assetFingerprint: assetA,
  port: 443,
  protocol: "HTTPS:",
  transport: "TCP"
});
const serviceB = identity.createServiceFingerprint({
  organisationId: "org",
  assetFingerprint: assetB,
  port: 443,
  protocol: "https",
  transport: "tcp"
});
equal(serviceA, serviceB, "equivalent services share a fingerprint");
notEqual(
  identity.createFindingFingerprint({
    organisationId: "org",
    assetFingerprint: assetA,
    ruleId: "http.csp",
    evidenceIdentity: "root"
  }),
  identity.createFindingFingerprint({
    organisationId: "org",
    assetFingerprint: assetA,
    ruleId: "http.hsts",
    evidenceIdentity: "root"
  }),
  "different rules do not collide"
);
const relationshipA = identity.createRelationshipFingerprint({
  organisationId: "org",
  fromFingerprint: assetA,
  toFingerprint: serviceA,
  type: "EXPOSES_SERVICE"
});
const relationshipB = identity.createRelationshipFingerprint({
  organisationId: "org",
  fromFingerprint: assetB,
  toFingerprint: serviceB,
  type: "exposes_service"
});
equal(relationshipA, relationshipB, "equivalent relationships share a fingerprint");
const pathA = identity.createAttackPathFingerprint({
  organisationId: "org",
  orderedNodeKeys: [assetA, serviceA],
  orderedEdgeKeys: [relationshipA]
});
const pathB = identity.createAttackPathFingerprint({
  organisationId: "org",
  orderedNodeKeys: [assetB, serviceB],
  orderedEdgeKeys: [relationshipB]
});
equal(pathA, pathB, "equivalent ordered paths share a fingerprint");

// Asset, service and finding lifecycle.
const discovered = lifecycle.applyPresenceLifecycle(null, true, 2);
equal(discovered.transition, "DISCOVERED", "new asset discovered");
const missed = lifecycle.applyPresenceLifecycle(discovered, false, 2);
equal(missed.transition, "MISSED", "first absence does not deactivate");
equal(missed.active, true, "asset remains active below threshold");
const inactive = lifecycle.applyPresenceLifecycle(missed, false, 2);
equal(inactive.transition, "INACTIVE", "second absence deactivates");
const reappeared = lifecycle.applyPresenceLifecycle(inactive, true, 2);
equal(reappeared.transition, "REAPPEARED", "inactive asset can reappear");
const findingCreated = lifecycle.applyFindingLifecycle(null, true, true, 1);
equal(findingCreated.status, "OPEN", "finding opens on first observation");
const preserved = lifecycle.applyFindingLifecycle(findingCreated, false, false, 1);
equal(preserved.transition, "PRESERVED", "failed module cannot resolve finding");
const resolved = lifecycle.applyFindingLifecycle(findingCreated, false, true, 1);
equal(resolved.status, "RESOLVED", "successful absence resolves finding");
const reopened = lifecycle.applyFindingLifecycle(resolved, true, true, 1);
equal(reopened.status, "REOPENED", "resolved finding reopens when observed");
equal(reopened.recurrenceCount, 1, "recurrence is counted");
equal(
  lifecycle.serviceStateTransition(true, "OPEN", true, "CLOSED", false),
  "CLOSED",
  "service close transition"
);

// Meaningful graph search, duplicate suppression and cycle prevention.
const nodes = [
  {
    id: "internet",
    key: "internet",
    label: "Internet",
    type: "INTERNET",
    isEntry: true,
    active: true
  },
  {
    id: "asset:public",
    key: "asset-public",
    label: "Public app",
    type: "WEB_APPLICATION",
    active: true,
    criticality: "HIGH"
  },
  {
    id: "service:web",
    key: "service-web",
    label: "HTTPS 443",
    type: "NETWORK_SERVICE",
    active: true,
    serviceId: "web",
    servicePort: 443
  },
  {
    id: "finding:shared",
    key: "finding-shared",
    label: "Shared weakness",
    type: "FINDING",
    active: true,
    findingId: "shared",
    findingSeverity: "HIGH"
  },
  {
    id: "asset:critical-a",
    key: "critical-a",
    label: "Admin",
    type: "CRITICAL_ASSET",
    active: true,
    critical: true,
    isTarget: true,
    criticality: "CRITICAL",
    administrative: true
  },
  {
    id: "asset:critical-b",
    key: "critical-b",
    label: "Customer API",
    type: "API_ENDPOINT",
    active: true,
    critical: true,
    isTarget: true,
    criticality: "CRITICAL",
    api: true
  }
];
const edges = [
  {
    id: "e1",
    key: "e1",
    source: "internet",
    target: "asset:public",
    relationship: "Internet reachable",
    confidence: "HIGH",
    state: "OBSERVED",
    evidence: "Public scope",
    active: true
  },
  {
    id: "e2",
    key: "e2",
    source: "asset:public",
    target: "service:web",
    relationship: "Exposes service",
    confidence: "HIGH",
    state: "OBSERVED",
    evidence: "TCP 443",
    active: true
  },
  {
    id: "e3",
    key: "e3",
    source: "service:web",
    target: "finding:shared",
    relationship: "Contains finding",
    confidence: "HIGH",
    state: "OBSERVED",
    evidence: "Header evidence",
    active: true
  },
  {
    id: "e4",
    key: "e4",
    source: "finding:shared",
    target: "asset:critical-a",
    relationship: "Could reach",
    confidence: "MEDIUM",
    state: "INFERRED",
    evidence: "Inventory dependency",
    active: true
  },
  {
    id: "e5",
    key: "e5",
    source: "finding:shared",
    target: "asset:critical-b",
    relationship: "Depends on",
    confidence: "MEDIUM",
    state: "INFERRED",
    evidence: "API dependency",
    active: true
  },
  {
    id: "cycle",
    key: "cycle",
    source: "asset:critical-a",
    target: "asset:public",
    relationship: "Cycle",
    confidence: "LOW",
    state: "INFERRED",
    evidence: "Cycle fixture",
    active: true
  }
];
const paths = attackPaths.findPotentialAttackPaths(nodes, edges, {
  maxDepth: 8,
  minimumConfidence: "LOW",
  requireFinding: true,
  requireTarget: true
});
equal(
  paths.length,
  2,
  "shared weakness creates two distinct paths without cycle expansion"
);
check(
  paths.every((path) => new Set(path.nodeIds).size === path.nodeIds.length),
  "paths contain no cycles"
);
check(paths[0].riskScore > 0, "path score is deterministic and positive");
check(
  attackPaths.shortestPotentialPath(paths).nodeIds.length >= 5,
  "shortest path remains meaningful"
);
const withoutInactiveEdge = attackPaths.findPotentialAttackPaths(
  nodes,
  edges.map((edge) => (edge.id === "e4" ? { ...edge, active: false } : edge)),
  { maxDepth: 8, minimumConfidence: "LOW", requireFinding: true, requireTarget: true }
);
equal(
  withoutInactiveEdge.length,
  1,
  "inactive relationships are excluded from path search"
);
const highConfidenceOnly = attackPaths.findPotentialAttackPaths(nodes, edges, {
  maxDepth: 8,
  minimumConfidence: "HIGH",
  requireFinding: true,
  requireTarget: true
});
equal(
  highConfidenceOnly.length,
  0,
  "confidence thresholds exclude lower-confidence path steps"
);

const scoringFinding = {
  id: "shared",
  severity: "HIGH",
  status: "OPEN",
  confidence: "HIGH",
  firstSeen: new Date("2026-01-01T00:00:00Z"),
  isNew: false,
  currentlyObserved: true,
  externallyReachable: true,
  asset: { criticality: "CRITICAL" },
  relatedFindingCount: 1,
  inAttackPath: true
};
const fixes = remediation.simulateBestNextFix({
  nodes,
  edges,
  currentPaths: paths,
  findings: [scoringFinding],
  candidates: [
    {
      findingId: "shared",
      title: "Fix shared weakness",
      assetName: "Public app",
      difficulty: "Low",
      severity: "HIGH",
      assetCriticality: "CRITICAL",
      confidence: "HIGH"
    }
  ]
});
equal(fixes[0].attackPathsReduced, 2, "fixing a shared weakness removes multiple paths");
check(
  fixes[0].estimatedRiskAfterFix < fixes[0].currentRisk,
  "remediation lowers organisation risk"
);
check(
  risk.calculateOrganisationRisk([scoringFinding]).score > 0,
  "organisation risk score is non-zero for material exposure"
);
equal(
  risk.calculateOrganisationRisk([{ ...scoringFinding, currentlyObserved: false }]).score,
  0,
  "unobserved finding does not contribute risk"
);

// SSRF and export controls.
for (const ip of [
  "127.0.0.1",
  "10.0.0.1",
  "169.254.169.254",
  "::1",
  "fe80::1",
  "::ffff:127.0.0.1",
  "2130706433"
]) {
  check(safety.isPrivateOrReservedIp(ip), `${ip} is blocked`);
}
equal(
  safety.isPrivateOrReservedIp("8.8.8.8"),
  false,
  "public IPv4 is allowed by range check"
);
check(safety.isBlockedHostname("metadata.google.internal"), "metadata hostname blocked");
check(safety.isBlockedHostname("admin.localhost"), "localhost-style hostname blocked");
assert.throws(() => safety.validatePublicUrl("http://127.0.0.1"));
assertions += 1;
assert.throws(() => safety.validatePublicUrl("http://169.254.169.254/latest/meta-data"));
assertions += 1;
equal(csv.sanitizeCsvCell("=SUM(A1:A2)"), "'=SUM(A1:A2)", "CSV formula is neutralised");
check(
  verification.matchesDnsVerification(
    [["riskmap-verification=abc"]],
    "riskmap-verification=abc"
  ),
  "DNS challenge matches exact token"
);
equal(
  verification.matchesFileVerification("abc\n", "riskmap-verification=abc"),
  true,
  "HTML file verification accepts bare token value"
);
equal(
  reporting.safeExportFilename("../../Northstar / Q3"),
  "northstar-q3",
  "report filenames are path-safe"
);
const reportSnapshot = {
  organisation: "Northstar Labs",
  type: "TECHNICAL",
  generatedAt: "2026-07-26T00:00:00.000Z",
  reportingPeriod: { start: "2026-06-26T00:00:00.000Z", end: "2026-07-26T00:00:00.000Z" },
  riskScore: 42,
  previousRiskScore: 36,
  summary: "Observed evidence only.",
  topFindings: [],
  assets: [],
  potentialAttackPaths: [],
  methodology: "Deterministic.",
  limitations: "Requires validation.",
  authorisedUse: "Authorised use only.",
  fictionalDemoData: true
};
equal(
  reporting.parseStoredReport(JSON.stringify(reportSnapshot)).riskScore,
  42,
  "stored report snapshots parse without live regeneration"
);
assert.throws(() => reporting.parseStoredReport("{}"));
assertions += 1;
equal(
  jobRuntime.isRetryableScanError(new Error("temporary resolver failure")),
  true,
  "transient scan errors are retryable"
);
equal(
  jobRuntime.isRetryableScanError(new Error("DOMAIN_NOT_VERIFIED")),
  false,
  "authorisation failures are not retried"
);
equal(
  jobRuntime.scanRetryDelayMs(3),
  40000,
  "retry delay uses bounded exponential backoff"
);

console.log(JSON.stringify({ status: "passed", assertions }, null, 2));
