const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ts = require("typescript");
const root = process.cwd();
const ignoredDirectories = new Set([
  "node_modules",
  "legacy",
  ".runtime",
  ".next",
  ".git",
  "coverage",
  "playwright-report",
  "test-results"
]);

function walk(directory, result = []) {
  if (!fs.existsSync(directory)) return result;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (ignoredDirectories.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(absolute, result);
    else result.push(absolute);
  }
  return result;
}

function resolveProjectImport(specifier) {
  const base = path.join(root, specifier.slice(2));
  const candidates = [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    `${base}.js`,
    `${base}.mjs`,
    `${base}.cjs`,
    path.join(base, "index.ts"),
    path.join(base, "index.tsx"),
    path.join(base, "index.js")
  ];
  return candidates.find((candidate) => fs.existsSync(candidate));
}

const sourceFiles = walk(root).filter((file) => /\.(ts|tsx)$/.test(file));
const syntaxErrors = [];
const missingImports = [];
for (const file of sourceFiles) {
  const source = fs.readFileSync(file, "utf8");
  const isTsx = file.endsWith(".tsx");
  const sourceFile = ts.createSourceFile(
    file,
    source,
    ts.ScriptTarget.Latest,
    true,
    isTsx ? ts.ScriptKind.TSX : ts.ScriptKind.TS
  );
  for (const diagnostic of sourceFile.parseDiagnostics ?? []) {
    const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
    const location =
      diagnostic.start === undefined
        ? ""
        : (() => {
            const point = sourceFile.getLineAndCharacterOfPosition(diagnostic.start);
            return `:${point.line + 1}:${point.character + 1}`;
          })();
    syntaxErrors.push(`${path.relative(root, file)}${location} ${message}`);
  }

  for (const match of source.matchAll(/(?:from\s+|import\s*\()(["'])(@\/[^"']+)\1/g)) {
    const specifier = match[2];
    if (!resolveProjectImport(specifier)) {
      missingImports.push(`${path.relative(root, file)} -> ${specifier}`);
    }
  }
}

const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const requiredScripts = [
  "dev",
  "worker",
  "typecheck",
  "lint",
  "format",
  "format:check",
  "test",
  "build",
  "test:e2e",
  "seed",
  "db:generate",
  "db:migrate",
  "validate",
  "validate:lock"
];
const missingScripts = requiredScripts.filter((script) => !packageJson.scripts?.[script]);

const envText =
  fs.readFileSync(path.join(root, ".env.example"), "utf8") +
  fs.readFileSync(path.join(root, ".env.compatibility.example"), "utf8");
const envKeys = new Set(
  envText
    .split(/\r?\n/)
    .map((line) => line.match(/^([A-Z][A-Z0-9_]*)=/)?.[1])
    .filter(Boolean)
);
const usedEnvKeys = new Set();
for (const file of sourceFiles) {
  const source = fs.readFileSync(file, "utf8");
  for (const match of source.matchAll(/\benv\.([A-Z][A-Z0-9_]*)\b/g))
    usedEnvKeys.add(match[1]);
  for (const match of source.matchAll(/process\.env\.([A-Z][A-Z0-9_]*)\b/g))
    usedEnvKeys.add(match[1]);
}
const missingEnvKeys = [...usedEnvKeys].filter(
  (key) => !envKeys.has(key) && !["RUN_INTEGRATION_TESTS", "CI"].includes(key)
);

const schema = fs.readFileSync(path.join(root, "prisma/schema.prisma"), "utf8");
const requiredModels = [
  "AssetPresence",
  "Service",
  "ServicePresence",
  "FindingObservation",
  "ScanModuleResult",
  "TechnologyObservation",
  "AttackPathObservation"
];
const missingModels = requiredModels.filter(
  (model) => !new RegExp(`model\\s+${model}\\s+\\{`).test(schema)
);
const requiredSchemaFields = [
  "fingerprint",
  "consecutivePresenceCount",
  "consecutiveAbsenceCount",
  "currentlyObserved",
  "recurrenceCount",
  "resolutionScanId"
];
const missingFields = requiredSchemaFields.filter(
  (field) => !new RegExp(`\\b${field}\\b`).test(schema)
);

const migration = fs.readFileSync(
  path.join(root, "prisma/migrations/20260725000000_init/migration.sql"),
  "utf8"
);
const migrationTables = [...migration.matchAll(/CREATE TABLE\s+"([^"]+)"/g)].map(
  (match) => match[1]
);
const migrationIndexes = [...migration.matchAll(/CREATE (?:UNIQUE )?INDEX/g)].length;

const lock = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
const expectedDeps = { ...packageJson.dependencies, ...packageJson.devDependencies };
const lockPackages = lock.packages ?? {};
const lockIsComplete = Object.keys(expectedDeps).every((name) =>
  Boolean(lockPackages[`node_modules/${name}`])
);

if (
  syntaxErrors.length ||
  missingImports.length ||
  missingScripts.length ||
  missingEnvKeys.length ||
  missingModels.length ||
  missingFields.length
) {
  if (syntaxErrors.length)
    console.error(`TypeScript syntax errors:\n${syntaxErrors.join("\n")}`);
  if (missingImports.length)
    console.error(`Missing internal imports:\n${missingImports.join("\n")}`);
  if (missingScripts.length)
    console.error(`Missing package scripts: ${missingScripts.join(", ")}`);
  if (missingEnvKeys.length)
    console.error(`Missing .env.example keys: ${missingEnvKeys.join(", ")}`);
  if (missingModels.length)
    console.error(`Missing Prisma models: ${missingModels.join(", ")}`);
  if (missingFields.length)
    console.error(`Missing lifecycle fields: ${missingFields.join(", ")}`);
  process.exit(1);
}

const harness = spawnSync(process.execPath, ["scripts/core-runtime-validation.cjs"], {
  cwd: root,
  encoding: "utf8"
});
if (harness.status !== 0) {
  process.stderr.write(harness.stdout);
  process.stderr.write(harness.stderr);
  process.exit(harness.status ?? 1);
}

console.log(
  `Phase 2 validation passed: ${sourceFiles.length} TypeScript/TSX files parsed.`
);
console.log(
  `Internal alias imports resolved and ${requiredScripts.length} required scripts are present.`
);
console.log(
  `Prisma Phase 2 structure contains ${requiredModels.length} required lifecycle models.`
);
console.log(
  `Migration declares ${migrationTables.length} tables and ${migrationIndexes} indexes.`
);
process.stdout.write(harness.stdout);
if (!lockIsComplete) {
  console.warn(
    "WARNING: package-lock.json is not a complete npm dependency lock. Regenerate it with npm install when the registry is available."
  );
}
