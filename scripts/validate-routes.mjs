import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const appRoot = path.join(root, "app");
const sourceRoots = [path.join(root, "app"), path.join(root, "components")];

function walk(directory, result = []) {
  if (!fs.existsSync(directory)) return result;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (["node_modules", ".next", ".git"].includes(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(absolute, result);
    else result.push(absolute);
  }
  return result;
}

function routeFromFile(file, endpointFile) {
  const relative = path.relative(appRoot, path.dirname(file));
  const segments = relative
    .split(path.sep)
    .filter((segment) => segment && !/^\(.+\)$/.test(segment));
  if (endpointFile && segments[0] === "api") return `/${segments.join("/")}`;
  if (segments[0] === "api") return null;
  return segments.length ? `/${segments.join("/")}` : "/";
}

const pageRoutes = walk(appRoot)
  .filter((file) => path.basename(file) === "page.tsx")
  .map((file) => routeFromFile(file, false))
  .filter(Boolean);
const apiRoutes = walk(path.join(appRoot, "api"))
  .filter((file) => path.basename(file) === "route.ts")
  .map((file) => routeFromFile(file, true))
  .filter(Boolean);

function matchesRoute(reference, candidates) {
  return candidates.some((candidate) => {
    const pattern = `^${candidate.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\\[[^/]+\\\]/g, "[^/]+")}$`;
    return new RegExp(pattern).test(reference);
  });
}

const missingPages = new Set();
const missingApis = new Set();
for (const file of sourceRoots
  .flatMap((directory) => walk(directory))
  .filter((file) => /\.(ts|tsx)$/.test(file))) {
  const content = fs.readFileSync(file, "utf8");
  for (const match of content.matchAll(
    /(?:href=|router\.(?:push|replace)\()\s*["'](\/[A-Za-z0-9_\-/]+)["']/g
  )) {
    const route = match[1];
    if (route?.startsWith("/api/")) continue;
    if (route && !matchesRoute(route, pageRoutes))
      missingPages.add(`${path.relative(root, file)} -> ${route}`);
  }
  for (const match of content.matchAll(/fetch\(\s*["'](\/api\/[A-Za-z0-9_\-/]+)["']/g)) {
    const route = match[1];
    if (route && !matchesRoute(route, apiRoutes))
      missingApis.add(`${path.relative(root, file)} -> ${route}`);
  }
}

if (missingPages.size || missingApis.size) {
  if (missingPages.size)
    console.error(`Missing page routes:\n${[...missingPages].join("\n")}`);
  if (missingApis.size)
    console.error(`Missing API routes:\n${[...missingApis].join("\n")}`);
  process.exit(1);
}
console.log(
  `Route validation passed: ${pageRoutes.length} pages and ${apiRoutes.length} API endpoints checked.`
);
