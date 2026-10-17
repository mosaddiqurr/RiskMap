import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const required = [
  "app/(public)/page.tsx",
  "app/(public)/analyze/page.tsx",
  "app/(public)/exposure-map/page.tsx",
  "app/(public)/report/page.tsx",
  "app/(public)/about/page.tsx",
  "app/api/analyze/route.ts",
  "components/analysis/workspace.tsx",
  "lib/analysis/dataset.ts",
  "lib/analysis/analyze.ts",
  "public/favicon.svg",
  "public/demo-dataset.json",
  "prisma/schema.prisma",
  "prisma/seed.ts",
  ".env.example",
  "Dockerfile",
  "docker-compose.yml"
];

const missing = required.filter((file) => !fs.existsSync(path.join(root, file)));
const allFiles = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (
      [
        "node_modules",
        ".next",
        ".git",
        "legacy",
        ".runtime",
        "test-results",
        "playwright-report"
      ].includes(entry.name)
    )
      continue;
    const absolute = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(absolute);
    else allFiles.push(absolute);
  }
}
walk(root);
const forbidden = [];
for (const file of allFiles.filter((file) => /\.(tsx?|md|css)$/.test(file))) {
  const content = fs.readFileSync(file, "utf8");
  if (/lorem ipsum/i.test(content)) forbidden.push(path.relative(root, file));
}
if (missing.length || forbidden.length) {
  if (missing.length) console.error("Missing required files:\n" + missing.join("\n"));
  if (forbidden.length)
    console.error("Forbidden placeholder text found:\n" + forbidden.join("\n"));
  process.exit(1);
}
console.log(
  `Structure validation passed: ${required.length} required files and ${allFiles.length} total files checked.`
);
