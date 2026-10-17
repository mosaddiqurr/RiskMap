import fs from "node:fs";

const packageJson = JSON.parse(fs.readFileSync("package.json", "utf8"));
const packageLock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));
const root = packageLock.packages?.[""];

if (!root) {
  console.error("package-lock.json does not contain a root package manifest.");
  process.exit(1);
}

const expected = {
  ...packageJson.dependencies,
  ...packageJson.devDependencies
};
const missing = Object.keys(expected).filter(
  (name) => !packageLock.packages?.[`node_modules/${name}`]
);
const mismatched = Object.entries(expected)
  .filter(([name, version]) => {
    const group = packageJson.dependencies?.[name] ? "dependencies" : "devDependencies";
    return root[group]?.[name] !== version;
  })
  .map(([name]) => name);
const installedEntries = Object.keys(packageLock.packages ?? {}).filter((key) =>
  key.startsWith("node_modules/")
);

if (
  packageLock.lockfileVersion !== 3 ||
  root.version !== packageJson.version ||
  missing.length ||
  mismatched.length ||
  installedEntries.length < Object.keys(expected).length
) {
  console.error("package-lock.json is incomplete or out of sync with package.json.");
  console.error(
    JSON.stringify(
      {
        packageVersion: packageJson.version,
        lockVersion: root.version,
        missingDirectPackages: missing,
        mismatchedRootEntries: mismatched,
        lockedNodeModuleEntries: installedEntries.length
      },
      null,
      2
    )
  );
  console.error("Run npm install successfully, then commit the regenerated lockfile.");
  process.exit(1);
}

console.log(
  `Lockfile validation passed: ${installedEntries.length} node_modules entries are recorded.`
);
