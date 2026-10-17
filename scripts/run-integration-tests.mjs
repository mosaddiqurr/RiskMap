import { existsSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const databaseFile = "prisma/integration.db";
for (const suffix of ["", "-journal", "-shm", "-wal"]) {
  const path = `${databaseFile}${suffix}`;
  if (existsSync(path)) rmSync(path, { force: true });
}
writeFileSync(databaseFile, "");

const env = {
  ...process.env,
  NODE_ENV: "test",
  DATABASE_URL: "file:./integration.db",
  SESSION_SECRET: "riskmap-integration-test-secret-1234567890",
  SCAN_MODE: "mock",
  RUN_INTEGRATION_TESTS: "1"
};

function run(command, args) {
  const result = spawnSync(command, args, {
    env,
    stdio: "inherit",
    windowsHide: true
  });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

run(process.execPath, ["node_modules/prisma/build/index.js", "migrate", "deploy"]);
run(process.execPath, [
  "node_modules/vitest/vitest.mjs",
  "run",
  "tests/integration",
  "--testTimeout",
  "30000"
]);
