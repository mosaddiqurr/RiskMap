import { spawn } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  openSync,
  closeSync,
  readFileSync,
  writeFileSync,
  unlinkSync
} from "node:fs";
import path from "node:path";

const root = process.cwd();
const runtimeDirectory = path.join(root, ".runtime");
const pidFile = path.join(runtimeDirectory, "analysis-server.json");
const action = process.argv[2] || "status";
const port = Number(process.env.PORT || 3000);
if (!Number.isInteger(port) || port < 1024 || port > 65535)
  throw new Error("Choose a PORT between 1024 and 65535.");
function readRecord() {
  try {
    const record = JSON.parse(readFileSync(pidFile, "utf8"));
    return path.resolve(record.root) === path.resolve(root) ? record : null;
  } catch {
    return null;
  }
}
function isAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}
async function isReady(url) {
  try {
    const response = await fetch(`${url}/api/health`, {
      signal: AbortSignal.timeout(1500)
    });
    return response.ok && (await response.json()).mode === "stateless-analysis";
  } catch {
    return false;
  }
}
const record = readRecord();
async function start() {
  if (record && isAlive(record.pid)) {
    console.log(`RiskMap analysis server is already running: ${record.url}`);
    return;
  }
  if (!existsSync(path.join(root, ".next", "BUILD_ID")))
    throw new Error("Run npm run build before starting the production preview.");
  const url = `http://127.0.0.1:${port}`;
  if (await isReady(url)) {
    console.log(
      `A RiskMap analysis server already responds at ${url}; it is not owned by this helper.`
    );
    return;
  }
  mkdirSync(runtimeDirectory, { recursive: true });
  const out = openSync(path.join(runtimeDirectory, "analysis-web.out.log"), "a");
  const err = openSync(path.join(runtimeDirectory, "analysis-web.err.log"), "a");
  const child = spawn(
    process.execPath,
    ["scripts/start-production.mjs", "--hostname", "127.0.0.1", "--port", String(port)],
    {
      cwd: root,
      env: { ...process.env, NODE_ENV: "production" },
      stdio: ["ignore", out, err],
      detached: true,
      windowsHide: true
    }
  );
  closeSync(out);
  closeSync(err);
  if (!child.pid) throw new Error("The analysis server could not be started.");
  child.on("error", (error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
  child.unref();
  writeFileSync(
    pidFile,
    JSON.stringify(
      { root, pid: child.pid, url, startedAt: new Date().toISOString() },
      null,
      2
    )
  );
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (await isReady(url)) {
      console.log(`RiskMap analysis server is ready: ${url}`);
      // Let pending Windows I/O close naturally instead of forcing a libuv shutdown.
      return;
    }
    if (!isAlive(child.pid))
      throw new Error("Server startup failed; inspect .runtime/analysis-web.err.log.");
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("Server startup did not become ready in 30 seconds.");
}
if (action === "status") {
  console.log(
    record && isAlive(record.pid)
      ? `RiskMap analysis server: ${record.url}`
      : "No owned analysis server is running."
  );
} else if (action === "stop") {
  if (record && isAlive(record.pid)) {
    process.kill(record.pid, "SIGTERM");
    console.log("Stopped the owned RiskMap analysis server.");
  }
  if (record) unlinkSync(pidFile);
} else if (action === "start") {
  await start();
} else {
  throw new Error("Use start, stop or status.");
}
