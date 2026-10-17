import { randomUUID } from "node:crypto";
import { mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { env } from "@/lib/env";

export type WorkerHeartbeat = {
  workerId: string;
  pid: number;
  startedAt: string;
  heartbeatAt: string;
  scanMode: string;
  activeJobs: number;
};

type WorkerLock = {
  workerId: string;
  pid: number;
  acquiredAt: string;
};

export const workerId = `${process.pid}-${randomUUID()}`;
const startedAt = new Date().toISOString();

function absoluteRuntimePath(value: string) {
  return path.isAbsolute(value) ? value : path.join(process.cwd(), value);
}

export async function writeWorkerHeartbeat(activeJobs: number) {
  const target = absoluteRuntimePath(env.WORKER_HEARTBEAT_FILE);
  await mkdir(path.dirname(target), { recursive: true });
  const temporary = `${target}.${process.pid}.tmp`;
  const heartbeat: WorkerHeartbeat = {
    workerId,
    pid: process.pid,
    startedAt,
    heartbeatAt: new Date().toISOString(),
    scanMode: env.SCAN_MODE,
    activeJobs
  };
  await writeFile(temporary, JSON.stringify(heartbeat, null, 2), { mode: 0o600 });
  await rename(temporary, target);
  return heartbeat;
}

export async function readWorkerHeartbeat(): Promise<WorkerHeartbeat | null> {
  try {
    const raw = await readFile(absoluteRuntimePath(env.WORKER_HEARTBEAT_FILE), "utf8");
    const heartbeat = JSON.parse(raw) as WorkerHeartbeat;
    if (
      typeof heartbeat.workerId !== "string" ||
      typeof heartbeat.heartbeatAt !== "string" ||
      typeof heartbeat.activeJobs !== "number"
    ) {
      return null;
    }
    return heartbeat;
  } catch {
    return null;
  }
}

export function workerHeartbeatIsFresh(
  heartbeat: WorkerHeartbeat | null,
  now = Date.now()
) {
  if (!heartbeat) return false;
  const timestamp = Date.parse(heartbeat.heartbeatAt);
  return Number.isFinite(timestamp) && now - timestamp <= env.WORKER_STALE_AFTER_MS;
}

function processIsAlive(pid: number) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

async function readWorkerLock(target: string): Promise<WorkerLock | null> {
  try {
    const value = JSON.parse(await readFile(target, "utf8")) as Partial<WorkerLock>;
    return typeof value.workerId === "string" &&
      typeof value.pid === "number" &&
      typeof value.acquiredAt === "string"
      ? (value as WorkerLock)
      : null;
  } catch {
    return null;
  }
}

export async function acquireWorkerLock() {
  const target = absoluteRuntimePath(env.WORKER_LOCK_FILE);
  await mkdir(path.dirname(target), { recursive: true });

  try {
    const handle = await open(target, "wx", 0o600);
    await handle.writeFile(
      JSON.stringify({ workerId, pid: process.pid, acquiredAt: new Date().toISOString() })
    );
    await handle.close();
    return target;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "EEXIST") throw error;
    try {
      const [lockStat, lock, heartbeat] = await Promise.all([
        stat(target),
        readWorkerLock(target),
        readWorkerHeartbeat()
      ]);
      if (
        (lock && processIsAlive(lock.pid)) ||
        (lock &&
          heartbeat?.workerId === lock.workerId &&
          workerHeartbeatIsFresh(heartbeat)) ||
        Date.now() - lockStat.mtimeMs <= env.WORKER_STALE_AFTER_MS
      ) {
        throw new Error("Another RiskMap worker holds the local worker lock.");
      }
      await rm(target, { force: true });
      return acquireWorkerLock();
    } catch (statError) {
      if ((statError as NodeJS.ErrnoException).code === "ENOENT")
        return acquireWorkerLock();
      throw statError;
    }
  }
}

export async function removeWorkerHeartbeat() {
  const target = absoluteRuntimePath(env.WORKER_HEARTBEAT_FILE);
  const heartbeat = await readWorkerHeartbeat();
  if (heartbeat?.workerId === workerId) await rm(target, { force: true });
}

export async function releaseWorkerLock(lockPath: string | null) {
  if (!lockPath) return;
  const lock = await readWorkerLock(lockPath);
  if (lock?.workerId === workerId) await rm(lockPath, { force: true });
}
