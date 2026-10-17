import { afterEach, describe, expect, it } from "vitest";
import { rm, utimes, writeFile } from "node:fs/promises";
import path from "node:path";
import { env } from "@/lib/env";
import {
  acquireWorkerLock,
  readWorkerHeartbeat,
  releaseWorkerLock,
  removeWorkerHeartbeat,
  workerHeartbeatIsFresh,
  writeWorkerHeartbeat
} from "@/lib/worker/coordination";

function absolute(value: string) {
  return path.isAbsolute(value) ? value : path.join(process.cwd(), value);
}

const lockPath = absolute(env.WORKER_LOCK_FILE);
const heartbeatPath = absolute(env.WORKER_HEARTBEAT_FILE);

afterEach(async () => {
  await Promise.all([
    rm(lockPath, { force: true }),
    removeWorkerHeartbeat(),
    rm(heartbeatPath, { force: true })
  ]);
});

describe("single-worker coordination", () => {
  it("writes and reads a fresh heartbeat", async () => {
    const written = await writeWorkerHeartbeat(2);
    const read = await readWorkerHeartbeat();
    expect(read).toMatchObject({ workerId: written.workerId, activeJobs: 2 });
    expect(workerHeartbeatIsFresh(read)).toBe(true);
    expect(
      workerHeartbeatIsFresh(
        read,
        Date.parse(written.heartbeatAt) + env.WORKER_STALE_AFTER_MS + 1
      )
    ).toBe(false);
  });

  it("prevents a second active local worker", async () => {
    const first = await acquireWorkerLock();
    await expect(acquireWorkerLock()).rejects.toThrow(/another riskmap worker/i);
    await releaseWorkerLock(first);
  });

  it("does not steal a live worker lock after its age threshold", async () => {
    const first = await acquireWorkerLock();
    const stale = new Date(Date.now() - env.WORKER_STALE_AFTER_MS - 1_000);
    await utimes(first, stale, stale);
    await expect(acquireWorkerLock()).rejects.toThrow(/another riskmap worker/i);
    await releaseWorkerLock(first);
  });

  it("recovers an abandoned stale lock", async () => {
    await writeFile(lockPath, JSON.stringify({ workerId: "abandoned" }));
    const stale = new Date(Date.now() - env.WORKER_STALE_AFTER_MS - 1_000);
    await utimes(lockPath, stale, stale);
    const recovered = await acquireWorkerLock();
    expect(recovered).toBe(lockPath);
    await releaseWorkerLock(recovered);
  });
});
