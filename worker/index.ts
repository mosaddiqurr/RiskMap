import { prisma } from "../lib/db";
import { env } from "../lib/env";
import { logger } from "../lib/observability/logger";
import { recoverStaleScanJobs } from "../lib/scanning/job-runtime";
import { claimNextScanJob, processScanJob } from "../lib/scanning/processor";
import { queueDueScheduledScans } from "../lib/services/scans";
import {
  acquireWorkerLock,
  releaseWorkerLock,
  removeWorkerHeartbeat,
  workerId,
  writeWorkerHeartbeat
} from "../lib/worker/coordination";

let stopping = false;
let lastMaintenanceSweep = 0;
let lockPath: string | null = null;
let heartbeatTimer: NodeJS.Timeout | null = null;
const activeJobs = new Map<string, Promise<void>>();

async function heartbeat() {
  await writeWorkerHeartbeat(activeJobs.size).catch((error) => {
    logger.warn("worker heartbeat write failed", { workerId, error });
  });
}

async function maintenanceSweep() {
  if (Date.now() - lastMaintenanceSweep < 60_000) return;
  const queued = await queueDueScheduledScans();
  const recovered = await recoverStaleScanJobs(new Set(activeJobs.keys()));
  if (queued || recovered.retried || recovered.failed) {
    logger.info("worker maintenance completed", {
      workerId,
      scheduledScansQueued: queued,
      staleJobsRetried: recovered.retried,
      staleJobsFailed: recovered.failed
    });
  }
  lastMaintenanceSweep = Date.now();
}

async function tick() {
  await maintenanceSweep();
  while (!stopping && activeJobs.size < env.SCAN_MAX_CONCURRENCY) {
    const job = await claimNextScanJob();
    if (!job) break;

    const task = processScanJob(job.id)
      .then((result) => {
        logger.info("scan job finished", {
          workerId,
          jobId: job.id,
          scanId: job.scanId,
          correlationId: job.scanId,
          result
        });
      })
      .catch((error) => {
        logger.error("scan job failed", {
          workerId,
          jobId: job.id,
          scanId: job.scanId,
          correlationId: job.scanId,
          error
        });
      })
      .finally(async () => {
        activeJobs.delete(job.id);
        await heartbeat();
      });

    activeJobs.set(job.id, task);
    logger.info("scan job claimed", {
      workerId,
      jobId: job.id,
      scanId: job.scanId,
      correlationId: job.scanId,
      attempts: job.attempts
    });
  }
}

async function shutdown() {
  stopping = true;
  if (heartbeatTimer) clearInterval(heartbeatTimer);
  await Promise.allSettled(activeJobs.values());
  if (lockPath) {
    await removeWorkerHeartbeat();
    await releaseWorkerLock(lockPath);
    lockPath = null;
  }
  await prisma.$disconnect();
}

async function main() {
  lockPath = await acquireWorkerLock();
  logger.info("RiskMap scan worker started", {
    workerId,
    pid: process.pid,
    scanMode: env.SCAN_MODE,
    maxConcurrency: env.SCAN_MAX_CONCURRENCY
  });
  await heartbeat();
  heartbeatTimer = setInterval(() => void heartbeat(), env.WORKER_HEARTBEAT_INTERVAL_MS);
  heartbeatTimer.unref();

  while (!stopping) {
    await tick();
    await new Promise((resolve) => setTimeout(resolve, env.SCAN_WORKER_POLL_MS));
  }
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    logger.info("worker shutdown requested", { workerId, signal });
    stopping = true;
  });
}

main()
  .catch((error) => {
    logger.error("worker fatal error", { workerId, error });
    process.exitCode = 1;
  })
  .finally(shutdown);
