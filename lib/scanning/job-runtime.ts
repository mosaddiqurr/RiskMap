import { JobStatus, ScanStatus } from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";

const nonRetryableMessages = [
  "Domain is not verified",
  "Explicit active-check authorisation is required",
  "The verified root domain is excluded from scanning",
  "DOMAIN_NOT_VERIFIED",
  "FORBIDDEN",
  "NOT_FOUND"
];

export function isRetryableScanError(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return !nonRetryableMessages.some((candidate) => message.includes(candidate));
}

export function scanRetryDelayMs(attempt: number) {
  const exponent = Math.max(0, attempt - 1);
  return Math.min(env.SCAN_JOB_RETRY_BASE_MS * 2 ** exponent, 15 * 60_000);
}

export async function scheduleScanJobRetry(input: {
  jobId: string;
  scanId: string;
  attempt: number;
  error: string;
}) {
  const availableAt = new Date(Date.now() + scanRetryDelayMs(input.attempt));
  await prisma.$transaction([
    prisma.scan.update({
      where: { id: input.scanId },
      data: {
        status: ScanStatus.QUEUED,
        progress: 0,
        startedAt: null,
        completedAt: null,
        error: `Retry scheduled after attempt ${input.attempt}: ${input.error}`
      }
    }),
    prisma.scanJob.update({
      where: { id: input.jobId },
      data: {
        status: JobStatus.QUEUED,
        availableAt,
        lockedAt: null,
        lastError: input.error
      }
    })
  ]);
  return availableAt;
}

export async function recoverStaleScanJobs(activeJobIds: ReadonlySet<string> = new Set()) {
  const staleBefore = new Date(Date.now() - env.SCAN_JOB_TIMEOUT_MS);
  const staleJobs = await prisma.scanJob.findMany({
    where: {
      status: JobStatus.RUNNING,
      lockedAt: { lt: staleBefore }
    },
    include: { scan: true }
  });

  let retried = 0;
  let failed = 0;
  for (const job of staleJobs) {
    if (activeJobIds.has(job.id)) continue;
    const message = `Worker lock exceeded ${env.SCAN_JOB_TIMEOUT_MS} ms and was recovered.`;
    if (job.attempts < env.SCAN_JOB_MAX_ATTEMPTS) {
      await scheduleScanJobRetry({
        jobId: job.id,
        scanId: job.scanId,
        attempt: job.attempts,
        error: message
      });
      retried += 1;
      continue;
    }
    await prisma.$transaction([
      prisma.scan.update({
        where: { id: job.scanId },
        data: {
          status: ScanStatus.FAILED,
          completedAt: new Date(),
          progress: 100,
          error: message
        }
      }),
      prisma.scanJob.update({
        where: { id: job.id },
        data: {
          status: JobStatus.FAILED,
          lockedAt: null,
          lastError: message
        }
      })
    ]);
    failed += 1;
  }
  return { inspected: staleJobs.length, retried, failed };
}
