# Worker coordination

This document describes retained compatibility regression modules. The active supplied-evidence application does not run scans, expose scan/account APIs or require a worker. See [active architecture](ARCHITECTURE.md).

The local prototype supports exactly one worker for a shared SQLite/runtime directory.
`acquireWorkerLock` writes JSON containing the worker ID, PID and start time using
exclusive file creation.

An existing lock is not recoverable merely because its file age exceeds a threshold.
It remains owned when:

- its recorded PID is alive;
- a matching heartbeat is fresh; or
- the lock itself is still within the stale window.

Only an old lock whose owner is genuinely unavailable is removed. Release and heartbeat
cleanup compare worker IDs before deleting files, so a stale process cannot remove a
new owner's state.

The worker writes structured JSON logs with `scanId` as the correlation ID. Heartbeats
include start/heartbeat times, scan mode and active job count. A duplicate worker exits
with a structured fatal error.

Job claiming uses a conditional `updateMany` from `QUEUED` to `RUNNING`; competing
claimers can observe the candidate, but only one conditional update succeeds. Retries
use bounded exponential delay. Stale running jobs are requeued only below the maximum
attempt count and otherwise become `FAILED`. SIGINT/SIGTERM stops new claims, waits for
active tasks, removes owned coordination files and disconnects Prisma.

Unit/integration coverage proves live-lock non-stealing, duplicate rejection, stale-lock
recovery, atomic competing claims, cancellation/retry, restart recovery and exhausted
failure.
