# Scan lifecycle

This document describes retained compatibility regression modules. The active supplied-evidence application does not run scans, expose scan/account APIs or require a worker. See [active architecture](ARCHITECTURE.md).

The API creates a `QUEUED` scan and matching job only after tenant, role, verified-domain,
concurrency, rate and plan checks. The worker conditionally claims one job, sets the scan
to `RUNNING`, persists `startedAt` and progress, and records module logs.

Successful mock or safe-live processing persists observations first, then reconciles
stable assets, services and findings for that scan. Only successfully completed modules
may produce authoritative absence transitions. Graph/path construction and deterministic
risk scoring run after reconciliation.

Terminal states:

- `COMPLETED`: every enabled module completed or was intentionally skipped.
- `PARTIALLY_COMPLETED`: useful evidence was reconciled but a later or individual module
  failed; incomplete modules cannot resolve/deactivate records.
- `FAILED`: no safe reconciliation completed and retry policy was exhausted or the error
  was permanent.
- `CANCELLED`: an authorised tenant member cancelled a still-queued job.

Cancellation and retry are idempotent by allowed source state. Failed/cancelled scans can
return to `QUEUED`; timestamps, error and progress are reset. Stale running jobs are
recovered through the bounded retry policy.

Asset, service, finding and path fingerprints exclude timestamps. Each completed scan
adds presence/observation records. Consecutive successful absences close services or
deactivate assets, findings resolve only when their responsible module succeeds, and a
later matching fingerprint reopens the finding with recurrence history.
