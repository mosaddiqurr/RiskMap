# Compatibility modules

The active supplied-evidence application uses the stateless workflow in [architecture](ARCHITECTURE.md). The original Prisma schema, migrations, worker, network-safety, reconciliation and historical engines remain for existing data and regression tests. They are excluded from the standalone application image. Retired account and scanning routes are absent.

`.env.compatibility.example`, Prisma scripts and the worker command apply to these modules. Routine local use needs none of them. Existing user databases must be preserved; integration tests use their isolated database as described in [testing](TESTING.md).

## Persistence and reconciliation

The SQLite/Prisma schema retains identities/tenants, scan execution, inventory presence, finding observations, path history and report metadata. [The schema](../prisma/schema.prisma) and [migration](../prisma/migrations/20260725000000_init/migration.sql) are the authoritative definitions.

Asset, service, finding and path fingerprints exclude timestamps. Reconciliation records observations and presence for each scan. Only successfully completed responsible modules can establish absence, resolve findings, close services or deactivate assets. A later matching fingerprint reopens a finding with recurrence history. Partial scans cannot establish authoritative completed-scan comparisons.

## Scan and job lifecycle

The retained scan service applies tenant, role, verified-domain, permission, exclusion, concurrency, rate and plan checks before creating a queued scan/job. A conditional claim moves one job from QUEUED to RUNNING. Observations persist before reconciliation, graph construction and scoring.

| State               | Meaning                                                                                          |
| ------------------- | ------------------------------------------------------------------------------------------------ |
| COMPLETED           | Enabled modules completed or were intentionally skipped                                          |
| PARTIALLY_COMPLETED | Useful evidence was reconciled but some work failed; incomplete modules cannot establish absence |
| FAILED              | No safe reconciliation completed and retry policy was exhausted or the error was permanent       |
| CANCELLED           | An authorized tenant member cancelled a still-queued job                                         |

Cancellation and retries are idempotent by allowed source state. Requeueing resets timestamps, errors and progress. Stale running jobs are recovered only within the bounded retry policy; exhausted jobs fail.

## Worker coordination

One worker is supported for a shared SQLite/runtime directory. Exclusive lock creation records worker ID, PID and start time. A lock remains owned while its process is alive, its heartbeat is fresh or it remains within the stale window. Only an old lock with an unavailable owner can be recovered.

Release and heartbeat cleanup compare worker IDs, preventing a stale worker from deleting a new owner's coordination files. Conditional job updates allow only one claimant. Retries use bounded exponential delay. Shutdown stops new claims, waits for active tasks, removes owned state and disconnects Prisma. Structured logs correlate work with `scanId`.

## Network safeguards

The retained safe-live provider requires a verified root domain, appropriate permission and explicit authorization for active checks, with exclusions honored. Demo verification is disabled in production and outside mock mode.

Supported observations are bounded DNS/email-policy checks, TLS metadata, limited root HTTP/HTTPS requests, header/security.txt checks and TCP handshakes on a hard allowlist. Exploitation, authentication attempts, payload delivery, aggressive crawling and denial-of-service testing are outside its behavior.

Address checks reject private, loopback, link-local, carrier-grade NAT, benchmarking, multicast, reserved, documentation, metadata and IPv4-mapped IPv6 destinations. Mixed public/blocked DNS answers reject the entire target. Each connection resolves and validates all addresses, pins a validated public address, sets the expected TLS server name/Host and revalidates redirects. Redirects outside the verified root boundary may be recorded without being followed.

Timeouts, body/redirect limits, job aborts, allowlisted ports, concurrency/rate budgets and bounded retries constrain work. Failed modules cannot erase prior evidence. DNS, HTTP, TLS and TCP adapters are injectable for tests without live targets. Network/provider, lifecycle, job-runtime and worker-coordination test suites preserve these guarantees.

## Scoring

The shared finding formula uses severity weights: critical 28, high 18, medium 10, low 4 and informational 1. Asset criticality multipliers are 1.35, 1.20, 1.00 and 0.80 for critical through low. Confidence multipliers are high 1.00, medium 0.82 and low 0.62.

Persisted context can add public reachability (×1.15), newly observed (+3), reopened (+3), age over 30 days (+2) or 90 days (+4 instead), up to four related-finding points, and current-path participation (+6). Status multipliers are open 1.00, reopened 1.05, in progress 0.80, accepted risk 0.70, resolved/false positive 0. An unobserved finding contributes zero; each contribution is capped at 35.

Sorted contributions are aggregated with diminishing weights:

```text
weightedTotal = Σ contribution[index] × 0.82^index
score = round(100 × (1 − exp(−weightedTotal / 70)))
```

The active importer supplies only evidence available in the uploaded snapshot; it does not fabricate persistence history or correlated-finding bonuses. Best Next Fix re-evaluates the graph and score after modeled finding removal. All scores remain deterministic prioritisation aids rather than calibrated probabilities.
