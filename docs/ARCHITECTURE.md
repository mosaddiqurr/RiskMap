# Architecture and analysis reference

## Runtime

Home, Analyze, Exposure Map, Report and About share a Next.js App Router layout and a tab-scoped React analysis provider. The active application runs in one Node process without a database or background worker.

`POST /api/analyze` → bounded UTF-8 request reader → strict Zod dataset parser → pure exposure graph → bounded path search → scoring and remediation simulation → UI and browser exports.

The API accepts at most 1 MiB, checks JSON content type and browser origin, and returns `Cache-Control: no-store`. `OPTIONS /api/analyze` supports explicit origin allowlists. `GET /api/health` checks the web process. Uploaded addresses, hostnames and references are never scanned or fetched. See [deployment](DEPLOYMENT.md) and [security](../SECURITY.md).

## Input model

The top-level fields are `version: 1`, `name`, `assets`, `services`, `findings` and `relationships`. Input must be UTF-8 JSON. Assets cannot be empty; services, findings and relationships may be empty.

| Collection    | Fields                                                                                                                                                             |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Assets        | `id`, `name`, `type`, `criticality`, `public`, `evidence`                                                                                                          |
| Services      | `id`, `assetId`, `port`, `protocol`, `confidence`, `evidence`                                                                                                      |
| Findings      | `id`, `assetId`, optional `serviceId`, `title`, `severity`, `confidence`, `category`, `description`, `evidence`, `remediation`, optional `cve` and ISO `firstSeen` |
| Relationships | `id`, `from`, `to`, `type`, `state`, `confidence`, `evidence`, optional `viaFindingId`                                                                             |

The parser rejects unknown fields, duplicate IDs within a collection, exact duplicate relationship evidence, invalid ports, control characters, invalid UTF-8 and broken references. A finding's service must belong to its asset. Relationships connect different existing assets; a `viaFindingId` must belong to the source asset. Independent relationship evidence may produce distinct parallel paths.

Limits: 100 assets, 200 services, 200 findings and 300 relationships, within the 1 MiB request limit. [The schema](../lib/analysis/dataset.ts) defines accepted enum values. [The complete fictional dataset](../public/demo-dataset.json) is the input template.

## Graph and path search

`public: true` creates an Internet entry edge. Asset names, IP strings and types alone do not imply public exposure. Sensitive targets are assets of type `CRITICAL_ASSET` or with `CRITICAL` criticality. Identity assets remain distinct from servers and services.

Relationships follow their supplied `from → to` direction. A finding-dependent transition passes through that finding's node, avoiding a parallel bypass. General dependencies remain during remediation. Each edge carries evidence, confidence and observed/inferred state.

Cycle-safe depth-first search starts at Internet or explicit entry nodes. A recorded path needs a finding, a meaningful exposure/service step and a sensitive target. Ordered node and edge identities distinguish parallel routes. Selected paths highlight their exact edge IDs; textual paths expose the complete chain and remediation context.

The active pipeline stops at eight nodes, 400 recorded paths or 30,000 explored states. Path/state-budget exhaustion sets a completeness flag in the UI and exports. Maximum depth remains a modeling boundary even without budget exhaustion. Results sort by score, then shorter length.

## Scoring and Best Next Fix

Path scores combine entry exposure, supplied finding severity, asset criticality, service sensitivity, chain length and administrative/data/API context. Inferred steps carry a penalty, and confidence adjusts the result. Scores are clamped to 0–100: critical ≥80, high ≥60, medium ≥35, otherwise low. Imported finding severity is separate from this path label. The UI exposes contributing terms.

Finding scores use severity, confidence, asset importance, explicit public exposure, a supplied first-seen date and mapped path participation. Contributions are capped and aggregated with diminishing weights. Imported evidence receives no fabricated newly-observed or correlated-findings bonus. The shared aggregation formula and additional persistence-only context are documented in [compatibility](COMPATIBILITY.md#scoring).

For each candidate, the simulation removes its finding node and dependent transitions, reruns the search and recalculates scores at the original analysis timestamp. Ranking considers score-point change, provably affected paths and their aggregate scores, severity, asset importance, confidence and a rough category-based effort estimate. Stable ties retain input order. Candidates with neither path nor rounded-score benefit are omitted.

Only original paths containing the selected finding are claimed as removed. Bounded re-search may discover a different subset. The preview keeps inventory, public reachability, general dependencies and unrelated findings. Qualitative benefit is High for at least two affected high/critical paths or 12 model-score points, Moderate for any affected path or five points, otherwise Limited.

## Reports, state and limitations

The immutable current snapshot supplies JSON, formula-safe CSV and the browser's A4 print/PDF layout. React escapes evidence text; export filenames are bounded and sanitized. Results live in browser-tab memory and disappear on refresh, tab close or Clear analysis.

Scores are relative analytical aids, not breach probabilities or proof of compromise. Supplied evidence may be incomplete, stale or incorrect. Open services and CVE references alone do not establish exploitability. Finding removal assumes full remediation; revalidate real controls and import updated evidence after applying a fix.

The active application provides no persistent history, account ownership model, live discovery or scanner-specific import adapters. Retained database and scanning code supports compatibility regressions and existing data; see [compatibility](COMPATIBILITY.md).
