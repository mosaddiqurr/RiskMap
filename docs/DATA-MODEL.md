# Data model

The active input is one UTF-8 RiskMap JSON dataset, `version: 1`, containing `name`, `assets`, `services`, `findings` and directed `relationships`. See [README](../README.md#supported-input), [the schema](../lib/analysis/dataset.ts) and [the complete fictional example](../public/demo-dataset.json).

Assets define explicit public exposure, type, criticality and evidence. Services reference assets. Findings reference assets and optionally a service on that same asset. Relationships connect different existing assets and may specify `viaFindingId` from their source asset. Finding-gated transitions pass through the corresponding finding node and disappear only in the modeled finding-removal preview.

The parser rejects unknown fields, duplicate collection IDs, identical relationship evidence, missing references, invalid ports, controls in text, non-UTF-8 bytes and oversized datasets. Limits are 1 MiB, 100 assets, 200 services, 200 findings and 300 relationships. Assets cannot be empty. Different relationship evidence may create distinct parallel paths.

The API does not persist datasets. The browser provider keeps the current analysis snapshot in memory. Graph nodes/edges, scoring contributors, ordered path nodes/edges, recommendations, completeness and limitations are exported in JSON. CSV exports findings; print/PDF uses the browser renderer.

## Compatibility persistence schema

The original SQLite/Prisma schema has 29 tables and 62 indexes. It preserves identities/tenants, scan execution, inventory presence, finding observations, path history, reports and related metadata for database reconciliation regressions and existing data. These are not active UI/API features and are excluded from the standalone runtime image. No migration or seed is required to run the analysis application.
