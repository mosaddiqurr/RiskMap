# Active architecture

Home, Analyze, Exposure Map, Report and About share one Next.js public layout and a tab-scoped React provider. No account, tenant, queue, worker or database is required.

`POST /api/analyze` reads at most 1 MiB of UTF-8 JSON, checks content type and browser origin, validates the strict dataset schema and returns `Cache-Control: no-store` results. `OPTIONS /api/analyze` supports explicit origin allowlists for separate hosting. Health checks the web process only. No uploaded address is scanned or fetched, and uploads are not stored.

The pure exposure constructor accepts explicit public/sensitive asset sets and finding-dependent relationship IDs. The bounded path, scoring and remediation engines are shared with the retained database regression pipeline. A finding removal only claims removal of paths containing that finding, even when a re-search is truncated. Score calculations hold the analysis timestamp constant.

React escapes evidence in graph details, paths, findings and reports. The current snapshot generates JSON/CSV blobs and a dedicated A4 browser print report. Results disappear on refresh, closing the tab or Clear analysis.

Obsolete enterprise UI/API handlers and dead adapters are removed. Schema, migration, reconciliation/history, worker and network-safety modules remain for compatibility regressions. Existing user databases are preserved. These modules are not imported by active routes or packaged in the standalone runtime image.

Production runs one Node process. An optional build-time API origin allows a second deployment of the same app to serve as the API host. Runtime origin allowlisting and a matching frontend CSP constrain requests. See [deployment](DEPLOYMENT.md).
