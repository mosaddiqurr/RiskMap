# Run RiskMap

Use Node 22.16 or a supported Node 24 release. Run `npm ci`, then `npm run dev`, and open `http://localhost:3000`. No `.env`, database migration, seed, account or worker is required for the active analysis workflow.

For a production preview: `npm run build`, then `npm start`. The loopback-only helper is `npm run runtime:start`; inspect it with `npm run runtime:status` and stop its owned process with `npm run runtime:stop`.

Load Northstar Labs from Analyze or upload a dataset matching `public/demo-dataset.json`. Results live only in this tab's memory. Use the Report page before refreshing if you want to retain a JSON, CSV or PDF copy.

The original database-backed ingestion engines and `.env.compatibility.example` remain for compatibility testing. `npm run test:integration` uses an isolated database. The obsolete enterprise UI and handlers are removed.
