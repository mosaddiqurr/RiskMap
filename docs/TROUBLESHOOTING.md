# Troubleshooting

## Port 3000 or 3100 is occupied

`npm run runtime:status` identifies the server owned by `.runtime/analysis-server.json`. `npm run runtime:stop` stops only that recorded server. Do not terminate unrelated Node processes. Set `PORT` to another loopback preview port if needed. Playwright manages its production server on port 3100 (override with `PLAYWRIGHT_PORT` when occupied).

## JSON upload is rejected

Download Sample JSON from Analyze. Use UTF-8, schema version 1, all four collections and valid cross-references. Unknown fields are rejected. Assets cannot be empty; the other collections can. The file must fit the 1 MiB and collection limits shown on the page. CSV is an export format.

## No paths or no next fix

Paths require explicit public exposure, a finding, a service/exposure step and a sensitive target. A target is `CRITICAL_ASSET` or has `CRITICAL` criticality. Check directed relationships and `viaFindingId` for transitions dependent on a weakness. No recommendation is returned when finding removal changes neither paths nor the rounded score; absence of mapped paths is not a clean security assessment.

## Results disappeared

Results stay in tab memory, without database or local-storage retention. Refresh, closing the tab and Clear analysis remove them. Export JSON before closing if a snapshot is needed.

## Analysis is at capacity

The process permits 60 requests per minute. Wait for the current window to finish. Browser requests also have a 30-second client timeout. Inspect dataset size and density before retrying repeated timeouts.

## Route typing still mentions old SaaS pages

Run `npm run build` to regenerate `.next` route types, then `npm run typecheck`. Obsolete enterprise routes have been removed.

## Playwright cannot find a browser

Run `npx playwright install chromium`, or set `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` to a compatible Chromium executable. On Windows, the configuration uses installed Microsoft Edge when available. Run a production build before `npm run test:e2e`.

## Browser download remains at 100%

Confirm free space on the destination and system drives. During publication validation, older local browser builds stalled while finalising both report downloads and a plain text control download, even after disk space was restored. The same exports completed in the newer installed Chromium with normal protections. Select a current compatible browser through `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`; do not disable system or browser security controls to make the test pass. See [FINAL_VALIDATION](../FINAL_VALIDATION.md) for the tested version and results.

## Database or worker setup errors

The active product does not need either. The isolated integration suite generates Prisma Client and uses only `prisma/integration.db`. Original worker/database scripts apply to compatibility modules; do not use them to repair the current analysis workflow or seed an existing user database.
