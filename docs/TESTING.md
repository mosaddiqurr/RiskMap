# Testing and release checks

## Local checks

Use the Node version described in [README](../README.md#quick-start), install dependencies with `npm ci`, then run:

```bash
npm run validate:lock
npm run db:generate
npm run format:check
npm run lint
npm run validate
npm test
npm run validate:performance
npm run build
npm run typecheck
npx playwright install chromium
npm run test:e2e
```

`npm run release:check` combines lock validation, type generation, formatting, typecheck, lint, structural checks, unit/integration tests and production build. Browser and performance checks remain separate commands. Run dependency audits after dependency changes; see [security](../SECURITY.md#dependency-audits).

The unit suites cover graph construction, path search, scoring, parsing, reports, API boundaries and retained backend regressions. The integration runner recreates only `prisma/integration.db`, applies the checked-in migration and reconciles fictional snapshots. It never resets or seeds `prisma/dev.db`. Generated Prisma Client is needed by compatibility tests; the active application requires no database.

## Browser checks

Build before Playwright and run typecheck after build so generated route types are current. Playwright uses a production server on loopback port 3100, reusing it when available. Set `PLAYWRIGHT_PORT` when that port is occupied.

The suite checks upload-to-report navigation, remediation, evidence, graph filters, JSON/CSV downloads, print/PDF rendering, error/empty/loading states, branding, keyboard access and automated WCAG A/AA checks. Projects cover 1440, 1366, 768 and 390 pixel widths. Additional landing-page checks verify automatic animation and complete desktop first-view visibility at short and wide viewport sizes.

Windows can use installed Edge. `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` selects a compatible local Chromium executable; CI uses managed Chromium. If a browser is unavailable, run `npx playwright install chromium` or set that override.

Screenshots, downloaded reports and traces go to ignored `test-results/` and `playwright-report/`. Two selected screenshots are kept in `docs/screenshots/` for README. Generated artifacts belong to the test run, rather than separate checked-in validation reports.

## Release acceptance

- Run the relevant automated checks and review failures against the current commit.
- Exercise demo/upload → analysis → graph and path evidence → Best Next Fix → comparison → JSON/CSV/print report.
- Inspect desktop, tablet and mobile layouts and current documentation links.
- Smoke-test the chosen deployment route, including direct routes, icons, health, API errors and configured origins. Docker and separately hosted frontend/API configurations require their own checks when used.
- Verify the actual HTTPS deployment before adding a hosted-demo link to README.

The performance command measures the real bounded analysis pipeline on the demo and a maximum-size synthetic inventory. Local timings, automated accessibility checks and successful builds describe the tested environment; they do not establish production capacity or complete assistive-technology coverage.
