# Testing

`npm test` runs the pure graph/path, scoring, parser, request, report, lifecycle and network-safety unit suites, then an isolated database reconciliation integration suite. It retains useful backend regressions without mounting enterprise routes.

Publication regressions cover exact demo parity, valid path direction, cycles, duplicate evidence, missing references, no-path/no-target cases, severity ordering, dominant and tied alternatives, no meaningful recommendation, comparison evidence and counts, HTTPS proxy origins, separate-host CORS, invalid configuration, byte/UTF-8 limits and the process request budget.

```bash
npm ci
npm run db:generate
npm run format:check
npm run lint
npm run validate
npm test
npm run validate:performance
npm run build
npm run typecheck
npm audit --omit=dev --audit-level=high
npm audit --audit-level=high
npx playwright install chromium
npm run test:e2e
```

The integration runner only replaces `prisma/integration.db`, applies the checked-in migration and exercises fictional snapshots. It never deletes or seeds `prisma/dev.db`. Compatibility tests need generated Prisma Client; `npm run build` and `npm run db:generate` generate it. No database is needed by the active API.

Playwright uses the production build and starts an owned loopback server on port 3100 (override with `PLAYWRIGHT_PORT` when occupied). It covers the full workflow, downloads, demo, evidence, graph filters, errors, empty/loading states, retired routes, branding, keyboard access and axe WCAG A/AA checks at 1440, 1366, 768 and 390 pixels. Tests write screenshots and a print report to ignored `test-results/screenshots`; four selected current screenshots are maintained in `docs/screenshots`. Use `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` for an explicit local Chromium executable; Windows can use installed Edge.

Download assertions check sanitised JSON/CSV filenames, every finding's evidence and remediation, report contents, print invocation and PDF rendering in each viewport. A replacement dataset is exported again to check that old evidence and timestamps are not reused. The PDF filename in the interactive print dialog is chosen by the browser/user.

Build before browser checks and typecheck after build, so regenerated route types are current. Performance runs the actual bounded analysis pipeline on the demo and a maximum-size synthetic dataset. Timings are machine-local evidence, not a capacity guarantee. See [FINAL_VALIDATION](../FINAL_VALIDATION.md) for the latest executed results.
