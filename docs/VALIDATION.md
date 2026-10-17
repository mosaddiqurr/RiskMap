# Validation

See [FINAL_VALIDATION](../FINAL_VALIDATION.md) for the latest executed results and [TESTING](TESTING.md) for repeatable commands. The active acceptance target is the supplied-evidence workflow, not authentication or scan administration.

The unit suites check pure analysis and retained backend regressions. Database integration uses only its disposable `prisma/integration.db`. The active application and browser suite run without a worker, seed or user database. Do not apply migrations or seed an existing database for routine acceptance.

Build before Playwright. Browser checks cover four viewport sizes, paths/evidence, remediation, exports, loading/error states, branding and axe WCAG A/AA. Artifacts go to ignored `test-results`, while four selected screenshots are maintained for README. Container and deployed-URL checks must be reported separately from local Next.js production startup.

For an owned loopback preview, use `npm run runtime:start`, `npm run runtime:status`, `npm run healthcheck` and `npm run runtime:stop`. The helper does not seed or migrate a database. Stop only processes created for this repository; do not terminate unrelated Node servers.
