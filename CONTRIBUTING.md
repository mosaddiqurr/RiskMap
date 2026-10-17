# Contributing

RiskMap is a focused exposure analysis tool. Changes should help a user understand potential attack paths, choose a Best Next Fix, compare the modeled result or export a useful report.

## Development

Use Node 22.16 or a supported Node 24 release, then run `npm ci` and `npm run dev`. The active application needs no environment file, seed, database migration, account or worker. Database and scanning regression modules remain for compatibility tests; see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

Keep changes focused. Use strict TypeScript, validate untrusted data with Zod, preserve observed/inferred evidence and expose modeling assumptions. Prefer pure functions for graph construction, path search and scoring. Supplied text must remain escaped in the UI and reports. A CVE or open service alone does not establish exploitability.

Add regression tests for meaningful logic changes. Check accessibility and all supported viewport sizes for material UI changes. Avoid tests that merely repeat implementation details.

```bash
npm run validate:lock
npm run format:check
npm run lint
npm run validate
npm test
npm run build
npm run typecheck
npm run test:e2e
npm audit --omit=dev --audit-level=high
npm audit --audit-level=high
```

The integration runner uses its own `prisma/integration.db`. Never seed, reset or delete an existing application database as part of routine validation. Build before browser checks, which run against a production server.

## Review

Explain the concrete user problem, resulting behavior, relevant tests and material limitations. Include screenshots for UI changes and distinguish a simulated improvement from a verified real-world fix. Preserve existing compatibility security controls if changing those modules; do not expose them without their original access checks.
