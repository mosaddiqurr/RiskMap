# Contributing

RiskMap changes should help users understand potential attack paths, choose a Best Next Fix, compare the modeled result or export a useful report.

Use the [quick start](README.md#quick-start) for setup and [testing guide](docs/TESTING.md) for validation commands, browser configuration and release checks. The active application needs no database or worker; [compatibility modules](docs/COMPATIBILITY.md) retain isolated backend regressions.

Keep changes focused, use strict TypeScript and validate untrusted data with Zod. Prefer pure graph, path and scoring functions. Preserve observed/inferred evidence, escaped report text and explicit modeling assumptions. An open service or CVE reference alone does not establish exploitability.

Add regression tests for meaningful logic changes. Check keyboard accessibility and supported viewports for material UI changes. Include relevant validation and screenshots in reviews, and explain the resulting behavior and material limitations.

Preserve compatibility access checks, network safeguards and existing user databases. Integration tests use only `prisma/integration.db`; routine validation must not reset or seed an application database.
