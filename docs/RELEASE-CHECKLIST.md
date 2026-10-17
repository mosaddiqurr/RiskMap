# Release checklist

Run the [testing gates](TESTING.md) and record actual results in [FINAL_VALIDATION](../FINAL_VALIDATION.md).

- Verify strict dataset ingestion, built-in/downloadable demo parity and complete upload-to-report journey.
- Verify graph direction, cycles, duplicate evidence, missing entities, filtering and selected-path edges.
- Verify dominant/tied/no-benefit recommendations, evidence and before/after counts.
- Run formatting, lint, typecheck, structural checks, backend/unit/integration tests and bounded performance.
- Run production build, production startup, both npm audits, Playwright and axe checks.
- Build and smoke-test the container when Docker is available.
- Verify separate-host CORS and HTTPS origin configuration.
- Keep four current screenshots and inspect desktop, tablet and mobile evidence.
- Inspect public files for private evidence, secrets, broken links and development attribution.
- Exclude dependencies, caches, local environment files, databases and generated test artifacts from publication.
- Replace `LIVE_DEMO_URL` only with a smoke-tested deployment URL; fill the author name if desired.
- Verify actual remote HTTPS deployment before advertising a live demo.

Do not commit, tag, push or deploy as part of a readiness pass. Review the working-tree diff and use the publication commands only after explicit authorization.
