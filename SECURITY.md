# Security policy

RiskMap accepts supplied evidence and makes no outbound requests to uploaded addresses, hostnames or CVE references. The server does not persist uploads; results live in browser-tab memory.

## Reporting an issue

Send a private report to the repository owner with the affected version, a reproduction using fictional data, impact and suggested remediation. Do not post private evidence or secrets in public issues.

## Active boundaries

- Strict versioned JSON, bounded strings/collections, unique IDs, duplicate-evidence rejection and validated references.
- One MiB declared/streamed body limit, fatal UTF-8 decoding and JSON content type.
- Same-origin browser checks by default; explicit HTTPS-origin allowlists for proxy/separate hosting.
- Exact-origin CORS without credentials or wildcard access, with `Vary: Origin` and `Cache-Control: no-store`.
- Per-process 60-request/minute budget, independent of forwarded IP claims.
- Bounded cycle-safe path search, evidence provenance and completeness information.
- Escaped UI/report text, sanitized filenames, formula-safe CSV and generic internal errors.
- No account administration, persistent analysis records or scanning endpoints in the active routes.

Public hosting needs HTTPS, ingress Host validation, body/time/concurrency limits and distributed rate controls. Disable analysis-body logging and caching. The application budget does not provide distributed denial-of-service protection. See [deployment](docs/DEPLOYMENT.md).

Scores and finding-removal previews are analytical hypotheses, not proof of exploitation or verified remediation. Use a trusted local instance for private evidence.

Retained database/scanning modules are compatibility regression code and are excluded from the standalone runtime. Their existing access checks and network safeguards must be preserved if separately maintained.

## Dependency audits

Run both dependency checks after dependency changes:

```bash
npm audit --omit=dev --audit-level=high
npm audit --audit-level=high
```

Audit results describe advisories at the time of the check. Repeatable application and browser checks are documented in [testing](docs/TESTING.md).

Never publish `.env`, credentials, real evidence, databases, logs or private reports. Northstar fixtures and publication screenshots are fictional.
