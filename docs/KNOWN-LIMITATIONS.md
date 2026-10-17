# Current limitations

RiskMap analyzes supplied evidence; it does not verify exploitation, access boundaries or confidence. An open service or CVE reference does not establish exploitability. Imported data may omit decisive context.

Potential paths require a finding and a sensitive target and are limited to eight nodes. Search records at most 400 paths and explores at most 30,000 states. Results identify budget truncation; depth remains a deliberate modeling boundary.

Best Next Fix simulates complete removal of a finding and its dependent transitions. It keeps general dependencies, reachability and other weaknesses. Path counts and score changes describe this model, not measured real-world risk reduction. Category-based effort estimates are rough ranking inputs.

Analysis data lives in the tab's memory. It is sent transiently to the server, without database retention. Refresh and Clear analysis discard it. No account isolation, saved-history dashboard or scanner-specific adapters are included. JSON is the only ingestion format; CSV and browser print/PDF are exports.

The local request budget is per-process. Public deployments need infrastructure-level body, concurrency, timeout and distributed rate controls. Database and scanning modules remain only for compatibility regressions. See [FINAL_VALIDATION](../FINAL_VALIDATION.md) for audit results and verified runtime/browser coverage. Tailwind 4 requires modern browsers (Safari 16.4+, Chrome 111+, Firefox 128+).
