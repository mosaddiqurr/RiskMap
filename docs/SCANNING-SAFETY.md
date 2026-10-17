# Scanning Safety

This document describes retained compatibility regression modules. The active supplied-evidence application does not run scans, expose scan/account APIs or require a worker. See [active architecture](ARCHITECTURE.md).

## Authorisation gate

Active checks require:

1. a root domain belonging to the current organisation
2. successful ownership verification
3. `SAFE_ACTIVE` permission
4. explicit active-check authorisation
5. no matching customer exclusion

Development demo verification is disabled in production and outside mock mode.

## Allowed safe-live behaviour

- A, AAAA, CNAME, MX, NS and TXT lookups
- SPF and DMARC policy observation
- TLS handshake and certificate metadata
- certificate Subject Alternative Name observation
- limited HTTP or HTTPS root requests
- bounded manual redirect handling
- response-header and `security.txt` checks
- TCP handshake only on the configured hard allowlist

## Prohibited behaviour

- exploitation or payload delivery
- authentication attempts
- password guessing, brute force or credential stuffing
- malware delivery
- denial-of-service testing
- aggressive crawling
- intrusive vulnerability validation
- scanning private, loopback, link-local, reserved or metadata destinations

## Address controls

`network-safety.ts` blocks:

- IPv4 private and carrier-grade NAT ranges
- loopback and link-local ranges
- benchmarking, multicast and reserved ranges
- documentation ranges
- IPv6 loopback, unique-local, link-local, multicast and documentation ranges
- IPv4-mapped IPv6 destinations
- localhost-style and cloud metadata hostnames
- decimal and shortened IP forms after URL normalisation

If a hostname returns both a public and blocked address, the entire resolution is rejected. The safe-live provider suppresses HTTP, TLS and TCP work for that target rather than selecting only the public answer.

## DNS rebinding and redirects

For each HTTP, TLS or TCP connection:

1. resolve all addresses
2. reject the request if any address is blocked
3. pin the socket lookup to a validated public address
4. set the expected TLS server name and Host header
5. handle redirects manually
6. validate protocol, credentials, port and hostname boundary again
7. resolve and pin the next destination independently

An external redirect can be recorded as evidence without being followed outside the verified root-domain boundary. Redirects to localhost or metadata endpoints are blocked.

## Resource limits

- short connection and request timeouts
- job-level abort signal
- bounded response body size
- maximum redirect count
- hard port allowlist intersected with configuration
- per-organisation active-scan limits
- global active-scan limits
- per-window organisation and global rate limits
- worker polling and concurrency controls
- bounded job retries and stale-job recovery

## Module-aware lifecycle safety

A failed DNS, HTTP, TLS, email or port module does not count as proof that previous evidence disappeared. Lifecycle absences apply only to successfully completed responsible modules. Partially completed scans are excluded from authoritative completed-scan comparisons.

## Adapter-based validation

`SafeLiveScanProvider` accepts injectable DNS, HTTP, TLS and TCP adapters. This allows the real provider logic to be tested without contacting unauthorised systems.

The unit fixtures cover:

- a public hostname with bounded observations
- private IPv4 and IPv6 loopback
- IPv4-mapped IPv6
- mixed public and private DNS answers
- redirects to localhost and metadata addresses
- excessive redirects
- DNS-rebinding-style adapter changes
- adapter timeout/failure paths
- disallowed ports

These tests are included but require Vitest dependencies before they can execute. The dependency-independent harness separately executes core address-range and URL-boundary assertions.

## Controlled owned-domain procedure

Use this only for a domain you own or have written authorisation to assess.

1. Keep `SCAN_MODE="mock"` while validating installation, migrations, seed and browser journeys.
2. Create a dedicated test subdomain with no sensitive production service behind it.
3. Confirm its DNS answers are public and do not include private, reserved or split-horizon addresses.
4. Add and verify the root domain through DNS TXT or the verification file.
5. Configure `SCAN_MODE="safe-live"` and keep the default hard port allowlist.
6. Start with `PASSIVE` permission and inspect DNS-only evidence.
7. Enable `SAFE_ACTIVE` only after recording explicit authorisation in the UI.
8. Use a narrow exclusion list for any hostname that must not receive HTTP, TLS or TCP checks.
9. Run one scan while watching structured worker logs and network egress.
10. Confirm redirects, response-size limits, timeouts and private-address failures are safe.
11. Return to mock mode after the controlled test.

Do not use random public systems as test targets.

## Technology and CVE limitations

Headers, page metadata, ports and safe banner metadata are technology observations, not vulnerability proof. A CVE-style match requires a sufficiently confident product and version match. Uncertain matches are described as potential version-related exposure and require validation. RiskMap never exploits a suspected CVE.

## Deployment defence in depth

Production must add network egress policy, controlled DNS, container isolation, shared rate limiting, durable queue leases, centralised logs and monitoring. Application validation is not the only safety boundary.
