# Deployment

RiskMap runs five pages and two API endpoints in one Next.js process. The analysis workflow requires no database, worker, credentials, persistence volume or migration. Uploaded data is processed transiently; results live in browser-tab memory.

## Local development

Run `npm ci`, then `npm run dev`, and open `http://localhost:3000`. Load the fictional demo from Analyze or upload `public/demo-dataset.json`.

The optional production-preview helper starts a loopback-only server after a build:

```bash
npm run runtime:start
npm run runtime:status
npm run runtime:stop
```

Set `PORT` in your shell to choose another preview port. The helper records its process in ignored `.runtime/analysis-server.json`; stop only the owned server. Playwright uses port 3100 by default and accepts `PLAYWRIGHT_PORT`.

## Production startup

Use a maintained Node 22 release (22.16 or later) or Node 24. Install build dependencies, generate compatibility types, and build:

```bash
npm ci
npm run build
npm start
```

`GET /api/health` returns `status: ok` and `mode: stateless-analysis`. The built-in demo is bundled, and `/demo-dataset.json` is a public relative URL. The favicon and report artwork are bundled assets.

For a standalone artifact, copy `public` and `.next/static` into `.next/standalone/public` and `.next/standalone/.next/static`, then run `node .next/standalone/server.js`. `HOSTNAME=0.0.0.0` and `PORT` control that server. The Dockerfile packages these directories automatically. Do not deploy a static HTML export: analysis needs the Node API.

## Optional container

The standard production architecture is the Node standalone server described above. Docker is an alternative packaging route and is not required for Node hosting. Verify a container build and smoke test on the chosen Docker host before using that route.

```bash
docker compose build
docker compose up -d
docker compose ps
```

Compose binds one service to `127.0.0.1:3000`. The runtime image uses a non-root user and the traced standalone server, without build tools, Prisma, compatibility workers or user databases. No storage volume is required. Put an HTTPS reverse proxy in front of the service for public hosting.

## HTTPS and origin configuration

Set `ANALYSIS_ALLOWED_ORIGINS=https://riskmap.example.com` on the server behind an HTTPS proxy. This is the browser's public origin, not the internal HTTP upstream. Multiple exact origins are comma-separated. No wildcard, origin paths, credentials or trailing slashes are accepted. HTTP is accepted only on loopback for local integration tests.

With the setting blank, requests must match the request Host and protocol and have same-origin fetch metadata. Origin-less non-browser API clients can submit data. The application does not trust forwarded hosts or forwarded client IPs. The ingress must validate its Host, terminate HTTPS and overwrite forwarding headers.

The API returns `Cache-Control: no-store` and `Vary: Origin`. An approved origin receives an exact `Access-Control-Allow-Origin` value on success, validation errors and capacity responses. `OPTIONS` permits only `POST` and `Content-Type`. Credentials and wildcard CORS are never enabled.

## Separate frontend/API hosts

The existing Next.js app can run on two hosts without introducing a second backend:

1. On the API host, set `ANALYSIS_ALLOWED_ORIGINS=https://front.example.com`. Build and start the normal Node app.
2. On the frontend host, set `NEXT_PUBLIC_API_BASE_URL=https://api.example.com` **before** `npm run build`. Its pages send analysis requests to that API. This value is public and must contain only the origin, with no trailing slash.
3. For Docker frontend builds, pass `--build-arg NEXT_PUBLIC_API_BASE_URL=https://api.example.com`.
4. Rebuild whenever the API base changes. The frontend's CSP permits that exact API origin. Keep the backend allowlist and ingress rules in sync.

Each host uses the same repository. The frontend remains a Next.js app; a CDN-only static export is not provided. Prefer a single host unless separation is required.

## Public ingress requirements

Set HTTPS, body limits of 1 MiB, finite read/connection timeouts, request concurrency limits and a distributed rate limit at the hosting layer. The application has a per-process 60-request/minute budget and bounded graph searches; these do not replace edge controls across replicas. For Nginx, set `client_max_body_size 1m`, `client_body_timeout 15s` and a suitable `proxy_read_timeout` (for example 30s), plus deployment-specific `limit_req`/`limit_conn` zones. Exclude `/api/analyze` from request-body logging and caching. Health checks can use `/api/health` without sending evidence.

There is no persistence or account ownership model. Review privacy before sending sensitive evidence to any public host. Exports happen in the browser, including print/PDF.

## Acceptance before advertising the URL

Verify Home -> demo/upload -> analysis -> graph/path evidence -> Best Next Fix -> remediation preview -> JSON/CSV/print report on the actual HTTPS URL. Check all direct routes, icon loading, API errors, preflight and a disallowed origin. Add a hosted-demo link to README only after that smoke test. See [testing](TESTING.md) for repeatable checks.

## Troubleshooting

| Issue                           | Action                                                                                                                                                                      |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Port occupied                   | Check `npm run runtime:status`; select another `PORT` or `PLAYWRIGHT_PORT` and preserve unrelated servers.                                                                  |
| JSON rejected                   | Start with Sample JSON. Use UTF-8, version 1, all collections, valid references and the documented size limits.                                                             |
| No paths or next fix            | Check explicit public exposure, directed/finding-gated relationships and sensitive targets. No recommendation is returned without modeled path or rounded-score benefit.    |
| Results disappeared             | Refresh, tab close and Clear analysis discard tab-scoped results. Export a snapshot before closing.                                                                         |
| Capacity or timeout response    | The process budget is 60 requests per minute and the client timeout is 30 seconds. Retry after the current window; inspect large or dense datasets before repeated retries. |
| Old generated route types       | Rebuild, then run typecheck.                                                                                                                                                |
| Database or worker setup errors | The active application requires neither. See [compatibility](COMPATIBILITY.md) and [testing](TESTING.md) for isolated backend checks.                                       |

The original schema and database regression pipeline are compatibility test material. Preserve existing user databases during deployment.
