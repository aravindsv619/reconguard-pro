# ReconGuard Pro — Security Overview

ReconGuard Pro is a keyless reconnaissance tool with two modes:

1. **Subdomain Enumeration & Takeover Risk** — discovers subdomains from 12 free
   public sources (plus optional keyed ones), probes them, and flags
   subdomain-takeover risk with verdicts.
2. **Lookalike Domain Detection** — generates typosquat/brand-impersonation
   candidates for a domain and scores how likely each is a real lookalike.

It runs fully **without any API keys**. Optional keys (SecurityTrails / Shodan /
c99) only add extra subdomain sources and are never required.

## Stack

- **Backend:** Python, FastAPI 0.146 / Starlette 1.9 / uvicorn (async), `httpx`,
  system `dig` for DNS records.
- **Frontend:** vanilla JavaScript (no framework), vendored Tailwind CSS,
  single-page app served as static files.
- **Tests:** 308 automated tests.
- **Packaging:** multi-stage Docker image (non-root), docker-compose, and a
  GitHub Actions workflow that publishes to GHCR.
- **Security tooling:** `pre-commit` hooks (detect-secrets, ruff, file hygiene,
  AST check) locally, plus a CI security pipeline (see below).

## Security CI/CD pipeline

Beyond the tests, GitHub Actions enforces three automated security gates. All
new workflows pin action versions, use least-privilege `permissions`, and run
on push/PR to the default branch (dependency/SAST also run on a weekly cron):

- **Dependency check** — `pip-audit` scans the pinned runtime and dev
  requirements and fails on any known advisory (`dependency-audit.yml`).
- **SAST** — `bandit` (`sast-bandit.yml`) for pattern-based issues plus GitHub
  **CodeQL** (`codeql.yml`) for semantic/dataflow analysis of the Python
  source. The single intentional `verify=False` on the probe-only HTTP client
  (needed to probe targets that serve expired/self-signed certs; no credentials
  are ever sent on it) is annotated `# nosec B501` with a justification, so the
  job catches only new, unreviewed findings.
- **DAST** — OWASP ZAP baseline (`dast-zap.yml`) runs against an **ephemeral**
  instance that the workflow builds and starts inside the CI runner
  (`SUBRECON_HOST=0.0.0.0`, `http://localhost:8080`). It is **non-blocking** and
  never targets a deployed/production instance; rule tuning lives in
  `.zap/rules.tsv`.

## Security posture

Audited against the OWASP Top 10 (2021), OWASP API Security Top 10 (2023), and
cloud/SSRF concerns. Status by area:

| Area | Status |
| --- | --- |
| A06 Vulnerable dependencies | **Fixed** — `pip-audit` reports no known vulnerabilities (7 Starlette advisories cleared via upgrade; unused python-multipart removed) |
| A04 / API4 Resource exhaustion / DoS | **Fixed** — active-job cap, per-client rate limit (in-memory, hardened with bounded memory + proactive eviction), request/wordlist size caps, bounded concurrency |
| A10 / API7 SSRF | **Fixed** — private/loopback/link-local/cloud-metadata IPs (incl. 169.254.169.254, IPv4+IPv6) blocked on every outbound probe; user-influenced probes pin the validated IP (no DNS-rebinding window) |
| A03 Injection | Verified — `dig` via argument list (no shell), CSV formula-injection neutralized, CRLF-safe download filenames, ReDoS-checked regexes |
| XSS | Verified — all external/source data HTML-escaped; strict CSP (`script-src 'self'`, no inline JS); Tailwind vendored (no third-party CDN) |
| A05 / API8 Misconfiguration | Verified — security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) on every response; binds 127.0.0.1 by default; scoped CORS; generic 500s (no stack traces) |
| A01 / API1 Access control | Verified — UUID job IDs, 404 on unknown/malformed, no path traversal |
| A08 Integrity | Verified — no third-party scripts; vendored assets; external JS only, no inline handlers |
| A09 Logging | Verified — no secrets or sensitive data logged |
| API10 3rd-party data | Verified — all source data validated before storage/render; response-size capped |

### Residual risks (be aware before deploying)

These are inherent to a single-user local recon tool and are documented rather
than hidden:

1. **No authentication.** Any client that can reach the API can start scans. Run
   it locally (the default bind is `127.0.0.1`) or place it behind an
   authenticating reverse proxy. **Do not expose the raw API to the public
   internet.**
2. **Egress by design.** The tool makes outbound requests to the target domain
   and to public recon sources. Only scan domains you own or are authorized to
   assess.

### Hardened (previously residual)

- **DNS-rebinding TOCTOU — fixed.** User-influenced probes (target domain,
  subdomains, lookalike candidates, takeover-verify targets) now **pin the
  validated IP**: after a host resolves and an address passes the
  `_is_safe_public_ip` guard, the HTTP/HTTPS probe connects to *that exact IP*
  while keeping the original hostname as the `Host` header and TLS SNI. httpx
  never performs a second, independent lookup, so a hostile resolver can no
  longer return a safe public IP for the guard check and a private/metadata IP
  for the connect — the resolve→connect window is closed. Redirect-following is
  disabled on the probe client so a 3xx cannot trigger an unpinned
  re-resolution. Fixed-trusted-source fetches (crt.sh, rdap.org, hackertarget,
  etc.) target hardcoded hostnames and are not user-controlled, so they are not
  pinned.
- **In-memory rate limit — hardened.** The limiter is in-memory and
  **per-process**, which is correct and sufficient for the single-instance
  deployment this tool ships as. It is hardened with **bounded memory**: a
  proactive periodic sweep evicts fully-refilled (idle) per-IP buckets, and a
  hard cap (`RATE_LIMIT_MAX_BUCKETS`, default 10000) with an emergency prune
  guarantees a flood of distinct client IPs can never grow the table without
  bound. An **external shared limiter** (e.g. Redis) would only be needed if the
  tool were scaled horizontally across multiple processes/replicas; it is
  intentionally not added to avoid a dependency for the single-user model.

## Responsible use

ReconGuard Pro is for **authorized security testing only**. Only scan domains
you own or have explicit permission to test. Unauthorized scanning may be
illegal.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository, or contact the
maintainer. Please do not file public issues for security reports.
