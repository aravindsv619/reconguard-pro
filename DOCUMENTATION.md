# ReconGuard Pro — Documentation

> External attack-surface recon — subdomain enumeration, takeover risk, and
> lookalike-domain detection, in a single self-contained web tool. **Keyless**
> (no API keys required) and dark-themed.

> ⚠️ **For authorized security testing only.** Only scan domains you own or
> have explicit written permission to test. Unauthorized scanning may be
> illegal.

---

## 1. What it does

ReconGuard Pro is a web application with **two modes**:

### Mode 1 — Subdomains (enumeration + takeover risk)
Given a domain you are authorized to assess, it:
1. **Discovers subdomains** from multiple free public intelligence sources
   (certificate-transparency logs, passive DNS, web archives) — no scanning of
   the target is required for discovery.
2. **Optionally brute-forces** subdomains with a bundled 2,400+ word list and
   generates altdns-style permutations (OFF by default — more intrusive).
3. **Resolves** each subdomain (A/AAAA, CNAME chain, full DNS records) and
   **probes** HTTP/HTTPS for liveness.
4. **Scores subdomain-takeover risk** (HIGH / VERIFY / MEDIUM / LOW / NONE)
   against a library of cloud/service fingerprints, then runs an **active
   verification** pass that turns the heuristic tier into a concrete
   **VULNERABLE / NOT_VULNERABLE / INCONCLUSIVE** verdict with evidence.
5. **Exports** everything to CSV.

### Mode 2 — Lookalike Domains (typosquat / brand-impersonation)
Given a domain, it generates confusingly-similar domains (hyphenation, TLD
swaps, typos, homoglyphs, combosquatting, etc.), checks which are registered /
live / have mail (MX), detects marketplace-parked (for-sale) domains, and scores
each as HIGH / MEDIUM / LOW / AVAILABLE — so you can spot phishing/impersonation
candidates. Optional keyless WHOIS/RDAP enrichment. CSV export.

---

## 2. Technology & architecture

| Layer | Technology |
| --- | --- |
| Backend | Python, **FastAPI 0.146** / **Starlette 1.9** / **uvicorn 0.54** (async) |
| HTTP client | `httpx` (async), with two clients: a TLS-verified client for sources/APIs and a separate probe client for target liveness |
| DNS | system `dig` (fast path) with a Python stdlib fallback |
| Frontend | Vanilla JavaScript (no framework), vendored Tailwind CSS, single-page app served as static files |
| Jobs | In-memory job store with UUID ids and a 1-hour TTL (no database) |
| Packaging | Multi-stage **Docker** image (non-root), **docker-compose**, GitHub Actions → **GHCR** |
| Tests | 17 test modules (pytest + respx), 340+ tests |

Design highlights:
- **Keyless by default** — all core discovery works with no API keys.
- **Concurrent, bounded** — sources run in parallel; per-subdomain analysis is
  bounded by an `asyncio.Semaphore`.
- **Resilient** — transient source failures (HTTP 429/502/503/504, timeouts)
  are retried with backoff; a failing source never crashes a scan, and the UI
  lists which sources were unavailable.

---

## 3. Data sources & services used

All outbound calls go to fixed, trusted hostnames. **9 keyless** sources run by
default; **3 optional keyed** sources are skipped unless you supply a key.

| Source | Type | API key |
| --- | --- | --- |
| crt.sh | Certificate Transparency | no |
| CertSpotter (SSLMate) | Certificate Transparency | no |
| HackerTarget | Passive DNS | no |
| AlienVault OTX (passive DNS) | Passive DNS | no |
| AlienVault OTX (URL list) | Passive URLs | no |
| RapidDNS | Passive DNS | no |
| URLScan.io | Crawl data | no |
| Wayback Machine (CDX) | Web archive | no |
| SubdomainCenter | Aggregator | no |
| SecurityTrails | Passive DNS | optional key |
| Shodan | Host data | optional key |
| c99.nl | Aggregator | optional (paid) key |

Lookalike mode additionally uses **RDAP** (`rdap.org`, keyless) for optional
registration lookups.

> **Coverage note:** passive sources are third-party and occasionally
> rate-limit or error (crt.sh — the richest — can return 502 under load). The
> tool retries transient failures and tells you which sources were unavailable.
> No passive tool finds *every* subdomain; enable Active DNS discovery for
> coverage that doesn't depend on these sources.

---

## 4. How it works (data flow)

```
                 ┌──────────── Browser SPA (static/index.html + app.js) ────────────┐
                 │  Subdomains mode            Lookalike mode                        │
                 └───────────┬───────────────────────────┬─────────────────────────┘
                             │ POST /api/enumerate        │ POST /api/lookalike
                             ▼                            ▼
                    ┌───────────────── FastAPI (main.py) ─────────────────┐
                    │  create UUID job → run in background                │
                    │                                                     │
   Subdomains:      │  query N sources concurrently (retry/backoff)       │
                    │  → dedupe → resolve DNS + CNAME chain                │
                    │  → HTTP/HTTPS probe (SSRF-guarded, IP-pinned)        │
                    │  → takeover fingerprint + active verify             │
   Lookalike:       │  generate candidates → resolve/probe → MX/RDAP      │
                    │  → parked detection → risk score                    │
                    └───────────────┬─────────────────────────────────────┘
                                    │ poll GET /api/status/{id}
                                    │ fetch GET /api/results/{id}
                                    ▼ download GET /api/download/{id}  (CSV)
```

---

## 5. API reference

### Subdomains mode
| Method | Path | Description |
| --- | --- | --- |
| POST | `/api/enumerate` | Start a scan. Body: `{domain, active?, permutations?, wordlist?, securitytrails_key?, shodan_key?, c99_key?}`. Returns `{job_id}`. |
| GET | `/api/status/{job_id}` | Progress, per-source status, count. |
| GET | `/api/results/{job_id}` | Full results JSON. |
| GET | `/api/download/{job_id}` | CSV report. |

**Subdomain CSV columns (16):**
`subdomain, ip_addresses, cname, http_status, https_status, sources, resolved,
alive, takeover_risk, takeover_service, takeover_detail, dns_status,
takeover_verdict, takeover_evidence, dns_records, recommended_action`

### Lookalike mode
| Method | Path | Description |
| --- | --- | --- |
| POST | `/api/lookalike` | Start a lookalike scan. Body: `{domain, check_whois?}`. Returns `{job_id}`. |
| GET | `/api/lookalike/status/{job_id}` | Progress. |
| GET | `/api/lookalike/results/{job_id}` | Full results JSON. |
| GET | `/api/lookalike/download/{job_id}` | CSV report. |

**Lookalike CSV columns (14):**
`candidate, technique, dns_status, ip_addresses, http_status, https_status,
page_title, has_mx, registered, registrar, creation_date, resembles_original,
risk, recommended_action`

### Health
| Method | Path | Description |
| --- | --- | --- |
| GET | `/health` | Liveness check → `{"status":"ok"}`. |

Errors: invalid domain → `400`, unknown job → `404`, too many requests → `429`.

---

## 6. Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `SUBRECON_HOST` | `127.0.0.1` | Bind address. Set to `0.0.0.0` **inside a container** so the mapped port is reachable. |
| `SUBRECON_CORS_ORIGINS` | `http://localhost:8080,http://127.0.0.1:8080` | Allowed CORS origins (comma-separated). |
| `SUBRECON_RATE_LIMIT` | `60` | Per-client scan-start requests per minute. |
| `SECURITYTRAILS_API_KEY` | (unset) | Optional — enables the SecurityTrails source. |
| `SHODAN_API_KEY` | (unset) | Optional — enables the Shodan source. |
| `C99_API_KEY` | (unset) | Optional — enables the c99.nl source. |

---

## 7. Installation

### Option A — Docker (quickest, nothing to build)

A prebuilt image is published to GHCR by CI on every push.

```bash
docker run --rm -p 8080:8080 -e SUBRECON_HOST=0.0.0.0 \
  ghcr.io/aravindsv619/reconguard-pro:latest
```

Open <http://localhost:8080>.

### Option B — docker compose

A `docker-compose.yml` is included (binds to `127.0.0.1:8080` by default):

```bash
docker compose up -d      # → http://localhost:8080
docker compose down
```

### Option C — from source

Requirements: Python 3.11+ (tested on 3.14), optionally `dig`
(`dnsutils` / `bind-utils`) for faster/fuller DNS records.

```bash
git clone https://github.com/aravindsv619/reconguard-pro.git
cd reconguard-pro
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python main.py        # → http://localhost:8080
```

Development / tests:

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
.venv/bin/pre-commit install     # optional: enable the pre-commit hook
```

---

## 8. How to use

1. Start the app (any option above) and open <http://localhost:8080>.
2. Pick a mode at the top: **Subdomains** (default) or **Lookalike Domains**.
3. **Subdomains:** enter a domain → **Start Scan**. Watch per-source status in
   the progress panel. For deeper coverage, open **Advanced options** and enable
   **Active DNS brute-force** / **permutations** (authorized targets only).
4. **Lookalike Domains:** enter a domain → **Find Lookalikes**. Tick
   **Check WHOIS/RDAP** for registration details (slower).
5. Review the dashboard (summary cards, filters, sortable table, risk badges,
   per-row DNS records) and click **Download CSV** to export.

### Reading the risk columns
- **Subdomain takeover:** `takeover_verdict` is the answer — **VULNERABLE**
  (investigate urgently), **NOT_VULNERABLE** (safe), **INCONCLUSIVE** (verify
  manually). `takeover_risk` is the heuristic tier behind it.
- **Lookalike:** **HIGH** = likely active impersonation; **MEDIUM** =
  live/parked/unrelated worth a look; **LOW** = minor; **AVAILABLE** =
  unregistered (consider defensively registering). Marketplace-parked
  (HugeDomains/Sedo/Dan) domains are detected and downgraded — they are
  for-sale, not active impersonation.

---

## 9. Publishing to GitHub & GHCR

The repo includes a GitHub Actions workflow (`.github/workflows/docker-publish.yml`)
that builds and publishes the Docker image to GHCR automatically.

### First-time setup (already done for this repo)

```bash
# set your git identity (once)
git config --global user.name "<your-name>"
git config --global user.email "<your-email>"

# create an empty repo on GitHub named reconguard-pro, then:
git remote add origin git@github.com:<owner>/reconguard-pro.git   # SSH
git push -u origin master
```

> Pushing requires your own GitHub credentials — an **SSH key** (recommended:
> Settings → SSH and GPG keys → New SSH key) or a **Personal Access Token**
> (scopes `repo`, `write:packages`) for HTTPS.

### What happens on push
1. Actions runs the CI: Docker build + publish to GHCR, plus the security
   pipeline (below).
2. The image is published as:
   - `ghcr.io/<owner>/reconguard-pro:latest` (default branch)
   - `ghcr.io/<owner>/reconguard-pro:sha-<short>` (per commit)
   - `ghcr.io/<owner>/reconguard-pro:vX.Y.Z` (when you push a `vX.Y.Z` tag)
3. Make the GHCR package **public** (once) so others can pull without logging in:
   GitHub profile → **Packages** → `reconguard-pro` → **Package settings** →
   **Change visibility → Public**.

### Cutting a release

```bash
git tag v1.0.0 && git push --tags     # → publishes :v1.0.0 image
```

### Day-to-day updates

```bash
git add -A && git commit -m "your message" && git push
# CI rebuilds and republishes automatically
```

---

## 10. CI/CD & security pipeline

GitHub Actions workflows under `.github/workflows/`:

| Workflow | Purpose |
| --- | --- |
| `docker-publish.yml` | Build the image and publish to GHCR |
| `dependency-audit.yml` | `pip-audit` dependency vulnerability scan |
| `sast-bandit.yml` | Bandit static analysis (Python security linter) |
| `codeql.yml` | GitHub CodeQL SAST (dataflow/taint analysis) |
| `dast-zap.yml` | OWASP ZAP baseline DAST against an ephemeral instance |

A local **pre-commit** hook (`.pre-commit-config.yaml`) runs a secret scan,
file-hygiene checks, and `ruff` before each commit.

### Security posture (summary)
Audited against OWASP Top 10 (2021) + API Top 10 (2023) + cloud/SSRF:
- **SSRF**: private/loopback/link-local/cloud-metadata IPs blocked on every
  probe; validated IP is pinned through to the connection (DNS-rebinding closed).
- **Injection**: `dig` via argument list (no shell); CSV formula-injection
  neutralized on all columns; dot-boundary host matching.
- **XSS / integrity**: strict Content-Security-Policy (`script-src 'self'`, no
  inline JS), Tailwind vendored (no CDN), all external data HTML-escaped.
- **Misconfiguration**: security headers on every response; binds `127.0.0.1`
  by default; scoped CORS; no stack-trace leaks.
- **DoS**: per-client rate limit, request/wordlist size caps, bounded
  concurrency, active-job cap.
- **Dependencies**: `pip-audit` clean.

See `SECURITY.md` for details and residual risks.

---

## 11. Honest limitations

- **No authentication** — this is a single-user local tool. Keep it on
  `127.0.0.1` (default) or behind an authenticating reverse proxy. **Do not
  expose the raw API to the public internet.**
- **Coverage varies** — passive sources are third-party; a low result count
  usually means sources were temporarily unavailable (the UI tells you which).
  Re-run shortly or use Active DNS discovery. **No passive tool finds *all*
  subdomains** — private/internal names never appear in public data.
- **Findings are leads, not verdicts** — lookalike HIGH flags are *candidates
  to investigate*, and any takedown/registration action is a separate manual
  and legal step.

---

## 12. Project layout

```
reconguard-pro/
├── main.py                      # FastAPI backend (both modes, all logic)
├── static/
│   ├── index.html               # SPA markup + styles
│   ├── app.js                   # SPA logic (external, CSP-safe)
│   └── tailwind.css             # vendored CSS
├── wordlists/default.txt        # bundled brute-force word list
├── tests/                       # pytest suite (17 modules)
├── requirements.txt             # runtime deps (pinned)
├── requirements-dev.txt         # dev/test deps
├── Dockerfile                   # multi-stage, non-root
├── docker-compose.yml
├── .pre-commit-config.yaml
├── .github/workflows/           # CI: docker, pip-audit, bandit, codeql, zap
├── README.md
├── SECURITY.md
└── DOCUMENTATION.md             # this file
```
