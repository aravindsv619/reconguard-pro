# SubRecon Pro

Subdomain enumeration and subdomain-takeover risk analysis in a single
self-contained web tool. SubRecon Pro aggregates subdomains from 11 public
passive-DNS sources, resolves and HTTP-probes each one, scores takeover risk
against a library of service fingerprints, and lets you export everything to
CSV — all from a dark-themed browser dashboard.

> ⚠️ **For authorized security testing only. Unauthorized use is illegal.**
> Only scan domains you own or have explicit permission to test.

## Features

- Passive subdomain discovery from 11 independent public sources (no scanning
  of the target is required for discovery).
- **Active DNS discovery (optional, OFF by default):** wordlist brute-forcing
  against a bundled 2,400+ label list plus altdns-style permutation generation.
  See [Active DNS discovery](#active-dns-discovery) below.
- DNS resolution (A/AAAA) and CNAME detection per subdomain.
- HTTP and HTTPS liveness probing with status codes.
- Subdomain-takeover risk scoring (HIGH / MEDIUM / LOW / NONE) using a built-in
  fingerprint library covering 30+ services (GitHub Pages, AWS S3/CloudFront,
  Heroku, Azure, Shopify, Netlify, Fastly, and more). Matching considers the
  CNAME, the subdomain name, and the reverse-DNS (PTR) hostname of each
  A-record, so dangling IP-only records are scored as well.
- Live progress tracking with per-source status.
- Filterable, sortable results table and a risk-breakdown chart.
- One-click CSV report download.
- Optional SecurityTrails, Shodan, and c99.nl API keys for additional coverage.

## Data sources

| Source | API key required |
| --- | --- |
| crt.sh | no |
| HackerTarget | no |
| AlienVault OTX | no |
| RapidDNS | no |
| URLScan.io | no |
| ThreatCrowd | no |
| Wayback Machine (CDX) | no |
| Anubis (jldc.me) | no |
| BufferOver | no |
| SecurityTrails | optional |
| Shodan | optional |
| c99.nl | optional (paid) |

## Requirements

- Python 3.11+ (tested on 3.14)
- `dig` (from `dnsutils` / `bind-utils`) is used as the fast path for CNAME
  lookups when available. When `dig` is absent, CNAME resolution falls back to
  the Python standard-library resolver (`socket.gethostbyname_ex`), so no
  external binary is required — `dig` only speeds things up.

## Installation

```bash
cd /home/aravind/New-SEC
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Usage

```bash
.venv/bin/python main.py
```

Then open <http://localhost:8080> in your browser, enter a target domain, and
click **Start Scan**. Watch sources complete in the progress panel, review the
results dashboard, and click **Download CSV** to export.

### Active DNS discovery

Passive discovery queries third-party datasets only and never touches the
target. **Active discovery is different and more intrusive:** it composes
candidate hostnames and resolves them, sending DNS queries that resolve against
the target's own authoritative resolvers.

> ⚠️ **Authorization warning.** Active mode is OFF by default. Only enable it on
> domains you own or are explicitly authorized to test. Active DNS brute-force
> and permutation discovery generate direct DNS lookups for the target and are
> noticeably more intrusive than passive discovery.

Enable it under **Advanced Options** in the scan form:

- **Enable active DNS brute-force** — composes `{label}.{domain}` from a
  wordlist and keeps hosts that resolve (A/AAAA or CNAME). Hits are tagged
  `bruteforce` in the `sources` column and shown with an amber **BF** chip.
- **Custom wordlist** — one subdomain label per line. Each label is lowercased
  and validated against `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`; invalid labels
  are silently dropped. Choose **Replace built-in** to use only your labels, or
  **Append to built-in** to add them to the bundled list. If the box is empty
  (or every label is invalid), discovery falls back to the built-in list.
- **Enable permutation discovery** — from every already-discovered host
  (passive + brute-force hits), generates altdns-style variants: prepend/append
  common words (`dev`, `staging`, `prod`, `test`, `qa`, `uat`, `api`, …) with
  `-` and `.` separators, increments trailing numbers (`api1` → `api2`, `api3`),
  and swaps `-`/`.`. Resolving variants are tagged `permutation` and shown with
  a violet **PERM** chip.

**Bundled default wordlist:** `wordlists/default.txt` (one label per line,
2,400+ deduped lowercase labels covering infrastructure, environments,
services, databases, cloud/orchestration, and app/web hosts). Regenerate it
with `python wordlists/gen_wordlist.py`.

**Bounds (DoS safety):**

- `MAX_ACTIVE_CANDIDATES = 20000` caps the total brute-force + permutation
  candidates generated per job; anything beyond the cap is skipped and a note
  is surfaced in the job status.
- `MAX_SUBDOMAINS_PER_JOB = 5000` still bounds the final analyzed set.
- `ANALYSIS_CONCURRENCY = 50` — active resolution shares the SAME bounded
  `asyncio.Semaphore` as passive analysis; there is no separate probe path, so
  every active host passes the identical hostname and SSRF (private/internal/
  metadata IP) guards.

**Request fields (all optional, backward compatible):** the `/api/enumerate`
body accepts `active` (bool, default `false`), `wordlist` (newline-separated
string), `wordlist_mode` (`"replace"` | `"append"`, default `"replace"`), and
`permutations` (bool, default `false`). Omitting all of them reproduces the
exact passive-only behavior and status payload.

### Optional API keys

SecurityTrails, Shodan, and c99.nl improve coverage. c99.nl is a **paid**
service — its subdomain finder requires a purchased API key (there is no free
keyless tier). Provide keys in either of two ways:

- Enter them in the **Advanced Options** section of the scan form (fields
  `securitytrails_key`, `shodan_key`, `c99_key` in the POST body), or
- Set environment variables before launching the server:

  ```bash
  export SECURITYTRAILS_API_KEY="your-key"
  export SHODAN_API_KEY="your-key"
  export C99_API_KEY="your-key"
  .venv/bin/python main.py
  ```

All three keyed sources are skipped silently when no key is supplied.

## Development & tests

The runtime stack in `requirements.txt` is all that is needed to run the app.
Test-only tooling lives in `requirements-dev.txt`:

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

The suite (under `tests/`) uses `respx` to mock every outbound HTTP call and
covers the source parsers (including crt.sh wildcard stripping, Wayback URL
parsing, and the key-optional SecurityTrails/Shodan skip), the three
`check_takeover` branches plus A-record PTR matching and the socket CNAME
fallback, the job state machine and cleanup, and the API/CSV contract.

## CSV report format

The downloaded CSV contains one row per subdomain with these columns:

```
subdomain, ip_addresses, cname, http_status, https_status, sources,
resolved, alive, takeover_risk, takeover_service, takeover_detail
```

List fields (`ip_addresses`, `sources`) are joined with `;` so they don't
collide with the CSV comma delimiter.

## API

| Method | Path | Description |
| --- | --- | --- |
| POST | `/api/enumerate` | Start a job. Body: `{domain, securitytrails_key?, shodan_key?, c99_key?, active?, wordlist?, wordlist_mode?, permutations?}`. The last four enable active discovery and are optional (omitting them keeps passive-only behavior). Returns `{job_id}`. |
| GET | `/api/status/{job_id}` | Poll job status, progress, and per-source state. |
| GET | `/api/results/{job_id}` | Full results JSON once the job is `done`. |
| GET | `/api/download/{job_id}` | Download the CSV report. |
| GET | `/health` | Health check (`{"status": "ok"}`). |

Jobs are held in memory and automatically expire one hour after creation.

## Security note

CORS is scoped to localhost origins by default
(`http://localhost:8080`, `http://127.0.0.1:8080`) for local, single-user use.
To allow other origins, set the `SUBRECON_CORS_ORIGINS` environment variable to
a comma-separated list of origins (e.g.
`SUBRECON_CORS_ORIGINS="https://recon.example.com"`). Credentials are not
enabled, so a wildcard origin is never paired with cookie/credential sharing.
If you deploy SubRecon Pro to a shared or public host, keep the origin list
tight and place the service behind authentication.

Additional hardening: the `domain` input is validated against a strict
RFC-1035 hostname rule (length- and label-capped, IP literals and
scheme/slash/`@`/whitespace rejected) before it reaches any outbound request;
the subdomain HTTP probe skips any host that resolves to a private, loopback,
link-local, or cloud-metadata address (SSRF guard); CSV export neutralizes
spreadsheet formula injection; and the per-job work and concurrent-job counts
are capped to limit resource exhaustion.

TLS handling uses two separate HTTP clients: a **verified** client (standard CA
validation) for all data-source and authenticated API calls — so SecurityTrails
and Shodan API keys are never sent over unverified TLS — and a separate client
with verification disabled used **only** to probe target subdomains for
liveness and takeover fingerprints, where expired or self-signed certificates
are common. No credentials are ever sent on the probe client.
