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
- Optional SecurityTrails and Shodan API keys for additional coverage.

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

### Optional API keys

SecurityTrails and Shodan improve coverage. Provide keys in either of two ways:

- Enter them in the **Advanced Options** section of the scan form, or
- Set environment variables before launching the server:

  ```bash
  export SECURITYTRAILS_API_KEY="your-key"
  export SHODAN_API_KEY="your-key"
  .venv/bin/python main.py
  ```

Both sources are skipped silently when no key is supplied.

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
| POST | `/api/enumerate` | Start a job. Body: `{domain, securitytrails_key?, shodan_key?}`. Returns `{job_id}`. |
| GET | `/api/status/{job_id}` | Poll job status, progress, and per-source state. |
| GET | `/api/results/{job_id}` | Full results JSON once the job is `done`. |
| GET | `/api/download/{job_id}` | Download the CSV report. |
| GET | `/health` | Health check (`{"status": "ok"}`). |

Jobs are held in memory and automatically expire one hour after creation.

## Security note

CORS is configured to allow all origins so the bundled frontend works out of
the box for local, single-user use. If you deploy SubRecon Pro to a shared or
public host, restrict `allow_origins` in `main.py` and place the service behind
authentication.

TLS handling uses two separate HTTP clients: a **verified** client (standard CA
validation) for all data-source and authenticated API calls — so SecurityTrails
and Shodan API keys are never sent over unverified TLS — and a separate client
with verification disabled used **only** to probe target subdomains for
liveness and takeover fingerprints, where expired or self-signed certificates
are common. No credentials are ever sent on the probe client.
