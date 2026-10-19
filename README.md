# ReconGuard Pro

Subdomain Enumeration, Takeover Risk & Lookalike Domain Recon in a single
self-contained web tool. ReconGuard Pro aggregates subdomains from 12 keyless
public passive-DNS sources (no API key needed for any of them), resolves and
HTTP-probes each one, scores takeover risk against a library of service
fingerprints, and lets you export everything to CSV — all from a dark-themed
browser dashboard.

> ⚠️ **For authorized security testing only. Unauthorized use is illegal.**
> Only scan domains you own or have explicit permission to test.

## Features

- Passive subdomain discovery from 12 independent **keyless** public sources
  (no API key required for any of them), including the exhaustive crt.sh parser
  plus CertSpotter, ThreatMiner, and SubdomainCenter (no scanning of the target
  is required for discovery).
- **Active DNS discovery (optional, OFF by default):** wordlist brute-forcing
  against a bundled 2,400+ label list plus altdns-style permutation generation.
  See [Active DNS discovery](#active-dns-discovery) below.
- DNS resolution (A/AAAA) and CNAME detection per subdomain, including a
  `dns_status` resolver outcome and the full multi-hop `cname_chain`.
- HTTP and HTTPS liveness probing with status codes.
- Subdomain-takeover risk scoring (HIGH / VERIFY / MEDIUM / LOW / NONE) using a
  built-in fingerprint library covering 30+ services (GitHub Pages, AWS
  S3/CloudFront, Heroku, Azure, Shopify, Netlify, Fastly, and more). Matching
  considers the CNAME, the subdomain name, and the reverse-DNS (PTR) hostname of
  each A-record, so dangling IP-only records are scored as well. The **VERIFY**
  tier flags dangling CNAMEs that point at an unclaimed-looking cloud resource
  (see [Takeover risk tiers](#takeover-risk-tiers)).
- **Active takeover verification:** every VERIFY/HIGH row gets a single guarded
  confirmation probe that turns the heuristic tier into a concrete
  **VULNERABLE / NOT_VULNERABLE / INCONCLUSIVE** verdict with human-readable
  evidence (`takeover_verdict` / `takeover_evidence`). See
  [Active takeover verification](#active-takeover-verification).
- **Full DNS-records listing:** every subdomain is enumerated across all record
  types (A/AAAA/CNAME/MX/NS/TXT/SOA) and surfaced as a per-subdomain Records
  panel and a trailing `dns_records` CSV column. See
  [`dns_records`](#dns_records).
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
| CertSpotter (SSLMate) | no |
| ThreatMiner | no |
| SubdomainCenter | no |
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

### Pre-commit hooks

A [`pre-commit`](https://pre-commit.com/) config (`.pre-commit-config.yaml`)
runs fast local checks before every commit. Enable it once after installing the
dev dependencies:

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pre-commit install
```

The hooks are:

- **detect-secrets** — blocks new credentials from being committed (a
  `.secrets.baseline` acknowledges the existing documentation placeholders and
  test fixtures, which are not real secrets).
- **Basic hygiene** — trailing-whitespace, end-of-file-fixer,
  check-added-large-files, check-yaml, check-json.
- **check-ast** — a fast Python syntax check (the full pytest suite is
  intentionally NOT a pre-commit hook; CI runs the tests).
- **ruff** — Python lint with autofix (rules in `ruff.toml`; line length is not
  enforced so existing long comments do not block commits).

Run everything on demand with `.venv/bin/pre-commit run --all-files`.

### Security CI (dependency / SAST / DAST)

GitHub Actions runs the security pipeline in addition to the GHCR image build:

- **Dependency audit** (`dependency-audit.yml`) — `pip-audit` against
  `requirements.txt` and `requirements-dev.txt` on push/PR and a weekly
  schedule; fails on any known vulnerability.
- **SAST** — `bandit` (`sast-bandit.yml`, medium+ severity) and GitHub
  **CodeQL** (`codeql.yml`, Python) on push/PR and weekly. Intentional,
  reviewed Bandit findings are annotated inline with `# nosec` + a
  justification so only new unreviewed issues fail the job.
- **DAST** (`dast-zap.yml`) — builds the Docker image, starts an **ephemeral**
  instance on `localhost:8080` in the runner (`SUBRECON_HOST=0.0.0.0`), and runs
  the OWASP ZAP baseline scan against it. The scan is **non-blocking** (reports
  findings without hard-failing) and runs only against the throwaway CI
  instance — never against a deployed/production target. Rule tuning lives in
  `.zap/rules.tsv`.

See [SECURITY.md](SECURITY.md) for the full posture.

## Takeover risk tiers

Each subdomain is scored into one of five tiers. Ordered most to least severe:

**HIGH > VERIFY > MEDIUM > LOW > NONE**

- **HIGH** — a service fingerprint confirmed the target is unclaimed/dangling
  (the response body matched a known takeover signature).
- **VERIFY** — the subdomain has a dangling CNAME pointing at a recognized cloud
  resource (see below) and the HTTP signal looks "gone" (404/503, or no response
  at all) without a confirmed body fingerprint. This is **not** a confirmed
  takeover: it means the resource may have been deprovisioned and the pointer
  left behind. **Manual confirmation is required** — check whether the resource
  still exists and is owned by you before assuming the record is safe or
  reclaimable. VERIFY sorts between MEDIUM and HIGH and is rendered with an amber
  badge in the dashboard.
- **MEDIUM** — a weaker/service-name match without a confirmed body fingerprint.
- **LOW** — a cloud-resource CNAME that still appears live (e.g. returns 200).
- **NONE** — no takeover indicators.

### Cloud resource coverage (`CLOUD_RESOURCE_PATTERNS`)

VERIFY detection matches the final CNAME-chain target (anchored host-suffix
match, no substring false positives) against these providers:

- **AWS** — Elastic Load Balancing (`*.elb.amazonaws.com`), S3
  (`*.s3*.amazonaws.com`, `*.s3-website-*.amazonaws.com`), CloudFront
  (`*.cloudfront.net`).
- **Azure** — Web Apps (`*.azurewebsites.net`), Traffic Manager
  (`*.trafficmanager.net`), Cloud App (`*.cloudapp.azure.com`), Blob Storage
  (`*.blob.core.windows.net`).
- **Heroku** — `*.herokudns.com`, `*.herokuapp.com`.
- **GitHub Pages** — `*.github.io`.
- **Google Cloud** — Storage (`*.storage.googleapis.com`), App Engine
  (`*.appspot.com`).
- **Fastly** — `*.fastly.net`.

VERIFY uses only already-gathered data (the CNAME chain plus the HTTP statuses
collected during the single guarded probe) and issues no additional network
request, so the SSRF guard is preserved.

## Active takeover verification

The VERIFY tier is a heuristic. On top of it, ReconGuard Pro runs an **active
confirmation pass** that resolves the dangling CNAME target's own DNS, probes
it once (guarded), and turns the tier into a concrete verdict with evidence.
Only VERIFY/HIGH rows are verified; every other row carries an empty verdict.

Each verified row exposes two fields (`takeover_verdict`, `takeover_evidence`)
and a verdict badge in the dashboard. The verdict is one of:

| Verdict | Meaning |
| --- | --- |
| `VULNERABLE` | The target shows a resource-not-found signature (or is NXDOMAIN for a user-chosen-name provider). The dangling pointer is likely claimable — **act now.** A confirmed `VULNERABLE` verdict also promotes the row's risk tier from VERIFY to HIGH. |
| `NOT_VULNERABLE` | The target still serves content or is an AWS-assigned (non-claimable) name. The record is dangling but not takeover-able as observed. |
| `INCONCLUSIVE` | No decisive signal (indeterminate response, SSRF-skipped probe, timeout, or any error). **Manual confirmation required.** |

### Who is claimable — the ELB/CloudFront vs S3/GitHub distinction

Not every cloud DNS name can be re-registered by an attacker, and the verdict
logic treats the two groups differently:

- **AWS ELB names are NOT attacker-claimable.** Elastic Load Balancing
  (`*.elb.amazonaws.com`) DNS names are issued by AWS, not chosen by the account
  owner, so an attacker cannot create a replacement with the same name. A
  dangling CNAME to one is usually a down/internal service (an ELB 503 means
  "no healthy targets"), not a takeover. The verifier resolves the CNAME-chain
  **final** target (with any trailing dot stripped before resolving, so a
  dotted name no longer silently fails to resolve): a target that still resolves
  reports `NOT_VULNERABLE`, and an NXDOMAIN target reports `INCONCLUSIVE`. A
  resolution error or timeout no longer falls through to a default verdict.
- **CloudFront now has an active no-distribution check.** When the CNAME points
  at `*.cloudfront.net`, the verifier probes the stripped target through the
  same SSRF guard and bounded semaphore (private IPs are never probed). If
  CloudFront returns its no-distribution signature — a 403/404 (or `Bad
  request`) whose body contains `The request could not be satisfied` — the alias
  is unclaimed and attacker-registerable, so the verdict is `VULNERABLE` and the
  risk is promoted VERIFY → HIGH. A healthy 200/301/302 is `NOT_VULNERABLE`; a
  timeout or blocked probe is `INCONCLUSIVE`. A **bare** 403 without the
  no-distribution signature is treated as `INCONCLUSIVE` (no false positive).
- **User-chosen names ARE attacker-claimable.** S3 buckets, GitHub Pages,
  Heroku apps, Azure sites, Google Cloud, and Fastly services use names the
  original owner picked. If that resource is deleted the name becomes free, so
  an attacker can re-register it. These providers reach `VULNERABLE` only on a
  provider-specific resource-not-found signature (e.g. S3 `NoSuchBucket`,
  GitHub Pages "There isn't a GitHub Pages site here", Heroku "No such app",
  Fastly "unknown domain") **or** when the target hostname is NXDOMAIN.

### Safety invariants

The confirmation probe reuses the existing SSRF guard (`_is_safe_public_ip`):
if the target resolves only to private/loopback/link-local/metadata IPs the
probe is **skipped** and the verdict is `INCONCLUSIVE`. The single probe is
bounded by the same `asyncio.Semaphore` as the rest of analysis (no new
fan-out) and uses a dedicated short timeout, and the whole verification body is
wrapped so it can never raise — any failure degrades to `INCONCLUSIVE`.

### `recommended_action`

Every flagged (VERIFY/HIGH) subdomain also carries a `recommended_action`
string derived from its final risk, verdict, and provider, so there is **always
a concrete next step** — never a dead end, including for an `INCONCLUSIVE`
verdict (which prompts manual ownership verification in the provider console). A
`VULNERABLE` row recommends removing the dangling record or reclaiming the
resource immediately. It is surfaced XSS-safe in the dashboard (the
per-subdomain Records panel, `escapeHtml`-ed) and exported as the 16th CSV
column (see [CSV report format](#csv-report-format)).

## Lookalike Domains mode

Alongside subdomain enumeration, ReconGuard Pro has a second mode that works the
other way round: instead of finding hosts *under* your domain, it proactively
hunts for confusingly-similar domains that **someone else** might register for
phishing or brand abuse. You give it one domain at a time; it generates
plausible lookalike variants, resolves and probes each one, and tells you which
ones are live, registered, or still available to register. For example, from
`brandco.ai` it surfaces `brand-co.com` and `brandco.com` — but the engine
is **general** and works for any domain you own, not just that example.

Switch to it with the **Lookalike Domains** tab at the top of the dashboard
(the UI defaults to the Subdomains mode, so existing workflows are unchanged).

> ⚠️ **For authorized brand protection only.** Use this mode only on domains you
> own or are authorized to protect. The findings are **candidates to
> investigate, not proof of malice** — a lookalike may be an unrelated legitimate
> site, a typo-parking page, or simply unregistered.

### Fully keyless

Candidate generation is pure and keyless — no API key and no network I/O to
produce the variants. Resolution and HTTP probing reuse the same guards as the
subdomain path (strict hostname validation, the SSRF private/loopback/metadata
IP guard before any probe, bounded concurrency, and capped response bodies).

### Permutation techniques

`generate_lookalikes(domain)` applies each of these techniques, deduped,
lowercased, and excluding the input domain itself:

- **Hyphenation** — insert a single hyphen between adjacent character groups
  (e.g. `brandco` → `brand-co`).
- **TLD swap** — keep the label and swap the TLD across a common set
  (`com`, `net`, `org`, `io`, `co`, `ai`, `app`, `dev`, …) plus the original.
- **Omission** — remove one character.
- **Insertion** — insert an adjacent-keyboard character between letters.
- **Repetition** — double a character.
- **Transposition** — swap two adjacent characters.
- **Replacement** — replace a character with a QWERTY-adjacent key.
- **Homoglyph** — apply visually-similar substitutions (`o`↔`0`, `l`↔`1`↔`i`,
  `m`↔`rn`, `w`↔`vv`, `cl`↔`d`, `b`↔`6`, `g`↔`9`, `s`↔`5`), bounded.
- **Combosquatting** — prepend/append common words (`login`, `secure`,
  `account`, `support`, `verify`, …) with a hyphen.
- **Subdomain / dot-insert** — insert a dot splitting the label
  (e.g. `brand.co.tld`).
- **Bitsquatting** — flip one bit of each alphabetic character, keeping only
  valid hostnames.

Generation is capped at `MAX_LOOKALIKE_CANDIDATES = 5000`; the cap is enforced
at every growth step so a pathological input can never blow up the candidate
set.

### Optional WHOIS / RDAP check

The **Check WHOIS/RDAP (slower)** flag is off by default. When enabled, each
candidate is looked up over RDAP (`https://rdap.org/domain/{domain}`) on the
**verified** TLS client to determine whether it is registered and to pull the
registrar and creation date when present. RDAP is rate-limited, so its
concurrency is kept deliberately low (`RDAP_CONCURRENCY = 5`) and any
error or timeout is **tolerated** — the candidate's `registered` field is marked
`unknown` and the lookup never blocks or fails the job. With the flag off, no
RDAP calls are made and `registered` stays `unknown`.

### Lookalike risk tiers

Each candidate is scored into one of these tiers (**candidates to investigate,
not proof of malice**):

- **HIGH** — resolves and serves a live site, and either has MX records or its
  page resembles your original. Treat as a possible phishing / brand-abuse site:
  investigate, consider monitoring or takedown, and confirm ownership.
- **MEDIUM** — resolves and is live but with no MX and no apparent mimicry, or is
  registered but parked / has no real site.
- **LOW** — resolves at the DNS level only, with no live site.
- **AVAILABLE** — does not resolve and (when WHOIS/RDAP was checked) appears
  unregistered. Consider **defensive registration** so an attacker can't grab it.

Every candidate also carries a `recommended_action` string with a concrete next
step appropriate to its tier (e.g. HIGH → investigate possible phishing/brand
abuse and confirm ownership; AVAILABLE → consider defensive registration).

### Lookalike CSV report

This mode exports its **own** report, separate from the 16-column subdomain CSV.
The lookalike CSV has these 14 columns, in order:

```
candidate, technique, dns_status, ip_addresses, http_status, https_status,
page_title, has_mx, registered, registrar, creation_date, resembles_original,
risk, recommended_action
```

`ip_addresses` is joined with `;`, and every text cell (including
attacker-influenced values like `page_title` and `registrar`) passes through the
same spreadsheet-formula-injection neutralizer used by the subdomain export.

### Lookalike API

| Method | Path | Description |
| --- | --- | --- |
| POST | `/api/lookalike` | Start a lookalike job. Body: `{domain, check_whois?}` (`check_whois` defaults to `false`). Returns `{job_id}`. |
| GET | `/api/lookalike/status/{job_id}` | Poll `status`, `progress`, `candidates_generated`, `candidates_checked`, and `registered_count`. |
| GET | `/api/lookalike/results/{job_id}` | Full candidate list plus a summary once the job is `done`. |
| GET | `/api/lookalike/download/{job_id}` | Download the lookalike CSV report. |

These endpoints are keyless, reuse the per-client rate limit and the combined
active-job cap, and keep their jobs in a store separate from the subdomain jobs
(also expiring one hour after creation).

## DNS reporting

### `dns_status`

Per-subdomain resolver outcome (one of six values):

| Value | Meaning |
| --- | --- |
| `RESOLVED` | A/AAAA records returned (`resolved` is `true` only in this case). |
| `NXDOMAIN` | The name does not exist. |
| `NO_ANSWER` | The name exists but has no A/AAAA (e.g. CNAME-only). |
| `SERVFAIL` | The resolver reported a server failure. |
| `TIMEOUT` | The lookup timed out. |
| `ERROR` | Other/unknown resolution error (also used for invalid hostnames). |

The `resolved` boolean is derived strictly as `dns_status == "RESOLVED"`, so a
CNAME-only host (no A/AAAA) now reports `resolved: false`. `dns_status` is shown
as its own **DNS** column in the results table.

### `cname_chain`

An additive JSON array (`list[str]`) listing every CNAME target following
multiple hops (bounded to 10 hops, loop-protected). The first element equals the
existing single `cname` field; the array is empty when there is no CNAME. The
single `cname` field is unchanged. In the dashboard the full chain (joined with
` -> `) is surfaced as a hover title on the CNAME cell when there is more than
one hop.

### `dns_records`

A per-subdomain listing of **every** DNS record type, not just the A/AAAA/CNAME
used for resolution. For each type in A, AAAA, CNAME, MX, NS, TXT, SOA, a
`dig +short <TYPE> <host>` lookup is run and its answer lines are parsed into a
list; the field is a JSON object keyed by record type (only types that returned
at least one answer appear). The lookup runs `dig` as an argument list (no
shell), gates the host through the hostname validator, and uses a short per-type
timeout so one slow type cannot stall the enumeration. When `dig` is absent it
falls back to the Python standard library (A/AAAA via `getaddrinfo`, CNAME via
the socket resolver; MX/NS/TXT/SOA are left empty in that mode).

This field is purely **additive** — it never touches `ip_addresses`, `cname`,
or `cname_chain`. In the dashboard each subdomain row has a small ▸ toggle that
reveals a **Records** panel listing all discovered record types. In the CSV it
is one trailing `dns_records` column where values are joined with `,` and types
with `;` so the whole listing stays inside a single comma-CSV cell, e.g.
`A=1.2.3.4;MX=10 mail.example.com;NS=ns1.example.com,ns2.example.com`.

## CSV report format

The downloaded CSV contains one row per subdomain with these 16 columns:

```
subdomain, ip_addresses, cname, http_status, https_status, sources,
resolved, alive, takeover_risk, takeover_service, takeover_detail, dns_status,
takeover_verdict, takeover_evidence, dns_records, recommended_action
```

The first 15 columns keep their exact order and meaning (`dns_status` is the
12th, `dns_records` the 15th). Column 16 — `recommended_action` — is appended
LAST, after `dns_records`; the first 15 columns are unchanged (no column was
reordered or removed). List fields (`ip_addresses`,
`sources`) are joined with `;` so they don't collide with the CSV comma
delimiter; `dns_records` uses its own `,`/`;` scheme (see
[`dns_records`](#dns_records)). Every text cell, including the new
columns, passes through the spreadsheet-formula-injection neutralizer before
export.

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
If you deploy ReconGuard Pro to a shared or public host, keep the origin list
tight and place the service behind authentication.

Additional hardening: the `domain` input is validated against a strict
RFC-1035 hostname rule (length- and label-capped, IP literals and
scheme/slash/`@`/whitespace rejected) before it reaches any outbound request;
the subdomain HTTP probe skips any host that resolves to a private, loopback,
link-local, or cloud-metadata address (SSRF guard); CSV export neutralizes
spreadsheet formula injection; and the per-job work and concurrent-job counts
are capped to limit resource exhaustion.

### Security headers and Content-Security-Policy

Every handled HTTP response (API, static, and handled errors — 404/422/429)
carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, and a strict `Content-Security-Policy`:

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';
base-uri 'none'; object-src 'none'; form-action 'self'
```

Because `script-src` is `'self'` with no third-party origins and no
`'unsafe-inline'` for scripts, **Tailwind is vendored locally** in
`static/tailwind.css` (hand-authored, offline — no CDN runtime script) and all
UI interactivity is wired with `addEventListener` instead of inline `on*`
handlers. `'unsafe-inline'` is granted to `style-src` **only**, for the page's
small inline `<style>` block and dynamic class strings; it does not weaken
script protection.

### Bind address and rate limiting

The server **binds to `127.0.0.1` by default** (overridable with the
`SUBRECON_HOST` environment variable), so it is not exposed on all interfaces
out of the box. `POST /api/enumerate` is protected by a per-client (IP)
in-memory rate limit, configurable via `SUBRECON_RATE_LIMIT` (default
`60`/minute); requests over the threshold receive HTTP 429. Outbound responses
and request wordlists are byte-capped to bound memory use.

### Deployment warning

ReconGuard Pro has **no authentication** — it is a single-user local tool. Run it
on localhost (the default) or behind an authenticating reverse proxy. **Do not
expose the raw API publicly.** Anyone who can reach the API can start scans and
read any job's results.

TLS handling uses two separate HTTP clients: a **verified** client (standard CA
validation) for all data-source and authenticated API calls — so SecurityTrails
and Shodan API keys are never sent over unverified TLS — and a separate client
with verification disabled used **only** to probe target subdomains for
liveness and takeover fingerprints, where expired or self-signed certificates
are common. No credentials are ever sent on the probe client.
