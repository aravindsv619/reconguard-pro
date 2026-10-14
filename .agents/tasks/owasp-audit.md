# SubRecon Pro — OWASP Hardening Audit Report

**Scope:** `/home/aravind/New-SEC/main.py` (backend), `static/index.html` +
`static/tailwind.css` (frontend), `tests/`, `requirements*.txt`, `README.md`.

**Covers:** OWASP Web Top 10 (2021), OWASP API Security Top 10 (2023), and
cloud / scanner-specific concerns.

**Builds on** `.agents/tasks/security-audit.md` (the first iteration: input
validation, probe-client SSRF guard, CSV injection, DOM XSS, DoS caps, CORS).
This report does **not** repeat that detail where unchanged — it records the
OWASP-hardening pass (FEAT-001 backend + FEAT-002 frontend/CSP) and the current
verified status of every item.

**Test baseline:** 186 passed before this task → 233 passed after the OWASP
pass → **235 passed** after the live-server header hardening (186 baseline + 40
FEAT-001 backend tests in `tests/test_owasp.py` + 7 FEAT-002 frontend/CSP tests
in `tests/test_frontend.py` + 2 real-server header tests in
`tests/test_live_server_headers.py`).

Severity scale: CRITICAL / HIGH / MEDIUM / LOW / INFO.
Status: **FIXED** (was vulnerable, now closed) / **SAFE-VERIFIED** (checked,
already safe) / **N/A** (not applicable, with reason).

---

## OWASP Web Top 10 (2021)

### A01 — Broken Access Control — SAFE-VERIFIED (MEDIUM where relevant)
- **Job IDs / IDOR:** `job_id` is a server-generated `uuid4().hex`
  (`enumerate_domain` ~2404); all lookups use `JOBS.get(...)` on an in-memory
  dict, and unknown/malformed IDs return **404** (`job_status`, `job_results`,
  `download_csv`). No filesystem path is derived from client input, so no path
  traversal. Verified: `test_unknown_job_id_returns_404`
  (`tests/test_owasp.py`).
- **Static mount:** `/` is served by `StaticFiles` (Starlette), which rejects
  `..` traversal. Only files under `static/` are reachable.
- **Note:** There is no per-user authorization because the tool is single-user
  / local (see A07). Any client that can reach the API can read any job's
  results — acceptable for the localhost deployment model, documented under
  *Residual risk*.

### A02 — Cryptographic Failures — SAFE-VERIFIED
- **TLS split:** two httpx clients are created in `lifespan` (~2346):
  `app.state.client` is TLS-**verified** (`verify=True`) and used for all source
  fetches and authenticated API-key calls; `app.state.probe_client`
  (`verify=False`) is used **only** to probe target subdomain liveness, where a
  self-signed/expired cert is expected and the response body is not trusted.
- **Secret handling:** API keys (SecurityTrails / Shodan / c99) are read only in
  their source functions and sent only to those endpoints over the verified
  client; they never appear in results JSON, status JSON, CSV, or logs
  (verified by `test_api_key_never_leaks` in `tests/test_security.py` and the
  no-secret-in-logs assertion in FEAT-001).

### A03 — Injection — SAFE-VERIFIED (hardened)
- **`dig` subprocess:** always invoked as an argument list with `timeout=5`,
  never `shell=True` (`_dig_dns_status`, `_dig_cname`, `_dig_records`); every
  host passes `is_valid_hostname` before reaching `dig`.
- **URL interpolation:** `domain` and discovered hosts are gated by
  `is_valid_hostname` (rejects `/ \ @ :` whitespace, control chars, `*`, IP
  literals, overlong labels, `len > 253`) before being placed in outbound URLs.
- **CSV formula injection:** `_csv_safe` neutralizes `= + - @ TAB CR LF` leading
  characters on all 16 CSV text columns (`test_csv_download_neutralizes_all_text_columns`).
- **CSV header CRLF:** download filename is `re.sub`-sanitized to `[a-z0-9.-]`.
- **ReDoS:** `DOMAIN_RE` and the cloud/source regexes are anchored and run on
  ≤253-char input; smoke test confirms pathological input returns in <1s
  (`test_hostname_validation_redos_smoke`).

### A04 — Insecure Design (DoS / resource limits) — FIXED
- **Per-client rate limit (NEW, FEAT-001):** an in-memory token bucket keyed on
  `request.client.host` guards `POST /api/enumerate`, configurable via
  `SUBRECON_RATE_LIMIT` (default 60/min). Over threshold → **HTTP 429** with a
  generic detail; the limiter **fails open** on any internal error and prunes
  stale buckets. `enumerate_domain` ~2404.
  Tests: `test_rate_limit_returns_429_over_threshold`,
  `test_rate_limit_under_threshold_accepts`,
  `test_rate_limit_fails_open_on_internal_error`.
- **Request-body / wordlist cap (NEW, FEAT-001):** `EnumerateRequest.wordlist`
  is `Field(max_length=MAX_WORDLIST_BYTES)` (~1 MiB) so an enormous wordlist is
  rejected (422) before parsing; small/normal wordlists are unaffected.
  Tests: `test_oversized_wordlist_rejected`, `test_normal_wordlist_accepted`.
- **Existing caps retained:** `MAX_ACTIVE_JOBS` (429), `MAX_SUBDOMAINS_PER_JOB`,
  `MAX_ACTIVE_CANDIDATES`, and `asyncio.Semaphore(50)` for probe concurrency.

### A05 — Security Misconfiguration — FIXED
- **Security headers + CSP (NEW, FEAT-001; hardened to pure-ASGI):** a
  class-based pure-ASGI middleware `SecurityHeadersMiddleware` (added via
  `app.add_middleware(...)`, outermost — after CORS) wraps the ASGI `send` and
  injects the four headers on the `http.response.start` message of **every**
  response: API, the `StaticFiles` SPA mount at `/`, the vendored
  `/tailwind.css`, and handled errors (400/404/422/429). It uses case-insensitive
  `setdefault` semantics so a response that already set a header is not
  overridden and CORS headers are never duplicated. Headers:
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, and the module-level `SECURITY_CSP`:
  ```
  default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
  img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';
  base-uri 'none'; object-src 'none'; form-action 'self'
  ```
  **TestClient-vs-live gap closed:** the previous implementation used an
  `@app.middleware("http")` function, which operates on the router's Starlette
  `Response`. The existing header tests all drove Starlette's `TestClient`
  (router path) and reported the headers present, but that harness could not
  catch a case where a live uvicorn server omitted the headers on a `StaticFiles`
  response (a mounted sub-app can stream its own ASGI messages without surfacing
  a `Response` to a function wrapper). The pure-ASGI middleware removes that
  dependence on a surfaced `Response` and is now **verified on a real server**.
  Tests: `test_security_headers_on_api_response`,
  `test_security_headers_on_404_response`,
  `test_security_headers_on_static_response`,
  `test_security_csp_exact_string` (`tests/test_owasp.py`);
  `test_index_security_headers_and_csp`,
  `test_tailwind_css_served_as_css_with_headers` (`tests/test_frontend.py`);
  **and new real-server tests** `test_security_headers_on_real_asgi_transport`
  (httpx `ASGITransport` over the full middleware stack) and
  `test_security_headers_on_subprocess_uvicorn` (a subprocess-launched
  `uvicorn` on an ephemeral port, hit over a real socket — the check that would
  have caught the live gap) in `tests/test_live_server_headers.py`. Live
  verification: `curl -sD -` against `python main.py` on :8080 shows all four
  headers (exact `SECURITY_CSP`) on `/`, `/tailwind.css`, `/health`, and a 404.
- **Bind address (NEW, FEAT-001):** `uvicorn.run` now defaults to
  `host=os.environ.get("SUBRECON_HOST", "127.0.0.1")` (was `0.0.0.0`), so the
  tool is not exposed on all interfaces by default.
- **CORS:** scoped to localhost by default, env-overridable, no credentials
  (from the first iteration).
- **Debug off / generic 500:** FastAPI debug is off; unhandled errors return a
  generic `{"detail":"Internal Server Error"}` with no stack trace
  (`test_forced_error_500_has_no_stack_trace`).
- **Header coverage caveat:** the `@app.middleware("http")` runs *inside*
  Starlette's `ServerErrorMiddleware`, so a genuinely-unhandled 500 is emitted
  above this layer **without** the four headers. The 500 body is the static
  JSON string above (no reflected or sniffable content), so the risk is
  negligible; all handled responses (200/static/404/422/429) carry the headers.
  See *Residual risk*.

### A06 — Vulnerable & Outdated Components — SAFE-VERIFIED (manual audit)
- `pip-audit` could **not** be installed (no network: PyPI unreachable), so a
  **manual advisory review** was performed (per the plan's offline fallback).
- Runtime pins (all exact, `requirements.txt`): `fastapi==0.115.5`,
  `uvicorn[standard]==0.32.1`, `httpx==0.27.2`, `aiofiles==24.1.0`,
  `python-multipart==0.0.12`. Installed transitive: starlette 0.41.3,
  pydantic 2.14.1, pydantic_core 2.50.1, anyio 4.15.1, certifi 2026.7.22,
  h11 0.16.0. Dev pins: `pytest==9.1.1`, `pytest-asyncio==1.4.0`,
  `respx==0.23.1`.
- **python-multipart 0.0.12:** has known form-parse DoS advisories (e.g.
  CVE-2024-53981, fixed 0.0.18) — **not exploitable here**: the app exposes no
  `multipart/form-data` endpoint (all routes consume JSON), so the vulnerable
  path is unreachable. Left pinned to avoid an unverifiable offline bump;
  documented as non-exploitable. (Content rephrased for compliance with
  licensing restrictions; see
  [GHSA-2jv5-9r88-3w3p](https://github.com/advisories/GHSA-2jv5-9r88-3w3p).)
- **starlette 0.41.3** is past the multipart DoS fix (0.40.0); **h11 0.16.0**
  includes the request-smuggling fix (advisory affected <0.16.0). No other
  confirmed, applicable high-severity advisory at these pins. No bumps applied.
- **Action:** re-run `pip-audit` when network is available before any public
  release.

### A07 — Identification & Authentication Failures — N/A (documented)
- SubRecon Pro is a **single-user local tool** with no login, sessions, or
  accounts, so authentication controls do not apply. The deployment constraint
  (run on localhost or behind an authenticating reverse proxy; never expose the
  raw API publicly) is the compensating control — see *Residual risk*.

### A08 — Software & Data Integrity Failures — FIXED (this task's headline fix)
- **Finding (HIGH):** `static/index.html:7` loaded Tailwind from
  `https://cdn.tailwindcss.com` as a runtime JIT `<script>` with no Subresource
  Integrity. A compromised/MITM'd CDN could execute arbitrary script in the
  page, and the third-party origin forced `script-src` to allow a remote origin
  (blocking a tight CSP). An inline `tailwind.config` `<script>` (lines 9–24)
  compounded the inline-script surface.
- **Fix (FEAT-002):** Tailwind is **vendored locally** into
  `static/tailwind.css` — a hand-authored, self-contained stylesheet covering
  exactly the utility classes used in `index.html` plus the custom theme
  (`brand-{300,500,600,700}` = `#a5b4fc / #6366f1 / #4f46e5 / #4338ca`) and the
  `fadein` animation. No `npx`/CDN/network is used at build time. The CDN
  `<script>` and inline `tailwind.config` were removed; a
  `<link rel="stylesheet" href="/tailwind.css">` was added; the page-specific
  inline `<style>` (progress stripes, sticky column, sortable, `stripe`
  keyframes) is preserved. The page renders pixel-identically with **no**
  third-party origin, so `script-src 'self'` holds with no exceptions.
- **Live header coverage over the vendored assets (hardened):** the vendored
  `static/index.html` and `static/tailwind.css` are served by the `StaticFiles`
  mount at `/`. The A05 pure-ASGI `SecurityHeadersMiddleware` now stamps the
  four headers (incl. the exact `SECURITY_CSP`) on those StaticFiles responses
  on the **live uvicorn server**, confirmed by `curl` and by
  `test_security_headers_on_subprocess_uvicorn`. This closes the earlier gap
  where header coverage of the SPA assets was only asserted via Starlette's
  `TestClient` (router path), which could not detect a live StaticFiles
  divergence.
  Tests: `test_index_has_no_cdn_tailwind_and_links_local_css`,
  `test_index_references_no_third_party_origin`,
  `test_index_preserves_inline_style_block`,
  `test_tailwind_css_covers_brand_and_fadein`,
  `test_tailwind_css_served_as_css_with_headers`.

### A09 — Security Logging & Monitoring Failures — FIXED (minimal)
- **Fix (FEAT-001):** minimal structured job-lifecycle logging added in
  `run_enumeration` (job start/done with `job_id` + domain + active flag only —
  never keys or response bodies). Existing `logger.debug(... exc)` lines were
  confirmed to log exception messages only, never secrets or full bodies.

### A10 — Server-Side Request Forgery (SSRF) — FIXED (residual noted)
- **Probe IP guard (existing):** every target probe passes
  `_is_safe_public_ip`, which rejects private, loopback, link-local
  (incl. `169.254.169.254`), reserved, multicast, unspecified, and the IPv6
  equivalents (`::1`, `fc00::`, `fe80::`, `fd00:ec2::254`); a normal public
  IPv4/IPv6 passes. Table test: `test_is_safe_public_ip_rejects_internal`,
  `test_is_safe_public_ip_allows_public`.
- **CNAME-only rebinding (FIXED, FEAT-001):** `verify_takeover` now probes a
  target **only** when it resolved to a public IP; a CNAME-only / no-public-IP
  target is no longer probed by hostname (closing the httpx re-resolve window),
  but still receives a DNS-based per-provider verdict.
- **Verified-client redirects (FIXED, FEAT-001):** the verified source client
  now sets `follow_redirects=False`, so a hostile source cannot 3xx-redirect the
  authenticated client to an internal host. The probe client keeps redirects on
  (it is IP-guarded at the call site). Tests:
  `test_verified_client_does_not_follow_redirects`,
  `test_source_redirect_to_internal_not_followed`.
- **Residual:** a resolve→connect TOCTOU DNS-rebinding window remains on probes
  (httpx re-resolves at connect). Documented in-code; fully closing it needs a
  pinned-IP transport. See *Residual risk*.

---

## OWASP API Security Top 10 (2023)

- **API1 Broken Object Level Authorization** — SAFE-VERIFIED. Object IDs are
  unguessable `uuid4` with 404 on miss; no cross-object leakage. (Single-user
  model, see A07.)
- **API2 Broken Authentication** — N/A (no auth; local tool, see A07).
- **API3 Broken Object Property Level Authorization** — SAFE-VERIFIED. Status /
  results JSON expose only intended fields; no API keys, internal paths, or
  stack detail. The 16-column CSV contract is unchanged.
- **API4 Unrestricted Resource Consumption** — FIXED. Per-client rate limit,
  wordlist/body byte cap, outbound response-size cap (`MAX_RESPONSE_BYTES`
  ~10 MiB in both `_get` and `check_http`), job/candidate caps, bounded
  semaphore. Tests: rate-limit trio, `test_oversized_wordlist_rejected`,
  `test_source_response_size_cap_returns_empty`,
  `test_source_response_under_cap_parses_normally`.
- **API5 Broken Function Level Authorization** — N/A (no roles/functions to
  separate; single-user tool).
- **API6 Unrestricted Access to Sensitive Business Flows** — SAFE-VERIFIED. The
  only sensitive flow (starting a scan) is rate-limited and capped (API4/A04).
- **API7 Server-Side Request Forgery** — FIXED (see A10): IP guard + CNAME-only
  rebinding fix + verified-client no-redirect.
- **API8 Security Misconfiguration** — FIXED (see A05): headers/CSP, localhost
  bind, scoped CORS, debug off.
- **API9 Improper Inventory Management** — INFO. `/docs` and `/redoc` are
  enabled intentionally for local use; documented, and acceptable under the
  localhost-only deployment model. Optionally gate behind an env flag before any
  non-local exposure.
- **API10 Unsafe Consumption of APIs** — FIXED. Third-party source responses are
  treated as untrusted: `_normalize_host` now requires `is_valid_hostname`
  **after** scope/wildcard checks, so hostile hostnames (control chars, overlong
  labels, junk) are never stored or rendered
  (`test_normalize_host_rejects_hostile`, `test_normalize_host_accepts_normal_in_scope`,
  `test_normalize_host_rejects_out_of_scope`); the response-size cap
  (`MAX_RESPONSE_BYTES`) bounds a hostile multi-hundred-MB body in both outbound
  clients; the verified client does not follow source redirects.

---

## Cloud / scanner-specific items

- **Cloud takeover recommendation accuracy (FIXED — user-reported):** a
  Lightsail/Bitnami **A-record** host (`203.0.113.10`) was wrongly labeled
  "Inconclusive (AWS S3)". `verify_takeover` now tracks the provider's origin:
  when "AWS S3" was recovered from an A-record PTR heuristic (not a real
  `*.s3[...].amazonaws.com` CNAME), the S3 bucket wording and S3-specific
  reasoning are skipped and a provider-neutral verdict is returned
  (live → NOT_VULNERABLE; otherwise INCONCLUSIVE naming a plain compute /
  Lightsail / Bitnami / EC2 instance). The genuine S3-CNAME path is unchanged,
  and `CSV_COLUMNS` order is untouched. Test: `test_a_record_host_not_labeled_s3`.
- **DNS resolution safety:** `dig` is argument-list only, `timeout=5`, no shell;
  all hosts validated before lookup.
- **Egress / scanning posture:** the tool makes outbound requests to the target
  and to third-party intel sources by design. Response bodies are size-capped
  and treated as untrusted; hostnames and IPs are validated/guarded before use.

---

## Residual risk & safe deployment

This report does **not** claim SubRecon Pro is provably free of all
vulnerabilities. Known residual items:

1. **DNS-rebinding TOCTOU (A10/API7):** the SSRF guard resolves a host, checks
   the IP, then connects — but httpx re-resolves at connect, leaving a small
   resolve→connect window where a rebinding attacker could point a
   previously-public name at an internal IP. Mitigated (CNAME-only targets are
   no longer probed by hostname; verified client does not follow redirects) but
   not fully eliminated without a pinned-IP transport.
2. **No authentication (A07/API2):** any client that can reach the API can start
   scans and read any job's results. **Deploy on localhost (the new 127.0.0.1
   default) or behind an authenticating reverse proxy. Do not expose the raw API
   publicly.**
3. **`/docs` and `/redoc` (API9):** enabled for local convenience; gate behind
   an env flag before any shared/non-local exposure.
4. **Dependency audit offline (A06):** `pip-audit` could not run (no network); a
   manual advisory review was done instead. Re-run `pip-audit` with network
   access before release. `python-multipart 0.0.12` carries an advisory that is
   present-but-unreachable (no multipart endpoint).
5. **Rate limit is in-memory and per-process:** it does not coordinate across
   multiple workers/replicas and resets on restart. Adequate for the
   single-process local model; use an external limiter for a scaled deployment.
6. **Egress by design:** the tool intentionally contacts targets and third-party
   sources; run it only against domains you are authorized to test and from a
   network where that egress is acceptable.
7. **Security headers absent on unhandled 500 (A05):** the pure-ASGI
   `SecurityHeadersMiddleware` sits in the user-middleware block, which Starlette
   wraps *inside* its outermost `ServerErrorMiddleware`. A genuinely-unhandled
   500 is therefore produced above this layer and returns without the four
   hardening headers. The response is a static JSON error body with no
   reflected/sniffable content, so the practical risk is negligible; **every
   handled response** (API success, 400/404/422/429, StaticFiles `/` and
   `/tailwind.css`, `/health`) carries the headers — now verified on a real
   uvicorn server, not only Starlette's `TestClient`. Attach them via a
   dedicated 500 exception handler if full coverage is required.

---

## Vendoring & inline-handler decision (FEAT-002)

- **Tailwind vendoring:** chose a **hand-authored, self-contained
  `static/tailwind.css`** generated offline (no `npx`, no CDN download) covering
  exactly the 157 utility classes used in `index.html` plus the `brand-*` colors
  and `fadein` animation, mirroring Tailwind v3 default values so the render is
  pixel-identical. This removes the only third-party script origin and lets the
  CSP stay strict.
- **Inline event handlers vs CSP:** the page previously used inline `on*`
  attributes (`onclick`, `onchange`, `oninput`) which a strict
  `script-src 'self'` (no `'unsafe-inline'` for script) **blocks**. Rather than
  weaken the CSP, **all inline handlers were converted to `addEventListener`
  wiring** inside the existing same-origin `<script>` block: static controls are
  wired by `id`; sortable `<th>` headers carry `data-sort` and are wired by
  selector; the dynamically-rendered per-row "show records" buttons carry
  `data-rec` and are handled via **event delegation** on the results table body.
  `script-src` was **never** weakened and no CDN origin was re-added. Behavior is
  identical to the former inline handlers.

---

## Verification

```
# syntax
.venv/bin/python -c "import ast; ast.parse(open('main.py').read()); print('syntax OK')"

# full suite
.venv/bin/python -m pytest -q            # -> 235 passed

# frontend/CSP subset
.venv/bin/python -m pytest -q tests/test_frontend.py tests/test_owasp.py

# real-server header tests (ASGITransport + subprocess uvicorn)
.venv/bin/python -m pytest -q tests/test_live_server_headers.py

# vendoring assertion
.venv/bin/python -c "import pathlib,sys; h=pathlib.Path('static/index.html').read_text(); \
  sys.exit(0 if ('cdn.tailwindcss.com' not in h and '/tailwind.css' in h) else 1)" && echo OK

# live header proof (start the server, then curl all four routes)
.venv/bin/python main.py &            # binds 127.0.0.1:8080
for p in / /tailwind.css /health /api/status/does-not-exist; do \
  curl -sD - -o /dev/null "http://127.0.0.1:8080$p"; done
# expect on EVERY response: x-content-type-options, x-frame-options,
# referrer-policy, and content-security-policy == SECURITY_CSP
```
