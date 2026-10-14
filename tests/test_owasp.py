"""Backend OWASP-hardening regression tests (FEAT-001).

Covers the server-side hardening added in main.py:
  * security headers + the exact SECURITY_CSP on API / 404 / static responses,
  * the per-client rate limit (429 over threshold, fail-open),
  * the request-body / wordlist size cap,
  * the outbound response-size cap in the verified source client,
  * _normalize_host rejecting hostile source hostnames (API10),
  * the _is_safe_public_ip IPv4+IPv6 table (A10),
  * the SSRF verified-client redirect-not-followed guard,
  * a forced-error 500 carrying no stack trace,
  * _csv_safe applied to all 16 CSV columns in order,
  * a ReDoS-safety smoke on pathological hostname input,
  * the cloud recommendation text no longer emitting S3 wording for a plain
    A-record (Lightsail/Bitnami) host.

All HTTP/DNS I/O is monkeypatched / respx-mocked so the suite stays offline.
"""

import asyncio
import csv
import io
import time

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

import main


@pytest.fixture(autouse=True)
def clear_jobs():
    main.JOBS.clear()
    yield
    main.JOBS.clear()


@pytest.fixture(autouse=True)
def reset_rate_buckets():
    # Each test starts with a clean token-bucket table so limiter state does
    # not leak between tests.
    main._RATE_BUCKETS.clear()
    yield
    main._RATE_BUCKETS.clear()


@pytest.fixture
def client(monkeypatch):
    """TestClient with run_enumeration stubbed to complete a job immediately."""

    async def fake_run(job_id, domain, keys, **kwargs):
        job = main.JOBS[job_id]
        job.status = "done"
        job.progress = 100
        job.subdomains_found = 0
        job.source_statuses = {name: "done" for name in main.SOURCES}
        job.results = []

    monkeypatch.setattr(main, "run_enumeration", fake_run)
    with TestClient(main.app) as c:
        yield c


# ---------------------------------------------------------------------------
# 1. Security headers + CSP (A05/A08)
# ---------------------------------------------------------------------------
_EXPECTED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
}


def _assert_security_headers(resp):
    for header, value in _EXPECTED_HEADERS.items():
        assert resp.headers.get(header) == value
    assert resp.headers.get("content-security-policy") == main.SECURITY_CSP


def test_security_headers_on_api_response(client):
    _assert_security_headers(client.get("/health"))


def test_security_headers_on_404_response(client):
    resp = client.get("/api/status/does-not-exist")
    assert resp.status_code == 404
    _assert_security_headers(resp)


def test_security_headers_on_static_response(client):
    # "/" is served by the static mount (index.html).
    resp = client.get("/")
    _assert_security_headers(resp)


def test_security_csp_exact_string():
    assert main.SECURITY_CSP == (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; object-src 'none'; form-action 'self'"
    )


# ---------------------------------------------------------------------------
# 2. Per-client rate limit (A04/API4)
# ---------------------------------------------------------------------------
def test_rate_limit_returns_429_over_threshold(client, monkeypatch):
    # Shrink the budget so the threshold is trivially crossed in-test.
    monkeypatch.setattr(main, "RATE_LIMIT_PER_MINUTE", 3)
    monkeypatch.setattr(main, "RATE_LIMIT_BURST", 3)

    statuses = [
        client.post("/api/enumerate", json={"domain": "example.com"}).status_code
        for _ in range(6)
    ]
    assert statuses[:3] == [200, 200, 200]
    assert 429 in statuses[3:]


def test_rate_limit_under_threshold_accepts(client):
    resp = client.post("/api/enumerate", json={"domain": "example.com"})
    assert resp.status_code == 200
    assert "job_id" in resp.json()


def test_rate_limit_fails_open_on_internal_error(monkeypatch):
    # Force an internal error inside the limiter; it must fail OPEN (allow).
    def boom(ip):
        raise RuntimeError("bucket backend down")

    # _rate_limit_ok itself swallows exceptions; simulate by making the body
    # raise and confirming the wrapper returns True.
    monkeypatch.setattr(main.time, "monotonic", boom)
    assert main._rate_limit_ok("1.2.3.4") is True


# ---------------------------------------------------------------------------
# 3. Request-body / wordlist size cap (A04/API4)
# ---------------------------------------------------------------------------
def test_oversized_wordlist_rejected(client):
    huge = "a\n" * (main.MAX_WORDLIST_BYTES)  # well over the byte cap
    resp = client.post(
        "/api/enumerate",
        json={"domain": "example.com", "active": True, "wordlist": huge},
    )
    assert resp.status_code == 422  # Pydantic max_length rejection, no OOM


def test_normal_wordlist_accepted(client):
    resp = client.post(
        "/api/enumerate",
        json={"domain": "example.com", "active": True, "wordlist": "api\ndev\nstaging"},
    )
    assert resp.status_code == 200
    assert "job_id" in resp.json()


# ---------------------------------------------------------------------------
# 4. Outbound response-size cap (API10/API4)
# ---------------------------------------------------------------------------
@respx.mock
async def test_source_response_size_cap_returns_empty(monkeypatch):
    # A hostile source streams a body far larger than MAX_RESPONSE_BYTES.
    monkeypatch.setattr(main, "MAX_RESPONSE_BYTES", 1024)
    oversized = "x" * (4096)
    respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(200, text=oversized)
    )
    async with httpx.AsyncClient() as c:
        out = await main.query_hackertarget(c, "example.com", {})
    # The capped body is dropped (treated as empty) -> no hosts, no crash.
    assert out == set()


@respx.mock
async def test_source_response_under_cap_parses_normally(monkeypatch):
    monkeypatch.setattr(main, "MAX_RESPONSE_BYTES", 10 * 1024 * 1024)
    respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(200, text="a.example.com,1.2.3.4")
    )
    async with httpx.AsyncClient() as c:
        out = await main.query_hackertarget(c, "example.com", {})
    assert out == {"a.example.com"}


# ---------------------------------------------------------------------------
# 5. _normalize_host rejects hostile source hostnames (API10)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "hostile",
    [
        "a" * 300 + ".example.com",      # overlong total
        ("a" * 64) + ".example.com",     # overlong single label
        "ev\x00il.example.com",          # control char
        "-bad-.example.com",             # label edge hyphen
        "ht tp.example.com",             # whitespace
        "http://x.example.com",          # scheme/slashes
        "a@b.example.com",               # '@'
    ],
)
def test_normalize_host_rejects_hostile(hostile):
    assert main._normalize_host(hostile, "example.com") is None


def test_normalize_host_accepts_normal_in_scope():
    assert main._normalize_host("API.Example.com", "example.com") == "api.example.com"
    assert main._normalize_host("*.sub.example.com", "example.com") == "sub.example.com"


def test_normalize_host_rejects_out_of_scope():
    assert main._normalize_host("evil.attacker.com", "example.com") is None


# ---------------------------------------------------------------------------
# 6. _is_safe_public_ip IPv4 + IPv6 table (A10)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "ip",
    [
        "169.254.169.254",  # cloud metadata
        "::1",              # IPv6 loopback
        "fc00::1",          # IPv6 ULA
        "fe80::1",          # IPv6 link-local
        "0.0.0.0",          # unspecified
        "10.0.0.1",         # RFC1918
        "192.168.1.1",      # RFC1918
        "169.254.0.1",      # link-local
        "172.16.0.1",       # RFC1918
        "fd00:ec2::254",    # IPv6 ULA metadata-style
    ],
)
def test_is_safe_public_ip_rejects_internal(ip):
    assert main._is_safe_public_ip(ip) is False


@pytest.mark.parametrize("ip", ["93.184.216.34", "2606:4700:4700::1111"])
def test_is_safe_public_ip_allows_public(ip):
    assert main._is_safe_public_ip(ip) is True


# ---------------------------------------------------------------------------
# 7. SSRF: verified source client does not follow redirects (A10/API7)
# ---------------------------------------------------------------------------
def test_verified_client_does_not_follow_redirects():
    with TestClient(main.app):
        assert main.app.state.client.follow_redirects is False
        # The probe client keeps redirects on (IP-guarded at the call site).
        assert main.app.state.probe_client.follow_redirects is True


@respx.mock
async def test_source_redirect_to_internal_not_followed(monkeypatch):
    # A hostile source 3xx-redirects to an internal metadata host. With
    # follow_redirects disabled the verified client must NOT chase it; the
    # source simply sees a non-200 and yields nothing.
    internal_hit = {"called": False}
    respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(302, headers={"Location": "http://169.254.169.254/"})
    )

    @respx.route(host="169.254.169.254")
    def _internal(request):
        internal_hit["called"] = True
        return httpx.Response(200, text="metadata")

    async with httpx.AsyncClient(follow_redirects=False) as c:
        out = await main.query_hackertarget(c, "example.com", {})
    assert out == set()
    assert internal_hit["called"] is False


# ---------------------------------------------------------------------------
# 8. Forced-error 500 carries no stack trace (A05)
# ---------------------------------------------------------------------------
def test_forced_error_500_has_no_stack_trace(monkeypatch):
    async def boom(job_id, domain, keys, **kwargs):
        raise RuntimeError("secret-internal-detail")

    # Make job creation itself blow up inside the handler path.
    def exploding_jobstate(*args, **kwargs):
        raise RuntimeError("boom-with-traceback")

    monkeypatch.setattr(main, "JobState", exploding_jobstate)
    with TestClient(main.app, raise_server_exceptions=False) as c:
        resp = c.post("/api/enumerate", json={"domain": "example.com"})
    assert resp.status_code == 500
    body = resp.text.lower()
    assert "traceback" not in body
    assert "runtimeerror" not in body
    assert "boom-with-traceback" not in body


# ---------------------------------------------------------------------------
# 9. _csv_safe applied to all 16 CSV columns, order unchanged
# ---------------------------------------------------------------------------
def test_csv_columns_order_and_count():
    assert len(main.CSV_COLUMNS) == 16
    assert main.CSV_COLUMNS[-1] == "recommended_action"


def test_csv_download_neutralizes_all_text_columns(client):
    # Seed a job whose every text column begins with a formula trigger so the
    # download must neutralize each one with a leading quote.
    job_id = "feedbeef"
    job = main.JobState(job_id=job_id, domain="example.com")
    job.status = "done"
    job.results = [
        main.SubdomainResult(
            subdomain="=cmd.example.com",
            ip_addresses=["=1.2.3.4"],
            cname="=evil.test",
            http_status=200,
            https_status=200,
            sources=["=src"],
            takeover_risk="=HIGH",
            takeover_service="=svc",
            takeover_detail="=detail",
            takeover_verdict="=VULNERABLE",
            takeover_evidence="=evidence",
            resolved=True,
            alive=True,
            dns_status="=RESOLVED",
            cname_chain=["=evil.test"],
            dns_records={"A": ["=1.2.3.4"]},
            recommended_action="=do-this",
        )
    ]
    main.JOBS[job_id] = job

    resp = client.get(f"/api/download/{job_id}")
    assert resp.status_code == 200
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert rows[0] == main.CSV_COLUMNS
    data = rows[1]
    # Every text column that started with '=' is prefixed with a single quote.
    for cell in data:
        if cell.startswith("="):
            raise AssertionError(f"unneutralized formula cell: {cell!r}")
    assert data[0] == "'=cmd.example.com"
    assert data[-1] == "'=do-this"


# ---------------------------------------------------------------------------
# 10. Unknown job_id -> 404
# ---------------------------------------------------------------------------
def test_unknown_job_id_returns_404(client):
    assert client.get("/api/status/" + "0" * 32).status_code == 404
    assert client.get("/api/results/" + "0" * 32).status_code == 404
    assert client.get("/api/download/" + "0" * 32).status_code == 404


# ---------------------------------------------------------------------------
# 11. ReDoS-safety smoke on pathological hostname input
# ---------------------------------------------------------------------------
def test_hostname_validation_redos_smoke():
    pathological = ("a" * 200 + "-") * 5 + ".example.com"
    start = time.perf_counter()
    for _ in range(200):
        main.is_valid_hostname(pathological)
        main._normalize_host(pathological, "example.com")
    assert time.perf_counter() - start < 1.0


# ---------------------------------------------------------------------------
# 12. Cloud recommendation text: no S3 wording for a plain A-record host
#     (user note: Lightsail/Bitnami A-record host wrongly labeled "AWS S3").
# ---------------------------------------------------------------------------
async def test_a_record_host_not_labeled_s3(monkeypatch):
    # A plain A-record host whose provider was recovered from the PTR heuristic
    # (no S3 CNAME target). verify_takeover must NOT emit S3 bucket wording.
    async def fake_resolve_dns_detailed(host):
        return ["203.0.113.10"], "RESOLVED"  # a public compute IP

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)

    result = main.SubdomainResult(
        subdomain="onboarding.example.com",
        ip_addresses=["203.0.113.10"],
        cname=None,
        http_status=200,
        https_status=200,
        sources=["crt.sh"],
        takeover_risk="LOW",
        takeover_service="AWS S3",  # mis-attributed by a loose PTR match
        takeover_detail="A-record ptr points to AWS S3",
        takeover_verdict="",
        takeover_evidence="",
        resolved=True,
        alive=True,
        dns_status="RESOLVED",
        cname_chain=[],
        dns_records={"A": ["203.0.113.10"]},
        recommended_action="",
    )

    async with httpx.AsyncClient() as c:
        out = await main.verify_takeover(result, c, asyncio.Semaphore(5))

    ev = out["evidence"].lower()
    assert "bucket" not in ev
    assert "nosuchbucket" not in ev
