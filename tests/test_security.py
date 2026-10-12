"""Security-focused tests for the hardening applied in main.py.

Covers: strict domain validation (400), the SSRF IP-range guard, CSV
formula-injection neutralization + safe filename, DoS job cap (429), CORS
default origins, API-key non-leakage, and job_id 404 behavior. These run
alongside the existing suite and must keep it green.
"""

import csv
import io

import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture(autouse=True)
def clear_jobs():
    main.JOBS.clear()
    yield
    main.JOBS.clear()


# ---------------------------------------------------------------------------
# 1. Strict domain validation
# ---------------------------------------------------------------------------
def test_is_valid_hostname_accepts_normal_domains():
    assert main.is_valid_hostname("example.com")
    assert main.is_valid_hostname("sub.example.co.uk")


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "foo bar/../x",
        "http://example.com",
        "a@b.com",
        "ex ample.com",
        "1.2.3.4",
        "192.168.1.1",
        "::1",
        "localhost",
        "has/slash.com",
        "has\\back.com",
        "tab\there.com",
        "crlf\r\n.com",
        "*.example.com",
    ],
)
def test_is_valid_hostname_rejects_bad_input(bad):
    assert not main.is_valid_hostname(bad)


def test_is_valid_hostname_rejects_over_253_chars():
    # Build a syntactically-fine name that exceeds the 253-char RFC cap.
    label = "a" * 50
    long_name = ".".join([label] * 5) + ".com"  # > 253 chars
    assert len(long_name) > main.MAX_DOMAIN_LENGTH
    assert not main.is_valid_hostname(long_name)


def test_is_valid_hostname_rejects_oversized_label():
    assert not main.is_valid_hostname(("a" * 64) + ".com")


# ---------------------------------------------------------------------------
# 2. SSRF IP-range guard
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.5.5",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "::1",
        "fc00::1",
        "0.0.0.0",
        "224.0.0.1",  # multicast
        "not-an-ip",
    ],
)
def test_is_safe_public_ip_rejects_internal(ip):
    assert not main._is_safe_public_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1"])
def test_is_safe_public_ip_allows_public(ip):
    assert main._is_safe_public_ip(ip)


async def test_analyze_subdomain_skips_probe_for_private_ip(monkeypatch):
    """A subdomain resolving only to internal IPs must NOT be HTTP-probed."""
    probe_called = False

    async def fake_resolve_dns_detailed(host):
        return ["127.0.0.1", "169.254.169.254"], "RESOLVED"

    async def fake_resolve_cname_chain(host):
        return []

    async def fake_resolve_cname(host):
        return None

    async def fake_check_http(client, host):
        nonlocal probe_called
        probe_called = True
        return 200, 200, "should-not-happen"

    async def fake_resolve_ptrs(ips):
        return []

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)

    import asyncio

    sem = asyncio.Semaphore(1)
    res = await main.analyze_subdomain(None, "internal.example.com", ["crt.sh"], sem)

    assert probe_called is False
    assert res["http_status"] is None
    assert res["https_status"] is None
    assert res["alive"] is False


async def test_analyze_subdomain_verify_private_ip_issues_no_probe(monkeypatch):
    """VERIFY detection on a private-IP host must still issue NO new probe.

    The host's only A record is internal, so the SSRF guard skips check_http;
    the dangling-CNAME-to-cloud-resource target is present but, with no HTTP
    statuses gathered (both None), VERIFY detection relies solely on the
    already-collected data and never triggers a network call.
    """
    probe_called = False

    async def fake_resolve_dns_detailed(host):
        return ["10.0.0.5"], "RESOLVED"

    async def fake_resolve_cname_chain(host):
        return ["app.us-east-1.elb.amazonaws.com"]

    async def fake_resolve_cname(host):
        return "app.us-east-1.elb.amazonaws.com"

    async def fake_check_http(client, host):
        nonlocal probe_called
        probe_called = True
        return 200, 200, "should-not-happen"

    async def fake_resolve_ptrs(ips):
        return []

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)

    import asyncio

    sem = asyncio.Semaphore(1)
    res = await main.analyze_subdomain(None, "internal.example.com", ["crt.sh"], sem)

    # No new unguarded probe fired (private IP → check_http skipped).
    assert probe_called is False
    # With no HTTP response gathered, the dangling cloud CNAME is flagged VERIFY.
    assert res["takeover_risk"] == "VERIFY"
    assert res["takeover_service"] == "AWS ELB"


async def test_analyze_subdomain_probes_public_ip(monkeypatch):
    probe_called = False

    async def fake_resolve_dns_detailed(host):
        return ["93.184.216.34"], "RESOLVED"

    async def fake_resolve_cname_chain(host):
        return []

    async def fake_resolve_cname(host):
        return None

    async def fake_check_http(client, host):
        nonlocal probe_called
        probe_called = True
        return 200, None, "ok"

    async def fake_resolve_ptrs(ips):
        return []

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)

    import asyncio

    sem = asyncio.Semaphore(1)
    res = await main.analyze_subdomain(None, "public.example.com", ["crt.sh"], sem)
    assert probe_called is True
    assert res["http_status"] == 200


async def test_analyze_subdomain_skips_invalid_hostname(monkeypatch):
    """A poisoned (invalid) subdomain never reaches resolution/probe."""
    called = {"dns": False, "http": False}

    async def fake_resolve_dns(host):
        called["dns"] = True
        return ["93.184.216.34"]

    async def fake_check_http(client, host):
        called["http"] = True
        return 200, None, ""

    monkeypatch.setattr(main, "resolve_dns", fake_resolve_dns)
    monkeypatch.setattr(main, "check_http", fake_check_http)

    import asyncio

    sem = asyncio.Semaphore(1)
    res = await main.analyze_subdomain(None, "bad host/../x", [], sem)
    assert called["dns"] is False
    assert called["http"] is False
    assert res["resolved"] is False


# ---------------------------------------------------------------------------
# 3. CSV injection neutralization + safe filename
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw",
    ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\t=1", "\rhi", "\nhi"],
)
def test_csv_safe_prefixes_dangerous(raw):
    assert main._csv_safe(raw).startswith("'")


@pytest.mark.parametrize("safe", ["example.com", "github.io", "", "normal text"])
def test_csv_safe_leaves_safe_values(safe):
    assert main._csv_safe(safe) == safe


def test_csv_download_neutralizes_injection(monkeypatch):
    main.JOBS.clear()
    job = main.JobState(job_id="csvjob", domain="example.com", status="done")
    job.results = [
        main.SubdomainResult(
            subdomain="=cmd.example.com",
            ip_addresses=["1.2.3.4"],
            cname="+evil.github.io",
            http_status=200,
            https_status=None,
            sources=["@src"],
            takeover_risk="NONE",
            takeover_service=None,
            takeover_detail="-dangerous detail",
            resolved=True,
            alive=True,
            dns_status="=cmd",
            cname_chain=["+evil.github.io"],
        )
    ]
    main.JOBS["csvjob"] = job

    with TestClient(main.app) as c:
        resp = c.get("/api/download/csvjob")
    assert resp.status_code == 200

    reader = csv.reader(io.StringIO(resp.text))
    header = next(reader)
    assert header == main.CSV_COLUMNS  # column contract (now 12 columns)
    assert header[-1] == "dns_status"
    row = next(reader)
    assert row[0].startswith("'")  # subdomain
    assert row[2].startswith("'")  # cname
    assert row[5].startswith("'")  # sources
    assert row[10].startswith("'")  # takeover_detail
    assert row[11].startswith("'")  # dns_status neutralized (12th column)


def test_csv_filename_has_no_crlf(monkeypatch):
    main.JOBS.clear()
    # domain is validated upstream, but confirm the sanitizer keeps the header
    # single-line even if a job somehow carried odd characters.
    job = main.JobState(job_id="fnjob", domain="exa\r\nmple.com", status="done")
    job.results = []
    main.JOBS["fnjob"] = job
    with TestClient(main.app) as c:
        resp = c.get("/api/download/fnjob")
    cd = resp.headers["content-disposition"]
    assert "\r" not in cd and "\n" not in cd


# ---------------------------------------------------------------------------
# 4. DoS job cap (429)
# ---------------------------------------------------------------------------
def test_max_active_jobs_returns_429(monkeypatch):
    async def never_run(job_id, domain, keys, **kwargs):
        return  # leave the job in its initial state

    monkeypatch.setattr(main, "run_enumeration", never_run)
    main.JOBS.clear()
    # Fill the pool with running jobs.
    for i in range(main.MAX_ACTIVE_JOBS):
        main.JOBS[f"job{i}"] = main.JobState(
            job_id=f"job{i}", domain="example.com", status="running"
        )

    with TestClient(main.app) as c:
        resp = c.post("/api/enumerate", json={"domain": "example.com"})
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# 5. CORS default origins
# ---------------------------------------------------------------------------
def test_cors_default_is_localhost_only():
    assert "http://localhost:8080" in main._cors_origins
    assert "http://127.0.0.1:8080" in main._cors_origins
    assert "*" not in main._cors_origins


# ---------------------------------------------------------------------------
# 6. API key non-leakage
# ---------------------------------------------------------------------------
def test_api_key_never_leaks(monkeypatch):
    secret = "SECRET-ST-KEY-123456"

    async def fake_run(job_id, domain, keys, **kwargs):
        # Mimic a completed job; the key must not appear anywhere surfaced.
        job = main.JOBS[job_id]
        job.status = "done"
        job.progress = 100
        job.results = [
            main.SubdomainResult(
                subdomain="a.example.com",
                ip_addresses=["1.2.3.4"],
                cname=None,
                http_status=200,
                https_status=None,
                sources=["SecurityTrails"],
                takeover_risk="NONE",
                takeover_service=None,
                takeover_detail=None,
                resolved=True,
                alive=True,
                dns_status="RESOLVED",
                cname_chain=[],
            )
        ]

    monkeypatch.setattr(main, "run_enumeration", fake_run)
    main.JOBS.clear()

    with TestClient(main.app) as c:
        job_id = c.post(
            "/api/enumerate",
            json={"domain": "example.com", "securitytrails_key": secret},
        ).json()["job_id"]
        status = c.get(f"/api/status/{job_id}").text
        results = c.get(f"/api/results/{job_id}").text
        csv_body = c.get(f"/api/download/{job_id}").text

    assert secret not in status
    assert secret not in results
    assert secret not in csv_body


# ---------------------------------------------------------------------------
# 7. job_id 404 behavior (unknown + malformed)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("jid", ["nope", "../etc/passwd", "' OR 1=1", "%2e%2e"])
def test_unknown_or_malformed_job_id_returns_404(jid):
    with TestClient(main.app) as c:
        assert c.get(f"/api/status/{jid}").status_code == 404
        assert c.get(f"/api/results/{jid}").status_code == 404
        assert c.get(f"/api/download/{jid}").status_code == 404
