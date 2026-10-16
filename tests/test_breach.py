"""Tests for the keyless breach-exposure engine + its separate job API.

All outbound HTTP (XposedOrNot + crt.sh) is respx-mocked so the suite stays
offline and deterministic. Pure helpers (generate_email_patterns,
_valid_email_for_domain, parse_*_lines, the CSV/summary builders) need no
mocking. The subdomain (16-col) and lookalike (14-col) CSV contracts are
untouched and remain covered by their own tests. asyncio_mode=auto so async
test functions need no decorator.
"""

import asyncio
import csv
import io

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

import main


@pytest.fixture(autouse=True)
def clear_jobs():
    main.BREACH_JOBS.clear()
    main.JOBS.clear()
    main.LOOKALIKE_JOBS.clear()
    main._RATE_BUCKETS.clear()
    yield
    main.BREACH_JOBS.clear()
    main.JOBS.clear()
    main.LOOKALIKE_JOBS.clear()
    main._RATE_BUCKETS.clear()


# ---------------------------------------------------------------------------
# 1. _valid_email_for_domain
# ---------------------------------------------------------------------------
def test_valid_email_matches_target_domain():
    assert main._valid_email_for_domain("careers@example.com", "example.com") is True
    assert main._valid_email_for_domain("CAREERS@EXAMPLE.COM", "example.com") is True


def test_valid_email_rejects_wrong_domain_and_junk():
    assert main._valid_email_for_domain("a@other.com", "example.com") is False
    assert main._valid_email_for_domain("no-at-sign", "example.com") is False
    assert main._valid_email_for_domain("a@b@example.com", "example.com") is False
    # URL-breaking / whitespace chars in the local part are rejected.
    assert main._valid_email_for_domain("a b@example.com", "example.com") is False
    assert main._valid_email_for_domain("a/b@example.com", "example.com") is False


# ---------------------------------------------------------------------------
# 2. generate_email_patterns
# ---------------------------------------------------------------------------
def test_generate_email_patterns_multi_token():
    out = main.generate_email_patterns(["Aruna VR"], "example.com")
    for expected in (
        "aruna.vr@example.com",
        "aruna@example.com",
        "avr@example.com",
        "arunavr@example.com",
        "vr.aruna@example.com",
        "aruna_vr@example.com",
    ):
        assert expected in out
    # Every produced address is valid and at the target domain.
    assert all(main._valid_email_for_domain(e, "example.com") for e in out)


def test_generate_email_patterns_single_token():
    out = main.generate_email_patterns(["Madonna"], "example.com")
    assert out == {"madonna@example.com"}


def test_generate_email_patterns_cap(monkeypatch):
    monkeypatch.setattr(main, "MAX_BREACH_EMAILS", 2)
    out = main.generate_email_patterns(["Aruna VR", "John Doe"], "example.com")
    assert len(out) <= 2


# ---------------------------------------------------------------------------
# 3. parse_email_lines / parse_name_lines
# ---------------------------------------------------------------------------
def test_parse_email_lines_filters_and_dedupes():
    text = "careers@example.com\n# a comment\n\nhr@example.com\ncareers@example.com\nx@other.com"
    out = main.parse_email_lines(text, "example.com")
    assert out == ["careers@example.com", "hr@example.com"]


def test_parse_name_lines_dedupes_preserving_order():
    out = main.parse_name_lines("Aruna VR\n# skip\n\nJohn Doe\naruna vr")
    assert out == ["Aruna VR", "John Doe"]


# ---------------------------------------------------------------------------
# 4. check_email_exposed via respx
# ---------------------------------------------------------------------------
@respx.mock
async def test_check_email_exposed_parses_breaches():
    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/check-email/careers@example.com").mock(
        return_value=httpx.Response(
            200, json={"breaches": [["AlienStealerLogs", "SomeOtherBreach"]], "status": "success"}
        )
    )
    async with httpx.AsyncClient() as c:
        res = await main.check_email_exposed(c, "careers@example.com")
    assert res == ["AlienStealerLogs", "SomeOtherBreach"]


@respx.mock
async def test_check_email_exposed_not_found_returns_none():
    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/check-email/clean@example.com").mock(
        return_value=httpx.Response(200, json={"Error": "Not found", "email": None})
    )
    async with httpx.AsyncClient() as c:
        res = await main.check_email_exposed(c, "clean@example.com")
    assert res is None


@respx.mock
async def test_check_email_exposed_retries_on_429(monkeypatch):
    monkeypatch.setattr(main, "BREACH_RETRY_BACKOFF", 0)  # no real sleep
    route = respx.get(f"{main.XPOSEDORNOT_BASE}/v1/check-email/a@example.com").mock(
        side_effect=[
            httpx.Response(429, json={}),
            httpx.Response(200, json={"breaches": [["B1"]], "status": "success"}),
        ]
    )
    async with httpx.AsyncClient() as c:
        res = await main.check_email_exposed(c, "a@example.com")
    assert res == ["B1"]
    assert route.call_count == 2


@respx.mock
async def test_check_email_exposed_persistent_error_returns_unknown(monkeypatch):
    monkeypatch.setattr(main, "BREACH_RETRY_BACKOFF", 0)
    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/check-email/err@example.com").mock(
        side_effect=httpx.ConnectError("boom")
    )
    async with httpx.AsyncClient() as c:
        res = await main.check_email_exposed(c, "err@example.com")
    assert res == main.BREACH_UNKNOWN


# ---------------------------------------------------------------------------
# 5. breach_analytics via respx (real-shaped JSON)
# ---------------------------------------------------------------------------
@respx.mock
async def test_breach_analytics_parses_real_shape():
    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/breach-analytics").mock(
        return_value=httpx.Response(
            200,
            json={
                "BreachMetrics": {"risk": [{"risk_label": "High", "risk_score": 7}]},
                "BreachesSummary": {"site": "AlienStealerLogs;Collection1"},
                "ExposedBreaches": {
                    "breaches_details": [
                        {
                            "breach": "AlienStealerLogs",
                            "xposed_data": "Passwords;Email addresses",
                        }
                    ]
                },
            },
        )
    )
    async with httpx.AsyncClient() as c:
        res = await main.breach_analytics(c, "careers@example.com")
    assert "AlienStealerLogs" in res["breaches"]
    assert "Collection1" in res["breaches"]
    assert "Passwords" in res["exposed_data"]
    assert "Email addresses" in res["exposed_data"]
    assert res["risk_label"] == "High"
    assert res["risk_score"] == 7


@respx.mock
async def test_breach_analytics_never_raises_on_error():
    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/breach-analytics").mock(
        side_effect=httpx.ConnectError("boom")
    )
    async with httpx.AsyncClient() as c:
        res = await main.breach_analytics(c, "x@example.com")
    assert res == {"breaches": [], "exposed_data": [], "risk_label": "", "risk_score": ""}


# ---------------------------------------------------------------------------
# 6. discover_emails from a canned crt.sh fixture
# ---------------------------------------------------------------------------
@respx.mock
async def test_discover_emails_extracts_and_validates():
    body = (
        '[{"name_value":"www.example.com\\nmail.example.com"},'
        '{"common_name":"example.com"}]'
        " contact careers@example.com and hr@example.com and evil@other.com"
    )
    respx.get("https://crt.sh/?q=%25.example.com&output=json").mock(
        return_value=httpx.Response(200, text=body)
    )
    async with httpx.AsyncClient() as c:
        out = await main.discover_emails(c, "example.com")
    assert "careers@example.com" in out
    assert "hr@example.com" in out
    # Addresses at a different domain are rejected.
    assert "evil@other.com" not in out


@respx.mock
async def test_discover_emails_enforces_cap(monkeypatch):
    monkeypatch.setattr(main, "MAX_BREACH_EMAILS", 1)
    body = "a@example.com b@example.com c@example.com"
    respx.get("https://crt.sh/?q=%25.example.com&output=json").mock(
        return_value=httpx.Response(200, text=body)
    )
    async with httpx.AsyncClient() as c:
        out = await main.discover_emails(c, "example.com")
    assert len(out) == 1


@respx.mock
async def test_discover_emails_never_raises():
    respx.get("https://crt.sh/?q=%25.example.com&output=json").mock(
        side_effect=httpx.ConnectError("boom")
    )
    async with httpx.AsyncClient() as c:
        out = await main.discover_emails(c, "example.com")
    assert out == set()


# ---------------------------------------------------------------------------
# 7. run_breach — drop/keep semantics + bounded concurrency + fixed host
# ---------------------------------------------------------------------------
@respx.mock
async def test_run_breach_drops_notfound_discovered_keeps_supplied(monkeypatch):
    # No discovery; one supplied + one pattern address. The API reports the
    # supplied address Not found (kept, but clean -> not in results) and the
    # pattern address exposed (surfaced).
    monkeypatch.setattr(main, "BREACH_CALL_DELAY", 0)
    monkeypatch.setattr(main, "BREACH_RETRY_BACKOFF", 0)
    # Keep the adaptive slowdown from pacing this offline test (the unmocked
    # role/pattern candidates come back UNKNOWN and would otherwise bump delay).
    monkeypatch.setattr(main, "BREACH_ADAPTIVE_STEP", 0)

    async def no_discovery(client, domain):
        return set()

    monkeypatch.setattr(main, "discover_emails", no_discovery)

    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/check-email/supplied@example.com").mock(
        return_value=httpx.Response(200, json={"Error": "Not found", "email": None})
    )
    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/check-email/aruna@example.com").mock(
        return_value=httpx.Response(200, json={"breaches": [["B1"]], "status": "success"})
    )
    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/breach-analytics").mock(
        return_value=httpx.Response(
            200,
            json={
                "BreachMetrics": {"risk": [{"risk_label": "Medium", "risk_score": 4}]},
                "BreachesSummary": {"site": "B1"},
                "ExposedBreaches": {"breaches_details": []},
            },
        )
    )

    async with httpx.AsyncClient() as c:
        main.app.state.client = c
        main.BREACH_JOBS["j1"] = main.BreachJobState(job_id="j1", domain="example.com")
        await main.run_breach(
            "j1", "example.com", "supplied@example.com", "Aruna"
        )

    job = main.BREACH_JOBS["j1"]
    assert job.status == "done"
    emails = {r["email"] for r in job.results}
    # Pattern address is surfaced; supplied Not-found address is dropped from
    # results but counted as a clean check.
    assert "aruna@example.com" in emails
    assert "supplied@example.com" not in emails
    assert job.exposed_count == 1
    assert job.checked_clean == 1
    exposed = next(r for r in job.results if r["email"] == "aruna@example.com")
    assert exposed["source"] == "pattern"
    assert exposed["breaches"] == ["B1"]


@respx.mock
async def test_run_breach_only_fixed_host_and_bounded_concurrency(monkeypatch):
    assert main.BREACH_CONCURRENCY <= 4
    monkeypatch.setattr(main, "BREACH_CALL_DELAY", 0)

    async def no_discovery(client, domain):
        return set()

    monkeypatch.setattr(main, "discover_emails", no_discovery)

    seen_hosts = set()

    def record(request):
        seen_hosts.add(request.url.host)
        return httpx.Response(200, json={"Error": "Not found", "email": None})

    respx.get(url__regex=r"https://api\.xposedornot\.com/.*").mock(side_effect=record)

    async with httpx.AsyncClient() as c:
        main.app.state.client = c
        main.BREACH_JOBS["j2"] = main.BreachJobState(job_id="j2", domain="example.com")
        await main.run_breach("j2", "example.com", "a@example.com\nb@example.com", None)

    assert seen_hosts == {"api.xposedornot.com"}
    assert main.BREACH_JOBS["j2"].status == "done"


# ---------------------------------------------------------------------------
# 8. CSV contract
# ---------------------------------------------------------------------------
def test_breach_csv_header_exact():
    content = main._build_breach_csv([])
    header = next(csv.reader(io.StringIO(content)))
    assert header == main.BREACH_CSV_COLUMNS
    assert len(header) == 6


def test_breach_csv_csv_safe_neutralizes_formula():
    row = {
        "email": "=evil@example.com",
        "breaches": ["=cmd|' /C calc'!A0", "B2"],
        "exposed_data": ["Passwords"],
        "risk_label": "High",
        "risk_score": 7,
        "source": "supplied",
    }
    content = main._build_breach_csv([row])
    reader = csv.reader(io.StringIO(content))
    next(reader)  # header
    first = next(reader)
    assert first[0].startswith("'=evil@example.com")  # email neutralized
    assert first[1].startswith("'=cmd")  # breaches neutralized + ';'-joined
    assert "B2" in first[1]
    assert first[4] == "7"  # numeric risk_score


# ---------------------------------------------------------------------------
# 9. _summarize_breach
# ---------------------------------------------------------------------------
def test_summarize_breach_counts():
    results = [
        {"email": "a@x.com", "breaches": ["B1", "B2"], "risk_label": "High"},
        {"email": "b@x.com", "breaches": ["B2"], "risk_label": "Low"},
    ]
    summ = main._summarize_breach(results, emails_checked=5, checked_clean=3)
    assert summ["emails_checked"] == 5
    assert summ["exposed_count"] == 2
    assert summ["breaches_count"] == 3  # total mentions
    assert summ["distinct_breaches"] == 2  # B1, B2
    assert summ["by_risk"] == {"high": 1, "medium": 0, "low": 1}
    assert summ["checked_clean"] == 3


# ---------------------------------------------------------------------------
# 10. API via TestClient (run_breach monkeypatched to a deterministic filler)
# ---------------------------------------------------------------------------
@pytest.fixture
def client(monkeypatch):
    async def fake_run(job_id, domain, emails, names):
        job = main.BREACH_JOBS[job_id]
        job.status = "done"
        job.progress = 100
        job.emails_discovered = 2
        job.emails_checked = 2
        job.exposed_count = 1
        job.checked_clean = 1
        job.results = [
            {
                "email": "careers@example.com",
                "breaches": ["AlienStealerLogs"],
                "exposed_data": ["Passwords"],
                "risk_label": "High",
                "risk_score": 7,
                "source": "discovered",
            }
        ]

    monkeypatch.setattr(main, "run_breach", fake_run)
    with TestClient(main.app) as c:
        yield c


def test_api_full_flow(client):
    resp = client.post("/api/breach", json={"domain": "example.com"})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    assert job_id

    status = client.get(f"/api/breach/status/{job_id}").json()
    assert status["status"] == "done"
    assert status["emails_discovered"] == 2
    assert status["exposed_count"] == 1

    results = client.get(f"/api/breach/results/{job_id}").json()
    assert results["domain"] == "example.com"
    assert results["summary"]["exposed_count"] == 1
    assert results["exposed"][0]["email"] == "careers@example.com"
    # The honest coverage disclaimer must be present.
    assert "not an exhaustive domain report" in results["coverage_note"]
    assert "XposedOrNot" in results["coverage_note"]


def test_api_download(client):
    job_id = client.post("/api/breach", json={"domain": "example.com"}).json()["job_id"]
    resp = client.get(f"/api/breach/download/{job_id}")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "breach_example.com_" in resp.headers["content-disposition"]
    reader = csv.reader(io.StringIO(resp.text))
    assert next(reader) == main.BREACH_CSV_COLUMNS
    first = next(reader)
    assert first[0] == "careers@example.com"


def test_api_unknown_job_404(client):
    assert client.get("/api/breach/status/nope").status_code == 404
    assert client.get("/api/breach/results/nope").status_code == 404
    assert client.get("/api/breach/download/nope").status_code == 404


def test_api_invalid_domain_400(client):
    resp = client.post("/api/breach", json={"domain": "not a domain"})
    assert resp.status_code == 400


def test_api_rate_limit_429(client, monkeypatch):
    monkeypatch.setattr(main, "RATE_LIMIT_PER_MINUTE", 2)
    monkeypatch.setattr(main, "RATE_LIMIT_BURST", 2)
    main._RATE_BUCKETS.clear()
    statuses = [
        client.post("/api/breach", json={"domain": "example.com"}).status_code
        for _ in range(6)
    ]
    assert 429 in statuses


def test_api_results_409_when_not_done(client, monkeypatch):
    async def never_run(job_id, domain, emails, names):
        return

    monkeypatch.setattr(main, "run_breach", never_run)
    job_id = client.post("/api/breach", json={"domain": "example.com"}).json()["job_id"]
    main.BREACH_JOBS[job_id].status = "running"
    assert client.get(f"/api/breach/results/{job_id}").status_code == 409
    assert client.get(f"/api/breach/download/{job_id}").status_code == 409


# ---------------------------------------------------------------------------
# 11. Pure helpers: deobfuscation, email/name extraction
# ---------------------------------------------------------------------------
def test_extract_domain_emails_mailto_inline_and_obfuscated():
    body = (
        'Reach <a href="mailto:careers@example.com">us</a> or email '
        "aruna.vr@example.com. Also info [at] example [dot] com. "
        "A vendor someone@gmail.com must be ignored. "
        "HTML entity: hr&#64;example.com"
    )
    out = main._extract_domain_emails(body, "example.com")
    assert "careers@example.com" in out
    assert "aruna.vr@example.com" in out
    assert "info@example.com" in out
    assert "hr@example.com" in out
    # Third-party vendor address at a DIFFERENT domain is excluded.
    assert "someone@gmail.com" not in out
    assert all(e.endswith("@example.com") for e in out)


def test_extract_person_names_conservative():
    body = (
        "<h2>Our Team</h2> Aruna VR leads engineering. "
        "Contact Us for details. Read More about privacy policy."
    )
    names = main._extract_person_names(body)
    assert "Aruna VR" in names
    # Stopword bigrams must not be treated as person names.
    assert "Contact Us" not in names
    assert "Read More" not in names


# ---------------------------------------------------------------------------
# 12. _scrape_host_pages — SSRF gate + harvest (respx + monkeypatched resolver)
# ---------------------------------------------------------------------------
@respx.mock
async def test_scrape_host_pages_harvests_public_host(monkeypatch):
    async def fake_resolve(host):
        return (["93.184.216.34"], "RESOLVED")  # a public, routable IP

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve)
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            text=(
                'mailto:careers@example.com inline aruna.vr@example.com '
                "info [at] example [dot] com someone@gmail.com. "
                "Our Team: Aruna VR heads hiring."
            ),
        )
    )
    # Other paths 404 — harvest still succeeds from '/'.
    respx.get(url__regex=r"https://example\.com/(contact|about|team|careers)").mock(
        return_value=httpx.Response(404, text="")
    )

    async with httpx.AsyncClient() as probe:
        emails, names = await main._scrape_host_pages(probe, "example.com", "example.com")

    assert "careers@example.com" in emails
    assert "aruna.vr@example.com" in emails
    assert "info@example.com" in emails
    assert "someone@gmail.com" not in emails
    assert "Aruna VR" in names


@respx.mock
async def test_scrape_host_pages_ssrf_private_ip_not_fetched(monkeypatch):
    async def fake_resolve(host):
        return (["10.0.0.5"], "RESOLVED")  # private — must be skipped

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve)

    fetched = {"called": False}

    def record(request):
        fetched["called"] = True
        return httpx.Response(200, text="careers@example.com")

    respx.get(url__regex=r"https?://internal\.example\.com.*").mock(side_effect=record)

    async with httpx.AsyncClient() as probe:
        emails, names = await main._scrape_host_pages(
            probe, "internal.example.com", "example.com"
        )

    assert emails == set()
    assert names == set()
    assert fetched["called"] is False  # SSRF guard: never probed the private host


# ---------------------------------------------------------------------------
# 13. discover_emails_rich — subdomain reuse + scrape + name harvest
# ---------------------------------------------------------------------------
@respx.mock
async def test_discover_emails_rich_unions_scrape_and_crtsh(monkeypatch):
    # crt.sh base harvest returns one address.
    respx.get("https://crt.sh/?q=%25.example.com&output=json").mock(
        return_value=httpx.Response(200, text="admin@example.com")
    )

    async def fake_hosts(client, domain):
        return ["example.com", "careers.example.com"]

    monkeypatch.setattr(main, "_discover_hosts", fake_hosts)

    async def fake_resolve(host):
        return (["93.184.216.34"], "RESOLVED")

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve)

    respx.get("https://example.com/").mock(
        return_value=httpx.Response(200, text="info@example.com Our Team: Aruna VR")
    )
    respx.get("https://careers.example.com/").mock(
        return_value=httpx.Response(
            200, text='mailto:careers@example.com and vendor@gmail.com'
        )
    )
    respx.get(url__regex=r"https://[a-z.]+/(contact|about|team|careers)$").mock(
        return_value=httpx.Response(404, text="")
    )

    job = main.BreachJobState(job_id="rich", domain="example.com")
    async with httpx.AsyncClient() as verified, httpx.AsyncClient() as probe:
        rich = await main.discover_emails_rich(verified, probe, "example.com", job)

    assert "admin@example.com" in rich["discovered"]  # crt.sh
    assert "info@example.com" in rich["discovered"]  # scraped root
    assert "careers@example.com" in rich["discovered"]  # scraped careers host
    assert "vendor@gmail.com" not in rich["discovered"]  # third-party excluded
    assert "Aruna VR" in rich["names"]
    assert job.emails_discovered >= 1


@respx.mock
async def test_discover_emails_rich_per_source_errors_isolated(monkeypatch):
    # crt.sh errors; _discover_hosts returns one host whose page times out.
    respx.get("https://crt.sh/?q=%25.example.com&output=json").mock(
        side_effect=httpx.ConnectError("boom")
    )

    async def fake_hosts(client, domain):
        return ["example.com"]

    monkeypatch.setattr(main, "_discover_hosts", fake_hosts)

    async def fake_resolve(host):
        return (["93.184.216.34"], "RESOLVED")

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve)
    respx.get(url__regex=r"https?://example\.com.*").mock(
        side_effect=httpx.ConnectTimeout("slow")
    )

    async with httpx.AsyncClient() as verified, httpx.AsyncClient() as probe:
        rich = await main.discover_emails_rich(verified, probe, "example.com", None)

    # Discovery completes (never raises) with an empty set.
    assert rich["discovered"] == set()
    assert rich["names"] == set()


async def test_discover_emails_rich_no_probe_client_crtsh_only(monkeypatch):
    async def fake_discover(client, domain):
        return {"base@example.com"}

    monkeypatch.setattr(main, "discover_emails", fake_discover)

    async with httpx.AsyncClient() as verified:
        rich = await main.discover_emails_rich(verified, None, "example.com", None)

    assert rich["discovered"] == {"base@example.com"}
    assert rich["names"] == set()


# ---------------------------------------------------------------------------
# 14. _discover_hosts — reuses SOURCES + always includes root/common hosts
# ---------------------------------------------------------------------------
async def test_discover_hosts_reuses_sources_and_includes_common(monkeypatch):
    async def fake_source(client, domain, keys):
        return {"team.example.com", "about.example.com"}

    monkeypatch.setattr(main, "SOURCES", {"fake": fake_source})

    async with httpx.AsyncClient() as verified:
        hosts = await main._discover_hosts(verified, "example.com")

    assert "example.com" in hosts  # root always included
    assert "www.example.com" in hosts  # common fallback
    assert "team.example.com" in hosts  # from reused source
    assert "about.example.com" in hosts
    assert len(hosts) <= main.MAX_SCRAPE_HOSTS


async def test_discover_hosts_source_failure_isolated(monkeypatch):
    async def boom(client, domain, keys):
        raise RuntimeError("source down")

    monkeypatch.setattr(main, "SOURCES", {"boom": boom})

    async with httpx.AsyncClient() as verified:
        hosts = await main._discover_hosts(verified, "example.com")

    # Still returns the root + common-host fallback despite the source failing.
    assert "example.com" in hosts
    assert "mail.example.com" in hosts


# ---------------------------------------------------------------------------
# 15. run_breach domain-only — strengthened discovery yields candidates
# ---------------------------------------------------------------------------
@respx.mock
async def test_run_breach_domain_only_uses_rich_discovery(monkeypatch):
    monkeypatch.setattr(main, "BREACH_CALL_DELAY", 0)
    monkeypatch.setattr(main, "BREACH_RETRY_BACKOFF", 0)

    async def fake_rich(verified, probe, domain, job):
        if job is not None:
            job.emails_discovered = 1
        return {"discovered": {"careers@example.com"}, "names": {"Aruna VR"}}

    monkeypatch.setattr(main, "discover_emails_rich", fake_rich)

    # careers@ (discovered) is exposed; info@ (role/pattern) is Not found ->
    # dropped; aruna.vr@ (name pattern) exposed -> kept and tagged 'pattern'.
    def check(request):
        local = request.url.path.rsplit("/", 1)[-1]
        if local in ("careers@example.com", "aruna.vr@example.com"):
            return httpx.Response(200, json={"breaches": [["B1"]], "status": "success"})
        return httpx.Response(200, json={"Error": "Not found", "email": None})

    respx.get(url__regex=r"https://api\.xposedornot\.com/v1/check-email/.*").mock(
        side_effect=check
    )
    respx.get(url__regex=r"https://api\.xposedornot\.com/v1/breach-analytics.*").mock(
        return_value=httpx.Response(
            200,
            json={
                "BreachMetrics": {"risk": [{"risk_label": "Low", "risk_score": 2}]},
                "BreachesSummary": {"site": "B1"},
                "ExposedBreaches": {"breaches_details": []},
            },
        )
    )

    async with httpx.AsyncClient() as c:
        main.app.state.client = c
        # No probe client needed: discovery is mocked.
        if hasattr(main.app.state, "probe_client"):
            delattr(main.app.state, "probe_client")
        main.BREACH_JOBS["dom"] = main.BreachJobState(job_id="dom", domain="example.com")
        await main.run_breach("dom", "example.com", None, None)

    job = main.BREACH_JOBS["dom"]
    assert job.status == "done"
    assert job.emails_checked > 0  # domain-only now checks candidates (not 0)
    emails = {r["email"]: r["source"] for r in job.results}
    assert emails.get("careers@example.com") == "discovered"
    assert emails.get("aruna.vr@example.com") == "pattern"
    # Role/pattern address the API doesn't know is NOT surfaced (verify-then-keep).
    assert "info@example.com" not in emails


@respx.mock
async def test_run_breach_domain_only_respects_cap(monkeypatch):
    monkeypatch.setattr(main, "BREACH_CALL_DELAY", 0)
    monkeypatch.setattr(main, "MAX_BREACH_EMAILS", 3)

    async def fake_rich(verified, probe, domain, job):
        return {
            "discovered": {f"d{i}@example.com" for i in range(10)},
            "names": set(),
        }

    monkeypatch.setattr(main, "discover_emails_rich", fake_rich)
    respx.get(url__regex=r"https://api\.xposedornot\.com/.*").mock(
        return_value=httpx.Response(200, json={"Error": "Not found", "email": None})
    )

    async with httpx.AsyncClient() as c:
        main.app.state.client = c
        main.BREACH_JOBS["cap"] = main.BreachJobState(job_id="cap", domain="example.com")
        await main.run_breach("cap", "example.com", None, None)

    job = main.BREACH_JOBS["cap"]
    assert job.status == "done"
    assert job.emails_checked <= 3  # MAX_BREACH_EMAILS honored


# ---------------------------------------------------------------------------
# 16. Rate-limit survival: serialization + exponential backoff + UNKNOWN
# ---------------------------------------------------------------------------
@pytest.fixture
def no_sleep(monkeypatch):
    """Mock asyncio.sleep so backoff/pacing tests never actually wait.

    Records every requested sleep duration so a test can assert a backoff path
    was taken, while returning immediately.
    """
    slept: list = []

    async def fake_sleep(secs, *a, **k):
        slept.append(secs)

    monkeypatch.setattr(main.asyncio, "sleep", fake_sleep)
    return slept


def test_breach_concurrency_is_serial():
    # The XposedOrNot calls MUST be serialized — this API cannot tolerate
    # parallelism. Kept as a tunable named constant.
    assert main.BREACH_CONCURRENCY == 1


@respx.mock
async def test_check_email_exposed_backoff_then_success(no_sleep):
    # 429 on the first call, 200 with breaches on the retry -> parsed exposed,
    # and the backoff path was taken (endpoint called twice, a sleep recorded).
    route = respx.get(
        f"{main.XPOSEDORNOT_BASE}/v1/check-email/careers@example.com"
    ).mock(
        side_effect=[
            httpx.Response(429, json={"detail": {"error": "Request dropped"}}),
            httpx.Response(200, json={"breaches": [["AlienStealerLogs"]], "status": "success"}),
        ]
    )
    async with httpx.AsyncClient() as c:
        res = await main.check_email_exposed(c, "careers@example.com")
    assert res == ["AlienStealerLogs"]
    assert route.call_count == 2  # backoff retry happened
    assert len(no_sleep) >= 1  # at least one backoff sleep


@respx.mock
async def test_check_email_exposed_honors_retry_after(no_sleep):
    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/check-email/a@example.com").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "5"}, json={}),
            httpx.Response(200, json={"breaches": [["B1"]], "status": "success"}),
        ]
    )
    async with httpx.AsyncClient() as c:
        res = await main.check_email_exposed(c, "a@example.com")
    assert res == ["B1"]
    # The Retry-After value (5s) was used as the backoff sleep.
    assert 5.0 in no_sleep


@respx.mock
async def test_check_email_exposed_cloudflare_challenge_then_unknown(no_sleep):
    # A Cloudflare "Just a moment" interstitial (served 200) must be treated as
    # a throttle and retried; if it NEVER clears -> UNKNOWN, never "not exposed".
    cf_html = (
        "<!DOCTYPE html><html><head><title>Just a moment...</title></head>"
        "<body>Checking your browser</body></html>"
    )
    route = respx.get(
        f"{main.XPOSEDORNOT_BASE}/v1/check-email/cf@example.com"
    ).mock(return_value=httpx.Response(200, text=cf_html))
    async with httpx.AsyncClient() as c:
        res = await main.check_email_exposed(c, "cf@example.com")
    assert res == main.BREACH_UNKNOWN  # indeterminate, NOT None/clean
    # Retried BREACH_MAX_RETRIES times before giving up.
    assert route.call_count == main.BREACH_MAX_RETRIES + 1


@respx.mock
async def test_check_email_exposed_violation_history_body_is_throttle(no_sleep):
    # The explicit "violation history" drop marker (even with a 200/JSON body)
    # is a throttle, not a result.
    route = respx.get(
        f"{main.XPOSEDORNOT_BASE}/v1/check-email/v@example.com"
    ).mock(
        side_effect=[
            httpx.Response(
                429,
                json={"detail": {"error": "Request dropped due to violation history"}},
            ),
            httpx.Response(200, json={"Error": "Not found", "email": None}),
        ]
    )
    async with httpx.AsyncClient() as c:
        res = await main.check_email_exposed(c, "v@example.com")
    # Retry cleared and the address is genuinely Not found.
    assert res is None
    assert route.call_count == 2


@respx.mock
async def test_check_email_exposed_notfound_is_not_unknown(no_sleep):
    # A genuine 'Not found' is clean (None) and distinct from UNKNOWN.
    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/check-email/clean@example.com").mock(
        return_value=httpx.Response(200, json={"Error": "Not found", "email": None})
    )
    async with httpx.AsyncClient() as c:
        res = await main.check_email_exposed(c, "clean@example.com")
    assert res is None
    assert res is not main.BREACH_UNKNOWN


@respx.mock
async def test_run_breach_mix_exposed_notfound_throttled(no_sleep, monkeypatch):
    # A mix of three SUPPLIED addresses: one exposed, one genuine Not-found,
    # one perpetually 429'd. Expect exposed_count=1, checked_clean=1 (not-found),
    # checked_unknown=1 (throttled) — and the throttled one is NOT reported clean.
    async def no_discovery(client, domain):
        return set()

    monkeypatch.setattr(main, "discover_emails", no_discovery)

    async def fake_rich(verified, probe, domain, job):
        return {"discovered": set(), "names": set()}

    monkeypatch.setattr(main, "discover_emails_rich", fake_rich)
    # Only the supplied addresses should be checked in this test.
    monkeypatch.setattr(main, "BREACH_ROLE_LOCALS", ())

    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/check-email/hit@example.com").mock(
        return_value=httpx.Response(200, json={"breaches": [["B1"]], "status": "success"})
    )
    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/check-email/clean@example.com").mock(
        return_value=httpx.Response(200, json={"Error": "Not found", "email": None})
    )
    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/check-email/throttled@example.com").mock(
        return_value=httpx.Response(429, json={"detail": {"error": "dropped"}})
    )
    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/breach-analytics").mock(
        return_value=httpx.Response(
            200,
            json={
                "BreachMetrics": {"risk": [{"risk_label": "Low", "risk_score": 2}]},
                "BreachesSummary": {"site": "B1"},
                "ExposedBreaches": {"breaches_details": []},
            },
        )
    )

    supplied = "hit@example.com\nclean@example.com\nthrottled@example.com"
    async with httpx.AsyncClient() as c:
        main.app.state.client = c
        if hasattr(main.app.state, "probe_client"):
            delattr(main.app.state, "probe_client")
        main.BREACH_JOBS["mix"] = main.BreachJobState(job_id="mix", domain="example.com")
        await main.run_breach("mix", "example.com", supplied, None)

    job = main.BREACH_JOBS["mix"]
    assert job.status == "done"
    emails = {r["email"] for r in job.results}
    assert job.exposed_count == 1
    assert "hit@example.com" in emails
    # The throttled address is NOT surfaced as exposed and NOT counted clean.
    assert "throttled@example.com" not in emails
    assert job.checked_clean == 1  # only the genuine Not-found
    assert job.checked_unknown == 1  # the perpetually-429 one

    # The summary exposes the indeterminate count distinctly.
    summ = main._summarize_breach(
        job.results, job.emails_checked, job.checked_clean, job.checked_unknown
    )
    assert summ["checked_unknown"] == 1
    assert summ["exposed_count"] == 1


@respx.mock
async def test_run_breach_supplied_three_known_exposed(no_sleep, monkeypatch):
    # Regression: the three known example.com emails still resolve to 3 exposed
    # with the serialized delay + backoff in place (mocked).
    async def fake_rich(verified, probe, domain, job):
        return {"discovered": set(), "names": set()}

    monkeypatch.setattr(main, "discover_emails_rich", fake_rich)
    # Only the three supplied addresses should be checked here.
    monkeypatch.setattr(main, "BREACH_ROLE_LOCALS", ())

    known = ("careers@example.com", "aruna.vr@example.com", "sooraj.s@example.com")
    for addr in known:
        # First call 429 (throttle), retry succeeds -> exercises backoff path.
        respx.get(f"{main.XPOSEDORNOT_BASE}/v1/check-email/{addr}").mock(
            side_effect=[
                httpx.Response(429, json={"detail": {"error": "dropped"}}),
                httpx.Response(200, json={"breaches": [["AlienStealerLogs"]], "status": "success"}),
            ]
        )
    respx.get(f"{main.XPOSEDORNOT_BASE}/v1/breach-analytics").mock(
        return_value=httpx.Response(
            200,
            json={
                "BreachMetrics": {"risk": [{"risk_label": "High", "risk_score": 7}]},
                "BreachesSummary": {"site": "AlienStealerLogs"},
                "ExposedBreaches": {"breaches_details": []},
            },
        )
    )

    supplied = "\n".join(known)
    async with httpx.AsyncClient() as c:
        main.app.state.client = c
        if hasattr(main.app.state, "probe_client"):
            delattr(main.app.state, "probe_client")
        main.BREACH_JOBS["known"] = main.BreachJobState(job_id="known", domain="example.com")
        await main.run_breach("known", "example.com", supplied, None)

    job = main.BREACH_JOBS["known"]
    assert job.status == "done"
    assert job.exposed_count == 3
    emails = {r["email"] for r in job.results}
    assert emails == set(known)
    assert job.checked_unknown == 0  # backoff defeated the throttle


@respx.mock
async def test_run_breach_calls_do_not_overlap(no_sleep, monkeypatch):
    # The XposedOrNot per-email checks must run one at a time (no overlap) given
    # BREACH_CONCURRENCY == 1. Record max in-flight concurrency via the mock.
    async def fake_rich(verified, probe, domain, job):
        return {"discovered": set(), "names": set()}

    monkeypatch.setattr(main, "discover_emails_rich", fake_rich)

    state = {"inflight": 0, "max": 0}

    async def record(request):
        state["inflight"] += 1
        state["max"] = max(state["max"], state["inflight"])
        # Yield control so an overlapping call could be observed if concurrent.
        await asyncio.sleep(0)
        state["inflight"] -= 1
        return httpx.Response(200, json={"Error": "Not found", "email": None})

    respx.get(url__regex=r"https://api\.xposedornot\.com/v1/check-email/.*").mock(
        side_effect=record
    )

    supplied = "a@example.com\nb@example.com\nc@example.com\nd@example.com"
    async with httpx.AsyncClient() as c:
        main.app.state.client = c
        if hasattr(main.app.state, "probe_client"):
            delattr(main.app.state, "probe_client")
        main.BREACH_JOBS["serial"] = main.BreachJobState(job_id="serial", domain="example.com")
        await main.run_breach("serial", "example.com", supplied, None)

    assert state["max"] == 1  # never more than one check in flight
