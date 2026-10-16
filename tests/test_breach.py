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
