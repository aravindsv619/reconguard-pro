"""API-contract tests using FastAPI TestClient.

Validates domain rejection, the job_id handshake, status/results shapes, and
the CSV download header row. run_enumeration is stubbed so no real network or
DNS I/O happens; the endpoint wiring is what's under test.
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


@pytest.fixture
def client(monkeypatch):
    # Replace enumeration with a deterministic synchronous filler so the job
    # reaches `done` immediately after POST.
    async def fake_run(job_id, domain, keys, **kwargs):
        job = main.JOBS[job_id]
        job.status = "done"
        job.progress = 100
        job.subdomains_found = 1
        job.source_statuses = {name: "done" for name in main.SOURCES}
        job.results = [
            main.SubdomainResult(
                subdomain="a.example.com",
                ip_addresses=["1.2.3.4"],
                cname="a.github.io",
                http_status=404,
                https_status=None,
                sources=["crt.sh"],
                takeover_risk="HIGH",
                takeover_service="GitHub Pages",
                takeover_detail="fingerprint matched",
                takeover_verdict="VULNERABLE",
                takeover_evidence="GitHub Pages 'no site here' signature",
                resolved=True,
                alive=True,
                dns_status="RESOLVED",
                cname_chain=["a.github.io"],
            )
        ]

    monkeypatch.setattr(main, "run_enumeration", fake_run)
    with TestClient(main.app) as c:
        yield c


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_enumerate_rejects_invalid_domain(client):
    resp = client.post("/api/enumerate", json={"domain": "not a domain"})
    assert resp.status_code == 400


def test_full_flow(client):
    resp = client.post("/api/enumerate", json={"domain": "example.com"})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    assert job_id

    status = client.get(f"/api/status/{job_id}").json()
    assert status["status"] == "done"
    assert status["progress"] == 100
    assert set(status["source_statuses"]) == set(main.SOURCES)

    results = client.get(f"/api/results/{job_id}").json()
    assert results["domain"] == "example.com"
    assert results["total"] == 1
    assert results["high_risk"] == 1
    row = results["subdomains"][0]
    for key in main.SubdomainResult.__annotations__:
        assert key in row


def test_status_404_for_unknown(client):
    assert client.get("/api/status/nope").status_code == 404


def test_download_csv_header(client):
    job_id = client.post("/api/enumerate", json={"domain": "example.com"}).json()["job_id"]
    resp = client.get(f"/api/download/{job_id}")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in resp.headers["content-disposition"]

    reader = csv.reader(io.StringIO(resp.text))
    header = next(reader)
    assert header == main.CSV_COLUMNS
    # First 12 columns are the fixed backward-compatible contract; dns_status
    # stays at index 11. The active-verification columns are appended after it.
    assert header[11] == "dns_status"
    assert header[12] == "takeover_verdict"
    assert header[13] == "takeover_evidence"
    # FEAT-001 grows the header to 14; FEAT-002 (dns_records) bumps it to 15.
    assert len(header) == 14
    first = next(reader)
    assert first[0] == "a.example.com"
    assert "1.2.3.4" in first[1]
    # dns_status value lands in the 12th cell.
    assert first[11] == "RESOLVED"
    # Appended verification cells.
    assert first[12] == "VULNERABLE"
    assert first[13] == "GitHub Pages 'no site here' signature"
