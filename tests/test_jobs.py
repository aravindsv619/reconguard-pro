"""Tests for the job engine (run_enumeration, cleanup_old_jobs)."""

import time

import httpx
import pytest
import respx

import main


@pytest.fixture(autouse=True)
def clear_jobs():
    main.JOBS.clear()
    yield
    main.JOBS.clear()


@pytest.fixture
def no_network_analysis(monkeypatch):
    """Stub DNS/HTTP so analysis does no real I/O."""
    async def fake_resolve_dns(host):
        return ["1.2.3.4"]

    async def fake_resolve_cname(host):
        return None

    async def fake_check_http(client, host, pinned_ip=None):
        return 200, None, ""

    async def fake_resolve_ptrs(ips):
        return []

    monkeypatch.setattr(main, "resolve_dns", fake_resolve_dns)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)


@respx.mock
async def test_run_enumeration_completes_and_dedups(no_network_analysis, monkeypatch):
    # Two sources return overlapping hosts with mixed case → dedup to lowercase.
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=[{"name_value": "A.example.com\nb.example.com"}])
    )
    respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(200, text="a.example.com,1.2.3.4\nc.example.com,2.2.2.2")
    )
    # Everything else returns empty / fails harmlessly.
    respx.route(host="otx.alienvault.com").mock(return_value=httpx.Response(200, json={"passive_dns": []}))
    respx.route().mock(return_value=httpx.Response(200, json={}))

    client = httpx.AsyncClient()
    main.app.state.client = client
    main.app.state.probe_client = client

    main.JOBS["j1"] = main.JobState(job_id="j1", domain="example.com")
    try:
        await main.run_enumeration("j1", "example.com", {})
    finally:
        await client.aclose()

    job = main.JOBS["j1"]
    assert job.status == "done"
    assert job.progress == 100
    subs = {r["subdomain"] for r in job.results}
    assert subs == {"a.example.com", "b.example.com", "c.example.com"}
    # crt.sh set each discovered host's source; a.example.com came from two sources.
    a_result = next(r for r in job.results if r["subdomain"] == "a.example.com")
    assert "crt.sh" in a_result["sources"] and "HackerTarget" in a_result["sources"]


@respx.mock
async def test_one_failing_source_does_not_abort(no_network_analysis):
    respx.get("https://crt.sh/").mock(side_effect=httpx.ConnectError("down"))
    respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(200, text="z.example.com,1.1.1.1")
    )
    respx.route().mock(return_value=httpx.Response(200, json={}))

    client = httpx.AsyncClient()
    main.app.state.client = client
    main.app.state.probe_client = client
    main.JOBS["j2"] = main.JobState(job_id="j2", domain="example.com")
    try:
        await main.run_enumeration("j2", "example.com", {})
    finally:
        await client.aclose()

    job = main.JOBS["j2"]
    # A down source (crt.sh connect error, retries exhausted -> SourceUnavailable)
    # is isolated per-source and does NOT abort the job; the healthy source's
    # hosts survive and the job still completes.
    assert job.status == "done"
    assert job.progress == 100
    assert job.source_statuses["HackerTarget"] == "done"
    assert {r["subdomain"] for r in job.results} == {"z.example.com"}


@respx.mock
async def test_raising_source_is_marked_error(no_network_analysis, monkeypatch):
    # A fetcher that raises (rather than swallowing) must be isolated and the
    # per-source status set to 'error' without aborting the job.
    async def boom(client, domain, keys):
        raise RuntimeError("unexpected")

    monkeypatch.setitem(main.SOURCES, "crt.sh", boom)
    respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(200, text="z.example.com,1.1.1.1")
    )
    respx.route().mock(return_value=httpx.Response(200, json={}))

    client = httpx.AsyncClient()
    main.app.state.client = client
    main.app.state.probe_client = client
    main.JOBS["j3"] = main.JobState(job_id="j3", domain="example.com")
    try:
        await main.run_enumeration("j3", "example.com", {})
    finally:
        await client.aclose()

    job = main.JOBS["j3"]
    assert job.status == "done"
    assert job.source_statuses["crt.sh"] == "error"
    assert {r["subdomain"] for r in job.results} == {"z.example.com"}


def test_cleanup_removes_old_but_keeps_running():
    main.JOBS["old"] = main.JobState(
        job_id="old", domain="a.com", status="done",
        created_at=time.time() - main.JOB_TTL_SECONDS - 10,
    )
    main.JOBS["old_running"] = main.JobState(
        job_id="old_running", domain="b.com", status="running",
        created_at=time.time() - main.JOB_TTL_SECONDS - 10,
    )
    main.JOBS["fresh"] = main.JobState(job_id="fresh", domain="c.com", status="done")

    main.cleanup_old_jobs()

    assert "old" not in main.JOBS
    assert "old_running" in main.JOBS  # never drop a running job
    assert "fresh" in main.JOBS
