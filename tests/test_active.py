"""Tests for active DNS discovery (brute-force + permutation).

Covers wordlist loading/parsing, candidate generation and the global candidate
cap, permutation variants, source tagging of active hits, the SSRF guard still
holding for active-discovered hosts, and the backward-compatibility of the
passive-only /api/enumerate path (active fields omitted). All DNS/HTTP I/O is
monkeypatched / respx-mocked so the suite stays offline and deterministic.
"""

import asyncio

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


# ---------------------------------------------------------------------------
# 1. Wordlist loading
# ---------------------------------------------------------------------------
def test_default_wordlist_non_empty_valid_deduped_lowercase():
    wl = main.DEFAULT_WORDLIST
    assert len(wl) >= 2000
    assert wl == [w.lower() for w in wl]
    assert len(wl) == len(set(wl))
    assert all(main._is_valid_label(w) for w in wl)


def test_load_default_wordlist_missing_file_returns_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DEFAULT_WORDLIST_PATH", str(tmp_path / "nope.txt"))
    # Never raises; returns [] so the app still starts.
    assert main.load_default_wordlist() == []


# ---------------------------------------------------------------------------
# 2. Custom wordlist parsing
# ---------------------------------------------------------------------------
def test_parse_custom_wordlist_keeps_valid_drops_invalid():
    out = main.parse_custom_wordlist(
        "API\nwww\n-bad\nhas space\nwww\n# comment\n\nunder_score\nok-dash\n"
    )
    # lowercased, deduped, order-preserving; invalid labels dropped silently.
    assert out == ["api", "www", "ok-dash"]


@pytest.mark.parametrize("empty", [None, "", "   \n  \n# only comment\n"])
def test_parse_custom_wordlist_empty_returns_list(empty):
    assert main.parse_custom_wordlist(empty) == []


# ---------------------------------------------------------------------------
# 3. Brute-force candidate generation + cap
# ---------------------------------------------------------------------------
def test_build_bruteforce_candidates_basic():
    c, trunc = main.build_bruteforce_candidates("example.com", ["www", "api"], 100)
    assert c == ["www.example.com", "api.example.com"]
    assert trunc is False


def test_build_bruteforce_candidates_respects_cap():
    c, trunc = main.build_bruteforce_candidates("example.com", ["a"] * 50, 10)
    assert len(c) == 10
    assert trunc is True


def test_build_bruteforce_candidates_skips_invalid_host():
    # A label that would produce an invalid hostname is skipped (defense in
    # depth). "-bad" never reaches here via parse, but prove the gate works.
    c, _ = main.build_bruteforce_candidates("example.com", ["-bad", "ok"], 100)
    assert "ok.example.com" in c
    assert all(main.is_valid_hostname(h) for h in c)


# ---------------------------------------------------------------------------
# 4. Permutation generation
# ---------------------------------------------------------------------------
def test_generate_permutations_variants():
    c, trunc = main.generate_permutations(
        {"api.example.com"},
        "example.com",
        main.PERMUTATION_WORDS,
        main.PERMUTATION_SEPARATORS,
        20000,
    )
    # word prepend/append with both separators
    assert "dev-api.example.com" in c
    assert "api-dev.example.com" in c
    assert "dev.api.example.com" in c
    assert "api.dev.example.com" in c
    # numeric append (altdns-style)
    assert "api2.example.com" in c
    # excludes the seed and base domain
    assert "api.example.com" not in c
    assert "example.com" not in c
    # every FQDN is valid
    assert all(main.is_valid_hostname(h) for h in c)
    assert trunc is False


def test_generate_permutations_number_increment_and_dashswap():
    c, _ = main.generate_permutations(
        {"api1.example.com", "dev-api.example.com"},
        "example.com",
        main.PERMUTATION_WORDS,
        main.PERMUTATION_SEPARATORS,
        20000,
    )
    assert "api2.example.com" in c
    assert "api3.example.com" in c
    assert "api4.example.com" in c
    # dash <-> dot swap
    assert "dev.api.example.com" in c


def test_generate_permutations_respects_cap():
    c, trunc = main.generate_permutations(
        {"api.example.com"},
        "example.com",
        main.PERMUTATION_WORDS,
        main.PERMUTATION_SEPARATORS,
        5,
    )
    assert len(c) == 5
    assert trunc is True


# ---------------------------------------------------------------------------
# 5. Active hits carry the correct source tag
# ---------------------------------------------------------------------------
@respx.mock
async def test_active_hit_tagged_bruteforce_and_permutation(monkeypatch):
    # All passive sources return empty / harmless.
    respx.route().mock(return_value=httpx.Response(200, json={}))

    # Only a specific brute-force label and a specific permutation resolve.
    resolving = {"www.example.com": ["93.184.216.34"], "www2.example.com": ["93.184.216.34"]}

    async def fake_resolve_dns_detailed(host):
        ips = resolving.get(host, [])
        return ips, ("RESOLVED" if ips else "NXDOMAIN")

    async def fake_resolve_cname_chain(host):
        return []

    async def fake_resolve_cname(host):
        return None

    async def fake_check_http(client, host, pinned_ip=None):
        return 200, None, ""

    async def fake_resolve_ptrs(ips):
        return []

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)
    # Use a tiny deterministic wordlist so www resolves and others don't.
    monkeypatch.setattr(main, "DEFAULT_WORDLIST", ["www", "nope"])

    client = httpx.AsyncClient()
    main.app.state.client = client
    main.app.state.probe_client = client
    main.JOBS["aj"] = main.JobState(job_id="aj", domain="example.com")
    try:
        await main.run_enumeration(
            "aj", "example.com", {}, active=True, permutations=True
        )
    finally:
        await client.aclose()

    job = main.JOBS["aj"]
    assert job.status == "done"
    by_host = {r["subdomain"]: r for r in job.results}
    # Brute-force hit tagged.
    assert "www.example.com" in by_host
    assert "bruteforce" in by_host["www.example.com"]["sources"]
    # Permutation hit (www -> www2) tagged.
    assert "www2.example.com" in by_host
    assert "permutation" in by_host["www2.example.com"]["sources"]
    # The active phases are registered as sources.
    assert job.source_statuses.get("bruteforce") == "done"
    assert job.source_statuses.get("permutation") == "done"


# ---------------------------------------------------------------------------
# 6. SSRF guard still holds for active-discovered hosts
# ---------------------------------------------------------------------------
@respx.mock
async def test_active_hosts_still_pass_ssrf_guard(monkeypatch):
    respx.route().mock(return_value=httpx.Response(200, json={}))

    probe_called = {"n": 0}

    async def fake_resolve_dns_detailed(host):
        # Every active candidate resolves to internal/metadata IPs.
        return ["127.0.0.1", "169.254.169.254"], "RESOLVED"

    async def fake_resolve_cname_chain(host):
        return []

    async def fake_resolve_cname(host):
        return None

    async def fake_check_http(client, host, pinned_ip=None):
        probe_called["n"] += 1
        return 200, 200, "should-not-happen"

    async def fake_resolve_ptrs(ips):
        return []

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)
    monkeypatch.setattr(main, "DEFAULT_WORDLIST", ["internal"])

    client = httpx.AsyncClient()
    main.app.state.client = client
    main.app.state.probe_client = client
    main.JOBS["sj"] = main.JobState(job_id="sj", domain="example.com")
    try:
        await main.run_enumeration("sj", "example.com", {}, active=True)
    finally:
        await client.aclose()

    job = main.JOBS["sj"]
    assert job.status == "done"
    # The private-IP host was never HTTP-probed...
    assert probe_called["n"] == 0
    # ...and it still shows as a resolved (DNS A record) brute-force hit, but
    # not alive and with no HTTP status (the SSRF guard skipped the probe).
    bf = next(
        (r for r in job.results if r["subdomain"] == "internal.example.com"), None
    )
    assert bf is not None
    assert bf["http_status"] is None
    assert bf["https_status"] is None
    assert bf["alive"] is False
    assert "bruteforce" in bf["sources"]


async def test_resolve_candidates_only_returns_hits(monkeypatch):
    """resolve_candidates keeps resolving candidates, drops non-resolving."""
    async def fake_resolve_dns_detailed(host):
        if host == "hit.example.com":
            return ["93.184.216.34"], "RESOLVED"
        return [], "NXDOMAIN"

    async def fake_resolve_cname_chain(host):
        return []

    async def fake_resolve_cname(host):
        return None

    async def fake_check_http(client, host, pinned_ip=None):
        return 200, None, ""

    async def fake_resolve_ptrs(ips):
        return []

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)

    sem = asyncio.Semaphore(5)
    hits = await main.resolve_candidates(
        None, ["hit.example.com", "miss.example.com"], sem, "bruteforce"
    )
    assert set(hits) == {"hit.example.com"}
    assert "bruteforce" in hits["hit.example.com"]["sources"]


# ---------------------------------------------------------------------------
# 7. Backward compatibility: passive-only path (active fields omitted)
# ---------------------------------------------------------------------------
def test_enumerate_omitting_active_fields_registers_no_active_sources(monkeypatch):
    captured = {}

    async def fake_run(job_id, domain, keys, **kwargs):
        captured.update(kwargs)
        job = main.JOBS[job_id]
        job.status = "done"
        job.progress = 100
        job.source_statuses = {name: "done" for name in main.SOURCES}

    monkeypatch.setattr(main, "run_enumeration", fake_run)

    with TestClient(main.app) as c:
        job_id = c.post("/api/enumerate", json={"domain": "example.com"}).json()["job_id"]
        status = c.get(f"/api/status/{job_id}").json()

    # Defaults flow through: active off, permutations off.
    assert captured.get("active") is False
    assert captured.get("permutations") is False
    # No active sources appear in the status payload.
    assert "bruteforce" not in status["source_statuses"]
    assert "permutation" not in status["source_statuses"]
    assert set(status["source_statuses"]) == set(main.SOURCES)


def test_enumerate_omitting_c99_key_behaves_as_before(monkeypatch):
    # Regression: POST /api/enumerate with c99_key omitted carries c99_key=None
    # in the keys dict (backward compatible) and registers c99 as a source,
    # exactly like SecurityTrails/Shodan when their key is absent.
    captured = {}

    async def fake_run(job_id, domain, keys, **kwargs):
        captured["keys"] = keys
        job = main.JOBS[job_id]
        job.status = "done"
        job.progress = 100
        job.source_statuses = {name: "done" for name in main.SOURCES}

    monkeypatch.setattr(main, "run_enumeration", fake_run)

    with TestClient(main.app) as c:
        job_id = c.post("/api/enumerate", json={"domain": "example.com"}).json()["job_id"]
        status = c.get(f"/api/status/{job_id}").json()

    # c99 key defaults to None, alongside the other keyed sources.
    assert captured["keys"]["c99_key"] is None
    assert captured["keys"]["securitytrails_key"] is None
    assert captured["keys"]["shodan_key"] is None
    # c99 is a registered source in the status panel.
    assert "c99" in status["source_statuses"]
    assert set(status["source_statuses"]) == set(main.SOURCES)


def test_enumerate_passes_active_fields_when_present(monkeypatch):
    captured = {}

    async def fake_run(job_id, domain, keys, **kwargs):
        captured.update(kwargs)
        main.JOBS[job_id].status = "done"

    monkeypatch.setattr(main, "run_enumeration", fake_run)

    with TestClient(main.app) as c:
        c.post(
            "/api/enumerate",
            json={
                "domain": "example.com",
                "active": True,
                "permutations": True,
                "wordlist": "www\nmail",
                "wordlist_mode": "append",
            },
        )

    assert captured["active"] is True
    assert captured["permutations"] is True
    assert captured["wordlist"] == "www\nmail"
    assert captured["wordlist_mode"] == "append"


def test_enumerate_coerces_unknown_wordlist_mode(monkeypatch):
    captured = {}

    async def fake_run(job_id, domain, keys, **kwargs):
        captured.update(kwargs)
        main.JOBS[job_id].status = "done"

    monkeypatch.setattr(main, "run_enumeration", fake_run)

    with TestClient(main.app) as c:
        c.post(
            "/api/enumerate",
            json={"domain": "example.com", "active": True, "wordlist_mode": "bogus"},
        )

    assert captured["wordlist_mode"] == "replace"


@respx.mock
async def test_custom_wordlist_all_invalid_falls_back_to_default(monkeypatch):
    respx.route().mock(return_value=httpx.Response(200, json={}))

    seen_hosts = []

    async def fake_resolve_dns_detailed(host):
        seen_hosts.append(host)
        return [], "NXDOMAIN"

    async def fake_resolve_cname_chain(host):
        return []

    async def fake_resolve_cname(host):
        return None

    async def fake_check_http(client, host, pinned_ip=None):
        return None, None, ""

    async def fake_resolve_ptrs(ips):
        return []

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)
    monkeypatch.setattr(main, "DEFAULT_WORDLIST", ["www", "mail"])

    client = httpx.AsyncClient()
    main.app.state.client = client
    main.app.state.probe_client = client
    main.JOBS["fb"] = main.JobState(job_id="fb", domain="example.com")
    try:
        # All custom labels invalid -> fall back to the (mocked) default list.
        await main.run_enumeration(
            "fb", "example.com", {}, active=True, wordlist="-bad\nhas space\n@@@"
        )
    finally:
        await client.aclose()

    # The default labels were used as the brute-force candidate base.
    assert "www.example.com" in seen_hosts
    assert "mail.example.com" in seen_hosts


@respx.mock
async def test_run_enumeration_truncation_note(monkeypatch):
    # A tiny cap forces truncation; the note is recorded in job state.
    respx.route().mock(return_value=httpx.Response(200, json={}))
    monkeypatch.setattr(main, "MAX_ACTIVE_CANDIDATES", 1)
    monkeypatch.setattr(main, "DEFAULT_WORDLIST", ["www", "mail", "dev"])

    async def fake_resolve_dns(host):
        return []

    async def fake_resolve_cname(host):
        return None

    async def fake_check_http(client, host, pinned_ip=None):
        return None, None, ""

    async def fake_resolve_ptrs(ips):
        return []

    monkeypatch.setattr(main, "resolve_dns", fake_resolve_dns)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)

    client = httpx.AsyncClient()
    main.app.state.client = client
    main.app.state.probe_client = client
    main.JOBS["tj"] = main.JobState(job_id="tj", domain="example.com")
    try:
        await main.run_enumeration("tj", "example.com", {}, active=True)
    finally:
        await client.aclose()

    job = main.JOBS["tj"]
    assert job.status == "done"
    assert any("candidate cap" in n for n in job.notes)
