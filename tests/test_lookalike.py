"""Tests for the keyless lookalike-domain engine + its separate job API.

All DNS/HTTP/RDAP I/O is monkeypatched or respx-mocked so the suite stays
offline and deterministic. Candidate generation (generate_lookalikes) is pure
and needs no mocking. The subdomain path and its 16-column CSV contract are
untouched and remain covered by tests/test_api.py.
"""

import csv
import io

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

import main


@pytest.fixture(autouse=True)
def clear_jobs():
    main.LOOKALIKE_JOBS.clear()
    main.JOBS.clear()
    main._RATE_BUCKETS.clear()
    yield
    main.LOOKALIKE_JOBS.clear()
    main.JOBS.clear()
    main._RATE_BUCKETS.clear()


# ---------------------------------------------------------------------------
# 1. split_domain
# ---------------------------------------------------------------------------
def test_split_domain_single_tld():
    assert main.split_domain("brandco.ai") == ("brandco", "ai")


def test_split_domain_multi_label_sld():
    assert main.split_domain("example.co.uk") == ("example", "co.uk")


def test_split_domain_no_dot():
    assert main.split_domain("brandco") == ("brandco", "")


# ---------------------------------------------------------------------------
# 2. generate_lookalikes — core assertions
# ---------------------------------------------------------------------------
def test_generate_contains_hyphenation_and_tldswap():
    out = main.generate_lookalikes("brandco.ai")
    # Hyphenation keeps the original TLD -> brand-co.ai; the TLD-swap set adds
    # brand-co/brandco under .com via hyphenation+tldswap combined coverage.
    assert "brand-co.ai" in out
    assert "brandco.com" in out
    # The specific real-world lookalike the user flagged.
    assert "brand-co.com" in out


def test_generate_dedup_lowercase_excludes_input_all_valid():
    out = main.generate_lookalikes("BrandCo.AI")
    assert "brandco.ai" not in out  # input excluded
    assert all(h == h.lower() for h in out)
    assert len(out) == len(set(out))
    assert all(main.is_valid_hostname(h) for h in out)


def test_generate_generality_other_domain():
    out = main.generate_lookalikes("example.io")
    assert len(out) > 20
    assert "example.io" not in out
    assert all(main.is_valid_hostname(h) for h in out)


def test_generate_covers_ai_tld_for_any_input():
    # 'ai' is in LOOKALIKE_TLDS, so the TLD-swap technique emits <label>.ai for
    # any input regardless of its own TLD. Locks in .ai coverage.
    assert "ai" in main.LOOKALIKE_TLDS
    assert "brandco.ai" in main.generate_lookalikes("brandco.com")
    assert "foo.ai" in main.generate_lookalikes("foo.io")


def test_generate_every_candidate_is_valid_hostname():
    # Safety net: every candidate emitted for a sample domain must be a
    # syntactically valid hostname (no empty labels, no leading/trailing
    # hyphens/dots, valid chars, labels <=63, total <=253). The emit() helper
    # filters through is_valid_hostname, so no invalid candidate can slip out.
    for sample in ("brandco.com", "example.io", "google.com", "a.co.uk"):
        out = main.generate_lookalikes(sample)
        invalid = [h for h in out if not main.is_valid_hostname(h)]
        assert invalid == [], f"invalid candidates for {sample}: {invalid}"


def test_generate_respects_cap(monkeypatch):
    monkeypatch.setattr(main, "MAX_LOOKALIKE_CANDIDATES", 15)
    out = main.generate_lookalikes("brandco.ai")
    assert len(out) == 15


# ---------------------------------------------------------------------------
# 3. Per-technique sample assertions
# ---------------------------------------------------------------------------
def test_technique_omission():
    out = main.generate_lookalikes("brandco.ai")
    assert "erdagent.ai" in out  # first char removed


def test_technique_transposition():
    out = main.generate_lookalikes("brandco.ai")
    assert "enrdagent.ai" in out  # swap first two chars


def test_technique_homoglyph():
    # 'o' -> '0' homoglyph on a label containing 'o'.
    out = main.generate_lookalikes("google.com")
    assert "g0ogle.com" in out


def test_technique_combosquat():
    out = main.generate_lookalikes("brandco.ai")
    assert "login-brandco.ai" in out
    assert "brandco-secure.ai" in out


def test_technique_dot_insert():
    out = main.generate_lookalikes("brandco.ai")
    assert "brand.co.ai" in out


def test_technique_tld_swap_cctld_kept():
    out = main.generate_lookalikes("brandco.ai")
    assert "brandco.ai" not in out  # input excluded
    assert "brandco.io" in out
    assert "brandco.net" in out


# ---------------------------------------------------------------------------
# 4. score_lookalike tiers
# ---------------------------------------------------------------------------
def test_score_high_live_resembles_not_parked():
    # HIGH now requires resemblance (not bare MX): resolves + live + resembles
    # + not parked. MX here is just a booster.
    risk, action = main.score_lookalike(
        "RESOLVED", 200, None, True, True, "unknown", False
    )
    assert risk == "HIGH"
    assert "investigate" in action.lower()
    assert "mx" in action.lower()  # MX noted as a booster


def test_score_high_resembles_without_mx():
    # Brand-containing live lookalike with NO MX is still HIGH (e.g.
    # brand-co.com — arguably the most important hit).
    risk, _ = main.score_lookalike(
        "RESOLVED", 200, None, False, True, "unknown", False
    )
    assert risk == "HIGH"


def test_score_medium_live_mx_but_no_resemblance_not_high():
    # REGRESSION GUARD (nersagent.com): live + MX but does NOT resemble the
    # brand -> MEDIUM, never HIGH. Bare MX must not escalate to HIGH anymore.
    risk, action = main.score_lookalike(
        "RESOLVED", 200, None, True, False, "unknown", False
    )
    assert risk == "MEDIUM"
    assert "unrelated" in action.lower()


def test_score_medium_resembles_but_parked():
    # Brand-ish but just a parking page -> MEDIUM (monitor for activation).
    risk, _ = main.score_lookalike(
        "RESOLVED", 200, None, False, True, "unknown", True
    )
    assert risk == "MEDIUM"


def test_score_low_live_parked_not_resembling():
    # Unrelated parked page -> LOW, not HIGH.
    risk, _ = main.score_lookalike(
        "RESOLVED", 200, None, True, False, "unknown", True
    )
    assert risk == "LOW"


def test_score_low_registered_no_live_site():
    risk, _ = main.score_lookalike("RESOLVED", None, None, False, False, True)
    assert risk == "LOW"


def test_score_low_dns_only():
    risk, _ = main.score_lookalike("RESOLVED", None, None, False, False, "unknown")
    assert risk == "LOW"


def test_score_available_unregistered():
    risk, action = main.score_lookalike("NXDOMAIN", None, None, False, False, False)
    assert risk == "AVAILABLE"
    assert "defensive registration" in action.lower()


def test_score_none():
    risk, _ = main.score_lookalike("NXDOMAIN", None, None, False, False, "unknown")
    assert risk == "NONE"


# ---------------------------------------------------------------------------
# 4b. Brand-signal helpers: _brand_tokens / _is_parked / _resembles_brand
# ---------------------------------------------------------------------------
def test_brand_tokens_excludes_stopwords_keeps_distinctive():
    # 'agent' is a generic stopword; the distinctive stem 'nerd' and the full
    # label 'brandco' must survive, but 'ai'/'for'/'home' (stopwords/short)
    # must be dropped.
    tokens = main._brand_tokens("brandco", "Nerd Agent - AI for Home Assistant")
    assert "brandco" in tokens
    assert "nerd" in tokens
    assert "assistant" in tokens
    assert "agent" not in tokens
    assert "ai" not in tokens
    assert "for" not in tokens
    assert "home" not in tokens


def test_brand_tokens_label_only_when_no_title():
    # Fetch failure path: tokens derive from the label alone, still distinctive.
    tokens = main._brand_tokens("brandco", None)
    assert "brandco" in tokens
    assert "nerd" in tokens


def test_is_parked_signatures_and_empty_title():
    assert main._is_parked("Parking Page") is True
    assert main._is_parked("This domain is for sale") is True
    assert main._is_parked("Buy this domain") is True
    assert main._is_parked("Coming Soon") is True
    assert main._is_parked("") is True          # empty title
    assert main._is_parked("   ") is True        # whitespace-only
    assert main._is_parked("Nerd Agent") is False
    assert main._is_parked(None) is False        # no probe -> not parked


def test_resembles_brand_label_containment():
    tokens = main._brand_tokens("brandco", "Nerd Agent")
    # Hyphen/dot variants normalize to contain the brand label.
    assert main._resembles_brand("brand-co.com", None, "brandco", tokens) is True
    assert main._resembles_brand("brandco.me", None, "brandco", tokens) is True
    assert main._resembles_brand("brandco-login.com", None, "brandco", tokens) is True


def test_resembles_brand_unrelated_label_and_title():
    tokens = main._brand_tokens("brandco", "Nerd Agent - AI for Home Assistant")
    # nersagent/nercagent do NOT contain 'brandco' and their titles share no
    # distinctive brand token -> do NOT resemble.
    assert main._resembles_brand(
        "nersagent.com", "New Era Realty Solutions - real estate in Miami",
        "brandco", tokens,
    ) is False
    assert main._resembles_brand(
        "nercagent.com", "NERC Agent", "brandco", tokens,
    ) is False


def test_resembles_brand_by_content_token():
    tokens = main._brand_tokens("brandco", "Nerd Agent - AI for Home Assistant")
    # Different label but title echoes the distinctive token 'nerd'.
    assert main._resembles_brand(
        "totally-other.com", "Nerd Helper", "brandco", tokens,
    ) is True


# ---------------------------------------------------------------------------
# 5. analyze_candidate tiers (monkeypatched DNS/HTTP/MX)
# ---------------------------------------------------------------------------
async def _run_analyze(monkeypatch, *, ips, dns_status, http, https, body, mx,
                       check_whois=False, original_title=None,
                       candidate="brand-co.com", brand_label="brandco",
                       brand_tokens=None):
    async def fake_resolve(host):
        return ips, dns_status

    async def fake_check_http(client, host):
        return http, https, body

    def fake_dig(host):
        return {"MX": ["10 mail.x"]} if mx else {}

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_dig_records", fake_dig)

    import asyncio
    sem = asyncio.Semaphore(5)
    rdap_sem = asyncio.Semaphore(5)
    return await main.analyze_candidate(
        None, None, candidate, "lookalike", original_title,
        check_whois, sem, rdap_sem, brand_label, brand_tokens,
    )


async def test_analyze_high_tier_brand_containing_label(monkeypatch):
    # 'brand-co' normalizes to contain the brand label 'brandco' -> resembles
    # -> live + not parked -> HIGH, even without MX.
    res = await _run_analyze(
        monkeypatch, ips=["93.184.216.34"], dns_status="RESOLVED",
        http=200, https=200, body="<title>Nerd Agent - AI for Home Assistant</title>",
        mx=False,
    )
    assert res["resembles_original"] is True
    assert res["risk"] == "HIGH"
    assert res["candidate"] == "brand-co.com"
    assert res["technique"] == "lookalike"


async def test_analyze_medium_unrelated_business_not_high(monkeypatch):
    # REGRESSION (nersagent.com): live + MX, label does NOT contain 'brandco',
    # title is a clearly different business sharing no distinctive brand token
    # -> resembles False -> MEDIUM, never HIGH.
    res = await _run_analyze(
        monkeypatch, ips=["93.184.216.34"], dns_status="RESOLVED",
        http=200, https=None,
        body="<title>New Era Realty Solutions - real estate in Miami</title>",
        mx=True, candidate="nersagent.com",
        original_title="Nerd Agent - AI for Home Assistant",
    )
    assert res["resembles_original"] is False
    assert res["risk"] == "MEDIUM"
    assert "unrelated" in res["recommended_action"].lower()


async def test_analyze_parked_not_high(monkeypatch):
    # Parked placeholder on a non-resembling label -> LOW, never HIGH.
    res = await _run_analyze(
        monkeypatch, ips=["93.184.216.34"], dns_status="RESOLVED",
        http=200, https=None, body="<title>Parking Page</title>", mx=True,
        candidate="berdagent.com",
        original_title="Nerd Agent - AI for Home Assistant",
    )
    assert res["resembles_original"] is False
    assert res["risk"] == "LOW"


async def test_analyze_brand_tld_variant_high(monkeypatch):
    # Brand TLD variant: same brand label, different TLD, live, MX -> HIGH.
    res = await _run_analyze(
        monkeypatch, ips=["93.184.216.34"], dns_status="RESOLVED",
        http=200, https=200, body="<title>Nerd Agent</title>", mx=True,
        candidate="brandco.me",
    )
    assert res["resembles_original"] is True
    assert res["risk"] == "HIGH"


async def test_analyze_low_tier(monkeypatch):
    # Resolves, no live site -> LOW. Non-resembling label so no HIGH path.
    res = await _run_analyze(
        monkeypatch, ips=["93.184.216.34"], dns_status="RESOLVED",
        http=None, https=None, body="", mx=False,
        candidate="unrelated-site.com", brand_label="brandco",
    )
    assert res["risk"] == "LOW"


async def test_analyze_available_tier(monkeypatch):
    res = await _run_analyze(
        monkeypatch, ips=[], dns_status="NXDOMAIN",
        http=None, https=None, body="", mx=False, check_whois=False,
    )
    # No whois -> registered stays 'unknown' -> NONE (not AVAILABLE without
    # a registration signal).
    assert res["risk"] == "NONE"


async def test_analyze_resembles_by_content_token(monkeypatch):
    # Label does NOT contain the brand, but the fetched title shares the
    # distinctive brand token 'nerd' -> resembles by content -> HIGH when live.
    res = await _run_analyze(
        monkeypatch, ips=["93.184.216.34"], dns_status="RESOLVED",
        http=200, https=None, body="<title>Nerd Helper</title>", mx=False,
        candidate="totally-other.com",
        original_title="Nerd Agent - AI for Home Assistant",
    )
    assert res["resembles_original"] is True
    assert res["risk"] == "HIGH"


async def test_analyze_fetch_failure_falls_back_to_label(monkeypatch):
    # Original-title fetch failed (brand_tokens from label only) and the
    # candidate serves no title: resemblance must fall back to label-containment
    # and NEVER raise. 'brand-co' still contains 'brandco' -> resembles.
    res = await _run_analyze(
        monkeypatch, ips=["93.184.216.34"], dns_status="RESOLVED",
        http=200, https=None, body="<title>Nerd Agent</title>", mx=False,
        original_title=None, candidate="brand-co.com",
    )
    assert res["resembles_original"] is True
    assert res["risk"] == "HIGH"


# ---------------------------------------------------------------------------
# 6. SSRF — a candidate resolving to a private/metadata IP is NOT probed
# ---------------------------------------------------------------------------
async def test_ssrf_private_ip_not_probed(monkeypatch):
    called = {"http": False}

    async def fake_resolve(host):
        return ["127.0.0.1"], "RESOLVED"

    async def fake_check_http(client, host):
        called["http"] = True
        return 200, 200, "<title>should not happen</title>"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_dig_records", lambda h: {})

    import asyncio
    res = await main.analyze_candidate(
        None, None, "brand-co.com", "lookalike", None, False,
        asyncio.Semaphore(5), asyncio.Semaphore(5),
    )
    assert called["http"] is False
    assert res["http_status"] is None
    assert res["https_status"] is None


async def test_ssrf_metadata_ip_not_probed(monkeypatch):
    called = {"http": False}

    async def fake_resolve(host):
        return ["169.254.169.254"], "RESOLVED"

    async def fake_check_http(client, host):
        called["http"] = True
        return 200, None, ""

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_dig_records", lambda h: {})

    import asyncio
    await main.analyze_candidate(
        None, None, "brand-co.com", "lookalike", None, False,
        asyncio.Semaphore(5), asyncio.Semaphore(5),
    )
    assert called["http"] is False


# ---------------------------------------------------------------------------
# 7. RDAP via respx
# ---------------------------------------------------------------------------
@respx.mock
async def test_rdap_registered_parsed():
    respx.get("https://rdap.org/domain/brand-co.com").mock(
        return_value=httpx.Response(
            200,
            json={
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                    }
                ],
                "events": [
                    {"eventAction": "registration", "eventDate": "2020-01-02T00:00:00Z"}
                ],
            },
        )
    )
    async with httpx.AsyncClient() as c:
        info = await main.rdap_lookup(c, "brand-co.com")
    assert info["registered"] is True
    assert info["registrar"] == "Example Registrar"
    assert info["creation_date"].startswith("2020-01-02")


@respx.mock
async def test_rdap_404_unregistered():
    respx.get("https://rdap.org/domain/free-domain.com").mock(
        return_value=httpx.Response(404, json={})
    )
    async with httpx.AsyncClient() as c:
        info = await main.rdap_lookup(c, "free-domain.com")
    assert info["registered"] is False


@respx.mock
async def test_rdap_error_tolerated():
    respx.get("https://rdap.org/domain/err.com").mock(
        side_effect=httpx.ConnectError("boom")
    )
    async with httpx.AsyncClient() as c:
        info = await main.rdap_lookup(c, "err.com")
    assert info["registered"] == "unknown"
    assert info["registrar"] == ""


@respx.mock
async def test_job_completes_despite_rdap_error(monkeypatch):
    # The whole job must still complete (status done) when RDAP errors.
    async def fake_resolve(host):
        return ["93.184.216.34"], "RESOLVED"

    async def fake_check_http(client, host):
        return 200, None, "<title>x</title>"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_dig_records", lambda h: {})
    # Keep candidate set tiny so the job finishes fast.
    monkeypatch.setattr(main, "MAX_LOOKALIKE_CANDIDATES", 3)
    respx.route(host="rdap.org").mock(side_effect=httpx.ConnectError("boom"))

    async with httpx.AsyncClient() as c:
        main.app.state.client = c
        main.app.state.probe_client = c
        main.LOOKALIKE_JOBS["j1"] = main.LookalikeJobState(
            job_id="j1", domain="brandco.ai", check_whois=True
        )
        await main.run_lookalike("j1", "brandco.ai", True)

    job = main.LOOKALIKE_JOBS["j1"]
    assert job.status == "done"
    assert job.candidates_checked == job.candidates_generated
    assert all(r["registered"] == "unknown" for r in job.results)


# ---------------------------------------------------------------------------
# 8. CSV contract
# ---------------------------------------------------------------------------
def test_lookalike_csv_header_exact():
    content = main._build_lookalike_csv([])
    header = next(csv.reader(io.StringIO(content)))
    assert header == main.LOOKALIKE_CSV_COLUMNS
    assert len(header) == 14


def test_lookalike_csv_csv_safe_neutralizes_formula():
    row = {
        "candidate": "=evil.com",
        "technique": "lookalike",
        "dns_status": "RESOLVED",
        "ip_addresses": ["1.2.3.4"],
        "http_status": 200,
        "https_status": None,
        "page_title": "=cmd|' /C calc'!A0",
        "has_mx": False,
        "registered": True,
        "registrar": "r",
        "creation_date": "2020",
        "resembles_original": False,
        "risk": "MEDIUM",
        "recommended_action": "x",
    }
    content = main._build_lookalike_csv([row])
    reader = csv.reader(io.StringIO(content))
    next(reader)  # header
    first = next(reader)
    assert first[0].startswith("'=evil.com")  # candidate neutralized
    assert first[6].startswith("'=cmd")  # page_title neutralized
    assert first[3] == "1.2.3.4"  # ip_addresses joined


# ---------------------------------------------------------------------------
# 9. API via TestClient (run_lookalike monkeypatched to deterministic filler)
# ---------------------------------------------------------------------------
@pytest.fixture
def client(monkeypatch):
    async def fake_run(job_id, domain, check_whois):
        job = main.LOOKALIKE_JOBS[job_id]
        job.status = "done"
        job.progress = 100
        job.candidates_generated = 1
        job.candidates_checked = 1
        job.registered_count = 1
        job.results = [
            {
                "candidate": "brand-co.com",
                "technique": "lookalike",
                "dns_status": "RESOLVED",
                "ip_addresses": ["93.184.216.34"],
                "http_status": 200,
                "https_status": 200,
                "page_title": "Nerd Agent",
                "has_mx": True,
                "registered": True,
                "registrar": "Example Registrar",
                "creation_date": "2020-01-02",
                "resembles_original": True,
                "risk": "HIGH",
                "recommended_action": "investigate",
            }
        ]

    monkeypatch.setattr(main, "run_lookalike", fake_run)
    with TestClient(main.app) as c:
        yield c


def test_api_full_flow(client):
    resp = client.post("/api/lookalike", json={"domain": "brandco.ai"})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    assert job_id

    status = client.get(f"/api/lookalike/status/{job_id}").json()
    assert status["status"] == "done"
    assert status["candidates_generated"] == 1
    assert status["registered_count"] == 1

    results = client.get(f"/api/lookalike/results/{job_id}").json()
    assert results["domain"] == "brandco.ai"
    assert results["summary"]["total"] == 1
    assert results["summary"]["high"] == 1
    assert results["summary"]["registered"] == 1
    assert results["summary"]["live"] == 1
    assert results["candidates"][0]["candidate"] == "brand-co.com"


def test_api_download(client):
    job_id = client.post("/api/lookalike", json={"domain": "brandco.ai"}).json()["job_id"]
    resp = client.get(f"/api/lookalike/download/{job_id}")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "lookalike_brandco.ai_" in resp.headers["content-disposition"]
    reader = csv.reader(io.StringIO(resp.text))
    assert next(reader) == main.LOOKALIKE_CSV_COLUMNS
    first = next(reader)
    assert first[0] == "brand-co.com"


def test_api_unknown_job_404(client):
    assert client.get("/api/lookalike/status/nope").status_code == 404
    assert client.get("/api/lookalike/results/nope").status_code == 404
    assert client.get("/api/lookalike/download/nope").status_code == 404


def test_api_invalid_domain_400(client):
    resp = client.post("/api/lookalike", json={"domain": "not a domain"})
    assert resp.status_code == 400


def test_api_rate_limit_429(client, monkeypatch):
    monkeypatch.setattr(main, "RATE_LIMIT_PER_MINUTE", 2)
    monkeypatch.setattr(main, "RATE_LIMIT_BURST", 2)
    main._RATE_BUCKETS.clear()
    statuses = [
        client.post("/api/lookalike", json={"domain": "brandco.ai"}).status_code
        for _ in range(6)
    ]
    assert 429 in statuses


def test_api_results_409_when_not_done(client, monkeypatch):
    # Create a job stuck in 'running' and confirm results/download give 409.
    async def never_run(job_id, domain, check_whois):
        return

    monkeypatch.setattr(main, "run_lookalike", never_run)
    job_id = client.post("/api/lookalike", json={"domain": "brandco.ai"}).json()["job_id"]
    main.LOOKALIKE_JOBS[job_id].status = "running"
    assert client.get(f"/api/lookalike/results/{job_id}").status_code == 409
    assert client.get(f"/api/lookalike/download/{job_id}").status_code == 409
