"""Tests for the data-source parsers in main.py.

Each endpoint is mocked with respx and the parser's normalized output is
asserted, including crt.sh wildcard stripping, Wayback URL host extraction,
and the key-optional skip for SecurityTrails/Shodan.
"""

import httpx
import pytest
import respx

import main

DOMAIN = "example.com"


@pytest.fixture
async def client():
    async with httpx.AsyncClient() as c:
        yield c


@respx.mock
async def test_crtsh_splits_and_strips_wildcards(client):
    respx.get("https://crt.sh/", params={"q": f"%.{DOMAIN}", "output": "json"}).mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name_value": "a.example.com\n*.example.com"},
                {"name_value": "b.example.com"},
                {"name_value": "notinscope.org"},
            ],
        )
    )
    out = await main.query_crtsh(client, DOMAIN, {})
    # Wildcard entry collapses to the bare domain; out-of-scope dropped.
    assert out == {"a.example.com", "b.example.com", "example.com"}


@respx.mock
async def test_hackertarget_parses_host_ip_lines(client):
    respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(200, text="a.example.com,1.2.3.4\nb.example.com,5.6.7.8")
    )
    out = await main.query_hackertarget(client, DOMAIN, {})
    assert out == {"a.example.com", "b.example.com"}


@respx.mock
async def test_hackertarget_error_body_returns_empty(client):
    respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(200, text="error check your search parameter")
    )
    out = await main.query_hackertarget(client, DOMAIN, {})
    assert out == set()


@respx.mock
async def test_alienvault_passive_dns(client):
    respx.get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{DOMAIN}/passive_dns"
    ).mock(
        return_value=httpx.Response(
            200, json={"passive_dns": [{"hostname": "c.example.com"}, {"hostname": "x.org"}]}
        )
    )
    out = await main.query_alienvault(client, DOMAIN, {})
    assert out == {"c.example.com"}


@respx.mock
async def test_rapiddns_td_cells(client):
    html = "<table><tr><td>d.example.com</td><td>1.1.1.1</td></tr>" \
           "<tr><td>e.example.com</td></tr></table>"
    respx.get(f"https://rapiddns.io/subdomain/{DOMAIN}").mock(
        return_value=httpx.Response(200, text=html)
    )
    out = await main.query_rapiddns(client, DOMAIN, {})
    assert out == {"d.example.com", "e.example.com"}


@respx.mock
async def test_rapiddns_garbage_degrades_to_empty(client):
    respx.get(f"https://rapiddns.io/subdomain/{DOMAIN}").mock(
        return_value=httpx.Response(200, text="not even html")
    )
    out = await main.query_rapiddns(client, DOMAIN, {})
    assert out == set()


@respx.mock
async def test_urlscan_results(client):
    respx.get("https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(
            200,
            json={"results": [{"page": {"domain": "f.example.com"}}, {"page": {"domain": "y.net"}}]},
        )
    )
    out = await main.query_urlscan(client, DOMAIN, {})
    assert out == {"f.example.com"}


@respx.mock
async def test_wayback_extracts_host_from_url(client):
    respx.get("https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(
            200,
            json=[["original"], ["https://i.example.com/path?a=1"], ["http://j.example.com/"]],
        )
    )
    out = await main.query_wayback(client, DOMAIN, {})
    assert out == {"i.example.com", "j.example.com"}


async def test_securitytrails_skips_without_key(client):
    out = await main.query_securitytrails(client, DOMAIN, {})
    assert out == set()


@respx.mock
async def test_securitytrails_with_key(client):
    respx.get(f"https://api.securitytrails.com/v1/domain/{DOMAIN}/subdomains").mock(
        return_value=httpx.Response(200, json={"subdomains": ["o", "p"]})
    )
    out = await main.query_securitytrails(client, DOMAIN, {"securitytrails_key": "k"})
    assert out == {"o.example.com", "p.example.com"}


async def test_shodan_skips_without_key(client):
    out = await main.query_shodan(client, DOMAIN, {})
    assert out == set()


@respx.mock
async def test_shodan_with_key(client):
    respx.get("https://api.shodan.io/dns/domain/" + DOMAIN).mock(
        return_value=httpx.Response(200, json={"subdomains": ["q", "r"]})
    )
    out = await main.query_shodan(client, DOMAIN, {"shodan_key": "k"})
    assert out == {"q.example.com", "r.example.com"}


async def test_c99_skips_without_key(client):
    out = await main.query_c99(client, DOMAIN, {})
    assert out == set()


@respx.mock
async def test_c99_with_key(client):
    respx.get("https://api.c99.nl/subdomainfinder").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "subdomains": [
                    {"subdomain": "WWW.example.com"},
                    {"subdomain": "api.example.com"},
                    {"subdomain": "www.example.com"},
                    {"subdomain": "notinscope.org"},
                ],
            },
        )
    )
    out = await main.query_c99(client, DOMAIN, {"c99_key": "k"})
    assert out == {"www.example.com", "api.example.com"}


@respx.mock
async def test_c99_handles_success_false(client):
    respx.get("https://api.c99.nl/subdomainfinder").mock(
        return_value=httpx.Response(
            200, json={"success": False, "error": "invalid key"}
        )
    )
    out = await main.query_c99(client, DOMAIN, {"c99_key": "bad"})
    assert out == set()


@respx.mock
async def test_c99_handles_html_error_body(client):
    respx.get("https://api.c99.nl/subdomainfinder").mock(
        return_value=httpx.Response(
            200, text="<html><body>blocked</body></html>"
        )
    )
    out = await main.query_c99(client, DOMAIN, {"c99_key": "k"})
    assert out == set()


@respx.mock
async def test_source_connect_error_raises_source_unavailable(client):
    # New contract: a genuine fetch failure (connection error, exhausted after
    # retries) propagates as SourceUnavailable so run_source marks the source
    # 'error' and the UI can report degraded coverage — it is NOT swallowed to
    # a silent empty "done".
    respx.get("https://crt.sh/").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(main.SourceUnavailable):
        await main.query_crtsh(client, DOMAIN, {})


# ---------------------------------------------------------------------------
# New KEYLESS sources (PART 1) + crt.sh common_name exhaustiveness
# ---------------------------------------------------------------------------
@respx.mock
async def test_crtsh_reads_common_name_and_multiline_name_value(client):
    respx.get("https://crt.sh/", params={"q": f"%.{DOMAIN}", "output": "json"}).mock(
        return_value=httpx.Response(
            200,
            json=[
                # only common_name set
                {"name_value": "", "common_name": "cn.example.com"},
                # multi-line name_value with a wildcard entry
                {"name_value": "multi1.example.com\n*.multi2.example.com"},
                # out-of-scope common_name is dropped
                {"name_value": "", "common_name": "evil.org"},
            ],
        )
    )
    out = await main.query_crtsh(client, DOMAIN, {})
    assert out == {"cn.example.com", "multi1.example.com", "multi2.example.com"}


@respx.mock
async def test_certspotter_parses_dns_names(client):
    respx.get("https://api.certspotter.com/v1/issuances").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"dns_names": ["a.example.com", "*.example.com"]},
                {"dns_names": ["b.example.com", "out.org"]},
            ],
        )
    )
    out = await main.query_certspotter(client, DOMAIN, {})
    # wildcard collapses to bare domain; out-of-scope dropped.
    assert out == {"a.example.com", "example.com", "b.example.com"}


@respx.mock
async def test_subdomaincenter_parses_json_array(client):
    respx.get("https://api.subdomain.center/").mock(
        return_value=httpx.Response(
            200,
            json=["e.example.com", "*.example.com", "elsewhere.org"],
        )
    )
    out = await main.query_subdomaincenter(client, DOMAIN, {})
    assert out == {"e.example.com", "example.com"}


@respx.mock
async def test_certspotter_connect_error_raises_source_unavailable(client):
    respx.get("https://api.certspotter.com/v1/issuances").mock(
        side_effect=httpx.ConnectError("boom")
    )
    with pytest.raises(main.SourceUnavailable):
        await main.query_certspotter(client, DOMAIN, {})


def test_sources_registry_contains_new_keyless_sources():
    for name in ("CertSpotter", "SubdomainCenter", "AlienVaultURLs"):
        assert name in main.SOURCES
        assert callable(main.SOURCES[name])
    # the keyless sources must still return data without any keys (not gated
    # behind a key early-return like the keyed sources).
    # The remaining working/valuable sources stay registered.
    for name in (
        "crt.sh", "HackerTarget", "AlienVault", "RapidDNS", "URLScan",
        "Wayback", "SecurityTrails", "Shodan", "c99",
    ):
        assert name in main.SOURCES


def test_sources_registry_excludes_dead_sources():
    # Chronically-dead sources were removed so the per-source status table
    # stops showing permanent failures. They must NOT reappear in the registry.
    for name in ("BufferOver", "ThreatMiner", "CommonCrawl", "ThreatCrowd", "Anubis"):
        assert name not in main.SOURCES
    # and their fetchers are gone from the module entirely.
    for attr in ("query_bufferover", "query_threatminer", "query_commoncrawl",
                 "query_threatcrowd", "query_anubis"):
        assert not hasattr(main, attr)


# ---------------------------------------------------------------------------
# _get retry-on-transient-failure (FIX 1) — all HTTP mocked + sleep patched
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Make retry backoff instantaneous and deterministic for the whole module."""
    async def _instant(_delay):
        return None
    monkeypatch.setattr(main.asyncio, "sleep", _instant)


@respx.mock
async def test_get_retries_502_then_succeeds(client):
    route = respx.get("https://crt.sh/retry502").mock(
        side_effect=[
            httpx.Response(502, text="bad gateway"),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    resp = await main._get(client, "https://crt.sh/retry502")
    assert resp.status_code == 200
    assert route.call_count == 2  # one retry after the 502


@respx.mock
async def test_get_does_not_retry_403(client):
    route = respx.get("https://crt.sh/forbidden").mock(
        return_value=httpx.Response(403, text="nope")
    )
    with pytest.raises(main.SourceUnavailable):
        await main._get(client, "https://crt.sh/forbidden")
    assert route.call_count == 1  # 403 is definitive — NOT retried


@respx.mock
async def test_get_does_not_retry_530(client):
    route = respx.get("https://crt.sh/down").mock(
        return_value=httpx.Response(530, text="origin down")
    )
    with pytest.raises(main.SourceUnavailable):
        await main._get(client, "https://crt.sh/down")
    assert route.call_count == 1


@respx.mock
async def test_get_429_honors_retry_after_then_succeeds(client, monkeypatch):
    seen = []

    async def _record(delay):
        seen.append(delay)

    monkeypatch.setattr(main.asyncio, "sleep", _record)
    route = respx.get("https://crt.sh/ratelimited").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "2"}),
            httpx.Response(200, json=[]),
        ]
    )
    resp = await main._get(client, "https://crt.sh/ratelimited")
    assert resp.status_code == 200
    assert route.call_count == 2
    # The numeric Retry-After (2s) was honored (clamped to the backoff cap).
    assert seen and seen[0] == 2.0


@respx.mock
async def test_get_timeout_then_succeeds(client):
    route = respx.get("https://crt.sh/timeout").mock(
        side_effect=[
            httpx.ConnectTimeout("slow"),
            httpx.Response(200, json=[]),
        ]
    )
    resp = await main._get(client, "https://crt.sh/timeout")
    assert resp.status_code == 200
    assert route.call_count == 2


@respx.mock
async def test_get_persistent_502_exhausts_and_raises(client):
    route = respx.get("https://crt.sh/always502").mock(
        return_value=httpx.Response(502, text="bad gateway")
    )
    with pytest.raises(main.SourceUnavailable):
        await main._get(client, "https://crt.sh/always502")
    assert route.call_count == main.SOURCE_RETRY_ATTEMPTS


# ---------------------------------------------------------------------------
# query_crtsh resilience (FIX 1)
# ---------------------------------------------------------------------------
@respx.mock
async def test_crtsh_502_then_200_recovers_and_parses(client):
    respx.get("https://crt.sh/").mock(
        side_effect=[
            httpx.Response(502, text="<html>502</html>"),
            httpx.Response(
                200,
                json=[
                    {"name_value": "a.example.com\n*.example.com",
                     "common_name": "cn.example.com"},
                ],
            ),
        ]
    )
    out = await main.query_crtsh(client, DOMAIN, {})
    assert out == {"a.example.com", "example.com", "cn.example.com"}


@respx.mock
async def test_crtsh_persistent_502_raises_source_unavailable(client):
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(502, text="x"))
    with pytest.raises(main.SourceUnavailable):
        await main.query_crtsh(client, DOMAIN, {})


@respx.mock
async def test_crtsh_persistent_html_body_raises_source_unavailable(client):
    # 200 OK but HTML error page every time -> unusable -> marked error.
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, text="<html>error</html>")
    )
    with pytest.raises(main.SourceUnavailable):
        await main.query_crtsh(client, DOMAIN, {})


# ---------------------------------------------------------------------------
# New source parsers (FIX 2)
# ---------------------------------------------------------------------------
@respx.mock
async def test_certspotter_follows_pagination(client):
    # First page full (len==PAGE_HINT) -> follow ?after=<last id>; second page
    # short -> stop. Build a full first page of distinct in-scope hosts.
    first = [
        {"id": str(i), "dns_names": [f"h{i}.example.com"]}
        for i in range(main.CERTSPOTTER_PAGE_HINT)
    ]
    respx.get(
        "https://api.certspotter.com/v1/issuances",
        params={"after": str(main.CERTSPOTTER_PAGE_HINT - 1)},
    ).mock(
        return_value=httpx.Response(200, json=[{"id": "x", "dns_names": ["last.example.com"]}])
    )
    # The initial page (no ?after=) must be matched by a broader route; respx
    # matches the most specific route first, so register the catch-all last.
    respx.get("https://api.certspotter.com/v1/issuances").mock(
        return_value=httpx.Response(200, json=first)
    )
    out = await main.query_certspotter(client, DOMAIN, {})
    assert "last.example.com" in out
    assert "h0.example.com" in out
    assert len(out) == main.CERTSPOTTER_PAGE_HINT + 1


@respx.mock
async def test_alienvault_urllist_parses_hostnames(client):
    respx.get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{DOMAIN}/url_list"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "has_next": False,
                "url_list": [
                    {"hostname": "a.example.com"},
                    {"hostname": "b.example.com"},
                    {"hostname": "out.org"},
                ],
            },
        )
    )
    out = await main.query_alienvault_urllist(client, DOMAIN, {})
    assert out == {"a.example.com", "b.example.com"}


# ---------------------------------------------------------------------------
# run_enumeration resilience (FIX 1/2): several dead sources don't zero the run
# ---------------------------------------------------------------------------
@respx.mock
async def test_run_enumeration_union_survives_several_dead_sources(monkeypatch):
    """When MULTIPLE passive sources error (transient 502, non-transient 403,
    and a connect error), the job still COMPLETES and the results are the UNION
    of the working sources — one dead source never zeroes the run. The erroring
    sources are reflected in source_statuses."""
    # Stub DNS/HTTP so the per-subdomain analysis does no real I/O (offline).
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
    main.JOBS.clear()

    # Two healthy sources with an overlapping host (prove dedup/union).
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(
            200, json=[{"name_value": "a.example.com\nshared.example.com"}]
        )
    )
    respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(
            200, text="b.example.com,1.1.1.1\nshared.example.com,2.2.2.2"
        )
    )
    # Dead sources: a non-transient 403 and a persistent 502 (retries exhaust).
    respx.route(host="urlscan.io").mock(return_value=httpx.Response(403))
    respx.route(host="rapiddns.io").mock(return_value=httpx.Response(502))
    # Everything else responds benignly-empty so it is 'done' with 0 hosts.
    respx.route().mock(return_value=httpx.Response(200, json={}))

    client = httpx.AsyncClient()
    main.app.state.client = client
    main.app.state.probe_client = client
    main.JOBS["ju"] = main.JobState(job_id="ju", domain="example.com")
    try:
        await main.run_enumeration("ju", "example.com", {})
    finally:
        await client.aclose()

    job = main.JOBS["ju"]
    assert job.status == "done"
    assert job.progress == 100
    subs = {r["subdomain"] for r in job.results}
    assert subs == {"a.example.com", "b.example.com", "shared.example.com"}
    assert job.source_statuses["crt.sh"] == "done"
    assert job.source_statuses["HackerTarget"] == "done"
    assert job.source_statuses["URLScan"] == "error"  # 403 non-transient
    assert job.source_statuses["RapidDNS"] == "error"  # persistent 502
