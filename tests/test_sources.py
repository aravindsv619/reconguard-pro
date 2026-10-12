"""Tests for the 11 data-source parsers in main.py.

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
async def test_threatcrowd_subdomains(client):
    respx.get("https://www.threatcrowd.org/searchApi/v2/domain/report/").mock(
        return_value=httpx.Response(200, json={"subdomains": ["g.example.com", "h.example.com"]})
    )
    out = await main.query_threatcrowd(client, DOMAIN, {})
    assert out == {"g.example.com", "h.example.com"}


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


@respx.mock
async def test_anubis_list(client):
    respx.get(f"https://jldc.me/anubis/subdomains/{DOMAIN}").mock(
        return_value=httpx.Response(200, json=["k.example.com", "l.example.com"])
    )
    out = await main.query_anubis(client, DOMAIN, {})
    assert out == {"k.example.com", "l.example.com"}


@respx.mock
async def test_bufferover_results(client):
    respx.get("https://tls.bufferover.run/dns").mock(
        return_value=httpx.Response(
            200, json={"Results": ["1.2.3.4,m.example.com", "5.6.7.8,n.example.com"]}
        )
    )
    out = await main.query_bufferover(client, DOMAIN, {})
    assert out == {"m.example.com", "n.example.com"}


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


@respx.mock
async def test_source_failure_returns_empty_not_raises(client):
    respx.get("https://crt.sh/").mock(side_effect=httpx.ConnectError("boom"))
    out = await main.query_crtsh(client, DOMAIN, {})
    assert out == set()
