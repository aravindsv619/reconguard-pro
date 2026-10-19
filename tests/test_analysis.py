"""Tests for the per-subdomain analysis helpers in main.py.

Covers the three check_takeover branches (HIGH on CNAME + body, LOW on
service-match-only, NONE on clean), plus the A-record PTR matching path and
the CNAME socket fallback.
"""

import httpx
import respx

import main


def test_takeover_high_cname_and_body():
    risk, service, detail = main.check_takeover(
        subdomain="foo.example.com",
        cname="foo.github.io",
        a_records=[],
        http_body="Oops! There isn't a GitHub Pages site here.",
        ptr_hosts=[],
    )
    assert risk == "HIGH"
    assert service == "GitHub Pages"
    assert "GitHub Pages" in detail


def test_takeover_low_service_match_without_body():
    risk, service, detail = main.check_takeover(
        subdomain="foo.example.com",
        cname="foo.github.io",
        a_records=[],
        http_body="totally unrelated content",
        ptr_hosts=[],
    )
    assert risk == "LOW"
    assert service == "GitHub Pages"
    assert "no takeover fingerprint confirmed" in detail


def test_takeover_none_when_clean():
    risk, service, detail = main.check_takeover(
        subdomain="foo.example.com",
        cname="foo.example.com",
        a_records=["1.2.3.4"],
        http_body="normal site",
        ptr_hosts=["host.example.com"],
    )
    assert risk == "NONE"
    assert service is None
    assert detail is None


def test_takeover_a_record_ptr_match_high():
    # No CNAME, no service in the name — only the A-record PTR reveals the service.
    risk, service, detail = main.check_takeover(
        subdomain="foo.example.com",
        cname=None,
        a_records=["52.1.2.3"],
        http_body="NoSuchBucket",
        ptr_hosts=["s3-website.s3.amazonaws.com"],
    )
    assert risk == "HIGH"
    assert service == "AWS S3"


def test_takeover_a_record_ptr_match_low_without_body():
    risk, service, detail = main.check_takeover(
        subdomain="foo.example.com",
        cname=None,
        a_records=["52.1.2.3"],
        http_body="",
        ptr_hosts=["s3-website.s3.amazonaws.com"],
    )
    assert risk == "LOW"
    assert service == "AWS S3"
    assert "A-record" in detail


def test_takeover_subdomain_name_endswith_key():
    risk, service, _ = main.check_takeover(
        subdomain="victim.herokuapp.com",
        cname=None,
        a_records=[],
        http_body="No such app",
        ptr_hosts=[],
    )
    assert risk == "HIGH"
    assert service == "Heroku"


# ---------------------------------------------------------------------------
# Dot-boundary host matching: attacker-controlled LOOKALIKE hosts that merely
# CONTAIN a provider domain as a substring must NOT be classified as that
# provider. This proves the fix for the "incomplete URL substring
# sanitization" alerts and keeps the match strictly on a DNS-label boundary.
# ---------------------------------------------------------------------------
def test_takeover_lookalike_cname_not_matched():
    # "s3.amazonaws.com.evil.com" ends with ".evil.com", not a real S3 host.
    risk, service, detail = main.check_takeover(
        subdomain="foo.example.com",
        cname="bucket.s3.amazonaws.com.evil.com",
        a_records=[],
        http_body="NoSuchBucket",
        ptr_hosts=[],
    )
    assert risk == "NONE"
    assert service is None
    assert detail is None


def test_takeover_lookalike_name_prefix_not_matched():
    # "evil-s3.amazonaws.com" is a different registrable domain (evil-s3…),
    # and "notcloudfront.net" is not cloudfront.net — neither may match.
    risk, service, _ = main.check_takeover(
        subdomain="victim.notcloudfront.net",
        cname="edge.notcloudfront.net",
        a_records=[],
        http_body="Bad request",
        ptr_hosts=[],
    )
    assert risk == "NONE"
    assert service is None


def test_match_cloud_resource_rejects_lookalikes():
    # Legitimate targets still match.
    assert main._match_cloud_resource("bucket.s3.amazonaws.com") == "AWS S3"
    assert main._match_cloud_resource("d123.cloudfront.net") == "AWS CloudFront"
    assert (
        main._match_cloud_resource("lb.us-east-1.elb.amazonaws.com") == "AWS ELB"
    )
    # Lookalikes must NOT match.
    assert main._match_cloud_resource("d123.cloudfront.net.evil.com") is None
    assert main._match_cloud_resource("notcloudfront.net") is None
    assert main._match_cloud_resource("bucket.s3.amazonaws.com.attacker.net") is None
    assert main._match_cloud_resource("evilcloudfront.net") is None


def test_host_matches_fingerprint_dot_boundary():
    # Exact host and true subdomains match.
    assert main._host_matches_fingerprint("cloudfront.net", "cloudfront.net")
    assert main._host_matches_fingerprint("d1.cloudfront.net", "cloudfront.net")
    # Trailing dot (dig output) is tolerated.
    assert main._host_matches_fingerprint("d1.cloudfront.net.", "cloudfront.net")
    # Lookalikes do NOT match.
    assert not main._host_matches_fingerprint("notcloudfront.net", "cloudfront.net")
    assert not main._host_matches_fingerprint(
        "cloudfront.net.evil.com", "cloudfront.net"
    )
    # Dotless AWS label token matches only on a label boundary.
    assert main._host_matches_fingerprint(
        "bucket.s3-website-us-east-1.amazonaws.com", "s3-website"
    )
    assert not main._host_matches_fingerprint(
        "bucket.evils3-website.amazonaws.com", "s3-website"
    )


def test_normalize_host_filters_and_strips():
    assert main._normalize_host("*.example.com", "example.com") == "example.com"
    assert main._normalize_host("A.Example.COM.", "example.com") == "a.example.com"
    assert main._normalize_host("other.org", "example.com") is None
    assert main._normalize_host("bad *.example.com", "example.com") is None


def test_socket_cname_fallback(monkeypatch):
    # dig unavailable → socket fallback supplies the canonical name.
    monkeypatch.setattr(main, "_dig_cname", lambda host: None)
    monkeypatch.setattr(
        main.socket,
        "gethostbyname_ex",
        lambda host: ("real-target.github.io", [], ["1.2.3.4"]),
    )
    assert main._resolve_cname_sync("foo.example.com") == "real-target.github.io"


def test_socket_cname_fallback_same_host_returns_none(monkeypatch):
    monkeypatch.setattr(main, "_dig_cname", lambda host: None)
    monkeypatch.setattr(
        main.socket,
        "gethostbyname_ex",
        lambda host: ("foo.example.com", [], ["1.2.3.4"]),
    )
    assert main._resolve_cname_sync("foo.example.com") is None


@respx.mock
async def test_check_http_probes_both_schemes():
    # DNS-rebinding fix: check_http now connects to the PINNED IP (the URL
    # authority is the IP) while the original hostname is kept as the Host
    # header. Mock by the IP URL and assert the Host header is preserved.
    pinned_ip = "93.184.216.34"
    http_route = respx.get(f"http://{pinned_ip}").mock(
        return_value=httpx.Response(200, text="hi")
    )
    https_route = respx.get(f"https://{pinned_ip}").mock(
        return_value=httpx.Response(404, text="nope")
    )
    async with httpx.AsyncClient() as c:
        http_status, https_status, body = await main.check_http(
            c, "foo.example.com", pinned_ip=pinned_ip
        )
    assert http_status == 200
    assert https_status == 404
    assert "hi" in body and "nope" in body
    # The connection address is the validated IP; the Host header is the
    # original hostname so virtual-hosted sites still resolve correctly.
    assert http_route.called and https_route.called
    assert http_route.calls.last.request.headers["Host"] == "foo.example.com"
    assert http_route.calls.last.request.url.host == pinned_ip


@respx.mock
async def test_check_http_never_probes_without_pinned_ip():
    # Defense in depth: with no pinned IP, check_http must NOT hand the hostname
    # to httpx for independent resolution — it returns empties and makes no call.
    route = respx.route().mock(return_value=httpx.Response(200, text="should-not-happen"))
    async with httpx.AsyncClient() as c:
        http_status, https_status, body = await main.check_http(c, "foo.example.com")
    assert (http_status, https_status, body) == (None, None, "")
    assert not route.called


@respx.mock
async def test_check_http_skips_private_pinned_ip():
    # Even if a private IP is somehow passed as pinned, the in-function
    # _is_safe_public_ip re-check blocks the connection (SSRF regression).
    route = respx.route().mock(return_value=httpx.Response(200, text="should-not-happen"))
    async with httpx.AsyncClient() as c:
        out = await main.check_http(c, "evil.example.com", pinned_ip="169.254.169.254")
    assert out == (None, None, "")
    assert not route.called


# ---------------------------------------------------------------------------
# DNS-rebinding TOCTOU: the probe pins the validated public IP and never
# reaches a private/metadata IP that a second resolution might return.
# ---------------------------------------------------------------------------
@respx.mock
async def test_rebinding_probe_pins_validated_public_ip(monkeypatch):
    # The GUARD resolution returns a PUBLIC IP. A simulated SECOND resolution
    # (what httpx would do at connect time) would return a PRIVATE/metadata IP.
    # With IP-pinning the probe must connect to the PUBLIC IP only; the private
    # address must never be contacted.
    public_ip = "93.184.216.34"
    private_ip = "169.254.169.254"

    async def fake_resolve_dns_detailed(host):
        # Guard check sees only the safe public IP.
        return [public_ip], "RESOLVED"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", lambda h: __import_awaitable([]))
    monkeypatch.setattr(main, "resolve_cname", lambda h: __import_awaitable(None))
    monkeypatch.setattr(main, "resolve_dns_records", lambda h: __import_awaitable({}))
    monkeypatch.setattr(main, "_resolve_ptrs", lambda ips: __import_awaitable([]))

    public_route = respx.get(f"http://{public_ip}").mock(
        return_value=httpx.Response(200, text="live")
    )
    respx.get(f"https://{public_ip}").mock(return_value=httpx.Response(200, text="live"))
    # Any request to the private IP must NEVER happen.
    private_route = respx.route(host=private_ip).mock(
        return_value=httpx.Response(200, text="SHOULD-NOT-BE-REACHED")
    )

    async with httpx.AsyncClient() as c:
        res = await main.analyze_subdomain(c, "target.example.com", ["src"], main.asyncio.Semaphore(5))

    # Probe connected to the pinned public IP with the hostname preserved.
    assert public_route.called
    assert public_route.calls.last.request.headers["Host"] == "target.example.com"
    # The private/metadata IP was never contacted.
    assert not private_route.called
    assert res["http_status"] == 200


@respx.mock
async def test_rebinding_private_only_host_never_probed(monkeypatch):
    # A host resolving ONLY to a private IP must never be probed (SSRF guard
    # regression still holds after the pinning refactor).
    async def fake_resolve_dns_detailed(host):
        return ["10.0.0.5"], "RESOLVED"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", lambda h: __import_awaitable([]))
    monkeypatch.setattr(main, "resolve_cname", lambda h: __import_awaitable(None))
    monkeypatch.setattr(main, "resolve_dns_records", lambda h: __import_awaitable({}))
    monkeypatch.setattr(main, "_resolve_ptrs", lambda ips: __import_awaitable([]))

    route = respx.route().mock(return_value=httpx.Response(200, text="should-not-happen"))

    async with httpx.AsyncClient() as c:
        res = await main.analyze_subdomain(c, "internal.example.com", ["src"], main.asyncio.Semaphore(5))

    assert not route.called
    assert res["http_status"] is None and res["https_status"] is None


def __import_awaitable(value):
    """Tiny helper: wrap a plain value in an awaitable for monkeypatched async
    functions (so lambdas can stand in for `async def`)."""
    async def _coro():
        return value

    return _coro()
