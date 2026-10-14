"""Tests for the active takeover-VERIFICATION pass (FEAT-001).

verify_takeover turns the heuristic VERIFY/HIGH tier into a concrete verdict
(VULNERABLE / NOT_VULNERABLE / INCONCLUSIVE) with human-readable evidence. It
reuses the exact security invariants of analyze_subdomain: every target fetch
routes through probe_client behind the _is_safe_public_ip SSRF guard, bounded
by the passed Semaphore, and it NEVER raises (errors -> INCONCLUSIVE).

All DNS/HTTP I/O is monkeypatched / respx-mocked so the suite stays offline and
deterministic (same patterns as tests/test_active.py).
"""

import asyncio
import socket

import httpx
import pytest
import respx

import main


@pytest.fixture(autouse=True)
def clear_jobs():
    main.JOBS.clear()
    yield
    main.JOBS.clear()


def _result(risk="VERIFY", cname=None, chain=None):
    return main.SubdomainResult(
        subdomain="svc.example.com",
        ip_addresses=[],
        cname=cname,
        http_status=None,
        https_status=None,
        sources=["crt.sh"],
        takeover_risk=risk,
        takeover_service=None,
        takeover_detail=None,
        takeover_verdict="",
        takeover_evidence="",
        resolved=False,
        alive=False,
        dns_status="NO_ANSWER",
        cname_chain=chain if chain is not None else ([cname] if cname else []),
    )


# ---------------------------------------------------------------------------
# (a) ELB target that still RESOLVES -> NOT_VULNERABLE
# ---------------------------------------------------------------------------
@respx.mock
async def test_elb_target_resolves_not_vulnerable(monkeypatch):
    # Probe would 503 (no healthy targets) but the ELB name still resolves.
    respx.route().mock(return_value=httpx.Response(503, text="no healthy targets"))

    async def fake_resolve_dns_detailed(host):
        # The ELB target still resolves to a public IP.
        return ["52.1.2.3"], "RESOLVED"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)

    client = httpx.AsyncClient()
    try:
        out = await main.verify_takeover(
            _result(cname="internal-lb.us-east-1.elb.amazonaws.com"),
            client,
            asyncio.Semaphore(5),
        )
    finally:
        await client.aclose()

    assert out["verdict"] == "NOT_VULNERABLE"
    ev = out["evidence"].lower()
    assert "elb" in ev
    # Evidence must explain ELB names are not attacker-claimable.
    assert "not" in ev and ("choosable" in ev or "claimable" in ev)


# ---------------------------------------------------------------------------
# (a2) ELB target with a TRAILING DOT still resolves -> NOT_VULNERABLE.
# Proves verify_takeover strips the trailing dot before resolving; a raw
# dotted name would otherwise fail to resolve and never hit NOT_VULNERABLE.
# ---------------------------------------------------------------------------
@respx.mock
async def test_elb_trailing_dot_target_resolves_not_vulnerable(monkeypatch):
    respx.route().mock(return_value=httpx.Response(503, text="no healthy targets"))

    seen = {"host": None}

    async def fake_resolve_dns_detailed(host):
        seen["host"] = host
        # Only resolve the trailing-dot-STRIPPED name; a raw dotted name does not.
        if host.endswith("."):
            return [], "NXDOMAIN"
        return ["52.1.2.3"], "RESOLVED"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)

    client = httpx.AsyncClient()
    try:
        out = await main.verify_takeover(
            _result(cname="internal-lb.us-east-1.elb.amazonaws.com."),
            client,
            asyncio.Semaphore(5),
        )
    finally:
        await client.aclose()

    assert out["verdict"] == "NOT_VULNERABLE"
    # The resolver was called with the trailing dot stripped.
    assert seen["host"] == "internal-lb.us-east-1.elb.amazonaws.com"


# ---------------------------------------------------------------------------
# (f) CloudFront no-distribution signature -> VULNERABLE
# ---------------------------------------------------------------------------
@respx.mock
async def test_cloudfront_no_distribution_signature_vulnerable(monkeypatch):
    respx.route().mock(
        return_value=httpx.Response(403, text="ERROR: The request could not be satisfied.")
    )

    async def fake_resolve_dns_detailed(host):
        return ["13.33.1.2"], "RESOLVED"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)

    client = httpx.AsyncClient()
    try:
        out = await main.verify_takeover(
            _result(cname="d123abc.cloudfront.net"),
            client,
            asyncio.Semaphore(5),
        )
    finally:
        await client.aclose()

    assert out["verdict"] == "VULNERABLE"
    assert "cloudfront" in out["evidence"].lower()


# CloudFront healthy 200 -> NOT_VULNERABLE
@respx.mock
async def test_cloudfront_healthy_not_vulnerable(monkeypatch):
    respx.route().mock(return_value=httpx.Response(200, text="ok"))

    async def fake_resolve_dns_detailed(host):
        return ["13.33.1.2"], "RESOLVED"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)

    client = httpx.AsyncClient()
    try:
        out = await main.verify_takeover(
            _result(cname="d123abc.cloudfront.net"),
            client,
            asyncio.Semaphore(5),
        )
    finally:
        await client.aclose()

    assert out["verdict"] == "NOT_VULNERABLE"


# CloudFront bare 403 WITHOUT the no-distribution signature -> INCONCLUSIVE
# (no false positive on a plain 403).
@respx.mock
async def test_cloudfront_bare_403_inconclusive(monkeypatch):
    respx.route().mock(return_value=httpx.Response(403, text="Forbidden"))

    async def fake_resolve_dns_detailed(host):
        return ["13.33.1.2"], "RESOLVED"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)

    client = httpx.AsyncClient()
    try:
        out = await main.verify_takeover(
            _result(cname="d123abc.cloudfront.net"),
            client,
            asyncio.Semaphore(5),
        )
    finally:
        await client.aclose()

    assert out["verdict"] == "INCONCLUSIVE"


# CloudFront timeout (no status) -> INCONCLUSIVE with a recommended action.
async def test_cloudfront_timeout_inconclusive(monkeypatch):
    async def fake_resolve_dns_detailed(host):
        return ["13.33.1.2"], "RESOLVED"

    async def fake_check_http(client, host):
        # Simulate a timeout: no status obtained from either scheme.
        return None, None, ""

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "check_http", fake_check_http)

    out = await main.verify_takeover(
        _result(cname="d123abc.cloudfront.net"),
        None,
        asyncio.Semaphore(5),
    )
    assert out["verdict"] == "INCONCLUSIVE"
    assert "cloudfront" in out["evidence"].lower()


# CloudFront VULNERABLE through analyze_subdomain promotes VERIFY -> HIGH.
async def test_analyze_subdomain_cloudfront_promoted_to_high(monkeypatch):
    async def fake_resolve_dns_detailed(host):
        return ["13.33.1.2"], "RESOLVED"

    async def fake_resolve_cname_chain(host):
        return ["d123abc.cloudfront.net"]

    async def fake_resolve_cname(host):
        return "d123abc.cloudfront.net"

    async def fake_resolve_ptrs(ips):
        return []

    async def fake_check_http(client, host):
        # Subdomain probe: 503 no body -> VERIFY tier. CloudFront target probe:
        # no-distribution signature -> VULNERABLE in the verify pass.
        if host.endswith("cloudfront.net"):
            return 403, None, "ERROR: The request could not be satisfied."
        return 503, None, ""

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)
    monkeypatch.setattr(main, "check_http", fake_check_http)

    res = await main.analyze_subdomain(
        None, "cdn.example.com", ["crt.sh"], asyncio.Semaphore(5)
    )

    assert res["takeover_verdict"] == "VULNERABLE"
    assert res["takeover_risk"] == "HIGH"
    # recommended_action must be populated for a VULNERABLE row.
    assert res["recommended_action"]
    assert "remove" in res["recommended_action"].lower() or "reclaim" in res["recommended_action"].lower()


# recommended_action is populated per verdict class for flagged rows.
async def test_recommended_action_populated_per_verdict_class(monkeypatch):
    async def fake_resolve_dns_detailed(host):
        return ["13.33.1.2"], "RESOLVED"

    async def fake_resolve_cname_chain(host):
        return ["d123abc.cloudfront.net"]

    async def fake_resolve_cname(host):
        return "d123abc.cloudfront.net"

    async def fake_resolve_ptrs(ips):
        return []

    async def fake_check_http(client, host):
        # CloudFront bare 403 (no signature) -> INCONCLUSIVE; subdomain 503 -> VERIFY.
        if host.endswith("cloudfront.net"):
            return 403, None, "Forbidden"
        return 503, None, ""

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)
    monkeypatch.setattr(main, "check_http", fake_check_http)

    res = await main.analyze_subdomain(
        None, "cdn.example.com", ["crt.sh"], asyncio.Semaphore(5)
    )

    # INCONCLUSIVE verdict must STILL carry a concrete next step (no dead end).
    assert res["takeover_verdict"] == "INCONCLUSIVE"
    assert res["recommended_action"]


def test_recommended_action_helper_covers_every_verdict_class():
    # Pure-helper coverage: each verdict class yields a non-empty action; a
    # non-flagged row yields ''.
    assert main._recommended_action("HIGH", main.VERDICT_VULNERABLE, "AWS CloudFront")
    assert main._recommended_action("VERIFY", main.VERDICT_NOT_VULNERABLE, "AWS ELB")
    assert main._recommended_action("VERIFY", main.VERDICT_INCONCLUSIVE, "AWS S3")
    assert main._recommended_action("VERIFY", "", None)  # flagged, no verdict yet
    assert main._recommended_action("NONE", "", None) == ""


# ---------------------------------------------------------------------------
# (b) GitHub Pages "no site here" body -> VULNERABLE
# ---------------------------------------------------------------------------
@respx.mock
async def test_github_pages_no_site_vulnerable(monkeypatch):
    respx.route().mock(
        return_value=httpx.Response(
            404, text="There isn't a GitHub Pages site here."
        )
    )

    async def fake_resolve_dns_detailed(host):
        return ["185.199.108.153"], "RESOLVED"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)

    client = httpx.AsyncClient()
    try:
        out = await main.verify_takeover(
            _result(risk="HIGH", cname="user.github.io"),
            client,
            asyncio.Semaphore(5),
        )
    finally:
        await client.aclose()

    assert out["verdict"] == "VULNERABLE"
    assert "github pages" in out["evidence"].lower()


# ---------------------------------------------------------------------------
# (c) S3 NoSuchBucket -> VULNERABLE; S3 200 listing -> NOT_VULNERABLE
# ---------------------------------------------------------------------------
@respx.mock
async def test_s3_nosuchbucket_vulnerable(monkeypatch):
    respx.route().mock(
        return_value=httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")
    )

    async def fake_resolve_dns_detailed(host):
        return ["52.216.1.1"], "RESOLVED"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)

    client = httpx.AsyncClient()
    try:
        out = await main.verify_takeover(
            _result(cname="bucket.s3.amazonaws.com"),
            client,
            asyncio.Semaphore(5),
        )
    finally:
        await client.aclose()

    assert out["verdict"] == "VULNERABLE"
    assert "s3" in out["evidence"].lower()


@respx.mock
async def test_s3_200_listing_not_vulnerable(monkeypatch):
    respx.route().mock(
        return_value=httpx.Response(200, text="<ListBucketResult>...</ListBucketResult>")
    )

    async def fake_resolve_dns_detailed(host):
        return ["52.216.1.1"], "RESOLVED"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)

    client = httpx.AsyncClient()
    try:
        out = await main.verify_takeover(
            _result(cname="bucket.s3.amazonaws.com"),
            client,
            asyncio.Semaphore(5),
        )
    finally:
        await client.aclose()

    assert out["verdict"] == "NOT_VULNERABLE"


# ---------------------------------------------------------------------------
# (d) SSRF regression: target resolves to a private IP -> no probe, INCONCLUSIVE
# ---------------------------------------------------------------------------
@respx.mock
async def test_private_ip_target_never_probed(monkeypatch):
    probe_called = {"n": 0}

    def _route(request):
        probe_called["n"] += 1
        return httpx.Response(200, text="should-not-happen")

    respx.route().mock(side_effect=_route)

    async def fake_resolve_dns_detailed(host):
        # Target resolves ONLY to private/metadata addresses.
        return ["127.0.0.1", "169.254.169.254"], "RESOLVED"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)

    client = httpx.AsyncClient()
    try:
        out = await main.verify_takeover(
            _result(cname="bucket.s3.amazonaws.com"),
            client,
            asyncio.Semaphore(5),
        )
    finally:
        await client.aclose()

    assert probe_called["n"] == 0
    assert out["verdict"] == "INCONCLUSIVE"
    assert "ssrf" in out["evidence"].lower()


# ---------------------------------------------------------------------------
# verify_takeover never raises: a resolver blowing up yields INCONCLUSIVE.
# ---------------------------------------------------------------------------
async def test_verify_never_raises(monkeypatch):
    async def boom(host):
        raise RuntimeError("resolver exploded")

    monkeypatch.setattr(main, "resolve_dns_detailed", boom)

    out = await main.verify_takeover(
        _result(cname="bucket.s3.amazonaws.com"),
        None,
        asyncio.Semaphore(5),
    )
    assert out["verdict"] == "INCONCLUSIVE"


# Non-flagged risk gets an empty verdict without any resolution/probe.
async def test_non_flagged_risk_empty_verdict():
    out = await main.verify_takeover(
        _result(risk="LOW", cname="bucket.s3.amazonaws.com"),
        None,
        asyncio.Semaphore(5),
    )
    assert out == {"verdict": "", "evidence": ""}


# ---------------------------------------------------------------------------
# (e) via analyze_subdomain: a non-flagged subdomain gets empty verdict/evidence
# ---------------------------------------------------------------------------
@respx.mock
async def test_analyze_subdomain_non_flagged_empty_verdict(monkeypatch):
    respx.route().mock(return_value=httpx.Response(200, text="welcome"))

    async def fake_resolve_dns_detailed(host):
        return ["93.184.216.34"], "RESOLVED"

    async def fake_resolve_cname_chain(host):
        return []

    async def fake_resolve_cname(host):
        return None

    async def fake_check_http(client, host):
        return 200, 200, "welcome"

    async def fake_resolve_ptrs(ips):
        return []

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)

    client = httpx.AsyncClient()
    try:
        res = await main.analyze_subdomain(
            client, "www.example.com", ["crt.sh"], asyncio.Semaphore(5)
        )
    finally:
        await client.aclose()

    assert res["takeover_risk"] == "NONE"
    assert res["takeover_verdict"] == ""
    assert res["takeover_evidence"] == ""


# A flagged (VERIFY) subdomain through analyze_subdomain gets a verdict set.
@respx.mock
async def test_analyze_subdomain_flagged_gets_verdict(monkeypatch):
    # Dangling S3 CNAME: the subdomain probe is skipped (no public A record),
    # check_takeover returns VERIFY, then verify_takeover confirms VULNERABLE.
    respx.route().mock(
        return_value=httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")
    )

    async def fake_resolve_dns_detailed(host):
        # The subdomain itself has no A record (CNAME-only); the S3 target
        # resolves to a public IP so the verification probe runs.
        if host.endswith("s3.amazonaws.com"):
            return ["52.216.1.1"], "RESOLVED"
        return [], "NO_ANSWER"

    async def fake_resolve_cname_chain(host):
        return ["bucket.s3.amazonaws.com"]

    async def fake_resolve_cname(host):
        return "bucket.s3.amazonaws.com"

    async def fake_check_http(client, host):
        return None, 404, "<Error><Code>NoSuchBucket</Code></Error>"

    async def fake_resolve_ptrs(ips):
        return []

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "check_http", fake_check_http)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)

    client = httpx.AsyncClient()
    try:
        res = await main.analyze_subdomain(
            client, "svc.example.com", ["crt.sh"], asyncio.Semaphore(5)
        )
    finally:
        await client.aclose()

    # The S3 NoSuchBucket body makes check_takeover return HIGH directly, and
    # the active pass then confirms the VULNERABLE verdict.
    # The S3 NoSuchBucket body makes check_takeover return HIGH directly, and
    # the active pass then confirms the VULNERABLE verdict.
    assert res["takeover_verdict"] == "VULNERABLE"
    assert res["takeover_risk"] == "HIGH"
    assert "nosuchbucket" in res["takeover_evidence"].lower()


# A VERIFY-tier row promoted to HIGH when the active pass confirms VULNERABLE.
async def test_analyze_subdomain_verify_promoted_to_high(monkeypatch):
    async def fake_resolve_dns_detailed(host):
        # Subdomain resolves to a public IP (so it is probed), and the S3 target
        # also resolves to a public IP (so the verification pass probes it).
        return ["52.216.1.1"], "RESOLVED"

    async def fake_resolve_cname_chain(host):
        return ["bucket.s3.amazonaws.com"]

    async def fake_resolve_cname(host):
        return "bucket.s3.amazonaws.com"

    async def fake_resolve_ptrs(ips):
        return []

    async def fake_check_http(client, host):
        # Subdomain probe: 503 with no body -> no fingerprint -> VERIFY tier.
        # Target (S3) probe: NoSuchBucket -> VULNERABLE in the verify pass.
        if host.endswith("s3.amazonaws.com"):
            return None, 404, "<Error><Code>NoSuchBucket</Code></Error>"
        return 503, None, ""

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)
    monkeypatch.setattr(main, "check_http", fake_check_http)

    res = await main.analyze_subdomain(
        None, "svc.example.com", ["crt.sh"], asyncio.Semaphore(5)
    )

    # check_takeover returns VERIFY (503, no fingerprint); the active pass then
    # confirms VULNERABLE and promotes the row VERIFY -> HIGH.
    assert res["takeover_verdict"] == "VULNERABLE"
    assert res["takeover_risk"] == "HIGH"
    assert "promoted" in res["takeover_evidence"].lower()


# ===========================================================================
# BUG 1 — the empty-error ELB regression. These drive the ACTUAL exception path
# (RAISE), not a mocked response, so over-mocking cannot hide the bug again.
# A real keyless scan of example.com produced
# "Verification could not complete (error: )." for every resolving ELB target
# because asyncio.TimeoutError/socket.gaierror/httpx.ConnectError('') all have
# an EMPTY str() and the probe sat inside verify_takeover's outer try/except.
# ===========================================================================


# (a) A resolving ELB whose probe RAISES asyncio.TimeoutError must still reach
# the ELB branch and return NOT_VULNERABLE (verdict depends on DNS resolution,
# not on the bare HTTP probe the ELB refuses to answer).
async def test_elb_resolving_target_probe_times_out_not_vulnerable(monkeypatch):
    async def fake_resolve_dns_detailed(host):
        return ["52.1.2.3"], "RESOLVED"

    async def boom_check_http(client, host):
        # Realistic, EMPTY-message error — the exact class that produced the bug.
        raise asyncio.TimeoutError()

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "check_http", boom_check_http)

    out = await main.verify_takeover(
        _result(cname="app-abcdef0123456789.elb.us-east-1.amazonaws.com"),
        None,
        asyncio.Semaphore(5),
    )

    # The probe timeout must NOT block the DNS-based ELB verdict.
    assert out["verdict"] == "NOT_VULNERABLE"
    ev = out["evidence"].lower()
    assert "elb" in ev
    # And the evidence can never be the empty-error marker.
    assert "(error: )" not in out["evidence"]


# (b) For a provider whose verdict depends on the PROBE (CloudFront), a probe
# that RAISES socket.gaierror (also empty str()) must yield a NON-EMPTY evidence
# string that names the exception type — proving the empty-error cannot recur.
async def test_verify_probe_error_evidence_is_non_empty(monkeypatch):
    async def fake_resolve_dns_detailed(host):
        return ["13.33.1.2"], "RESOLVED"

    async def boom_check_http(client, host):
        raise socket.gaierror()

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "check_http", boom_check_http)

    out = await main.verify_takeover(
        _result(cname="d123abc.cloudfront.net"),
        None,
        asyncio.Semaphore(5),
    )

    # No status obtained -> CloudFront INCONCLUSIVE, but the evidence must be
    # non-empty and carry the diagnosable probe-error (gaierror).
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["evidence"].strip() != ""
    assert "gaierror" in out["evidence"]
    assert "(error: )" not in out["evidence"]


# (c) When the OUTER work (DNS resolution) itself RAISES an empty-message error,
# the catch-all must record the exception type and never emit "(error: )".
async def test_outer_catchall_records_exception_type(monkeypatch):
    async def boom_resolve(host):
        raise asyncio.TimeoutError()

    monkeypatch.setattr(main, "resolve_dns_detailed", boom_resolve)

    out = await main.verify_takeover(
        _result(cname="svc.s3.amazonaws.com"),
        None,
        asyncio.Semaphore(5),
    )

    assert out["verdict"] == "INCONCLUSIVE"
    assert out["evidence"].strip() != ""
    assert "TimeoutError" in out["evidence"]
    assert "(error: )" not in out["evidence"]


# ELB target resolution ERROR (not NXDOMAIN) is handled WITHIN the ELB branch
# with a specific, retriable message — not the generic indeterminate case.
async def test_elb_resolution_error_specific_message(monkeypatch):
    async def fake_resolve_dns_detailed(host):
        return [], "TIMEOUT"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)

    out = await main.verify_takeover(
        _result(cname="internal-lb.us-east-1.elb.amazonaws.com"),
        None,
        asyncio.Semaphore(5),
    )

    assert out["verdict"] == "INCONCLUSIVE"
    ev = out["evidence"].lower()
    assert "resolution did not complete" in ev
    assert "timeout" in ev


# ===========================================================================
# BUG 2 — a dangling CNAME with NO A record on the subdomain must still be
# captured and verdicted. The subdomain is NXDOMAIN/NO_ANSWER for A/AAAA but
# CNAMEs to *.cloudfront.net; the record must be KEPT, matched as CloudFront,
# flagged VERIFY, then promoted to HIGH/VULNERABLE on the no-distribution body.
# ===========================================================================
async def test_dangling_cname_without_a_record_cloudfront_vulnerable(monkeypatch):
    async def fake_resolve_dns_detailed(host):
        # The CloudFront TARGET resolves; the SUBDOMAIN has NO A record.
        if host.endswith("cloudfront.net"):
            return ["13.33.1.2"], "RESOLVED"
        return [], "NXDOMAIN"

    async def fake_resolve_cname_chain(host):
        # dig CNAME-TYPE query still returns the CNAME RR despite no A record.
        return ["d123abc.cloudfront.net"]

    async def fake_resolve_cname(host):
        return "d123abc.cloudfront.net"

    async def fake_resolve_ptrs(ips):
        return []

    async def fake_check_http(client, host):
        # CloudFront no-distribution signature on the target probe.
        if host.endswith("cloudfront.net"):
            return 403, None, "ERROR: The request could not be satisfied."
        return None, None, ""

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)
    monkeypatch.setattr(main, "check_http", fake_check_http)

    res = await main.analyze_subdomain(
        None, "insuranext.example.com", ["crt.sh"], asyncio.Semaphore(5)
    )

    # The CNAME is KEPT even though the subdomain is NXDOMAIN for A/AAAA.
    assert res["cname"] == "d123abc.cloudfront.net"
    assert res["cname_chain"] == ["d123abc.cloudfront.net"]
    # It matches CloudFront and reaches a confirmed VULNERABLE verdict.
    assert main._match_cloud_resource(res["cname"]) == "AWS CloudFront"
    assert res["takeover_verdict"] == "VULNERABLE"
    assert res["takeover_risk"] == "HIGH"
    assert res["resolved"] is False  # no A record on the subdomain itself
    assert res["recommended_action"]


# The same capture rule applies GENERALLY: an A-less ELB CNAME is kept and
# verdicted (not CloudFront-only). A resolving ELB target -> NOT_VULNERABLE.
async def test_dangling_cname_without_a_record_elb_kept_and_verdicted(monkeypatch):
    async def fake_resolve_dns_detailed(host):
        if host.endswith("elb.amazonaws.com"):
            return ["52.1.2.3"], "RESOLVED"
        return [], "NO_ANSWER"

    async def fake_resolve_cname_chain(host):
        return ["internal-lb.us-east-1.elb.amazonaws.com"]

    async def fake_resolve_cname(host):
        return "internal-lb.us-east-1.elb.amazonaws.com"

    async def fake_resolve_ptrs(ips):
        return []

    async def boom_check_http(client, host):
        # The ELB target refuses the bare probe (empty-message timeout) and must
        # NOT swallow the verdict. The subdomain's own probe (no A record) just
        # returns no status.
        if host.endswith("elb.amazonaws.com"):
            raise asyncio.TimeoutError()
        return None, None, ""

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)
    monkeypatch.setattr(main, "check_http", boom_check_http)

    res = await main.analyze_subdomain(
        None, "svc.example.com", ["crt.sh"], asyncio.Semaphore(5)
    )

    assert res["cname"] == "internal-lb.us-east-1.elb.amazonaws.com"
    assert main._match_cloud_resource(res["cname"]) == "AWS ELB"
    # Resolving ELB target -> NOT_VULNERABLE, with no empty-error marker.
    assert res["takeover_verdict"] == "NOT_VULNERABLE"
    assert "(error: )" not in res["takeover_evidence"]


# ===========================================================================
# Regression — a normal A-record subdomain (no cloud CNAME) is unchanged.
# ===========================================================================
@respx.mock
async def test_normal_a_record_subdomain_unchanged(monkeypatch):
    respx.route().mock(return_value=httpx.Response(200, text="welcome"))

    async def fake_resolve_dns_detailed(host):
        return ["93.184.216.34"], "RESOLVED"

    async def fake_resolve_cname_chain(host):
        return []

    async def fake_resolve_cname(host):
        return None

    async def fake_resolve_ptrs(ips):
        return []

    async def fake_check_http(client, host):
        return 200, 200, "welcome"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)
    monkeypatch.setattr(main, "check_http", fake_check_http)

    client = httpx.AsyncClient()
    try:
        res = await main.analyze_subdomain(
            client, "www.example.com", ["crt.sh"], asyncio.Semaphore(5)
        )
    finally:
        await client.aclose()

    assert res["takeover_risk"] == "NONE"
    assert res["takeover_verdict"] == ""
    assert res["recommended_action"] == ""
    assert res["resolved"] is True
    assert res["alive"] is True


# ===========================================================================
# A-RECORD CloudFront — a host served DIRECTLY by CloudFront edge IPs (no
# *.cloudfront.net CNAME; the provider is identified from the edge IP's PTR)
# must NOT be dropped at LOW with an empty verdict. It is routed into
# verify_takeover, which probes the ALIAS (the subdomain) and renders a verdict.
# This is the live gap from the review (bimi.example.com): A-record-PTR
# CloudFront hits previously never reached verify_takeover.
# ===========================================================================
async def test_arecord_cloudfront_healthy_not_vulnerable(monkeypatch):
    # Healthy owned distribution: the alias (subdomain) answers 200. The host
    # has CloudFront A records (PTR identifies CloudFront) and NO CNAME.
    async def fake_resolve_dns_detailed(host):
        return ["93.184.216.34"], "RESOLVED"

    async def fake_resolve_cname_chain(host):
        return []

    async def fake_resolve_cname(host):
        return None

    async def fake_resolve_ptrs(ips):
        return ["server-93-184-216-34.maa51.r.cloudfront.net"]

    async def fake_check_http(client, host):
        return 200, 200, "welcome"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)
    monkeypatch.setattr(main, "check_http", fake_check_http)

    res = await main.analyze_subdomain(
        None, "bimi.example.com", ["crt.sh"], asyncio.Semaphore(5)
    )

    # Identified as CloudFront via the A-record PTR, flagged (not LOW), and
    # routed into verify_takeover which sets a concrete verdict (NOT empty).
    assert res["takeover_service"] == "AWS CloudFront"
    assert res["takeover_risk"] == "VERIFY"
    assert res["takeover_verdict"] == "NOT_VULNERABLE"
    assert res["takeover_evidence"]
    assert res["recommended_action"]


async def test_arecord_cloudfront_unclaimed_alias_vulnerable(monkeypatch):
    # The alias is NOT claimed by any distribution: probing the subdomain
    # returns the CloudFront no-distribution signature -> VULNERABLE, HIGH.
    async def fake_resolve_dns_detailed(host):
        return ["93.184.216.34"], "RESOLVED"

    async def fake_resolve_cname_chain(host):
        return []

    async def fake_resolve_cname(host):
        return None

    async def fake_resolve_ptrs(ips):
        return ["server-93-184-216-34.maa51.r.cloudfront.net"]

    async def fake_check_http(client, host):
        return 403, None, "ERROR: The request could not be satisfied."

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)
    monkeypatch.setattr(main, "check_http", fake_check_http)

    res = await main.analyze_subdomain(
        None, "bimi.example.com", ["crt.sh"], asyncio.Semaphore(5)
    )

    assert res["takeover_service"] == "AWS CloudFront"
    assert res["takeover_verdict"] == "VULNERABLE"
    assert res["takeover_risk"] == "HIGH"
    assert res["recommended_action"]


def test_check_takeover_arecord_cloudfront_ptr_is_verify():
    # A CloudFront A-record PTR (no CNAME) is routed to VERIFY so a verdict can
    # be rendered. An S3 A-record PTR without a body stays LOW (unchanged) —
    # only CloudFront's alias is verifiably claimable from an A-record hit.
    risk, service, detail = main.check_takeover(
        subdomain="bimi.example.com",
        cname=None,
        a_records=["93.184.216.34"],
        http_body="",
        ptr_hosts=["server-93-184-216-34.maa51.r.cloudfront.net"],
        http_status=200,
        https_status=200,
    )
    assert risk == "VERIFY"
    assert service == "AWS CloudFront"

    # Regression: an S3 A-record PTR (no body) is still LOW, not VERIFY.
    risk_s3, service_s3, _ = main.check_takeover(
        subdomain="foo.example.com",
        cname=None,
        a_records=["52.1.2.3"],
        http_body="",
        ptr_hosts=["s3-website.s3.amazonaws.com"],
    )
    assert risk_s3 == "LOW"
    assert service_s3 == "AWS S3"
