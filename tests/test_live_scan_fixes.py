"""Tests for the keyless live-scan fixes (reproduced from example.com).

Three bugs, all exercised against the `onboarding.example.com` row (an AWS
ap-south-1 Lightsail/Bitnami compute host, DNS RESOLVED, HTTP 200, HTTPS 200,
previously mis-reported as AWS S3 / LOW / INCONCLUSIVE-dangling):

BUG 1 — AWS matching is scoped to real S3. EC2/Lightsail compute PTRs
(`*.compute.amazonaws.com`, `*.compute-1.amazonaws.com`) are NORMAL hosting:
takeover_service empty, risk NONE, verdict ''. True S3 hostnames/CNAMEs still
classify as AWS S3.

BUG 2 — a host whose HTTP or HTTPS probe returns a healthy status (2xx or a
normal non-takeover 3xx) is LIVE and claimed, so it is NEVER a VERIFY/takeover
flag from a mere service match. A legitimately-detected live cloud resource
(e.g. a live ELB) ends in NOT_VULNERABLE, never INCONCLUSIVE-dangling. The
dangling signal (404/503/no-response on a claimable provider) still -> VERIFY.

All direct check_takeover calls need no mocks; the analyze_subdomain cases mock
only the leaf DNS/HTTP I/O so the real classification logic is exercised.
"""

import asyncio

import main


# ---------------------------------------------------------------------------
# BUG 1 — compute/Lightsail PTRs are NOT AWS S3; true S3 still is.
# ---------------------------------------------------------------------------
def test_ec2_compute_ptr_is_not_s3():
    # An EC2/Lightsail A-record PTR (the onboarding.example.com shape) must NOT
    # match any AWS fingerprint or cloud pattern: no service, risk NONE.
    risk, service, detail = main.check_takeover(
        subdomain="onboarding.example.com",
        cname=None,
        a_records=["203.0.113.10"],
        http_body="<html>app</html>",
        ptr_hosts=["ec2-203-0-113-10.ap-south-1.compute.amazonaws.com"],
        http_status=200,
        https_status=200,
    )
    assert risk == "NONE"
    assert service is None


def test_compute_1_ptr_is_not_s3():
    # The legacy us-east-1 "compute-1.amazonaws.com" PTR shape is also normal
    # hosting, never AWS S3.
    risk, service, _ = main.check_takeover(
        subdomain="box.example.com",
        cname=None,
        a_records=["54.1.2.3"],
        http_body="",
        ptr_hosts=["ec2-54-1-2-3.compute-1.amazonaws.com"],
        http_status=200,
        https_status=200,
    )
    assert risk == "NONE"
    assert service is None


def test_true_s3_ptr_is_s3():
    # A genuine S3 PTR still classifies as AWS S3 (held LOW without a body).
    risk, service, _ = main.check_takeover(
        subdomain="foo.example.com",
        cname=None,
        a_records=["52.1.2.3"],
        http_body="",
        ptr_hosts=["foo.s3.amazonaws.com"],
    )
    assert service == "AWS S3"
    assert risk == "LOW"


def test_true_s3_website_ptr_is_s3():
    # A genuine S3 website PTR still classifies as AWS S3 via the new
    # "s3-website" fingerprint key.
    risk, service, _ = main.check_takeover(
        subdomain="foo.example.com",
        cname=None,
        a_records=["52.1.2.3"],
        http_body="",
        ptr_hosts=["foo.s3-website-us-east-1.amazonaws.com"],
    )
    assert service == "AWS S3"
    assert risk == "LOW"


def test_true_s3_cname_with_nosuchbucket_is_high():
    # A dangling S3 CNAME with the NoSuchBucket body is still a confirmed HIGH.
    risk, service, _ = main.check_takeover(
        subdomain="bucket.example.com",
        cname="bucket.s3.amazonaws.com",
        a_records=[],
        http_body="<Error><Code>NoSuchBucket</Code></Error>",
        ptr_hosts=[],
        http_status=404,
        https_status=None,
        cname_chain=["bucket.s3.amazonaws.com"],
    )
    assert service == "AWS S3"
    assert risk == "HIGH"


# ---------------------------------------------------------------------------
# BUG 2 — live hosts are never a VERIFY flag; dangling still VERIFY.
# ---------------------------------------------------------------------------
async def test_onboarding_live_lightsail_not_flagged(monkeypatch):
    # Full onboarding.example.com repro via analyze_subdomain: a live
    # Lightsail/EC2 compute host (DNS RESOLVED, HTTP 200, HTTPS 200) must NOT
    # be flagged — takeover_service falsy, risk NONE, verdict '', and NO
    # "remove the record if it is dangling" action.
    async def fake_resolve_dns_detailed(host):
        return ["203.0.113.10"], "RESOLVED"

    async def fake_resolve_cname_chain(host):
        return []

    async def fake_resolve_cname(host):
        return None

    async def fake_resolve_dns_records(host):
        return {"A": ["203.0.113.10"]}

    async def fake_resolve_ptrs(ips):
        return ["ec2-203-0-113-10.ap-south-1.compute.amazonaws.com"]

    async def fake_check_http(client, host):
        return 200, 200, "<html>app</html>"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "resolve_dns_records", fake_resolve_dns_records)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)
    monkeypatch.setattr(main, "check_http", fake_check_http)

    res = await main.analyze_subdomain(
        None, "onboarding.example.com", ["CertSpotter"], asyncio.Semaphore(5)
    )

    assert not res["takeover_service"]
    assert res["takeover_risk"] == "NONE"
    assert res["takeover_verdict"] == ""
    assert res["recommended_action"] == ""
    assert "dangling" not in (res["recommended_action"] or "")


async def test_live_elb_cname_not_vulnerable_not_dangling(monkeypatch):
    # A live (200/200) ELB CNAME: a service IS detected (AWS ELB), but the host
    # is live, so it is never VERIFY/HIGH. verify_takeover (via cloud_low)
    # resolves the ELB target and renders NOT_VULNERABLE — never INCONCLUSIVE
    # with a 'remove the record if dangling' action.
    elb = "demo-alb-1234567890.us-east-1.elb.amazonaws.com"

    async def fake_resolve_dns_detailed(host):
        # Both the subdomain and the ELB target resolve to a public IP.
        return ["52.54.156.108"], "RESOLVED"

    async def fake_resolve_cname_chain(host):
        return [elb]

    async def fake_resolve_cname(host):
        return elb

    async def fake_resolve_dns_records(host):
        return {"CNAME": [elb]}

    async def fake_resolve_ptrs(ips):
        return []

    async def fake_check_http(client, host):
        return 200, 200, "<html>welcome</html>"

    monkeypatch.setattr(main, "resolve_dns_detailed", fake_resolve_dns_detailed)
    monkeypatch.setattr(main, "resolve_cname_chain", fake_resolve_cname_chain)
    monkeypatch.setattr(main, "resolve_cname", fake_resolve_cname)
    monkeypatch.setattr(main, "resolve_dns_records", fake_resolve_dns_records)
    monkeypatch.setattr(main, "_resolve_ptrs", fake_resolve_ptrs)
    monkeypatch.setattr(main, "check_http", fake_check_http)

    res = await main.analyze_subdomain(
        None, "docs.example.com", ["crt.sh"], asyncio.Semaphore(5)
    )

    assert res["takeover_service"] == "AWS ELB"
    assert res["takeover_risk"] not in ("VERIFY", "HIGH")
    assert res["takeover_verdict"] == "NOT_VULNERABLE"
    assert "dangling" not in (res["recommended_action"] or "")


def test_dangling_elb_still_verify():
    # Regression guard: a genuinely dangling (503, no healthy host) ELB CNAME
    # is still a VERIFY candidate — the dangling path is untouched.
    risk, service, _ = main.check_takeover(
        subdomain="meet.example.com",
        cname="foo.us-east-1.elb.amazonaws.com",
        a_records=[],
        http_body="",
        ptr_hosts=[],
        http_status=503,
        https_status=None,
        cname_chain=["foo.us-east-1.elb.amazonaws.com"],
    )
    assert risk == "VERIFY"
    assert service == "AWS ELB"


def test_dangling_s3_no_response_still_verify():
    # A claimable S3 CNAME with no HTTP response at all stays VERIFY.
    risk, service, _ = main.check_takeover(
        subdomain="assets.example.com",
        cname="assets.s3.amazonaws.com",
        a_records=[],
        http_body="",
        ptr_hosts=[],
        http_status=None,
        https_status=None,
        cname_chain=["assets.s3.amazonaws.com"],
    )
    assert risk == "VERIFY"
    assert service == "AWS S3"


def test_dangling_heroku_404_still_verify():
    # A claimable Heroku CNAME returning 404 stays VERIFY (fingerprint not in
    # body, so it falls to the gone-signal VERIFY path).
    risk, service, _ = main.check_takeover(
        subdomain="app.example.com",
        cname="app.herokudns.com",
        a_records=[],
        http_body="",
        ptr_hosts=[],
        http_status=404,
        https_status=None,
        cname_chain=["app.herokudns.com"],
    )
    assert risk == "VERIFY"
    assert service == "Heroku"
