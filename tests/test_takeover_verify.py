"""Tests for the VERIFY takeover tier (dangling CNAME to a cloud resource).

VERIFY sits between MEDIUM and HIGH in the risk ordering
(HIGH > VERIFY > MEDIUM > LOW > NONE). It flags a CNAME chain whose final
target is a known cloud resource (CLOUD_RESOURCE_PATTERNS) that returns a
"gone" HTTP signal (404/503) or no response at all, WITHOUT a body
fingerprint confirming an actual takeover. It must never override a stronger
HIGH/MEDIUM fingerprint match and issues no network request (it only reads the
already-gathered CNAME + HTTP status data passed to check_takeover).
"""

import main


def test_match_cloud_resource_anchored():
    assert main._match_cloud_resource("foo.us-east-1.elb.amazonaws.com") == "AWS ELB"
    assert main._match_cloud_resource("app.herokuapp.com") == "Heroku"
    assert main._match_cloud_resource("d123.cloudfront.net") == "AWS CloudFront"
    # Anchored: substring/suffix spoofing must NOT match.
    assert main._match_cloud_resource("example.com") is None
    assert main._match_cloud_resource("evil-amazonaws.com.attacker.net") is None
    assert main._match_cloud_resource(None) is None
    assert main._match_cloud_resource("") is None


def test_verify_dangling_elb_503():
    risk, service, detail = main.check_takeover(
        subdomain="meet.example.com",
        cname="foo.us-east-1.elb.amazonaws.com",
        a_records=[],
        http_body="",  # no fingerprint in the body
        ptr_hosts=[],
        http_status=503,
        https_status=None,
        cname_chain=["foo.us-east-1.elb.amazonaws.com"],
    )
    assert risk == "VERIFY"
    assert service == "AWS ELB"
    # An anchored ELB CNAME always routes into the verify pass; the detail
    # names the ELB target so the verdict is diagnosable.
    assert "foo.us-east-1.elb.amazonaws.com" in detail


def test_verify_dangling_404():
    risk, service, detail = main.check_takeover(
        subdomain="old.example.com",
        cname="app.herokuapp.com",
        a_records=[],
        http_body="generic error page",
        ptr_hosts=[],
        http_status=None,
        https_status=404,
        cname_chain=["app.herokudns.com", "app.herokuapp.com"],
    )
    assert risk == "VERIFY"
    assert service == "Heroku"
    assert "404" in detail


def test_verify_no_response_at_all():
    # No HTTP response gathered (both None) + cloud-resource CNAME → VERIFY.
    risk, service, detail = main.check_takeover(
        subdomain="svc.example.com",
        cname="bucket.s3.amazonaws.com",
        a_records=[],
        http_body="",
        ptr_hosts=[],
        http_status=None,
        https_status=None,
        cname_chain=["bucket.s3.amazonaws.com"],
    )
    assert risk == "VERIFY"
    assert service == "AWS S3"
    assert "no HTTP response" in detail


def test_verify_does_not_override_high():
    # A real body-fingerprint match stays HIGH even though the CNAME is a
    # cloud resource and the status is a "gone" signal.
    risk, service, detail = main.check_takeover(
        subdomain="foo.example.com",
        cname="foo.github.io",
        a_records=[],
        http_body="There isn't a GitHub Pages site here",
        ptr_hosts=[],
        http_status=404,
        https_status=None,
        cname_chain=["foo.github.io"],
    )
    assert risk == "HIGH"
    assert service == "GitHub Pages"


def test_cloud_resource_healthy_200_elb_is_low_not_flag():
    # BUG 2: a healthy 200 ELB/ALB CNAME is a LIVE, claimed host, so it is
    # classified AWS ELB -> LOW (never a VERIFY flag). It still routes into the
    # verify pass via the cloud_low path, where verify_takeover renders
    # NOT_VULNERABLE from the resolving target.
    risk, service, detail = main.check_takeover(
        subdomain="live.example.com",
        cname="app.us-east-1.elb.amazonaws.com",
        a_records=[],
        http_body="welcome",
        ptr_hosts=[],
        http_status=200,
        https_status=200,
        cname_chain=["app.us-east-1.elb.amazonaws.com"],
    )
    assert risk == "LOW"
    assert service == "AWS ELB"


def test_cloud_resource_healthy_200_non_elb_not_verify():
    # A healthy 200 on a NON-ELB cloud CNAME (CloudFront) is a live resource,
    # so VERIFY must not fire from a "gone" signal — the gone/no-response gate
    # is unchanged for providers other than ELB.
    risk, service, detail = main.check_takeover(
        subdomain="live.example.com",
        cname="d123.cloudfront.net",
        a_records=[],
        http_body="welcome",
        ptr_hosts=[],
        http_status=200,
        https_status=200,
        cname_chain=["d123.cloudfront.net"],
    )
    assert risk != "VERIFY"


def test_non_cloud_cname_404_not_verify():
    # A 404 on a CNAME that is NOT a known cloud resource must not be VERIFY.
    risk, service, detail = main.check_takeover(
        subdomain="foo.example.com",
        cname="internal.example.net",
        a_records=[],
        http_body="",
        ptr_hosts=[],
        http_status=404,
        https_status=None,
        cname_chain=["internal.example.net"],
    )
    assert risk == "NONE"
    assert service is None
