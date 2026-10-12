"""Tests for the per-subdomain analysis helpers in main.py.

Covers the three check_takeover branches (HIGH on CNAME + body, LOW on
service-match-only, NONE on clean), plus the A-record PTR matching path and
the CNAME socket fallback.
"""

import httpx
import pytest
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
    respx.get("http://foo.example.com").mock(return_value=httpx.Response(200, text="hi"))
    respx.get("https://foo.example.com").mock(return_value=httpx.Response(404, text="nope"))
    async with httpx.AsyncClient() as c:
        http_status, https_status, body = await main.check_http(c, "foo.example.com")
    assert http_status == 200
    assert https_status == 404
    assert "hi" in body and "nope" in body
