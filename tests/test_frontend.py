"""Frontend supply-chain + CSP regression tests (FEAT-002).

Verifies the Tailwind-vendoring and CSP coupling done in FEAT-002:
  * GET / and GET /tailwind.css carry the FEAT-001 security headers incl. the
    exact SECURITY_CSP,
  * static/index.html no longer references cdn.tailwindcss.com or an inline
    tailwind.config, and DOES link the local /tailwind.css,
  * GET /tailwind.css serves 200 with a text/css content type,
  * the served HTML references no third-party (https://) asset origin,
  * no inline on* event-handler ATTRIBUTES remain (they would be blocked by the
    strict script-src 'self' CSP; interactivity is wired via addEventListener),
  * the inline <style> block is preserved.

All I/O is local (TestClient + the checked-in static files); no network.
"""

import re

from fastapi.testclient import TestClient

import main

INDEX = main._static_dir and __import__("pathlib").Path(main._static_dir) / "index.html"
CSS = __import__("pathlib").Path(main._static_dir) / "tailwind.css"


_EXPECTED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
}


def _assert_security_headers(resp):
    for header, value in _EXPECTED_HEADERS.items():
        assert resp.headers.get(header) == value
    assert resp.headers.get("content-security-policy") == main.SECURITY_CSP


def test_index_security_headers_and_csp():
    with TestClient(main.app) as client:
        resp = client.get("/")
        assert resp.status_code == 200
        _assert_security_headers(resp)


def test_tailwind_css_served_as_css_with_headers():
    with TestClient(main.app) as client:
        resp = client.get("/tailwind.css")
        assert resp.status_code == 200
        assert "text/css" in resp.headers.get("content-type", "")
        _assert_security_headers(resp)


def test_index_has_no_cdn_tailwind_and_links_local_css():
    html = INDEX.read_text()
    # The CDN runtime script and inline tailwind.config must be gone entirely.
    assert "cdn.tailwindcss.com" not in html
    assert "tailwind.config" not in html
    # The local stylesheet must be linked.
    assert '<link rel="stylesheet" href="/tailwind.css">' in html


def test_index_preserves_inline_style_block():
    html = INDEX.read_text()
    assert "<style>" in html and "</style>" in html
    # A couple of marker rules from the preserved inline <style>.
    assert ".progress-stripes" in html
    assert ".sticky-col" in html


def test_index_references_no_third_party_origin():
    html = INDEX.read_text()
    # No remote asset origins at all (CSP is default-src 'self').
    origins = re.findall(r"https?://[a-zA-Z0-9.-]+", html)
    assert origins == [], f"unexpected external origins: {origins}"


def test_index_has_no_inline_event_handler_attributes():
    html = INDEX.read_text()
    # Inline on* handler ATTRIBUTES (e.g. onclick="...") are blocked by a strict
    # script-src 'self' CSP, so none may survive. We only flag real attributes
    # (an on-word immediately preceded by whitespace inside a tag and followed
    # by ="). Occurrences inside JS comments/strings use ("..." quoting) that
    # this attribute-shaped pattern still allows, so restrict to attribute form
    # with a preceding space and a tag-ish context by excluding comment lines.
    handler_attr = re.compile(r'\son(click|change|input|submit|load|error|mouseover|keydown)\s*=\s*"')
    offenders = []
    for ln in html.splitlines():
        stripped = ln.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue
        if handler_attr.search(ln):
            offenders.append(ln.strip())
    assert offenders == [], f"inline handler attributes remain: {offenders}"


def test_tailwind_css_covers_brand_and_fadein():
    css = CSS.read_text()
    # Custom theme carried over from the former inline tailwind.config.
    assert "#a5b4fc" in css  # brand-300
    assert "#6366f1" in css  # brand-500 (focus ring)
    assert "#4f46e5" in css  # brand-600
    assert "#4338ca" in css  # brand-700 (hover:bg-brand-700)
    assert "animate-fadein" in css
    assert "@keyframes fadein" in css
