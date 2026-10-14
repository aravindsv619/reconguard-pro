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


JS = __import__("pathlib").Path(main._static_dir) / "app.js"

# An inline <script> with a body (executable inline JS) is refused by the strict
# script-src 'self' CSP (no 'unsafe-inline', no nonce), which silently kills ALL
# interactivity. Only an EXTERNAL reference (<script src=...>) is allowed. This
# pattern matches an opening <script ...> whose attributes do NOT include a src.
_INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc\s*=)[^>]*>", re.IGNORECASE)


def test_index_has_no_inline_executable_script():
    """Under script-src 'self' an inline <script> body is CSP-blocked, so the
    page must carry only external <script src=...> references (the root cause of
    the dead 'Start Scan' button was the whole inline block being refused)."""
    html = INDEX.read_text()
    # Strip HTML comments first so a comment that merely MENTIONS a script tag
    # cannot be mistaken for a real one.
    html_no_comments = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
    offenders = _INLINE_SCRIPT_RE.findall(html_no_comments)
    assert offenders == [], f"inline <script> blocks remain (CSP-blocked): {offenders}"
    # The externalized application JS must be referenced from the same origin.
    assert '<script src="/app.js"></script>' in html


def test_app_js_served_as_javascript_with_headers():
    """/app.js must serve 200 with a javascript content type and carry the same
    security headers (incl. the exact CSP) as every other response."""
    with TestClient(main.app) as client:
        resp = client.get("/app.js")
        assert resp.status_code == 200
        assert "javascript" in resp.headers.get("content-type", "")
        _assert_security_headers(resp)


def test_app_js_contains_the_relocated_logic():
    """Externalizing must only RELOCATE the logic, not change it: the key
    functions, the CSP-safe addEventListener wiring, and the data-sort / data-rec
    delegation all live in app.js now."""
    js = JS.read_text()
    for fn in ("function startScan", "function toggleAdvanced", "function cancelScan",
               "function downloadCSV", "function applyFilters", "function sortResults",
               "function toggleRecords"):
        assert fn in js, f"missing relocated {fn!r}"
    assert "getElementById('startBtn').addEventListener('click', startScan)" in js
    assert "th[data-sort]" in js
    assert "button[data-rec]" in js
    # XSS-safe rendering preserved (no innerHTML of raw server data).
    assert "function escapeHtml" in js


def test_csp_unchanged_still_script_src_self_no_unsafe_inline():
    """The fix must NOT weaken the CSP: script-src stays 'self' with no
    'unsafe-inline' and no CDN origin."""
    csp = main.SECURITY_CSP
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp.split("script-src", 1)[1].split(";", 1)[0]
    assert "cdn.tailwindcss.com" not in csp


def test_tailwind_css_covers_brand_and_fadein():
    css = CSS.read_text()
    # Custom theme carried over from the former inline tailwind.config.
    assert "#a5b4fc" in css  # brand-300
    assert "#6366f1" in css  # brand-500 (focus ring)
    assert "#4f46e5" in css  # brand-600
    assert "#4338ca" in css  # brand-700 (hover:bg-brand-700)
    assert "animate-fadein" in css
    assert "@keyframes fadein" in css
