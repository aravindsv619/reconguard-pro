"""Lookalike-mode frontend tests (FEAT-002).

Mirrors tests/test_frontend.py. Verifies that adding the Lookalike Domains mode
to static/index.html + static/app.js:
  * keeps the strict CSP coupling intact (no inline <script>, no inline on*
    handler attributes, exact SECURITY_CSP + security headers on / and /app.js),
  * still links only the same-origin /app.js and /tailwind.css (no third-party
    origin),
  * adds the mode switch (ids subdomainMode / lookalikeMode and the two switch
    buttons) to index.html, defaulting to Subdomains,
  * adds the lookalike logic to app.js in the flat scope, wired via
    addEventListener, with escapeHtml-safe rendering of candidate / page_title /
    registrar,
  * leaves the existing subdomain UI 100% intact.

All I/O is local (TestClient + the checked-in static files); no network.
"""

import re

from fastapi.testclient import TestClient

import main

INDEX = __import__("pathlib").Path(main._static_dir) / "index.html"
JS = __import__("pathlib").Path(main._static_dir) / "app.js"


_EXPECTED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
}


def _assert_security_headers(resp):
    for header, value in _EXPECTED_HEADERS.items():
        assert resp.headers.get(header) == value
    assert resp.headers.get("content-security-policy") == main.SECURITY_CSP


# Reuse the exact detection patterns from test_frontend.py so the lookalike
# additions are held to the same CSP standard.
_INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc\s*=)[^>]*>", re.IGNORECASE)
_HANDLER_ATTR_RE = re.compile(
    r'\son(click|change|input|submit|load|error|mouseover|keydown)\s*=\s*"'
)


def test_index_has_mode_switch_defaulting_to_subdomains():
    html = INDEX.read_text()
    # Both mode containers exist.
    assert 'id="subdomainMode"' in html
    assert 'id="lookalikeMode"' in html
    # The two switch buttons exist.
    assert 'id="modeSubdomains"' in html
    assert 'id="modeLookalike"' in html
    # Lookalike mode is hidden by default (Subdomains visible).
    m = re.search(r'<div id="lookalikeMode"[^>]*>', html)
    assert m is not None, "lookalikeMode container missing"
    assert "hidden" in m.group(0), "lookalikeMode must be hidden by default"
    # The subdomain container must NOT be hidden by default.
    sub = re.search(r'<div id="subdomainMode"[^>]*>', html)
    assert sub is not None and "hidden" not in sub.group(0)


def test_index_has_lookalike_controls():
    html = INDEX.read_text()
    for marker in (
        'id="lookalikeDomainInput"',
        'id="lookalikeDomainError"',
        'id="lookalikeWhois"',
        'id="findLookalikesBtn"',
        'id="lookalikeProgressBar"',
        'id="lookalikeProgressText"',
        'id="lookalikeCardTotal"',
        'id="lookalikeCardLive"',
        'id="lookalikeCardHigh"',
        'id="lookalikeCardAvailable"',
        'id="lookalikeResultsTable"',
        'id="lookalikeDownloadBtn"',
    ):
        assert marker in html, f"missing lookalike control {marker!r}"


def test_index_still_has_subdomain_ui_intact():
    html = INDEX.read_text()
    # A sampling of the original subdomain UI must survive unchanged.
    for marker in (
        'id="domainInput"',
        'id="startBtn"',
        'id="resultsTable"',
        'id="downloadBtn"',
        'id="progressBar"',
    ):
        assert marker in html, f"subdomain UI marker {marker!r} was lost"


def test_index_has_no_inline_executable_script():
    html = INDEX.read_text()
    html_no_comments = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
    offenders = _INLINE_SCRIPT_RE.findall(html_no_comments)
    assert offenders == [], f"inline <script> blocks remain (CSP-blocked): {offenders}"
    # A cache-buster query (?v=N) is allowed; still same-origin /app.js.
    assert re.search(r'<script src="/app\.js(\?v=\d+)?"></script>', html)


def test_index_has_no_inline_event_handler_attributes():
    html = INDEX.read_text()
    offenders = []
    for ln in html.splitlines():
        stripped = ln.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue
        if _HANDLER_ATTR_RE.search(ln):
            offenders.append(ln.strip())
    assert offenders == [], f"inline handler attributes remain: {offenders}"


def test_index_links_app_js_and_tailwind_and_no_third_party_origin():
    html = INDEX.read_text()
    assert '<link rel="stylesheet" href="/tailwind.css">' in html
    # A cache-buster query (?v=N) is allowed; still same-origin /app.js.
    assert re.search(r'<script src="/app\.js(\?v=\d+)?"></script>', html)
    origins = re.findall(r"https?://[a-zA-Z0-9.-]+", html)
    assert origins == [], f"unexpected external origins: {origins}"


def test_app_js_contains_lookalike_functions():
    js = JS.read_text()
    for fn in (
        "function startLookalike",
        "function switchMode",
        "function pollLookalikeStatus",
        "function loadLookalikeResults",
        "function displayLookalikeResults",
        "function renderLookalikeTable",
        "function lookalikeRiskBadge",
        "function downloadLookalikeCSV",
    ):
        assert fn in js, f"missing lookalike function {fn!r}"


def test_app_js_wires_lookalike_controls_via_addeventlistener():
    js = JS.read_text()
    assert "getElementById('findLookalikesBtn').addEventListener('click', startLookalike)" in js
    assert "getElementById('lookalikeDownloadBtn').addEventListener('click', downloadLookalikeCSV)" in js
    assert "getElementById('lookalikeSearchInput').addEventListener('input', applyLookalikeFilters)" in js
    # Mode switch wiring to switchMode.
    assert "switchMode('subdomains')" in js
    assert "switchMode('lookalike')" in js
    # Lookalike sortable headers scoped to the lookalike container.
    assert "#lookalikeMode th[data-sort]" in js


def test_app_js_lookalike_render_is_escapehtml_safe():
    js = JS.read_text()
    # The render path must escape attacker-influenced fields.
    render = js.split("function renderLookalikeTable", 1)[1]
    render = render.split("function cancelLookalike", 1)[0]
    assert "escapeHtml(r.candidate" in render
    assert "escapeHtml(r.page_title" in render
    # registrar is escaped (in renderLookalikeTable's title attribute).
    assert "escapeHtml(String(r.registrar))" in render
    # The risk value goes through the whitelisting badge, not raw.
    assert "lookalikeRiskBadge(r.risk)" in render


def test_app_js_lookalike_risk_badge_whitelists_enum():
    js = JS.read_text()
    badge = js.split("function lookalikeRiskBadge", 1)[1].split("function registeredCell", 1)[0]
    for label in ("HIGH", "MEDIUM", "LOW", "AVAILABLE", "NONE"):
        assert f"'{label}'" in badge, f"risk badge does not whitelist {label}"


def test_index_security_headers_and_csp():
    with TestClient(main.app) as client:
        resp = client.get("/")
        assert resp.status_code == 200
        _assert_security_headers(resp)


def test_app_js_served_with_headers_and_csp():
    with TestClient(main.app) as client:
        resp = client.get("/app.js")
        assert resp.status_code == 200
        assert "javascript" in resp.headers.get("content-type", "")
        _assert_security_headers(resp)


def test_csp_unchanged_still_script_src_self_no_unsafe_inline():
    csp = main.SECURITY_CSP
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp.split("script-src", 1)[1].split(";", 1)[0]
