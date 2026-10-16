"""Breach-Exposure-mode frontend tests (FEAT-002).

Mirrors tests/test_lookalike_frontend.py. Verifies that adding the Breach
Exposure mode to static/index.html + static/app.js:
  * keeps the strict CSP coupling intact (no inline <script>, no inline on*
    handler attributes, exact SECURITY_CSP + security headers on / and /app.js),
  * still links only the same-origin /app.js and /tailwind.css (no third-party
    origin) and bumps the cache-buster to /app.js?v=4,
  * adds the third mode button (#modeBreach) and the #breachMode container to
    index.html, hidden by default while Subdomains stays visible,
  * adds the breach logic to app.js in the flat scope, wired via
    addEventListener, with escapeHtml-safe rendering of email / breaches /
    exposed_data / source (breach data is attacker-influenced PII),
  * leaves the existing Subdomains + Lookalike UI 100% intact.

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


# Reuse the exact detection patterns from test_lookalike_frontend.py so the
# breach additions are held to the same CSP standard.
_INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc\s*=)[^>]*>", re.IGNORECASE)
_HANDLER_ATTR_RE = re.compile(
    r'\son(click|change|input|submit|load|error|mouseover|keydown)\s*=\s*"'
)


def test_index_has_third_mode_button_and_breach_container_hidden_by_default():
    html = INDEX.read_text()
    # The third mode button exists alongside the first two.
    assert 'id="modeSubdomains"' in html
    assert 'id="modeLookalike"' in html
    assert 'id="modeBreach"' in html
    # The breach container exists and is hidden by default.
    assert 'id="breachMode"' in html
    m = re.search(r'<div id="breachMode"[^>]*>', html)
    assert m is not None, "breachMode container missing"
    assert "hidden" in m.group(0), "breachMode must be hidden by default"
    # Subdomains stays the visible default.
    sub = re.search(r'<div id="subdomainMode"[^>]*>', html)
    assert sub is not None and "hidden" not in sub.group(0)


def test_index_has_breach_form_controls():
    html = INDEX.read_text()
    for marker in (
        'id="breachDomainInput"',
        'id="breachDomainError"',
        'id="breachEmails"',
        'id="breachNames"',
        'id="checkBreachBtn"',
        'id="breachProgressPanel"',
        'id="breachProgressBar"',
        'id="breachProgressText"',
        'id="breachCancelBtn"',
        'id="breachResultsPanel"',
        'id="breachResultDomain"',
        'id="breachDownloadBtn"',
        'id="breachCardChecked"',
        'id="breachCardExposed"',
        'id="breachCardBreaches"',
        'id="breachCardHigh"',
        'id="breachFilterBtns"',
        'id="breachSearchInput"',
        'id="breachResultsTable"',
        'id="breachEmptyRow"',
    ):
        assert marker in html, f"missing breach control {marker!r}"


def test_index_has_honest_coverage_note():
    html = INDEX.read_text()
    assert "Keyless check via XposedOrNot" in html
    assert "Coverage limited to discovered/supplied addresses" in html
    assert "not an exhaustive domain report" in html
    assert "authorized use only" in html


def test_index_still_has_subdomain_and_lookalike_ui_intact():
    html = INDEX.read_text()
    for marker in (
        # Subdomain UI
        'id="domainInput"',
        'id="startBtn"',
        'id="resultsTable"',
        'id="downloadBtn"',
        'id="progressBar"',
        # Lookalike UI
        'id="lookalikeMode"',
        'id="lookalikeDomainInput"',
        'id="findLookalikesBtn"',
        'id="lookalikeResultsTable"',
    ):
        assert marker in html, f"existing UI marker {marker!r} was lost"


def test_index_script_tag_is_v4():
    html = INDEX.read_text()
    assert '<script src="/app.js?v=4"></script>' in html


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
    assert re.search(r'<script src="/app\.js(\?v=\d+)?"></script>', html)
    origins = re.findall(r"https?://[a-zA-Z0-9.-]+", html)
    assert origins == [], f"unexpected external origins: {origins}"


def test_app_js_contains_breach_functions():
    js = JS.read_text()
    for fn in (
        "function startBreach",
        "function updateBreachProgress",
        "function pollBreachStatus",
        "function loadBreachResults",
        "function displayBreachResults",
        "function applyBreachFilters",
        "function sortBreachResults",
        "function applyBreachSort",
        "function renderBreachTable",
        "function breachRiskBadge",
        "function cancelBreach",
        "function downloadBreachCSV",
    ):
        assert fn in js, f"missing breach function {fn!r}"


def test_app_js_switchmode_handles_breach():
    js = JS.read_text()
    # switchMode references the breach mode + container.
    sm = js.split("function switchMode", 1)[1].split("function startLookalike", 1)[0]
    assert "'breach'" in sm
    assert "breachMode" in sm


def test_app_js_wires_breach_controls_via_addeventlistener():
    js = JS.read_text()
    assert "getElementById('checkBreachBtn').addEventListener('click', startBreach)" in js
    assert "getElementById('breachCancelBtn').addEventListener('click', cancelBreach)" in js
    assert "getElementById('breachDownloadBtn').addEventListener('click', downloadBreachCSV)" in js
    assert "getElementById('breachSearchInput').addEventListener('input', applyBreachFilters)" in js
    # Third mode button wired to switchMode('breach').
    assert "switchMode('breach')" in js
    # Subdomains + lookalike mode wiring survives.
    assert "switchMode('subdomains')" in js
    assert "switchMode('lookalike')" in js
    # Breach sortable headers scoped to the breach container.
    assert "#breachMode th[data-sort]" in js


def test_app_js_breach_render_is_escapehtml_safe():
    js = JS.read_text()
    render = js.split("function renderBreachTable", 1)[1]
    render = render.split("function cancelBreach", 1)[0]
    # Email + source escaped before reaching innerHTML.
    assert "escapeHtml(r.email" in render
    assert "escapeHtml(r.source" in render
    # Each breach name + exposed-data category escaped (arrays joined from
    # escaped elements).
    assert "escapeHtml(String(b))" in render
    assert "escapeHtml(String(x))" in render
    # risk value goes through the whitelisting badge, not raw.
    assert "breachRiskBadge(r.risk_label)" in render
    # The render path must NOT innerHTML a raw API value.
    assert "innerHTML = r." not in render


def test_app_js_breach_risk_badge_whitelists_labels():
    js = JS.read_text()
    badge = js.split("function breachRiskBadge", 1)[1].split("function renderBreachTable", 1)[0]
    assert "'high'" in badge
    assert "'medium'" in badge
    # Anything else falls through to the grey Low badge.
    assert "bg-gray-500" in badge


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
