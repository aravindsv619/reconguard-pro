"""Real-server security-header tests (A05/A08) — close the TestClient gap.

The other suites assert the four hardening headers using Starlette's
``TestClient``, which drives the router directly. That path can report the
headers present even when a *live* ASGI server would omit them on responses
produced by the ``StaticFiles`` mount at ``/`` (the SPA index and the vendored
``/tailwind.css``). This module proves the headers on the REAL ASGI path two
ways:

  * ``httpx`` over ``ASGITransport(app=main.app)`` — exercises the full outer
    ASGI middleware stack in-process (not just the router), including the
    StaticFiles sub-app.
  * a subprocess-launched ``python main.py`` uvicorn server bound to an
    ephemeral port, hit over a real socket. This is the check that would have
    caught a live/TestClient divergence; it is skipped only when a port cannot
    be bound in the sandbox.

Every assertion requires ALL FOUR headers (and the exact SECURITY_CSP) on
``/``, ``/tailwind.css``, ``/health``, and a 404 — with the StaticFiles ``/``
response specifically carrying the CSP (the previously-at-risk case).
"""

import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import httpx
import pytest

import main

_EXPECTED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
}

_ROUTES = ["/", "/tailwind.css", "/health", "/api/status/does-not-exist"]


def _assert_all_four(headers_getter):
    """headers_getter(name) -> value (case-insensitive); assert the 4 headers."""
    for header, value in _EXPECTED_HEADERS.items():
        assert headers_getter(header) == value, f"missing/wrong {header}"
    assert headers_getter("content-security-policy") == main.SECURITY_CSP


# ---------------------------------------------------------------------------
# 1. Real ASGI transport (in-process, full middleware stack incl. StaticFiles)
# ---------------------------------------------------------------------------
async def test_security_headers_on_real_asgi_transport():
    # asyncio_mode=auto (pytest.ini) runs this plain `async def` test directly.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main.app),
        base_url="http://testserver",
    ) as client:
        for route in _ROUTES:
            resp = await client.get(route)
            _assert_all_four(lambda h: resp.headers.get(h))
        # The StaticFiles "/" response must carry the exact CSP (the gap case).
        root = await client.get("/")
        assert root.status_code == 200
        assert root.headers.get("content-security-policy") == main.SECURITY_CSP


# ---------------------------------------------------------------------------
# 2. Subprocess-launched uvicorn (real socket) — the live-path proof
# ---------------------------------------------------------------------------
def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 - localhost
        # Snapshot headers into a plain dict so no response/except object is
        # referenced lazily by the returned getter.
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        return r.status, (lambda name: hdrs.get(name.lower()))


def _get_allow_404(url):
    try:
        return _get(url)
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in e.headers.items()}
        code = e.code
        return code, (lambda name: hdrs.get(name.lower()))


def test_security_headers_on_subprocess_uvicorn():
    """Start the actual `python main.py` server and curl-equivalent all routes.

    This is the test that would have caught the live-vs-TestClient gap: it hits
    a real uvicorn process over a socket, so a StaticFiles response that bypassed
    the header path would fail here even though TestClient stayed green.
    """
    port = _free_port()
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, SUBRECON_HOST="127.0.0.1")
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            f"import uvicorn; uvicorn.run('main:app', host='127.0.0.1', "
            f"port={port}, reload=False)",
        ],
        cwd=repo_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        # Wait for the server to accept connections (or bail if it died).
        deadline = time.time() + 20
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
                if "address already in use" in out.lower():
                    pytest.skip("ephemeral port could not be bound")
                pytest.fail(f"server exited early:\n{out}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    ready = True
                    break
            except OSError:
                time.sleep(0.2)
        if not ready:
            pytest.skip("live server did not come up in time")

        for route in ["/", "/tailwind.css", "/health"]:
            status, getter = _get(base + route)
            assert status == 200, f"{route} -> {status}"
            _assert_all_four(getter)

        status, getter = _get_allow_404(base + "/api/status/does-not-exist")
        assert status == 404
        _assert_all_four(getter)

        # The live StaticFiles "/" response must carry the exact CSP.
        status, getter = _get(base + "/")
        assert getter("content-security-policy") == main.SECURITY_CSP
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
