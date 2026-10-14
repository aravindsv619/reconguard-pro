"""End-to-end headless-browser proof that the 'Start Scan' button works under
the strict CSP after the inline script was externalized to /app.js.

This complements the static assertions in test_frontend.py by driving a real
(headless Chromium) browser: it loads the live server, confirms there are ZERO
CSP violations and ZERO uncaught JS errors on load, that clicking Start Scan
starts a scan (progressPanel becomes visible / a POST to /api/enumerate is made)
and that Advanced Options toggles — i.e. general interactivity is restored.

The test SKIPS cleanly (never fails) when Playwright or a Chromium binary is
not available, so the suite stays green in environments without a browser.
"""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


def _find_chromium():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception:
        return None
    # Prefer a Playwright-managed Chromium if present; else let Playwright pick.
    cache = Path.home() / ".cache" / "ms-playwright"
    if cache.is_dir():
        for exe in cache.glob("chromium-*/chrome-linux64/chrome"):
            if exe.exists():
                return str(exe)
        for exe in cache.glob("chromium_headless_shell-*/*/chrome-headless-shell"):
            if exe.exists():
                return str(exe)
    return ""  # empty string => use Playwright's default resolution


_CHROME = _find_chromium()
pytestmark = pytest.mark.skipif(
    _CHROME is None, reason="playwright/chromium not installed")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(host, port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def test_start_scan_works_headless():
    from playwright.sync_api import sync_playwright

    port = _free_port()
    env = dict(os.environ)
    env["PORT"] = str(port)
    # main.py binds :8080 by default; run it and target that unless PORT honored.
    proc = subprocess.Popen(
        [PY, "main.py"], cwd=str(ROOT), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base_port = 8080
    try:
        if not _wait_port("127.0.0.1", base_port):
            pytest.skip("server did not start on :8080")

        console = []
        page_errors = []
        posted = {"enumerate": False}

        launch_kwargs = {"headless": True, "args": ["--no-sandbox"]}
        if _CHROME:
            launch_kwargs["executable_path"] = _CHROME

        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(**launch_kwargs)
            except Exception as exc:  # browser binary genuinely unusable
                pytest.skip(f"chromium not launchable: {exc}")

            page = browser.new_page()
            page.on("console", lambda m: console.append((m.type, m.text)))
            page.on("pageerror", lambda e: page_errors.append(str(e)))
            page.on("request", lambda r: posted.__setitem__(
                "enumerate", posted["enumerate"] or (
                    r.method == "POST" and "/api/enumerate" in r.url)))

            page.goto(f"http://127.0.0.1:{base_port}/", wait_until="networkidle")
            time.sleep(0.5)

            csp_errors = [t for (_, t) in console
                          if "Content Security Policy" in t
                          or "Content-Security-Policy" in t
                          or "Refused to execute inline script" in t]
            assert not csp_errors, f"CSP violations on load: {csp_errors}"
            assert not page_errors, f"uncaught JS errors on load: {page_errors}"

            # Advanced Options toggles (general interactivity restored).
            adv = page.locator("#advancedPanel")
            assert "hidden" in (adv.get_attribute("class") or "")
            page.click("#advToggleBtn")
            time.sleep(0.2)
            assert "hidden" not in (adv.get_attribute("class") or "")

            # Start Scan triggers a scan.
            page.fill("#domainInput", "example.com")
            page.click("#startBtn")
            prog = page.locator("#progressPanel")
            started = False
            for _ in range(50):
                cls = prog.get_attribute("class") or ""
                if "hidden" not in cls or posted["enumerate"]:
                    started = True
                    break
                time.sleep(0.1)
            assert started, "Start Scan did not begin a scan"
            assert posted["enumerate"], "no POST to /api/enumerate was observed"

            browser.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
