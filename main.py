"""ReconGuard Pro — subdomain enumeration, takeover-risk, and lookalike-domain backend.

A FastAPI application that aggregates subdomains from 11 public passive-DNS
sources, resolves and probes each one, scores subdomain-takeover risk, and
exposes an in-memory job API plus a single-file dark-themed frontend.
"""

import asyncio
import csv
import html
import io
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, TypedDict

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("reconguard")

USER_AGENT = "Mozilla/5.0 (compatible; ReconGuard/1.0)"
SOURCE_TIMEOUT = 15.0
HTTP_PROBE_TIMEOUT = 5.0
ANALYSIS_CONCURRENCY = 50
JOB_TTL_SECONDS = 3600

# DoS caps (resource exhaustion guards). MAX_ACTIVE_JOBS bounds the number of
# simultaneously pending/running jobs (POSTs beyond it get 429);
# MAX_SUBDOMAINS_PER_JOB bounds how many discovered hosts a single job will
# analyze (DNS/HTTP probe) so a huge passive-DNS result set can't exhaust the
# process. Probe concurrency itself stays bounded by Semaphore(ANALYSIS_CONCURRENCY).
MAX_ACTIVE_JOBS = 20
MAX_SUBDOMAINS_PER_JOB = 5000

# Maximum total length of a domain name per RFC 1035 (<= 253 chars).
MAX_DOMAIN_LENGTH = 253

# Response-size cap (API10/API4): the maximum number of body bytes read from
# any outbound fetch (source fetches via _get, target probes via check_http).
# A hostile source or target that streams a multi-hundred-MB body cannot OOM
# the process — reads are aborted past this cap and the caller treats the
# response as empty. 10 MiB is far larger than any real passive-DNS/probe body.
MAX_RESPONSE_BYTES = 10 * 1024 * 1024

# Request-body cap (A04/API4): the maximum length of the raw custom wordlist
# string accepted in an EnumerateRequest, enforced by Pydantic BEFORE the value
# is buffered/parsed, so an enormous wordlist cannot exhaust memory. Valid
# labels within an accepted wordlist are still post-parse capped by
# MAX_ACTIVE_CANDIDATES. 1 MiB holds well over 100k typical labels.
MAX_WORDLIST_BYTES = 1 * 1024 * 1024

# Per-client (IP) rate limit (A04/API4) for POST /api/enumerate. A simple
# in-memory token bucket keyed by client IP: SUBRECON_RATE_LIMIT tokens are
# refilled over RATE_LIMIT_WINDOW seconds, with a burst capacity of
# RATE_LIMIT_BURST. The default is generous for a single-user local tool; the
# limiter FAILS OPEN on any internal error so it never blocks legitimate work.
try:
    RATE_LIMIT_PER_MINUTE = max(1, int(os.environ.get("SUBRECON_RATE_LIMIT", "60")))
except (TypeError, ValueError):
    RATE_LIMIT_PER_MINUTE = 60
RATE_LIMIT_WINDOW = 60.0
RATE_LIMIT_BURST = RATE_LIMIT_PER_MINUTE
# Drop stale per-IP buckets opportunistically once this many are tracked.
RATE_LIMIT_MAX_BUCKETS = 10000

# Security headers applied to EVERY HTTP response (API, static, and error) by
# the security-headers middleware. The Content-Security-Policy is defined as a
# module-level constant so FEAT-002 (frontend) and the tests import the exact
# same string. It is kept tight: scripts only from 'self' (Tailwind is vendored
# locally in FEAT-002, no third-party script origin); 'unsafe-inline' is
# allowed for style ONLY (the frontend keeps a small inline <style> + dynamic
# class strings) which does not weaken script protection.
SECURITY_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "object-src 'none'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware:
    """Pure-ASGI middleware that stamps hardening headers on EVERY response.

    A plain ``@app.middleware("http")`` wrapper operates on the Starlette
    ``Response`` object returned by the router, which is reliable for API
    handlers but is NOT a dependable place to harden responses produced by a
    mounted sub-app such as ``StaticFiles`` at ``/`` (the SPA index and the
    vendored ``/tailwind.css``). A sub-app can stream its own ASGI messages
    without ever surfacing a Starlette ``Response`` to the outer wrapper, so
    the headers can silently go missing on the live server even while the
    TestClient path (which exercises the router directly) still shows them.

    Wrapping ``send`` at the ASGI layer closes that gap: we intercept the
    ``http.response.start`` message for every response — API, StaticFiles, and
    handled-error (400/404/422/429) alike — and add the four headers unless the
    downstream app already set them (``setdefault`` semantics, case-insensitive
    per RFC 7230). Because this is added via ``app.add_middleware`` it sits in
    the outer ASGI stack and runs after CORS, so CORS headers are preserved and
    none of the security headers are duplicated.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                # ASGI header names are raw bytes; compare case-insensitively.
                present = {name.lower() for name, _ in headers}
                for name, value in _SECURITY_HEADERS:
                    if name.lower().encode("latin-1") not in present:
                        headers.append(
                            (name.encode("latin-1"), value.encode("latin-1"))
                        )
            await send(message)

        await self.app(scope, receive, send_with_headers)


# The exact header set applied by SecurityHeadersMiddleware (A05/A08):
# nosniff defeats content-type sniffing, DENY blocks framing/clickjacking,
# no-referrer stops referrer leakage, and SECURITY_CSP constrains origins.
_SECURITY_HEADERS: list[tuple[str, str]] = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy", SECURITY_CSP),
]

# ---------------------------------------------------------------------------
# Active DNS discovery (brute-force + permutation) — all OFF by default.
# ---------------------------------------------------------------------------
# Candidate-level DoS bound: the total number of generated brute-force +
# permutation candidates is capped here, independently of MAX_SUBDOMAINS_PER_JOB
# (which still bounds the FINAL analyzed set). Active mode may generate up to
# MAX_ACTIVE_CANDIDATES candidates but, after dedup/merge, still only analyzes
# MAX_SUBDOMAINS_PER_JOB hosts — matching existing passive behavior.
MAX_ACTIVE_CANDIDATES = 20000

# Active resolution shares the SAME bounded-concurrency semaphore as passive
# analysis (asyncio.Semaphore(ANALYSIS_CONCURRENCY)); this constant documents
# the intended active concurrency and is currently equal to ANALYSIS_CONCURRENCY.
ACTIVE_RESOLVE_CONCURRENCY = 50

# ---------------------------------------------------------------------------
# Lookalike / typosquat domain discovery (keyless) — FEAT-001.
# ---------------------------------------------------------------------------
# These power the SEPARATE /api/lookalike* job API. The engine is pure/offline
# for candidate generation and reuses every existing guard
# (is_valid_hostname/DOMAIN_RE, _is_safe_public_ip SSRF, _csv_safe,
# resolve_dns_detailed, _dig_records, check_http, the verified RDAP client,
# _rate_limit_ok, MAX_ACTIVE_JOBS, MAX_RESPONSE_BYTES, bounded Semaphores) for
# the network/analysis phase.

# Candidate-level DoS bound: generate_lookalikes stops producing candidates at
# this cap, enforced at EVERY growth step (mirrors MAX_ACTIVE_CANDIDATES for
# the active-discovery generators). Chosen smaller than MAX_ACTIVE_CANDIDATES
# because every surviving candidate is independently DNS/HTTP/RDAP probed.
MAX_LOOKALIKE_CANDIDATES = 5000

# TLDs tried for the TLD-swap and combosquat techniques. A pragmatic set of the
# TLDs most abused for brand impersonation (not an exhaustive IANA list).
LOOKALIKE_TLDS = [
    "com", "net", "org", "io", "co", "ai", "app", "dev", "info", "biz",
    "online", "site", "xyz", "cc", "me", "tech", "store", "us", "uk", "in",
]

# QWERTY physical-keyboard adjacency (lowercase letters only) used by the
# insertion and replacement (fat-finger) techniques: each key maps to the keys
# physically next to it on a US QWERTY layout.
QWERTY_ADJACENCY = {
    "q": "wa", "w": "qeas", "e": "wrsd", "r": "etdf", "t": "ryfg",
    "y": "tugh", "u": "yihj", "i": "uojk", "o": "ipkl", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc", "g": "ftyhbv",
    "h": "gyujnb", "j": "huikmn", "k": "jiolm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
}

# Homoglyph substitutions (ASCII-only, visually-confusable) applied by the
# homoglyph technique. Each key may be replaced by any string in its list
# (single and multi-char pairs kept bidirectionally where it makes sense).
HOMOGLYPHS = {
    "o": ["0"],
    "0": ["o"],
    "l": ["1", "i"],
    "1": ["l", "i"],
    "i": ["1", "l"],
    "m": ["rn"],
    "w": ["vv"],
    "d": ["cl"],
    "b": ["6"],
    "6": ["b"],
    "g": ["9"],
    "9": ["g"],
    "s": ["5"],
    "5": ["s"],
}

# Words prepended/appended (hyphenated) by the combosquatting technique
# (e.g. ``login-brandco.com`` / ``brandco-secure.com``).
COMBOSQUAT_WORDS = [
    "login", "secure", "account", "support", "verify", "auth",
    "mail", "help", "app", "portal", "pay", "update",
]

# Best-effort multi-label public suffixes so split_domain keeps the full
# registrable label for domains like ``example.co.uk``. This is NOT a complete
# Public Suffix List — it covers the common ccTLD SLDs only.
MULTI_LABEL_SLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "com.br", "com.cn", "co.jp", "co.nz",
    "co.za", "com.mx", "com.sg", "com.tr",
}

# RDAP (whois) lookup settings for the OPTIONAL registration check. Uses the
# verified (TLS-validated) client. Bounded concurrency + a hard per-lookup
# timeout so a slow RDAP server can never stall a job.
RDAP_CONCURRENCY = 5
RDAP_TIMEOUT = 8.0
RDAP_ENDPOINT = "https://rdap.org/domain/{}"

# ---------------------------------------------------------------------------
# Breach-exposure engine (FEAT-001) — keyless XposedOrNot.
# ---------------------------------------------------------------------------
# These power the SEPARATE /api/breach* job API. All outbound breach calls go
# through the VERIFIED client (app.state.client) to the FIXED trusted host
# api.xposedornot.com ONLY; no user-controlled host is ever fetched. Email
# discovery reuses the existing crt.sh fetch via _get. A09: the engine NEVER
# logs emails, breach names, or exposed data — only job_id + domain + counts.
XPOSEDORNOT_BASE = "https://api.xposedornot.com"

# Dedicated concurrency for breach checks — the keyless XposedOrNot per-email
# endpoint rate-limits HARD and fast (a handful of calls in quick succession
# earns HTTP 429 + a Cloudflare "Just a moment" challenge, and the throttle has
# memory: a "violation history" keeps dropping subsequent calls). The API simply
# cannot tolerate parallelism, so we SERIALIZE the XposedOrNot calls (==1) and
# pace them. This makes large lists slower but CORRECT — a throttled check is
# never silently treated as "not exposed". Kept as a tunable named constant.
# (Page-scrape discovery has its own SCRAPE_CONCURRENCY and is unaffected.)
# MUST stay <= 4.
BREACH_CONCURRENCY = 1
# Polite pause between successive XposedOrNot calls to stay under the throttle.
# ~1.0-1.5s keeps a keyless caller below the drop threshold. Larger lists take
# proportionally longer by design — correctness over speed.
BREACH_REQUEST_DELAY = 1.2
# The inter-call delay run_breach actually paces with (the adaptive base). Kept
# as a separate name so it can be overridden to 0 in offline tests without
# touching the documented BREACH_REQUEST_DELAY; defaults to BREACH_REQUEST_DELAY.
BREACH_CALL_DELAY = BREACH_REQUEST_DELAY
BREACH_CHECK_TIMEOUT = 15.0
# Exponential-backoff base for a throttled (429 / Cloudflare challenge) check:
# retry sleeps BREACH_RETRY_BACKOFF * 2**attempt (i.e. ~2s, 4s, 8s) — honoring a
# Retry-After header when the API sends one.
BREACH_RETRY_BACKOFF = 2.0
# Max retries for a throttled check before it is marked UNKNOWN (indeterminate).
BREACH_MAX_RETRIES = 4
# Upper bound on a single backoff sleep (also caps a hostile Retry-After value).
BREACH_MAX_BACKOFF = 30.0
# Adaptive slowdown: once a 429 is seen in a job, the inter-call delay is bumped
# by this step (up to BREACH_ADAPTIVE_MAX) so one throttle doesn't cascade into
# all-429s for the rest of the job.
BREACH_ADAPTIVE_STEP = 1.0
BREACH_ADAPTIVE_MAX = 6.0
# DoS cap: the total candidate address set a single breach job will check.
MAX_BREACH_EMAILS = 2000

# --- Keyless page-scrape discovery bounds (FEAT-001 strengthen) ---
# The strengthened domain-only discovery reuses the EXISTING subdomain
# enumeration to find the domain's own hosts, then fetches a BOUNDED subset of
# the live ones through the SSRF-guarded probe client to harvest mailto:/inline
# emails and conservative person names. Every bound below is a hard DoS/blast-
# radius cap; the whole path is best-effort and never aborts the breach job.
#
# Max distinct hosts we will attempt to fetch (after SSRF gating).
MAX_SCRAPE_HOSTS = 25
# Low concurrency for page fetches — separate from the breach-API Semaphore(3).
SCRAPE_CONCURRENCY = 5
# Short per-request timeout for scraping the domain's own pages.
SCRAPE_TIMEOUT = 5.0
# Common contact-style paths probed per host (best-effort, in addition to '/').
SCRAPE_PATHS = ("/", "/contact", "/about", "/team", "/careers")
# Common hostname prefixes used as a fallback when subdomain discovery is empty
# (and always unioned in, since these pages routinely publish addresses).
SCRAPE_COMMON_HOSTS = ("www", "mail", "careers", "about", "contact", "team")
# Keyless role-based local parts: extremely common org addresses that cost only
# a handful of breach-API checks. Checked as {local}@domain, source 'pattern'.
BREACH_ROLE_LOCALS = (
    "info", "contact", "careers", "hr", "admin", "support",
    "sales", "security", "it", "hello", "team", "jobs", "no-reply",
)
# Cap on the number of harvested person names fed to generate_email_patterns.
MAX_HARVEST_NAMES = 50

# Sentinel the breach client returns when the API outcome is indeterminate
# (persistent error / non-200 after retry) — DISTINCT from None ("Not found").
BREACH_UNKNOWN = "UNKNOWN"

# Permissive-but-safe RFC-ish local part: letters, digits, and the common
# punctuation (. _ % + -). Anchored, no whitespace / URL-breaking chars, so a
# validated address is always safe to interpolate into the FIXED-host URL.
BREACH_EMAIL_RE = re.compile(r"^[a-z0-9][a-z0-9._%+-]{0,63}$")

# Conservative "First Last" person-name token: two-to-three capitalized words.
# Each token is either a capitalized word ([A-Z][a-z]+) or an all-caps token of
# length >= 2 (surname initials like "VR", "KM"). Heuristic only — every
# generated address is still gated by the breach API (verify-then-keep), so a
# false name can never surface noise.
_NAME_TOKEN = r"(?:[A-Z][a-z]{1,19}|[A-Z]{2,4})"
PERSON_NAME_RE = re.compile(rf"\b{_NAME_TOKEN}(?:\s+{_NAME_TOKEN}){{1,2}}\b")
# Obvious non-name capitalized bigrams to drop before pattern-generation.
NAME_STOPWORDS = frozenset(
    {
        "the", "and", "for", "our", "your", "all", "about", "contact", "team",
        "home", "careers", "privacy", "policy", "terms", "cookie", "cookies",
        "learn", "more", "read", "get", "started", "sign", "log", "login",
        "menu", "page", "site", "copyright", "rights", "reserved", "inc", "llc",
        "ltd", "company", "services", "solutions", "products", "news", "blog",
        "email", "phone", "address", "follow", "us", "we", "are", "is", "to",
        "view", "open", "close", "next", "prev", "back", "skip", "main",
    }
)

# Email-pattern templates for name-based candidate generation. Each entry is a
# callable mapping (first, last, f) -> local part; generate_email_patterns
# applies, validates and dedupes them. 'f' is the first-name initial.
EMAIL_PATTERNS = [
    lambda first, last, f: f"{first}.{last}",   # first.last
    lambda first, last, f: f"{first}",          # first
    lambda first, last, f: f"{f}{last}",        # flast
    lambda first, last, f: f"{first}{last}",    # firstlast
    lambda first, last, f: f"{last}.{first}",   # last.first
    lambda first, last, f: f"{first}_{last}",   # first_last
]

# Absolute path to the bundled default wordlist, resolved relative to this file.
DEFAULT_WORDLIST_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "wordlists", "default.txt"
)

# Strict single-label validator (one DNS label, RFC-1035). Applied to every
# wordlist label and to every generated permutation fragment.
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Permutation (altdns-style) seed words and separators.
PERMUTATION_WORDS = [
    "dev", "staging", "prod", "test", "qa", "uat", "old", "new",
    "1", "2", "01", "02", "admin", "internal", "api",
]
PERMUTATION_SEPARATORS = ["-", "."]

DOMAIN_RE = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _is_valid_label(label: str) -> bool:
    """True iff `label` is a single valid DNS label after lowercasing.

    Used to validate wordlist labels and generated permutation fragments
    before they are composed into a full hostname.
    """
    if not isinstance(label, str):
        return False
    return bool(LABEL_RE.match(label.strip().lower()))


def load_default_wordlist() -> list[str]:
    """Load the bundled default wordlist from DEFAULT_WORDLIST_PATH.

    Lowercases/strips each line, drops blanks, `#` comments, invalid labels,
    and duplicates (preserving first-seen order). Never raises — on a missing
    or unreadable file it logs at debug level and returns [] so the app still
    starts.
    """
    out: list[str] = []
    seen: set[str] = set()
    try:
        with open(DEFAULT_WORDLIST_PATH, encoding="utf-8") as fh:
            for raw in fh:
                label = raw.strip().lower()
                if not label or label.startswith("#"):
                    continue
                if not _is_valid_label(label) or label in seen:
                    continue
                seen.add(label)
                out.append(label)
    except Exception as exc:  # noqa: BLE001
        logger.debug("default wordlist load failed: %s", exc)
        return []
    return out


# Loaded once at import; the list is static.
DEFAULT_WORDLIST: list[str] = load_default_wordlist()


def parse_custom_wordlist(text: Optional[str]) -> list[str]:
    """Parse a user-supplied newline-separated wordlist into valid labels.

    Lowercases/strips, drops blanks and `#` comments, keeps only labels passing
    `_is_valid_label`, de-duplicates preserving order. Invalid labels are
    SILENTLY dropped (never a 400). Returns [] for empty/None input.
    """
    if not text:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw in text.split("\n"):
        label = raw.strip().lower()
        if not label or label.startswith("#"):
            continue
        if not _is_valid_label(label) or label in seen:
            continue
        seen.add(label)
        out.append(label)
    return out


def build_bruteforce_candidates(
    domain: str, labels: list[str], limit: int
) -> tuple[list[str], bool]:
    """Compose `{label}.{domain}` candidates (no network I/O).

    Stops once `limit` candidates are produced (candidate-cap enforcement) and
    skips any composed host that fails `is_valid_hostname` (defense in depth).
    Returns (candidates, truncated) where `truncated` is True if more labels
    remained when the cap was hit.
    """
    candidates: list[str] = []
    truncated = False
    for i, label in enumerate(labels):
        if len(candidates) >= limit:
            # More labels remain beyond the cap.
            truncated = i < len(labels)
            break
        host = f"{label}.{domain}".lower()
        if is_valid_hostname(host):
            candidates.append(host)
    return candidates, truncated


def generate_permutations(
    known_hosts,
    domain: str,
    words: list[str],
    separators: list[str],
    limit: int,
) -> tuple[list[str], bool]:
    """Generate altdns-style permutations from already-discovered hosts.

    For each in-scope host under `domain`, take the label portion left of the
    base domain and generate variants: (a) prepend/append each word with each
    separator; (b) increment a trailing number in the first label (+1..+3);
    (c) swap `-`<->`.` within the label portion. All lowercased, re-validated
    with `is_valid_hostname` (invalid dropped), de-duplicated, excluding the
    base domain and anything already in `known_hosts`, and never exceeding
    `limit` total. Returns (candidates, truncated). No network I/O.
    """
    domain = domain.lower()
    suffix = "." + domain
    known_set = {h.lower() for h in known_hosts}
    candidates: list[str] = []
    seen: set[str] = set()
    truncated = False

    def emit(host: str) -> bool:
        """Append a validated, novel candidate.

        Returns False once the cap is reached, signaling the caller to stop
        generating (and marking the result truncated). Returns True to continue.
        """
        nonlocal truncated
        host = host.lower()
        if host in seen or host in known_set or host == domain:
            return True
        if not is_valid_hostname(host):
            return True
        if len(candidates) >= limit:
            truncated = True
            return False
        seen.add(host)
        candidates.append(host)
        if len(candidates) >= limit:
            # Cap now full; any further generation would be dropped.
            truncated = True
            return False
        return True

    for host in known_set:
        host = host.lower()
        # Only permute in-scope hosts strictly below the base domain.
        if not host.endswith(suffix):
            continue
        prefix = host[: -len(suffix)]  # label portion left of base domain
        if not prefix:
            continue

        # (a) prepend / append each word with each separator.
        for word in words:
            for sep in separators:
                if not emit(f"{word}{sep}{prefix}{suffix}"):
                    return candidates, truncated
                if not emit(f"{prefix}{sep}{word}{suffix}"):
                    return candidates, truncated
            # Numeric words are also appended directly (no separator), the
            # common altdns pattern that turns `api` into `api1`, `api2`, ...
            if word.isdigit():
                if not emit(f"{prefix}{word}{suffix}"):
                    return candidates, truncated

        # (b) increment a trailing number in the first (leftmost) label.
        first_label = prefix.split(".")[0]
        rest = prefix[len(first_label):]  # includes leading '.' if any
        m = re.match(r"^(.*?)(\d+)$", first_label)
        if m:
            stem, num = m.group(1), m.group(2)
            width = len(num)
            base_val = int(num)
            for delta in (1, 2, 3):
                new_num = str(base_val + delta).zfill(width)
                new_first = f"{stem}{new_num}"
                if not emit(f"{new_first}{rest}{suffix}"):
                    return candidates, truncated

        # (c) swap '-' <-> '.' within the label portion.
        if "-" in prefix:
            if not emit(f"{prefix.replace('-', '.')}{suffix}"):
                return candidates, truncated
        if "." in prefix:
            if not emit(f"{prefix.replace('.', '-')}{suffix}"):
                return candidates, truncated

    return candidates, truncated


def is_valid_hostname(name: str) -> bool:
    """Strict RFC-1035 hostname check applied BEFORE a value is interpolated
    into any outbound URL / passed to ``dig`` / HTTP-probed.

    Rejects: empty input, anything longer than 253 chars, empty or oversized
    (>63 char) labels, schemes (``http://``), slashes, ``@``, whitespace, and
    IP addresses (the trailing ``[a-zA-Z]{2,}`` TLD rule in DOMAIN_RE rejects
    all-numeric final labels, so bare IPv4/IPv6 literals do not match).
    """
    if not name or len(name) > MAX_DOMAIN_LENGTH:
        return False
    # Reject obvious URL / injection characters early (defense in depth; the
    # regex already excludes them, but this keeps intent explicit).
    if any(c in name for c in "/\\@ \t\r\n:") or "*" in name:
        return False
    labels = name.split(".")
    if any(len(label) == 0 or len(label) > 63 for label in labels):
        return False
    # Reject bare IP literals explicitly (DOMAIN_RE also rejects them).
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        pass
    return bool(DOMAIN_RE.match(name))


def _is_safe_public_ip(ip: str) -> bool:
    """Return True only for globally-routable public addresses.

    Returns False (unsafe → do NOT probe) for private, loopback, link-local
    (incl. the 169.254.169.254 cloud metadata address), reserved, multicast,
    and unspecified ranges for both IPv4 and IPv6
    (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1, fc00::/7, ...).
    Unparseable input is treated as unsafe. This is the SSRF guard that keeps
    the probe client from reaching internal/metadata endpoints.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    ):
        return False
    return True


def _csv_safe(value) -> str:
    """Neutralize CSV formula/injection per OWASP.

    If the stringified value begins with a formula trigger (= + - @) or a
    control char (tab, CR, LF) that spreadsheet apps may interpret, prefix a
    single quote so the cell is treated as text. Preserves the value otherwise.
    """
    text = "" if value is None else str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r", "\n"):
        return "'" + text
    return text


# ---------------------------------------------------------------------------
# Lookalike / typosquat engine (FEAT-001) — keyless; generation is pure/offline
# ---------------------------------------------------------------------------
def split_domain(domain: str) -> tuple[str, str]:
    """Split ``domain`` into (registrable_label, tld).

    If the domain ends with one of the MULTI_LABEL_SLDS suffixes (e.g.
    ``co.uk``), the TLD is that two-label suffix and the registrable label is
    everything before it. Otherwise the split is on the LAST dot. A bare label
    with no dot returns (label, "").

    Best-effort only: MULTI_LABEL_SLDS is a short hand-curated set, NOT the full
    Public Suffix List, so exotic multi-label suffixes may split imperfectly.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    for suffix in MULTI_LABEL_SLDS:
        dotted = "." + suffix
        if domain.endswith(dotted) and len(domain) > len(dotted):
            label = domain[: -len(dotted)]
            # Only the left-most label is the registrable part of interest.
            return label, suffix
    if "." in domain:
        label, _, tld = domain.rpartition(".")
        return label, tld
    return domain, ""


def generate_lookalikes(domain: str) -> set[str]:
    """Generate lookalike/typosquat candidates for ``domain``.

    PURE and KEYLESS: no network I/O. Each technique runs in its own documented
    block and emits via a bounded ``emit`` helper that lowercases, dedups,
    excludes the input domain, keeps only ``is_valid_hostname``-valid hosts, and
    stops the whole generation once MAX_LOOKALIKE_CANDIDATES is reached (the cap
    is checked at every growth step, like generate_permutations).
    """
    domain = (domain or "").strip().lower().rstrip(".")
    label, tld = split_domain(domain)
    out: set[str] = set()
    # Sentinel raised internally once the cap is hit to unwind all technique
    # loops cleanly (each technique is wrapped in try/except below).
    if not label:
        return out

    class _CapReached(Exception):
        pass

    def emit(host: str) -> None:
        host = (host or "").lower()
        if not host or host == domain or host in out:
            return
        if not is_valid_hostname(host):
            return
        if len(out) >= MAX_LOOKALIKE_CANDIDATES:
            raise _CapReached
        out.add(host)
        if len(out) >= MAX_LOOKALIKE_CANDIDATES:
            raise _CapReached

    def with_tld(new_label: str, new_tld: Optional[str] = None) -> str:
        t = new_tld if new_tld is not None else tld
        return f"{new_label}.{t}" if t else new_label

    alpha = "abcdefghijklmnopqrstuvwxyz"
    try:
        # --- Hyphenation: insert a single hyphen between adjacent char groups.
        # Emit under the original TLD (e.g. brandco -> brand-co.ai) AND a
        # bounded subset of the lookalike TLDs (so brand-co.com is covered —
        # the common cross-TLD hyphenated impersonation). ---
        hyphen_tlds = ([tld] if tld else []) + LOOKALIKE_TLDS[:5]
        for i in range(1, len(label)):
            if label[i - 1] != "-" and label[i] != "-":
                hyphenated = label[:i] + "-" + label[i:]
                for t in hyphen_tlds:
                    if t:
                        emit(f"{hyphenated}.{t}")

        # --- TLD swap: same label with each LOOKALIKE_TLD plus the original. ---
        for t in LOOKALIKE_TLDS:
            emit(f"{label}.{t}")
        if tld:
            emit(f"{label}.{tld}")

        # --- Omission: remove one character. ---
        for i in range(len(label)):
            emit(with_tld(label[:i] + label[i + 1:]))

        # --- Insertion: insert a keyboard-adjacent char between letters. ---
        for i in range(len(label)):
            for adj in QWERTY_ADJACENCY.get(label[i], ""):
                emit(with_tld(label[:i] + adj + label[i:]))
                emit(with_tld(label[: i + 1] + adj + label[i + 1:]))

        # --- Repetition: double a character. ---
        for i in range(len(label)):
            emit(with_tld(label[:i] + label[i] + label[i:]))

        # --- Transposition: swap two adjacent characters. ---
        for i in range(len(label) - 1):
            swapped = label[:i] + label[i + 1] + label[i] + label[i + 2:]
            emit(with_tld(swapped))

        # --- Replacement: replace a char with a QWERTY-adjacent char. ---
        for i in range(len(label)):
            for adj in QWERTY_ADJACENCY.get(label[i], ""):
                emit(with_tld(label[:i] + adj + label[i + 1:]))

        # --- Homoglyph: apply confusable substitutions one position at a time
        # (bounded — one substitution per emitted candidate). ---
        for i in range(len(label)):
            for repl in HOMOGLYPHS.get(label[i], []):
                emit(with_tld(label[:i] + repl + label[i + 1:]))

        # --- Combosquatting: prepend/append each word with a hyphen, keeping
        # the original TLD plus a bounded subset of the TLD-swap set. ---
        combo_tlds = [tld] if tld else []
        combo_tlds += LOOKALIKE_TLDS[:5]
        for word in COMBOSQUAT_WORDS:
            for t in combo_tlds:
                if not t:
                    continue
                emit(f"{word}-{label}.{t}")
                emit(f"{label}-{word}.{t}")

        # --- Subdomain / dot-insert: insert a dot splitting the label, e.g.
        # brandco -> brand.co.tld. ---
        for i in range(1, len(label)):
            emit(with_tld(label[:i] + "." + label[i:]))

        # --- Bitsquatting: flip one bit of each alpha char, keep valid hosts. ---
        for i, ch in enumerate(label):
            for bit in range(8):
                flipped = chr(ord(ch) ^ (1 << bit))
                if flipped in alpha and flipped != ch:
                    emit(with_tld(label[:i] + flipped + label[i + 1:]))
    except _CapReached:
        pass

    return out


# Generic words that carry no distinctive brand signal. When a brand label or
# an original page title is reduced to tokens, these are dropped so resemblance
# keys off the DISTINCTIVE part (e.g. 'nerd' for brandco), not a word any
# unrelated business might share ('agent', 'solutions', 'services', ...).
BRAND_STOPWORDS = frozenset(
    {
        "home", "welcome", "ai", "the", "app", "apps", "inc", "llc", "ltd",
        "co", "corp", "company", "solutions", "services", "service", "agent",
        "agents", "agency", "and", "for", "online", "official", "site",
        "website", "web", "page", "login", "portal", "group", "io", "net",
        "com", "org", "of", "to", "your", "best", "free", "new", "get",
    }
)

# Case-insensitive substrings that mark a page as parked/placeholder rather than
# a real site. Matched against the candidate's title/content slice. An empty or
# whitespace-only title is also treated as parked (handled in _is_parked).
PARKED_SIGNATURES = (
    "parking page",
    "parked",
    "domain for sale",
    "buy this domain",
    "coming soon",
    "under construction",
    "this domain is for sale",
    "godaddy",
    "sedo",
    "default web page",
    "namecheap parking",
    "domain is parked",
    "domain parked",
)


def _normalize_label(label: Optional[str]) -> str:
    """Lowercase ``label`` and strip everything but [a-z0-9].

    Used so hyphen/dot variants compare equal: 'brand-co' and 'brand.co'
    both normalize to 'brandco'. Returns "" for falsy input.
    """
    if not label:
        return ""
    return re.sub(r"[^a-z0-9]", "", label.lower())


def _brand_tokens(brand_label: str, original_title: Optional[str]) -> set[str]:
    """Derive the DISTINCTIVE brand tokens for the original domain.

    Combines the normalized registrable brand label with the significant words
    of the original page title, drops BRAND_STOPWORDS and very short (<3 char)
    tokens, and ALSO adds the leading distinctive fragment of the brand label
    (e.g. 'nerd' from 'brandco' once the generic suffix 'agent' is removed) so
    a content match can key off the distinctive part. Best-effort, never raises.
    """
    tokens: set[str] = set()
    norm_label = _normalize_label(brand_label)
    if norm_label:
        tokens.add(norm_label)
        # Peel off a trailing generic stopword to expose the distinctive stem,
        # e.g. 'brandco' -> 'nerd' (since 'agent' is a stopword). Only strip
        # ONE suffix and only when a meaningful (>=3 char) stem remains.
        for stop in BRAND_STOPWORDS:
            if len(stop) >= 3 and norm_label.endswith(stop) and \
                    len(norm_label) - len(stop) >= 3:
                tokens.add(norm_label[: -len(stop)])
                break
    if original_title:
        for word in re.split(r"[^a-z0-9]+", original_title.lower()):
            if len(word) >= 3 and word not in BRAND_STOPWORDS:
                tokens.add(word)
    return {t for t in tokens if len(t) >= 3}


def _is_parked(title: Optional[str]) -> bool:
    """True when a candidate's title/content looks like a parking/placeholder.

    Case-insensitive substring match against PARKED_SIGNATURES; an empty or
    whitespace-only title (a live site with no real title) also counts as
    parked. Best-effort, never raises.
    """
    if title is None:
        return False
    text = title.strip().lower()
    if not text:
        return True
    return any(sig in text for sig in PARKED_SIGNATURES)


def _resembles_brand(
    candidate: str,
    candidate_title: Optional[str],
    brand_label: str,
    brand_tokens: set[str],
) -> bool:
    """Best-effort brand-resemblance for one candidate.

    True when EITHER:
      (a) the candidate's registrable label CONTAINS the original brand label
          (or vice-versa) once hyphens/dots are removed — so 'brand-co',
          'brandco.<tld>' and 'brandco-login' all match 'brandco'; OR
      (b) the candidate's fetched title shares a DISTINCTIVE brand token with
          the original (tokens already exclude generic stopwords), which lets a
          content match catch look-alikes that reworded their label.

    This is a heuristic, NOT a proof of impersonation: it is tuned to flag
    brand-containing / content-echoing sites while letting coincidental
    unrelated businesses (different label AND no shared distinctive token) fall
    through. Never raises.
    """
    norm_brand = _normalize_label(brand_label)
    if norm_brand:
        cand_label, _ = split_domain(candidate)
        norm_cand = _normalize_label(cand_label)
        if norm_cand and (norm_brand in norm_cand or norm_cand in norm_brand):
            return True
    if candidate_title and brand_tokens:
        cand_words = {
            w for w in re.split(r"[^a-z0-9]+", candidate_title.lower())
            if len(w) >= 3
        }
        if cand_words & brand_tokens:
            return True
    return False


def score_lookalike(
    dns_status: Optional[str],
    http_status: Optional[int],
    https_status: Optional[int],
    has_mx: bool,
    resembles_original: bool,
    registered,
    parked: bool = False,
) -> tuple[str, str]:
    """Return (risk, recommended_action) for a lookalike candidate.

    Tiers (honest wording — a candidate to INVESTIGATE, never an assertion of
    malice). HIGH now means "likely brand impersonation worth urgent
    investigation", NOT "any live domain with mail": a bare MX record is only a
    BOOSTER noted in the action text, never a sole trigger.

      HIGH     — resolves AND a live HTTP site (2xx/3xx) AND the page/label
                 resembles the original brand AND is NOT parked. Likely active
                 impersonation infra.
      MEDIUM   — resolves + live + NOT parked but does NOT resemble the brand
                 (a live but apparently-unrelated/generic site — possibly a
                 coincidental unrelated business); OR resolves + live +
                 resembles but parked (brand-ish parking page worth monitoring).
      LOW      — resolves + live + parked + not resembling (unrelated parked
                 page); OR resolves (DNS only) with no live site; OR registered
                 but no live site.
      AVAILABLE— does not resolve and (when whois was checked) appears
                 unregistered. A defensive-registration opportunity.
      NONE     — anything else (e.g. unresolved with unknown registration).
    """
    resolves = dns_status == "RESOLVED"
    live = _http_live(http_status) or _http_live(https_status)
    mx_note = " It also publishes mail (MX) records." if has_mx else ""

    if resolves and live:
        if resembles_original and not parked:
            return (
                "HIGH",
                "Likely brand impersonation to investigate urgently: it "
                "resolves, serves a live site, and its label or page content "
                "resembles your brand." + mx_note + " Confirm it is not owned "
                "by you, then consider monitoring and, if confirmed malicious, "
                "takedown.",
            )
        if resembles_original and parked:
            return (
                "MEDIUM",
                "Resembles your brand but currently shows a parked/placeholder "
                "page." + mx_note + " Worth monitoring in case it is activated; "
                "confirm it is not owned by you.",
            )
        if parked:
            return (
                "LOW",
                "Resolves and is live but shows a parked/placeholder page and "
                "does not resemble your brand." + mx_note + " Low priority; "
                "re-check periodically.",
            )
        return (
            "MEDIUM",
            "Resolves and is live but its label and page title do not resemble "
            "your brand — the title suggests a possibly-unrelated business, so "
            "a human should confirm before acting." + mx_note + " Lower "
            "priority; confirm ownership.",
        )
    if resolves and registered is True and not live:
        return (
            "LOW",
            "Registered and resolves but no live site (possibly parked). "
            "Monitor for activation.",
        )
    if resolves:
        return (
            "LOW",
            "Resolves at the DNS level but has no live site. Low priority; "
            "re-check periodically.",
        )
    if registered is False:
        return (
            "AVAILABLE",
            "Unregistered lookalike. Consider defensive registration to keep it "
            "out of an impersonator's hands.",
        )
    return (
        "NONE",
        "Does not resolve; registration status unknown. No action needed now.",
    )


def _http_live(status: Optional[int]) -> bool:
    """True iff an HTTP status indicates a live site (2xx or 3xx)."""
    return status is not None and 200 <= status < 400


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(body: str) -> Optional[str]:
    """Cheaply extract the <title> text from a bounded HTML slice.

    Operates on a bounded prefix of ``body`` (the title is always near the top)
    and collapses whitespace. Returns None when no title is found. Never raises.
    """
    try:
        if not body:
            return None
        match = _TITLE_RE.search(body[:65536])
        if not match:
            return None
        title = re.sub(r"\s+", " ", match.group(1)).strip()
        return title or None
    except Exception:  # noqa: BLE001
        return None


async def fetch_title(probe_client: httpx.AsyncClient, host: str) -> Optional[str]:
    """Best-effort page title for ``host`` (SSRF-guarded). Never raises.

    Mirrors analyze_subdomain's guard: validate the hostname, resolve it, and
    only probe when at least one resolved IP passes _is_safe_public_ip (so the
    probe can never reach a private/metadata address). The body is bounded by
    check_http/_read_capped_body. Returns None on any failure.
    """
    try:
        if not is_valid_hostname(host):
            return None
        ip_addresses, _ = await resolve_dns_detailed(host)
        if ip_addresses and not any(_is_safe_public_ip(ip) for ip in ip_addresses):
            return None
        _http, _https, body = await check_http(probe_client, host)
        return _extract_title(body)
    except Exception:  # noqa: BLE001
        return None


async def rdap_lookup(verified_client: httpx.AsyncClient, candidate: str) -> dict:
    """Look up registration data for ``candidate`` via RDAP. Never raises.

    Issues a single GET to RDAP_ENDPOINT on the VERIFIED (TLS-validated) client,
    bounded by RDAP_TIMEOUT. On success parses ``registered`` (True when the
    RDAP object exists), the registrar name, and the registration/creation date
    from the RDAP JSON. On ANY error/timeout/non-200 returns a neutral
    ``{"registered": "unknown", "registrar": "", "creation_date": ""}`` so a job
    is never blocked by whois.
    """
    unknown = {"registered": "unknown", "registrar": "", "creation_date": ""}
    try:
        resp = await asyncio.wait_for(
            verified_client.get(RDAP_ENDPOINT.format(candidate)),
            timeout=RDAP_TIMEOUT,
        )
        if resp.status_code == 404:
            # RDAP 404 is an authoritative "no such registration".
            return {"registered": False, "registrar": "", "creation_date": ""}
        if resp.status_code != 200:
            return dict(unknown)
        data = resp.json()
        if not isinstance(data, dict):
            return dict(unknown)
        registrar = ""
        for ent in data.get("entities", []) or []:
            if not isinstance(ent, dict):
                continue
            roles = ent.get("roles", []) or []
            if "registrar" in roles:
                registrar = _rdap_entity_name(ent)
                if registrar:
                    break
        creation_date = ""
        for ev in data.get("events", []) or []:
            if not isinstance(ev, dict):
                continue
            if ev.get("eventAction") == "registration":
                creation_date = str(ev.get("eventDate", "") or "")
                break
        return {
            "registered": True,
            "registrar": registrar,
            "creation_date": creation_date,
        }
    except Exception:  # noqa: BLE001
        return dict(unknown)


def _rdap_entity_name(entity: dict) -> str:
    """Pull a human-readable name from an RDAP entity's vCard, best-effort."""
    try:
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) == 2:
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    return str(item[3] or "")
        return str(entity.get("handle", "") or "")
    except Exception:  # noqa: BLE001
        return ""


# ---------------------------------------------------------------------------
# Breach-exposure helpers (pure/offline) + keyless XposedOrNot client (FEAT-001)
# ---------------------------------------------------------------------------
def _valid_email_for_domain(email: str, domain: str) -> bool:
    """True iff ``email`` is a syntactically safe address at exactly ``domain``.

    Lowercases, requires exactly one '@', the local part must match
    BREACH_EMAIL_RE (no whitespace / URL-breaking chars), and the domain part
    must equal the target domain exactly. The validated address is always safe
    to interpolate into the FIXED-host XposedOrNot URL.
    """
    try:
        if not email or not domain:
            return False
        email = email.strip().lower()
        domain = domain.strip().lower().rstrip(".")
        if email.count("@") != 1:
            return False
        local, _, dom = email.partition("@")
        if dom != domain:
            return False
        return bool(BREACH_EMAIL_RE.match(local))
    except Exception:  # noqa: BLE001
        return False


def generate_email_patterns(names: list[str], domain: str) -> set[str]:
    """Build candidate addresses at ``domain`` from a list of person names.

    For each name: a single token -> only ``{first}@``; a multi-token name uses
    the FIRST token as ``first`` and the LAST token as ``last`` and applies the
    EMAIL_PATTERNS templates ({first}.{last}, {first}, {flast}, {firstlast},
    {last}.{first}, {first}_{last}). All addresses are lowercased, validated via
    _valid_email_for_domain, deduped, and the set is capped at MAX_BREACH_EMAILS.
    """
    out: set[str] = set()
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return out
    for raw in names or []:
        if len(out) >= MAX_BREACH_EMAILS:
            break
        # Keep only alphanumeric tokens so "O'Brien" / punctuation don't leak
        # URL-breaking chars; the final _valid_email_for_domain gate is the
        # authoritative filter.
        tokens = [re.sub(r"[^a-z0-9]", "", t.lower()) for t in (raw or "").split()]
        tokens = [t for t in tokens if t]
        if not tokens:
            continue
        locals_: list[str] = []
        if len(tokens) == 1:
            locals_.append(tokens[0])  # single-token name -> {first}@
        else:
            first, last = tokens[0], tokens[-1]
            f = first[0]
            for tmpl in EMAIL_PATTERNS:
                try:
                    locals_.append(tmpl(first, last, f))
                except Exception:  # noqa: BLE001
                    continue
        for local in locals_:
            if len(out) >= MAX_BREACH_EMAILS:
                break
            candidate = f"{local}@{domain}"
            if _valid_email_for_domain(candidate, domain):
                out.add(candidate)
    return out


def parse_email_lines(text: Optional[str], domain: str) -> list[str]:
    """Parse supplied email lines, keeping only valid addresses at ``domain``.

    Splits on newlines, strips, drops blanks and '#' comment lines, lowercases,
    validates with _valid_email_for_domain, and dedupes preserving first-seen
    order (capped at MAX_BREACH_EMAILS). The byte-cap on the raw text is the
    BreachRequest field's ``max_length`` (not enforced here).
    """
    out: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        if len(out) >= MAX_BREACH_EMAILS:
            break
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if _valid_email_for_domain(line, domain) and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def parse_name_lines(text: Optional[str]) -> list[str]:
    """Parse supplied person-name lines, deduped preserving first-seen order.

    Splits on newlines, strips, drops blanks and '#' comment lines. Dedupe is
    case-insensitive; the original-cased first occurrence is kept.
    """
    out: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        if len(out) >= MAX_BREACH_EMAILS:
            break
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key = line.lower()
        if key not in seen:
            seen.add(key)
            out.append(line)
    return out


def _is_throttle_response(resp: httpx.Response) -> bool:
    """True when an XposedOrNot response is a rate-limit / Cloudflare challenge.

    The keyless endpoint signals throttling in several shapes and we must treat
    ALL of them as "retry", never as a "Not found" / clean result:
      * HTTP 429 (explicit rate limit) or 403 (Cloudflare block);
      * an HTML body (``<!DOCTYPE html`` / ``Just a moment`` interstitial)
        returned with ANY status, including 200;
      * a JSON body carrying the "violation history" drop marker.
    Never logs the body (A09) — only inspects it.
    """
    try:
        if resp.status_code in (429, 403):
            return True
        # Peek at the body cheaply. A JSON error endpoint is tiny; the Cloudflare
        # interstitial is HTML. We only read a prefix for the HTML sniff.
        ctype = (resp.headers.get("content-type") or "").lower()
        if "text/html" in ctype:
            return True
        body = resp.text or ""
        head = body.lstrip()[:512].lower()
        if head.startswith("<!doctype html") or head.startswith("<html"):
            return True
        if "just a moment" in head or "violation history" in head:
            return True
    except Exception:  # noqa: BLE001 — never raise while sniffing.
        return False
    return False


def _retry_after_seconds(resp: httpx.Response) -> Optional[float]:
    """Parse a Retry-After header (delta-seconds form) into a bounded float."""
    try:
        raw = resp.headers.get("retry-after")
        if not raw:
            return None
        secs = float(raw.strip())
        if secs < 0:
            return None
        return min(secs, BREACH_MAX_BACKOFF)
    except (TypeError, ValueError):
        return None


async def check_email_exposed(
    client: httpx.AsyncClient, email: str
):
    """Keyless XposedOrNot per-email breach check. Never raises.

    GET {XPOSEDORNOT_BASE}/v1/check-email/{email} on the VERIFIED client,
    bounded by BREACH_CHECK_TIMEOUT. The keyless endpoint throttles aggressively
    (HTTP 429 + a Cloudflare "Just a moment" challenge once a "violation
    history" builds up), so a throttled check is retried with EXPONENTIAL
    BACKOFF (~2s, 4s, 8s; up to BREACH_MAX_RETRIES), honoring a Retry-After
    header when present. Returns:
      * a flattened list[str] of breach names when status == 'success';
      * ``None`` when the API reports {'Error': 'Not found'} (clean/unknown
        address the breach DB does not know);
      * the BREACH_UNKNOWN sentinel when the check is INDETERMINATE — a
        persistent throttle (429/Cloudflare challenge that never clears) or any
        other non-200 / parse error after retries are exhausted. A throttled
        check is NEVER silently reported as "not exposed".
    NEVER logs the email or the response body (A09).
    """
    url = f"{XPOSEDORNOT_BASE}/v1/check-email/{email}"

    async def _fetch():
        return await asyncio.wait_for(
            client.get(url), timeout=BREACH_CHECK_TIMEOUT
        )

    try:
        for attempt in range(BREACH_MAX_RETRIES + 1):
            resp = await _fetch()

            # Explicit throttle / Cloudflare challenge -> exponential backoff.
            if _is_throttle_response(resp):
                if attempt >= BREACH_MAX_RETRIES:
                    # Retries exhausted; indeterminate, NOT "not exposed".
                    return BREACH_UNKNOWN
                hinted = _retry_after_seconds(resp)
                backoff = hinted if hinted is not None else min(
                    BREACH_RETRY_BACKOFF * (2 ** attempt), BREACH_MAX_BACKOFF
                )
                await asyncio.sleep(backoff)
                continue

            if resp.status_code != 200:
                return BREACH_UNKNOWN

            try:
                data = resp.json()
            except Exception:  # noqa: BLE001 — non-JSON 200 is indeterminate.
                return BREACH_UNKNOWN
            if not isinstance(data, dict):
                return BREACH_UNKNOWN
            # Authoritative "no breach record" marker.
            if data.get("Error") == "Not found":
                return None
            if data.get("status") == "success":
                names: list[str] = []
                # 'breaches' is shaped [[name, name, ...]] (a single-element
                # outer list wrapping the breach-name list). Flatten defensively.
                for group in data.get("breaches", []) or []:
                    if isinstance(group, (list, tuple)):
                        for name in group:
                            if name:
                                names.append(str(name))
                    elif group:
                        names.append(str(group))
                return names
            # Unexpected-but-not-error payload: treat as indeterminate.
            return BREACH_UNKNOWN
        # Loop fell through (all attempts throttled).
        return BREACH_UNKNOWN
    except Exception:  # noqa: BLE001 — never raise; caller treats as unknown.
        return BREACH_UNKNOWN


async def breach_analytics(client: httpx.AsyncClient, email: str) -> dict:
    """Keyless XposedOrNot detailed analytics for an exposed email. Never raises.

    GET {XPOSEDORNOT_BASE}/v1/breach-analytics?email={email} on the VERIFIED
    client, bounded by BREACH_CHECK_TIMEOUT. Parses defensively with .get()
    fallbacks and returns a fixed-shape dict:
      {'breaches': [names...], 'exposed_data': [categories...],
       'risk_label': str, 'risk_score': int|''}.
    NEVER logs the email or the body (A09).
    """
    neutral = {"breaches": [], "exposed_data": [], "risk_label": "", "risk_score": ""}
    url = f"{XPOSEDORNOT_BASE}/v1/breach-analytics?email={email}"
    try:
        resp = await asyncio.wait_for(
            client.get(url), timeout=BREACH_CHECK_TIMEOUT
        )
        if resp.status_code != 200:
            return dict(neutral)
        data = resp.json()
        if not isinstance(data, dict):
            return dict(neutral)

        breaches: set[str] = set()
        exposed: set[str] = set()
        risk_label = ""
        risk_score: object = ""

        metrics = data.get("BreachMetrics")
        if isinstance(metrics, dict):
            risk = metrics.get("risk")
            if isinstance(risk, list) and risk and isinstance(risk[0], dict):
                risk_label = str(risk[0].get("risk_label", "") or "")
                rs = risk[0].get("risk_score", "")
                try:
                    risk_score = int(rs)
                except (TypeError, ValueError):
                    risk_score = ""
            # xposed_data may live under BreachMetrics as a fallback.
            for item in metrics.get("xposed_data", []) or []:
                if isinstance(item, dict):
                    cat = item.get("children") or item.get("name")
                    if isinstance(cat, list):
                        for c in cat:
                            if isinstance(c, dict) and c.get("name"):
                                exposed.add(str(c["name"]))
                    elif cat:
                        exposed.add(str(cat))

        summary = data.get("BreachesSummary")
        if isinstance(summary, dict):
            site = summary.get("site", "") or ""
            for name in str(site).split(";"):
                name = name.strip()
                if name:
                    breaches.add(name)

        exposed_breaches = data.get("ExposedBreaches")
        if isinstance(exposed_breaches, dict):
            for det in exposed_breaches.get("breaches_details", []) or []:
                if not isinstance(det, dict):
                    continue
                bname = det.get("breach")
                if bname:
                    breaches.add(str(bname))
                xd = det.get("xposed_data", "")
                if isinstance(xd, str):
                    for cat in xd.split(";"):
                        cat = cat.strip()
                        if cat:
                            exposed.add(cat)
                elif isinstance(xd, (list, tuple)):
                    for cat in xd:
                        if cat:
                            exposed.add(str(cat))

        return {
            "breaches": sorted(breaches),
            "exposed_data": sorted(exposed),
            "risk_label": risk_label,
            "risk_score": risk_score,
        }
    except Exception:  # noqa: BLE001 — never raise.
        return dict(neutral)


def _deobfuscate_page_text(text: str) -> str:
    """Decode HTML entities and normalize common email-obfuscation spellings.

    Turns ``name [at] domain [dot] com`` / ``name(at)domain(dot)com`` and the
    HTML-entity variants into plain ``name@domain.com`` so the email regex can
    match them. Purely textual; never executes anything from the page.
    """
    if not text:
        return ""
    text = html.unescape(text)
    # ' [at] ' / '(at)' / ' AT ' -> '@'   and   ' [dot] ' / '(dot)' -> '.'
    text = re.sub(r"\s*[\[\(\{]\s*at\s*[\]\)\}]\s*", "@", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*[\[\(\{]\s*dot\s*[\]\)\}]\s*", ".", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+at\s+", "@", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+dot\s+", ".", text, flags=re.IGNORECASE)
    return text


def _extract_domain_emails(text: str, domain: str) -> set[str]:
    """Extract validated ``local@domain`` addresses from untrusted page text.

    Deobfuscates first, then regex-matches ONLY addresses whose host equals the
    target ``domain`` (third-party vendor/gmail addresses are ignored) and gates
    every hit through _valid_email_for_domain. Returns lowercased, deduped set.
    """
    out: set[str] = set()
    if not text or not domain:
        return out
    decoded = _deobfuscate_page_text(text)
    pattern = re.compile(
        r"[a-z0-9][a-z0-9._%+-]{0,63}@" + re.escape(domain),
        re.IGNORECASE,
    )
    for match in pattern.findall(decoded):
        if len(out) >= MAX_BREACH_EMAILS:
            break
        email = match.strip().lower()
        if _valid_email_for_domain(email, domain):
            out.add(email)
    return out


def _extract_person_names(text: str) -> set[str]:
    """Heuristically extract conservative 'First Last' person names from text.

    Best-effort and intentionally conservative: requires two-to-three
    capitalized tokens, drops obvious non-name/stopword bigrams, and caps the
    result. These names are only ever turned into pattern candidates that must
    be CONFIRMED by the breach API (verify-then-keep), so false positives can
    never surface as noise.
    """
    out: set[str] = set()
    if not text:
        return out
    decoded = html.unescape(text)
    for match in PERSON_NAME_RE.finditer(decoded):
        if len(out) >= MAX_HARVEST_NAMES:
            break
        name = match.group(0).strip()
        tokens = name.split()
        if len(tokens) < 2:
            continue
        if any(t.lower() in NAME_STOPWORDS for t in tokens):
            continue
        out.add(name)
    return out


async def _scrape_host_pages(
    probe_client: httpx.AsyncClient, host: str, domain: str
) -> tuple[set[str], set[str]]:
    """Fetch a few pages of ONE host (SSRF-guarded) and harvest emails + names.

    Mirrors the subdomain-liveness probe's SSRF discipline EXACTLY: the host is
    resolved and the HTTP(S) probe only runs when a resolved IP passes
    _is_safe_public_ip (private/internal/loopback/link-local/metadata hosts are
    never fetched). Fetches go through the verify=False probe client with a
    short timeout and the MAX_RESPONSE_BYTES body cap (inside check_http). Every
    page is wrapped in try/except so one failure never aborts discovery.

    Returns (emails, names). Never raises. Never logs page content (A09).
    """
    emails: set[str] = set()
    names: set[str] = set()
    if not is_valid_hostname(host):
        return emails, names
    try:
        # SSRF gate — identical to analyze_subdomain: resolve first, and only
        # probe when at least one resolved address is a public IP. A host with
        # no A/AAAA records is skipped here (no CNAME-chain probing for scrape).
        ip_addresses, _dns_status = await resolve_dns_detailed(host)
        if not ip_addresses or not any(_is_safe_public_ip(ip) for ip in ip_addresses):
            return emails, names
    except Exception:  # noqa: BLE001 — never raise.
        return emails, names

    for path in SCRAPE_PATHS:
        for scheme in ("https", "http"):
            try:
                req = probe_client.build_request(
                    "GET", f"{scheme}://{host}{path}", timeout=SCRAPE_TIMEOUT
                )
                resp = await probe_client.send(req, stream=True)
                try:
                    raw = await _read_capped_body(resp)
                finally:
                    await resp.aclose()
                resp._content = raw if raw is not None else b""
                body = resp.text
            except Exception:  # noqa: BLE001 — per-request isolation.
                continue
            emails |= _extract_domain_emails(body, domain)
            names |= _extract_person_names(body)
            # One successful scheme per path is enough; avoid double-fetching.
            break
    return emails, names


async def _discover_hosts(verified_client: httpx.AsyncClient, domain: str) -> list[str]:
    """Return candidate hostnames for ``domain`` by REUSING the existing
    subdomain enumeration SOURCES, unioned with the root + common hosts.

    Reuses the same passive SOURCES machinery the Subdomains mode uses (so
    pages like careers./about./team. are found); each source runs in its own
    try/except and the root domain plus SCRAPE_COMMON_HOSTS are always included
    as a fallback. Validated with is_valid_hostname; capped at MAX_SCRAPE_HOSTS.
    """
    hosts: set[str] = {domain}
    for prefix in SCRAPE_COMMON_HOSTS:
        hosts.add(f"{prefix}.{domain}")

    async def _run_source(fn) -> set[str]:
        try:
            return set(await fn(verified_client, domain, {})) or set()
        except Exception:  # noqa: BLE001 — one source failing never aborts.
            return set()

    try:
        results = await asyncio.gather(
            *(_run_source(fn) for fn in SOURCES.values()),
            return_exceptions=True,
        )
        for found in results:
            if isinstance(found, set):
                hosts |= found
    except Exception:  # noqa: BLE001 — never raise.
        pass

    valid = [h for h in hosts if is_valid_hostname(h)]
    # Deterministic, bounded: prefer the root domain + shorter (more public)
    # names first so the cap keeps the most likely address-bearing pages.
    valid.sort(key=lambda h: (h != domain, len(h), h))
    return valid[:MAX_SCRAPE_HOSTS]


async def discover_emails(client: httpx.AsyncClient, domain: str) -> set[str]:
    """Best-effort email discovery at ``domain`` from crt.sh. Never raises.

    Fetches the crt.sh certificate index (same URL shape as query_crtsh) via the
    bounded _get helper, regex-extracts any ``...@{domain}`` substrings from the
    raw response text, validates each with _valid_email_for_domain, lowercases /
    dedupes, and caps the set at MAX_BREACH_EMAILS. On ANY failure it logs at
    DEBUG (job_id/domain only, never addresses) and returns what it gathered.

    This is the crt.sh-only base harvest; the strengthened keyless crawl lives
    in discover_emails_rich, which unions these results with addresses scraped
    from the domain's own live pages plus harvested names.
    """
    out: set[str] = set()
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return out
    try:
        resp = await _get(client, f"https://crt.sh/?q=%25.{domain}&output=json")
        text = resp.text or ""
        out |= _extract_domain_emails(text, domain)
    except Exception as exc:  # noqa: BLE001 — never raise.
        logger.debug("email discovery failed for %s: %s", domain, exc)
    return out


async def discover_emails_rich(
    verified_client: httpx.AsyncClient,
    probe_client: Optional[httpx.AsyncClient],
    domain: str,
    job: Optional["BreachJobState"] = None,
) -> dict:
    """Strengthened keyless discovery for a DOMAIN-ONLY breach run. Never raises.

    Unions three keyless sources and returns::

        {"discovered": set[str],  # addresses scraped from the domain's pages
                                  # (+ crt.sh) — source 'discovered'
         "names": set[str]}       # conservative person names harvested from the
                                  # same pages — fed to generate_email_patterns

    Pipeline (every stage best-effort, bounded, SSRF-safe):
      1. crt.sh base harvest (discover_emails).
      2. Reuse the EXISTING subdomain enumeration (_discover_hosts) to find the
         domain's own hosts, then fetch a BOUNDED subset of the LIVE/public ones
         (MAX_SCRAPE_HOSTS, SSRF-gated via _is_safe_public_ip, probe client,
         SCRAPE_TIMEOUT, MAX_RESPONSE_BYTES) under a low Semaphore and scrape
         mailto:/inline emails + person names.

    Role-based locals and name->pattern generation happen in run_breach so the
    verify-then-keep rule and source tagging stay in one place. ``job`` (when
    passed) has emails_discovered bumped as pages are scraped. A09: counts +
    host only, never addresses/page content.
    """
    result = {"discovered": set(), "names": set()}
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return result

    discovered: set[str] = set()
    names: set[str] = set()

    # 1. crt.sh base harvest (unchanged contract).
    try:
        discovered |= await discover_emails(verified_client, domain)
    except Exception:  # noqa: BLE001 — never raise.
        pass

    # 2. Page-scrape the domain's own hosts (the main win). Only runs when a
    #    probe client is available (always true in the live app).
    if probe_client is not None:
        try:
            hosts = await _discover_hosts(verified_client, domain)
        except Exception:  # noqa: BLE001
            hosts = [domain]

        sem = asyncio.Semaphore(SCRAPE_CONCURRENCY)

        async def _scrape(host: str) -> tuple[set[str], set[str]]:
            async with sem:
                return await _scrape_host_pages(probe_client, host, domain)

        try:
            scraped = await asyncio.gather(
                *(_scrape(h) for h in hosts),
                return_exceptions=True,
            )
        except Exception:  # noqa: BLE001
            scraped = []

        for item in scraped:
            if isinstance(item, tuple):
                page_emails, page_names = item
                discovered |= page_emails
                names |= page_names
                if job is not None:
                    job.emails_discovered = len(discovered)

    # Honor the global cap on the scraped/discovered set.
    result["discovered"] = set(list(discovered)[:MAX_BREACH_EMAILS])
    result["names"] = set(list(names)[:MAX_HARVEST_NAMES])
    return result


async def analyze_candidate(
    probe_client: httpx.AsyncClient,
    verified_client: httpx.AsyncClient,
    candidate: str,
    technique: str,
    original_title: Optional[str],
    check_whois: bool,
    sem: asyncio.Semaphore,
    rdap_sem: asyncio.Semaphore,
    brand_label: str = "",
    brand_tokens: Optional[set[str]] = None,
) -> dict:
    """Analyze one lookalike candidate. Returns a fixed-shape result dict.

    All probing happens under ``sem`` (bounded concurrency, NO unbounded
    fan-out). Flow mirrors analyze_subdomain: is_valid_hostname gate ->
    resolve_dns_detailed -> HTTP probe ONLY when a resolved IP passes
    _is_safe_public_ip (SSRF guard). MX comes from _dig_records.

    Brand resemblance (``resembles_original``) is computed by _resembles_brand
    from the original's ``brand_label`` + distinctive ``brand_tokens``: a
    candidate resembles when its registrable label contains the brand label
    (hyphens/dots ignored) OR its fetched title shares a distinctive brand
    token. If the original-title fetch failed, ``brand_tokens`` is simply empty
    and resemblance falls back to label-containment only (never raises). RDAP
    runs under ``rdap_sem`` only when ``check_whois`` is set.
    """
    if brand_tokens is None:
        brand_tokens = _brand_tokens(brand_label, original_title)
    dns_status = "ERROR"
    ip_addresses: list[str] = []
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    page_title: Optional[str] = None
    has_mx = False
    registered = "unknown"
    registrar = ""
    creation_date = ""

    async with sem:
        if not is_valid_hostname(candidate):
            return {
                "candidate": candidate,
                "technique": technique,
                "dns_status": "ERROR",
                "ip_addresses": [],
                "http_status": None,
                "https_status": None,
                "page_title": None,
                "has_mx": False,
                "registered": "unknown",
                "registrar": "",
                "creation_date": "",
                "resembles_original": False,
                "risk": "NONE",
                "recommended_action": "Invalid hostname; skipped.",
            }

        ip_addresses, dns_status = await resolve_dns_detailed(candidate)
        if dns_status == "RESOLVED":
            # SSRF guard: only probe when at least one resolved IP is public.
            if ip_addresses and not any(_is_safe_public_ip(ip) for ip in ip_addresses):
                http_status, https_status, body = None, None, ""
            else:
                http_status, https_status, body = await check_http(
                    probe_client, candidate
                )
                page_title = _extract_title(body)
            try:
                has_mx = bool(_dig_records(candidate).get("MX"))
            except Exception:  # noqa: BLE001
                has_mx = False

        if check_whois:
            async with rdap_sem:
                info = await rdap_lookup(verified_client, candidate)
            registered = info.get("registered", "unknown")
            registrar = info.get("registrar", "")
            creation_date = info.get("creation_date", "")

    resembles_original = _resembles_brand(
        candidate, page_title, brand_label, brand_tokens
    )
    live = _http_live(http_status) or _http_live(https_status)
    # Parked detection only matters for a live site; an unresolved/dead
    # candidate has no page to classify.
    parked = _is_parked(page_title) if live else False
    risk, recommended_action = score_lookalike(
        dns_status,
        http_status,
        https_status,
        has_mx,
        resembles_original,
        registered,
        parked,
    )
    return {
        "candidate": candidate,
        "technique": technique,
        "dns_status": dns_status,
        "ip_addresses": ip_addresses,
        "http_status": http_status,
        "https_status": https_status,
        "page_title": page_title,
        "has_mx": has_mx,
        "registered": registered,
        "registrar": registrar,
        "creation_date": creation_date,
        "resembles_original": resembles_original,
        "risk": risk,
        "recommended_action": recommended_action,
    }


# ---------------------------------------------------------------------------
# Takeover fingerprints
# ---------------------------------------------------------------------------
TAKEOVER_FINGERPRINTS = {
    "github.io": {"service": "GitHub Pages", "fingerprint": "There isn't a GitHub Pages site here", "severity": "HIGH"},
    "s3.amazonaws.com": {"service": "AWS S3", "fingerprint": "NoSuchBucket", "severity": "HIGH"},
    "s3-website": {"service": "AWS S3", "fingerprint": "NoSuchBucket", "severity": "HIGH"},
    "s3-accelerate": {"service": "AWS S3", "fingerprint": "NoSuchBucket", "severity": "HIGH"},
    "cloudfront.net": {"service": "AWS CloudFront", "fingerprint": "Bad request", "severity": "MEDIUM"},
    "herokudns.com": {"service": "Heroku", "fingerprint": "No such app", "severity": "HIGH"},
    "herokuapp.com": {"service": "Heroku", "fingerprint": "No such app", "severity": "HIGH"},
    "azurewebsites.net": {"service": "Azure Web Apps", "fingerprint": "404 Web Site not found", "severity": "HIGH"},
    "azure-api.net": {"service": "Azure API Management", "fingerprint": "404 Resource not found", "severity": "HIGH"},
    "trafficmanager.net": {"service": "Azure Traffic Manager", "fingerprint": "404", "severity": "MEDIUM"},
    "zendesk.com": {"service": "Zendesk", "fingerprint": "Help Center Closed", "severity": "HIGH"},
    "myshopify.com": {"service": "Shopify", "fingerprint": "Sorry, this shop is currently unavailable", "severity": "HIGH"},
    "fastly.net": {"service": "Fastly", "fingerprint": "Fastly error: unknown domain", "severity": "HIGH"},
    "pantheonsite.io": {"service": "Pantheon", "fingerprint": "404 error unknown site", "severity": "HIGH"},
    "domains.tumblr.com": {"service": "Tumblr", "fingerprint": "Whatever you were looking for doesn't currently exist", "severity": "MEDIUM"},
    "ghost.io": {"service": "Ghost", "fingerprint": "The thing you were looking for is no longer here", "severity": "HIGH"},
    "netlify.com": {"service": "Netlify", "fingerprint": "Not Found - Request ID", "severity": "HIGH"},
    "webflow.io": {"service": "Webflow", "fingerprint": "The page you are looking for doesn't exist", "severity": "HIGH"},
    "surge.sh": {"service": "Surge.sh", "fingerprint": "project not found", "severity": "HIGH"},
    "gitbook.io": {"service": "GitBook", "fingerprint": "sign in to gitbook", "severity": "MEDIUM"},
    "readme.io": {"service": "ReadMe", "fingerprint": "project not found", "severity": "HIGH"},
    "helpscoutdocs.com": {"service": "HelpScout", "fingerprint": "No settings were found", "severity": "HIGH"},
    "uservoice.com": {"service": "UserVoice", "fingerprint": "This UserVoice subdomain is currently available", "severity": "HIGH"},
    "freshdesk.com": {"service": "Freshdesk", "fingerprint": "There is no helpdesk here", "severity": "HIGH"},
    "intercom.io": {"service": "Intercom", "fingerprint": "This page doesn't exist", "severity": "HIGH"},
    "launchrock.com": {"service": "LaunchRock", "fingerprint": "It looks like you may have taken a wrong turn", "severity": "MEDIUM"},
    "unbounce.com": {"service": "Unbounce", "fingerprint": "The requested URL was not found", "severity": "HIGH"},
    "strikingly.com": {"service": "Strikingly", "fingerprint": "page not found", "severity": "MEDIUM"},
    "tilda.cc": {"service": "Tilda", "fingerprint": "page not found", "severity": "MEDIUM"},
    "wordpress.com": {"service": "WordPress", "fingerprint": "Do you want to register", "severity": "MEDIUM"},
    "squarespace.com": {"service": "Squarespace", "fingerprint": "No Such Account", "severity": "HIGH"},
    "wix.com": {"service": "Wix", "fingerprint": "Looks Like This Domain Isn't Connected To A Website Yet", "severity": "MEDIUM"},
    "desk.com": {"service": "Salesforce Desk", "fingerprint": "Please try again or try Desk.com free for 14 days", "severity": "HIGH"},
    "campaignmonitor.com": {"service": "Campaign Monitor", "fingerprint": "Double check the URL", "severity": "HIGH"},
    "cargo.site": {"service": "Cargo", "fingerprint": "If you're moving your domain away from Cargo", "severity": "MEDIUM"},
    "airee.ru": {"service": "Airee", "fingerprint": "Ошибка 402", "severity": "HIGH"},
}


# ---------------------------------------------------------------------------
# Cloud-resource CNAME targets (for the VERIFY takeover tier)
# ---------------------------------------------------------------------------
# Risk ordering used everywhere: HIGH > VERIFY > MEDIUM > LOW > NONE
# (sort weights HIGH=4, VERIFY=3, MEDIUM=2, LOW=1, NONE=0). The VERIFY tier
# sits between MEDIUM and HIGH: it flags a dangling CNAME pointing at a known
# cloud resource that returns a "gone" HTTP signal (404/503) but where no
# body fingerprint confirmed an actual takeover. It is a "confirm manually"
# signal, never a confirmed takeover — hence weaker than a fingerprint-backed
# HIGH/MEDIUM but stronger than an unconfirmed LOW.
#
# Each entry is (compiled anchored regex, provider_name). Patterns are anchored
# with \Z so they match the FULL (lowercased, trailing-dot-stripped) CNAME
# target and never a mere substring (which would create false positives such
# as "evil-amazonaws.com.attacker.net").
CLOUD_RESOURCE_PATTERNS = [
    # AWS ELB (classic + regional)
    (re.compile(r"^.+\.elb\.amazonaws\.com\Z"), "AWS ELB"),
    (re.compile(r"^.+\.elb\.[a-z0-9-]+\.amazonaws\.com\Z"), "AWS ELB"),
    # AWS S3 (global, website, and regional endpoints)
    (re.compile(r"^.+\.s3\.amazonaws\.com\Z"), "AWS S3"),
    (re.compile(r"^.+\.s3-website[.-][a-z0-9-]+\.amazonaws\.com\Z"), "AWS S3"),
    (re.compile(r"^.+\.s3\.[a-z0-9-]+\.amazonaws\.com\Z"), "AWS S3"),
    # CloudFront
    (re.compile(r"^.+\.cloudfront\.net\Z"), "AWS CloudFront"),
    # Azure
    (re.compile(r"^.+\.azurewebsites\.net\Z"), "Azure Web Apps"),
    (re.compile(r"^.+\.trafficmanager\.net\Z"), "Azure Traffic Manager"),
    (re.compile(r"^.+\.cloudapp\.azure\.com\Z"), "Azure Cloud App"),
    (re.compile(r"^.+\.blob\.core\.windows\.net\Z"), "Azure Blob Storage"),
    # Heroku
    (re.compile(r"^.+\.herokudns\.com\Z"), "Heroku"),
    (re.compile(r"^.+\.herokuapp\.com\Z"), "Heroku"),
    # GitHub Pages
    (re.compile(r"^.+\.github\.io\Z"), "GitHub Pages"),
    # GCP
    (re.compile(r"^.+\.storage\.googleapis\.com\Z"), "Google Cloud Storage"),
    (re.compile(r"^.+\.appspot\.com\Z"), "Google App Engine"),
    # Fastly
    (re.compile(r"^.+\.fastly\.net\Z"), "Fastly"),
]


# Verdict constants for the active takeover-VERIFICATION pass (FEAT-001).
# These turn the heuristic VERIFY tier into a concrete, human-readable verdict.
VERDICT_VULNERABLE = "VULNERABLE"
VERDICT_NOT_VULNERABLE = "NOT_VULNERABLE"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
# Dedicated (shorter) timeout for the single confirmation probe so a slow
# target cannot stall the bounded verification pass.
VERIFY_HTTP_TIMEOUT = 5.0


def _match_cloud_resource(target: Optional[str]) -> Optional[str]:
    """Return the cloud provider name a CNAME target points at, else None.

    ``target`` is lowercased and its trailing dot stripped, then matched with
    the anchored CLOUD_RESOURCE_PATTERNS so only a full-hostname suffix match
    counts (no substring false positives). Returns the provider name on the
    first matching pattern, or None when the target is empty/unknown.
    """
    if not target:
        return None
    host = target.strip().rstrip(".").lower()
    if not host:
        return None
    for pattern, provider in CLOUD_RESOURCE_PATTERNS:
        if pattern.match(host):
            return provider
    return None


def _recommended_action(risk: str, verdict: str, service: Optional[str]) -> str:
    """Return a short, concrete next step for a flagged subdomain.

    Derived purely from the post-verify risk/verdict/service so a flagged row
    (VERIFY/HIGH) ALWAYS has an actionable next step — never a dead end, even
    for an INCONCLUSIVE verdict. Returns '' for non-flagged rows.
    """
    svc = f" ({service})" if service else ""
    if verdict == VERDICT_VULNERABLE:
        return (
            f"Takeover confirmed{svc}: remove the dangling DNS record or reclaim "
            "the resource immediately."
        )
    if verdict == VERDICT_NOT_VULNERABLE:
        return (
            f"No takeover detected{svc}; the target appears owned. Remove the "
            "record only if the service is intentionally decommissioned."
        )
    if verdict == VERDICT_INCONCLUSIVE:
        return (
            f"Inconclusive{svc}: manually verify resource ownership in the "
            "provider console and remove the record if it is dangling."
        )
    # Flagged (VERIFY/HIGH) but no verdict text yet — still give a next step.
    if risk in ("VERIFY", "HIGH"):
        return (
            f"Investigate and verify resource ownership urgently{svc}; confirm "
            "whether the CNAME target is claimable."
        )
    return ""


# ---------------------------------------------------------------------------
# Typing
# ---------------------------------------------------------------------------
class SubdomainResult(TypedDict):
    subdomain: str
    ip_addresses: list[str]
    cname: Optional[str]
    http_status: Optional[int]
    https_status: Optional[int]
    sources: list[str]
    # Risk ordering: HIGH > VERIFY > MEDIUM > LOW > NONE (see CLOUD_RESOURCE_PATTERNS).
    takeover_risk: str  # HIGH | VERIFY | MEDIUM | LOW | NONE
    takeover_service: Optional[str]
    takeover_detail: Optional[str]
    # Active-verification verdict (FEAT-001): VULNERABLE | NOT_VULNERABLE |
    # INCONCLUSIVE, or '' for rows that were not flagged (risk not in
    # {VERIFY, HIGH}). takeover_evidence cites the exact observation.
    takeover_verdict: str
    takeover_evidence: str
    resolved: bool
    alive: bool
    dns_status: str  # RESOLVED | NXDOMAIN | NO_ANSWER | SERVFAIL | TIMEOUT | ERROR
    cname_chain: list[str]
    # Additive (FEAT-002): ALL DNS records keyed by type (A/AAAA/CNAME/MX/NS/
    # TXT/SOA). Does NOT change ip_addresses/cname/cname_chain. {} when the host
    # is invalid or resolution failed.
    dns_records: dict
    # Additive (PART 4): a concrete next step derived from the final
    # risk + verdict + service, so a flagged row is never a dead end (always
    # populated for VERIFY/HIGH rows, including INCONCLUSIVE verdicts). Empty
    # for non-flagged rows.
    recommended_action: str


@dataclass
class JobState:
    job_id: str
    domain: str
    status: str = "pending"  # pending | running | done | error
    progress: int = 0  # 0-100
    current_source: str = ""
    subdomains_found: int = 0
    source_statuses: dict = field(default_factory=dict)  # source -> pending|running|done|error
    results: list = field(default_factory=list)
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    cancelled: bool = False
    # Human-readable notes surfaced in the status endpoint (e.g. candidate-cap
    # truncation messages for active discovery). Empty for passive-only jobs.
    notes: list = field(default_factory=list)


JOBS: dict[str, JobState] = {}


@dataclass
class LookalikeJobState:
    """In-memory state for a lookalike-domain job.

    SEPARATE from JobState/JOBS: lookalike jobs have their own store and TTL
    cleanup so the subdomain path is never touched. ``results`` holds the
    per-candidate dicts returned by analyze_candidate.
    """
    job_id: str
    domain: str
    check_whois: bool
    status: str = "pending"
    progress: int = 0
    candidates_generated: int = 0
    candidates_checked: int = 0
    registered_count: int = 0
    results: list = field(default_factory=list)
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)


LOOKALIKE_JOBS: dict[str, LookalikeJobState] = {}


@dataclass
class BreachJobState:
    """In-memory state for a keyless breach-exposure job (FEAT-001).

    SEPARATE from JobState/LookalikeJobState and their stores so the subdomain
    (16-col) and lookalike (14-col) paths are never touched. ``results`` holds
    the per-email exposure dicts produced by run_breach.
    """
    job_id: str
    domain: str
    status: str = "pending"  # pending | running | done | error
    progress: int = 0  # 0-100
    emails_discovered: int = 0
    emails_checked: int = 0
    exposed_count: int = 0
    checked_clean: int = 0
    # Count of checks that ended INDETERMINATE (throttled/Cloudflare/error after
    # backoff) — reported distinctly so a "0 exposed" is never silently a
    # throttled result mistaken for "confirmed clean".
    checked_unknown: int = 0
    results: list = field(default_factory=list)
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)


BREACH_JOBS: dict[str, BreachJobState] = {}


class EnumerateRequest(BaseModel):
    domain: str
    securitytrails_key: Optional[str] = None
    shodan_key: Optional[str] = None
    c99_key: Optional[str] = None
    # Active DNS discovery (OFF by default). Omitting all of these reproduces
    # today's passive-only behavior byte-for-byte.
    active: bool = False
    # A04/API4: cap the raw wordlist string so an enormous payload cannot be
    # buffered/parsed into memory. Rejected with 422 before parsing when it
    # exceeds MAX_WORDLIST_BYTES chars; valid labels inside an accepted
    # wordlist are still post-parse capped by MAX_ACTIVE_CANDIDATES.
    wordlist: Optional[str] = Field(default=None, max_length=MAX_WORDLIST_BYTES)
    wordlist_mode: Optional[str] = "replace"  # "replace" | "append"
    permutations: bool = False


# ---------------------------------------------------------------------------
# Source helpers
# ---------------------------------------------------------------------------
def _normalize_host(host: str, domain: str) -> Optional[str]:
    """Lowercase, strip wildcards/whitespace, and keep only in-scope hosts."""
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    host = host.lstrip("*.")
    if not host or "*" in host or " " in host:
        return None
    domain = domain.lower()
    if not (host == domain or host.endswith("." + domain)):
        return None
    # API10: a hostile source can return a syntactically-invalid host (control
    # chars, overlong >63 labels, scheme/slash/@ junk, IP literals). Require the
    # strict RFC-1035 check BEFORE returning so such a value is never stored in
    # `collected` nor rendered as a `subdomain`. Scope semantics above are
    # unchanged; this only rejects malformed in-scope strings.
    if not is_valid_hostname(host):
        return None
    return host


async def _read_capped_body(resp: httpx.Response) -> Optional[bytes]:
    """Return the response body, or None if it exceeds MAX_RESPONSE_BYTES.

    API10/API4 guard: a hostile source/target streaming a huge body must not
    OOM the process. Prefer an early Content-Length rejection; otherwise read
    incrementally and abort once the cap is crossed. Returns None to signal the
    caller to treat the response as empty (never raises on oversize).
    """
    try:
        length = resp.headers.get("content-length")
        if length is not None:
            try:
                if int(length) > MAX_RESPONSE_BYTES:
                    return None
            except (TypeError, ValueError):
                pass
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                return None
            chunks.append(chunk)
        return b"".join(chunks)
    except Exception:  # noqa: BLE001 — treat any read error as empty body.
        return None


async def _get(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
    """Fetch a URL on the verified source client, bounded by SOURCE_TIMEOUT and
    MAX_RESPONSE_BYTES.

    The body is streamed and capped so a hostile source cannot return a
    multi-hundred-MB body and exhaust memory. On an oversize body the response
    content is replaced with an empty payload (``_content = b""``) so the
    caller's ``.json()``/``.text`` parsing yields empty/None and the source
    degrades to an empty result set instead of crashing.
    """
    async def _send() -> httpx.Response:
        req = client.build_request("GET", url, **kwargs)
        resp = await client.send(req, stream=True)
        try:
            body = await _read_capped_body(resp)
        finally:
            await resp.aclose()
        # httpx needs _content set to allow .text/.json() after a streamed read.
        resp._content = body if body is not None else b""
        return resp

    return await asyncio.wait_for(_send(), timeout=SOURCE_TIMEOUT)


async def query_crtsh(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    out: set[str] = set()
    try:
        # crt.sh occasionally returns an empty body or an HTML error page
        # instead of JSON under load; retry ONCE on empty/non-JSON before
        # giving up. Parse BOTH name_value (newline-delimited SAN list) AND
        # common_name from EVERY entry so the discovery is exhaustive.
        data = None
        for attempt in range(2):
            resp = await _get(client, f"https://crt.sh/?q=%25.{domain}&output=json")
            try:
                parsed = resp.json()
            except Exception:  # noqa: BLE001 — empty body / HTML error page
                parsed = None
            if parsed:
                data = parsed
                break
        for entry in data or []:
            if not isinstance(entry, dict):
                continue
            name_value = entry.get("name_value", "") or ""
            for name in name_value.split("\n"):
                norm = _normalize_host(name, domain)
                if norm:
                    out.add(norm)
            norm_cn = _normalize_host(entry.get("common_name", "") or "", domain)
            if norm_cn:
                out.add(norm_cn)
    except Exception as exc:  # noqa: BLE001
        logger.debug("crtsh failed: %s", exc)
    return out


async def query_certspotter(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    """SSLMate Cert Spotter issuances (KEYLESS, lower rate limit, no key).

    Parses the v1 issuances JSON array; each issuance object carries a
    ``dns_names`` list of covered hostnames. Content was rephrased for
    compliance with licensing restrictions.
    """
    out: set[str] = set()
    try:
        resp = await _get(
            client,
            "https://api.certspotter.com/v1/issuances"
            f"?domain={domain}&include_subdomains=true&expand=dns_names",
        )
        data = resp.json()
        if isinstance(data, list):
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                for name in entry.get("dns_names", []) or []:
                    norm = _normalize_host(name, domain)
                    if norm:
                        out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("certspotter failed: %s", exc)
    return out


async def query_threatminer(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    """ThreatMiner passive-DNS subdomains (KEYLESS). rt=5 returns subdomains."""
    out: set[str] = set()
    try:
        resp = await _get(
            client,
            f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
        )
        data = resp.json()
        if isinstance(data, dict):
            for host in data.get("results", []) or []:
                norm = _normalize_host(str(host), domain)
                if norm:
                    out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("threatminer failed: %s", exc)
    return out


async def query_subdomaincenter(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    """subdomain.center passive discovery (KEYLESS). Returns a JSON array."""
    out: set[str] = set()
    try:
        resp = await _get(client, f"https://api.subdomain.center/?domain={domain}")
        data = resp.json()
        if isinstance(data, list):
            for host in data:
                norm = _normalize_host(str(host), domain)
                if norm:
                    out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("subdomaincenter failed: %s", exc)
    return out


async def query_hackertarget(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    out: set[str] = set()
    try:
        resp = await _get(client, f"https://api.hackertarget.com/hostsearch/?q={domain}")
        text = resp.text
        if "error" in text.lower() or "api count exceeded" in text.lower():
            return out
        for line in text.splitlines():
            part = line.split(",")[0]
            norm = _normalize_host(part, domain)
            if norm:
                out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("hackertarget failed: %s", exc)
    return out


async def query_alienvault(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    out: set[str] = set()
    try:
        resp = await _get(
            client,
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        )
        data = resp.json()
        for entry in data.get("passive_dns", []):
            norm = _normalize_host(entry.get("hostname", ""), domain)
            if norm:
                out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("alienvault failed: %s", exc)
    return out


async def query_rapiddns(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    out: set[str] = set()
    try:
        resp = await _get(client, f"https://rapiddns.io/subdomain/{domain}?full=1&down=1")
        for cell in re.findall(r"<td>([^<]+)</td>", resp.text):
            norm = _normalize_host(cell, domain)
            if norm:
                out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("rapiddns failed: %s", exc)
    return out


async def query_urlscan(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    out: set[str] = set()
    try:
        resp = await _get(
            client,
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000",
        )
        data = resp.json()
        for result in data.get("results", []):
            page = result.get("page", {})
            norm = _normalize_host(page.get("domain", ""), domain)
            if norm:
                out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("urlscan failed: %s", exc)
    return out


async def query_threatcrowd(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    out: set[str] = set()
    try:
        resp = await _get(
            client,
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
        )
        data = resp.json()
        for sub in data.get("subdomains", []):
            norm = _normalize_host(sub, domain)
            if norm:
                out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("threatcrowd failed: %s", exc)
    return out


async def query_wayback(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    out: set[str] = set()
    try:
        resp = await _get(
            client,
            f"https://web.archive.org/cdx/search/cdx?url=*.{domain}"
            "&output=json&fl=original&collapse=urlkey&limit=10000",
        )
        data = resp.json()
        rows = data[1:] if data and isinstance(data[0], list) else data
        for row in rows:
            url = row[0] if isinstance(row, list) else row
            match = re.search(r"https?://([^/:]+)", str(url))
            host = match.group(1) if match else str(url)
            norm = _normalize_host(host, domain)
            if norm:
                out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("wayback failed: %s", exc)
    return out


async def query_anubis(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    out: set[str] = set()
    try:
        resp = await _get(client, f"https://jldc.me/anubis/subdomains/{domain}")
        data = resp.json()
        if isinstance(data, list):
            for sub in data:
                norm = _normalize_host(sub, domain)
                if norm:
                    out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("anubis failed: %s", exc)
    return out


async def query_bufferover(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    out: set[str] = set()
    try:
        resp = await _get(client, f"https://tls.bufferover.run/dns?q=.{domain}")
        data = resp.json()
        rows = []
        if isinstance(data, dict):
            rows = (data.get("Results") or []) + (data.get("FDNS") or []) + (data.get("RDNS") or [])
        for row in rows:
            # format: ip,subdomain  (sometimes ip,other,subdomain)
            parts = str(row).split(",")
            host = parts[-1] if parts else ""
            norm = _normalize_host(host, domain)
            if norm:
                out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("bufferover failed: %s", exc)
    return out


async def query_securitytrails(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    out: set[str] = set()
    api_key = keys.get("securitytrails_key") or os.environ.get("SECURITYTRAILS_API_KEY")
    if not api_key:
        return out
    try:
        resp = await _get(
            client,
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": api_key, "Authorization": api_key},
        )
        data = resp.json()
        for sub in data.get("subdomains", []):
            norm = _normalize_host(f"{sub}.{domain}", domain)
            if norm:
                out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("securitytrails failed: %s", exc)
    return out


async def query_shodan(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    out: set[str] = set()
    api_key = keys.get("shodan_key") or os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return out
    try:
        resp = await _get(
            client, f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        )
        data = resp.json()
        for sub in data.get("subdomains", []):
            norm = _normalize_host(f"{sub}.{domain}", domain)
            if norm:
                out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("shodan failed: %s", exc)
    return out


async def query_c99(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    out: set[str] = set()
    api_key = keys.get("c99_key") or os.environ.get("C99_API_KEY")
    if not api_key:
        return out
    try:
        resp = await _get(
            client,
            f"https://api.c99.nl/subdomainfinder?key={api_key}&domain={domain}&json",
        )
        data = resp.json()
        # Be defensive: c99 returns {"success": bool, "subdomains": [...]}.
        # On an invalid key / failed lookup success is false (or an error
        # field is present); handle that and any missing/empty list without
        # raising. Non-JSON/HTML error bodies raise in resp.json() and are
        # caught below, yielding an empty result.
        if not isinstance(data, dict) or not data.get("success"):
            return out
        for entry in data.get("subdomains") or []:
            host = entry.get("subdomain", "") if isinstance(entry, dict) else ""
            norm = _normalize_host(host, domain)
            if norm:
                out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("c99 failed: %s", exc)
    return out


SOURCES = {
    "crt.sh": query_crtsh,
    "HackerTarget": query_hackertarget,
    "AlienVault": query_alienvault,
    "RapidDNS": query_rapiddns,
    "URLScan": query_urlscan,
    "ThreatCrowd": query_threatcrowd,
    "Wayback": query_wayback,
    "Anubis": query_anubis,
    "BufferOver": query_bufferover,
    # New keyless sources (always run, no key/toggle).
    "CertSpotter": query_certspotter,
    "ThreatMiner": query_threatminer,
    "SubdomainCenter": query_subdomaincenter,
    "SecurityTrails": query_securitytrails,
    "Shodan": query_shodan,
    "c99": query_c99,
}


# ---------------------------------------------------------------------------
# Per-subdomain analysis
# ---------------------------------------------------------------------------
async def resolve_dns(host: str) -> list[str]:
    """Return the set of A/AAAA addresses for host, or [] on failure.

    Kept for backward compatibility; delegates to resolve_dns_detailed and
    discards the status so existing callers/tests see unchanged behavior.
    """
    ips, _status = await resolve_dns_detailed(host)
    return ips


# Record types enumerated for the per-subdomain DNS records listing (FEAT-002).
# Order is the display/serialization order used in the CSV cell and UI panel.
DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


# dns_status vocabulary and the risk-ordering note live together here:
# dns_status in {RESOLVED, NXDOMAIN, NO_ANSWER, SERVFAIL, TIMEOUT, ERROR}.
# Risk ordering used across the app: HIGH > VERIFY > MEDIUM > LOW > NONE
# (weights HIGH=4, VERIFY=3, MEDIUM=2, LOW=1, NONE=0).
def _dig_dns_status(host: str) -> Optional[tuple[list[str], str]]:
    """Resolve A/AAAA records and an authoritative status via the `dig` binary.

    Returns (ip_addresses, dns_status) using dig's rcode + answer section:
    NOERROR with A/AAAA answers -> RESOLVED; NOERROR with no address answer ->
    NO_ANSWER; NXDOMAIN -> NXDOMAIN; SERVFAIL -> SERVFAIL; a dig timeout ->
    TIMEOUT. Returns None when dig is unavailable/unusable so the caller can
    fall back to the stdlib resolver.

    Security: invoked with an argument LIST (never a shell string); ``host`` is
    gated by ``is_valid_hostname`` upstream and the call has a hard 5s timeout.
    """
    try:
        out = subprocess.run(
            ["dig", "+noall", "+answer", "+comments", "A", host],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        # dig not installed — signal the caller to use the stdlib fallback.
        return None
    except subprocess.TimeoutExpired:
        return [], "TIMEOUT"
    except Exception:  # noqa: BLE001
        return None

    text = out.stdout or ""
    # Extract the response rcode from the "status: XXX" header line.
    m = re.search(r"status:\s*([A-Z]+)", text)
    status_code = m.group(1) if m else None
    if status_code == "NXDOMAIN":
        return [], "NXDOMAIN"
    if status_code == "SERVFAIL":
        return [], "SERVFAIL"

    # Collect A/AAAA answers (ignore CNAME/other RR types in the answer section).
    ips: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) >= 5 and parts[3] in ("A", "AAAA"):
            addr = parts[4].strip()
            if addr and addr not in ips:
                ips.append(addr)

    if status_code == "NOERROR":
        return (ips, "RESOLVED") if ips else (ips, "NO_ANSWER")
    if status_code is None:
        # Couldn't parse a status header — let the stdlib fallback decide.
        return None
    # Any other rcode: report what we have, defaulting to NO_ANSWER when empty.
    return (ips, "RESOLVED") if ips else (ips, "NO_ANSWER")


def _socket_dns_status(host: str) -> tuple[list[str], str]:
    """stdlib-resolver fallback returning (ip_addresses, dns_status).

    Stdlib limitation: ``socket.getaddrinfo`` collapses most DNS failure modes
    into a single ``gaierror`` and cannot distinguish NXDOMAIN from SERVFAIL
    from a CNAME-only NO_ANSWER. Best-effort mapping only: EAI_NONAME /
    EAI_NODATA -> NXDOMAIN, socket.timeout -> TIMEOUT, anything else -> ERROR.
    """
    try:
        infos = socket.getaddrinfo(
            host, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.timeout:
        return [], "TIMEOUT"
    except socket.gaierror as exc:
        name_errnos = {
            getattr(socket, "EAI_NONAME", None),
            getattr(socket, "EAI_NODATA", None),
        }
        name_errnos.discard(None)
        if exc.errno in name_errnos:
            return [], "NXDOMAIN"
        return [], "ERROR"
    except Exception:  # noqa: BLE001
        return [], "ERROR"
    ips: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in ips:
            ips.append(addr)
    return (ips, "RESOLVED") if ips else (ips, "NO_ANSWER")


def _resolve_dns_detailed_sync(host: str) -> tuple[list[str], str]:
    """Prefer dig's authoritative status; fall back to the stdlib resolver."""
    dig_result = _dig_dns_status(host)
    if dig_result is not None:
        return dig_result
    return _socket_dns_status(host)


async def resolve_dns_detailed(host: str) -> tuple[list[str], str]:
    """Return (ip_addresses, dns_status), running the blocking work off-loop.

    dns_status is one of RESOLVED, NXDOMAIN, NO_ANSWER, SERVFAIL, TIMEOUT,
    ERROR. Uses `dig` when present for a precise status signal, else the stdlib
    resolver with best-effort mapping (see _socket_dns_status).
    """
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(None, _resolve_dns_detailed_sync, host)
    except Exception:  # noqa: BLE001
        return [], "ERROR"


async def _resolve_ptrs(ip_addresses: list[str]) -> list[str]:
    """Resolve PTR hostnames for a list of IPs off the event loop."""
    if not ip_addresses:
        return []
    loop = asyncio.get_running_loop()

    def _run() -> list[str]:
        hosts: list[str] = []
        for ip in ip_addresses:
            ptr = _reverse_ptr(ip)
            if ptr:
                hosts.append(ptr)
        return hosts

    try:
        return await loop.run_in_executor(None, _run)
    except Exception:  # noqa: BLE001
        return []


def _dig_cname(host: str) -> Optional[str]:
    """Resolve a CNAME via the `dig` binary (fast, authoritative when present).

    Security: the subprocess is invoked with an argument LIST (never a shell
    string, never ``shell=True``), so ``host`` cannot be interpreted as shell
    syntax. ``host`` is additionally gated by ``is_valid_hostname`` upstream
    (see ``analyze_subdomain``) and the call has a hard 5s timeout.
    """
    try:
        out = subprocess.run(
            ["dig", "+short", "CNAME", host],
            capture_output=True,
            text=True,
            timeout=5,
        )
        value = out.stdout.strip().splitlines()
        if value:
            return value[0].strip().rstrip(".").lower() or None
    except Exception:  # noqa: BLE001
        return None
    return None


def _socket_cname(host: str) -> Optional[str]:
    """Pure-Python CNAME fallback using the stdlib resolver.

    ``socket.gethostbyname_ex`` returns the canonical hostname the OS resolver
    followed to. When that canonical name differs from the queried host it is,
    in practice, the CNAME target. This requires no external binary, so CNAME
    (and CNAME-based takeover) detection still works where `dig` is absent.

    BUG 2 limitation (best-effort only): ``gethostbyname_ex`` resolves A
    records, so a DANGLING CNAME whose target has NO A record (e.g. a deleted
    CloudFront/ELB/S3 endpoint) raises ``gaierror`` and this returns None,
    losing the CNAME. That is exactly the dangling-record case we must surface.
    Mitigation: ``_resolve_cname_sync`` ALWAYS prefers ``_dig_cname`` (a
    dedicated CNAME-TYPE query that returns the CNAME RR even when the target
    has no A record) and only falls back here when ``dig`` is genuinely absent.
    The box in production has ``dig``; this stdlib path is a degraded fallback.
    """
    try:
        canonical, aliases, _ = socket.gethostbyname_ex(host)
    except Exception:  # noqa: BLE001
        return None
    canonical = (canonical or "").strip().rstrip(".").lower()
    host_norm = host.strip().rstrip(".").lower()
    if canonical and canonical != host_norm:
        return canonical
    for alias in aliases or []:
        alias_norm = (alias or "").strip().rstrip(".").lower()
        if alias_norm and alias_norm != host_norm:
            return alias_norm
    return None


def _resolve_cname_sync(host: str) -> Optional[str]:
    """Try `dig` first, then fall back to the stdlib socket resolver.

    BUG 2: dig-first is REQUIRED, not just an optimization. ``_dig_cname`` runs
    a CNAME-TYPE query, so it returns the CNAME RR even for a dangling CNAME
    whose target has no A record (NXDOMAIN-on-target). ``_socket_cname`` cannot
    see that case (it needs an A record), so a CNAME captured via dig is what
    keeps a dangling *.cloudfront.net/*.elb.* record flowing into
    _match_cloud_resource -> VERIFY -> verify_takeover.
    """
    cname = _dig_cname(host)
    if cname:
        return cname
    return _socket_cname(host)


async def resolve_cname(host: str) -> Optional[str]:
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(None, _resolve_cname_sync, host)
    except Exception:  # noqa: BLE001
        return None


# Hard cap on CNAME hops followed; stops runaway/looping chains.
MAX_CNAME_HOPS = 10


def _resolve_cname_chain_sync(host: str) -> list[str]:
    """Follow the CNAME chain (dig-first, socket fallback) up to MAX_CNAME_HOPS.

    Returns the ordered list of CNAME targets. The first element equals the
    single-hop value from _resolve_cname_sync, so cname_chain[0] always matches
    the existing `cname` field. Stops on no further CNAME, on revisiting a host
    (loop protection), or at the hop cap.
    """
    chain: list[str] = []
    seen: set[str] = set()
    current = host.strip().rstrip(".").lower()
    for _ in range(MAX_CNAME_HOPS):
        if current in seen:
            break
        seen.add(current)
        nxt = _resolve_cname_sync(current)
        if not nxt:
            break
        nxt = nxt.strip().rstrip(".").lower()
        if not nxt or nxt == current:
            break
        chain.append(nxt)
        current = nxt
    return chain


async def resolve_cname_chain(host: str) -> list[str]:
    """Async wrapper for _resolve_cname_chain_sync (runs off the event loop)."""
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(None, _resolve_cname_chain_sync, host)
    except Exception:  # noqa: BLE001
        return []


def _dig_records(host: str) -> dict[str, list[str]]:
    """Return all DNS records for ``host`` keyed by record type (FEAT-002).

    For every type in ``DNS_RECORD_TYPES`` a ``dig +noall +answer <TYPE>
    <host>`` query is run and its answer SECTION is parsed. Only answer lines
    whose TYPE column equals the queried type are kept, so a CNAME chain that
    ``dig`` echoes in the answer section does NOT leak into the A/MX/NS/TXT/SOA
    buckets. Only types that produced at least one answer appear in the
    returned dict (purely additive; never changes ip_addresses/cname/
    cname_chain).

    Why not ``dig +short``: for a host that is a CNAME, ``dig +short <TYPE>``
    follows the CNAME and prints the CNAME target hostname with no type label,
    so the target leaks into every record type. ``+noall +answer`` keeps the
    TYPE column, letting us filter by it.

    Security: the subprocess is invoked with an argument LIST (never a shell
    string, never ``shell=True``) and ``host`` is gated by
    ``is_valid_hostname`` here (returns {} for invalid hosts) with a hard 5s
    timeout per query.

    dig-absent fallback: on ``FileNotFoundError`` the stdlib resolver fills A/
    AAAA (socket.getaddrinfo) and CNAME (_socket_cname); MX/NS/TXT/SOA are left
    empty (documented stdlib limitation). This function never raises — on any
    other exception it returns whatever was gathered so far.
    """
    if not is_valid_hostname(host):
        return {}

    records: dict[str, list[str]] = {}
    try:
        for rtype in DNS_RECORD_TYPES:
            try:
                out = subprocess.run(
                    ["dig", "+noall", "+answer", rtype, host],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except FileNotFoundError:
                # dig not installed — stdlib fallback for the types it can do.
                return _socket_records(host)
            except subprocess.TimeoutExpired:
                continue
            values: list[str] = []
            for line in (out.stdout or "").splitlines():
                parsed = _parse_answer_line(line)
                if parsed is None:
                    continue
                line_type, rdata = parsed
                # Keep this line only if its answer-section TYPE matches the
                # queried type. This drops the echoed CNAME chain from every
                # other bucket (the acme.com cdn.* leak).
                if line_type != rtype:
                    continue
                # Hostname-valued record data (CNAME/NS/SOA/MX target) carries a
                # trailing dot; strip a single one for clean display. TXT and
                # A/AAAA content is preserved verbatim.
                cleaned = rdata if rtype == "TXT" else _strip_trailing_dot(rtype, rdata)
                if cleaned and cleaned not in values:
                    values.append(cleaned)
            if values:
                records[rtype] = values
    except Exception:  # noqa: BLE001 — never raise; return partial results.
        return records
    return records


# Resource-record type tokens we may encounter in a dig answer-section line.
_RR_TYPES = frozenset(DNS_RECORD_TYPES)


def _parse_answer_line(line: str) -> Optional[tuple[str, str]]:
    """Parse one ``dig +noall +answer`` answer line into (TYPE, RDATA).

    Lines look like ``NAME TTL CLASS TYPE RDATA...`` e.g.::

        cdn.acme.com.   300 IN CNAME d2nw98z1ioq9pm.cloudfront.net.
        d2nw98z1ioq9pm.cloudfront.net. 60 IN A 3.175.86.76

    Returns ``None`` for blank/comment/unparseable lines. RDATA is everything
    after the TYPE token joined by single spaces (so multi-token RDATA like
    ``10 mail.example.com.`` or a SOA record is preserved). The TYPE is located
    by finding the token after the ``IN`` class, falling back to the first
    token that is a known RR type.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith(";"):
        return None
    tokens = stripped.split()
    type_idx = -1
    # Prefer the standard shape: TYPE is the token right after the IN class.
    for i, tok in enumerate(tokens):
        if tok == "IN" and i + 1 < len(tokens):
            type_idx = i + 1
            break
    # Defensive fallback: no IN class present — take the first known RR type.
    if type_idx == -1:
        for i, tok in enumerate(tokens):
            if tok in _RR_TYPES:
                type_idx = i
                break
    if type_idx == -1 or type_idx + 1 > len(tokens) - 1:
        return None
    line_type = tokens[type_idx]
    rdata = " ".join(tokens[type_idx + 1:]).strip()
    if not rdata:
        return None
    return line_type, rdata


def _strip_trailing_dot(rtype: str, rdata: str) -> str:
    """Strip a single trailing dot from the hostname portion of ``rdata``.

    For MX the RDATA is ``<priority> <host>.`` so only the final token's
    trailing dot is removed and the priority is kept. For other hostname-valued
    types (CNAME/NS/SOA target fields) a single trailing dot on the whole value
    is removed. A/AAAA pass through unchanged (no trailing dot present).
    """
    if rtype == "MX":
        parts = rdata.split()
        if parts:
            parts[-1] = parts[-1].rstrip(".") if parts[-1].endswith(".") else parts[-1]
        return " ".join(parts)
    if rdata.endswith("."):
        return rdata[:-1]
    return rdata


def _socket_records(host: str) -> dict[str, list[str]]:
    """stdlib fallback for _dig_records: A/AAAA via getaddrinfo, CNAME via
    _socket_cname. MX/NS/TXT/SOA are unavailable without a resolver library and
    are therefore omitted (documented limitation)."""
    records: dict[str, list[str]] = {}
    a: list[str] = []
    aaaa: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for info in infos:
            family = info[0]
            addr = info[4][0]
            if family == socket.AF_INET6:
                if addr not in aaaa:
                    aaaa.append(addr)
            else:
                if addr not in a:
                    a.append(addr)
    except Exception:  # noqa: BLE001
        pass
    if a:
        records["A"] = a
    if aaaa:
        records["AAAA"] = aaaa
    try:
        cname = _socket_cname(host)
    except Exception:  # noqa: BLE001
        cname = None
    if cname:
        records["CNAME"] = [cname]
    return records


async def resolve_dns_records(host: str) -> dict[str, list[str]]:
    """Async wrapper around _dig_records, running the blocking subprocess work
    off the event loop. Returns {} on any error (never raises)."""
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(None, _dig_records, host)
    except Exception:  # noqa: BLE001
        return {}


async def check_http(client: httpx.AsyncClient, host: str) -> tuple[Optional[int], Optional[int], str]:
    """Probe http:// and https://; return (http_status, https_status, body).

    ``client`` here is the probe client (TLS verification disabled) so that
    arbitrary target subdomains presenting expired or self-signed certs do not
    produce spurious failures. It is never used for authenticated API calls.

    SSRF note: callers MUST only invoke this for hosts whose resolved IPs are
    public (see the ``_is_safe_public_ip`` gate in ``analyze_subdomain``). This
    function does not re-resolve, so the IP-range guard lives at the single
    call site to avoid a resolve/connect TOCTOU window.
    """
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    body = ""
    for scheme in ("http", "https"):
        try:
            # Stream + cap the probe body (API10/API4): a hostile target must
            # not OOM the process with a huge body. The status code is still
            # recorded; an oversize body is dropped (treated as empty) so
            # fingerprint matching simply finds nothing rather than crashing.
            req = client.build_request(
                "GET", f"{scheme}://{host}", timeout=HTTP_PROBE_TIMEOUT
            )
            resp = await client.send(req, stream=True)
            try:
                raw = await _read_capped_body(resp)
            finally:
                await resp.aclose()
            resp._content = raw if raw is not None else b""
            if scheme == "http":
                http_status = resp.status_code
            else:
                https_status = resp.status_code
            body += resp.text
        except Exception:  # noqa: BLE001
            continue
    return http_status, https_status, body


def _reverse_ptr(ip: str) -> Optional[str]:
    """Best-effort reverse DNS for an IP, used to surface A-record takeover
    vectors (a dangling record resolving to a deprovisioned cloud host whose
    PTR still names the service domain). Returns None on failure."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
    except Exception:  # noqa: BLE001
        return None
    return (host or "").strip().rstrip(".").lower() or None


def check_takeover(
    subdomain: str,
    cname: Optional[str],
    a_records: list[str],
    http_body: str,
    ptr_hosts: Optional[list[str]] = None,
    http_status: Optional[int] = None,
    https_status: Optional[int] = None,
    cname_chain: Optional[list[str]] = None,
) -> tuple[str, Optional[str], Optional[str]]:
    """Return (risk, service, detail).

    Two-signal logic: a known service domain must appear in the CNAME, the
    subdomain name, or an A-record's reverse-DNS hostname, and the service
    fingerprint string must be present in the HTTP body to confirm a
    HIGH/MEDIUM finding. A service match without a body confirmation is
    downgraded to LOW.

    ``a_records`` lets A-record-only takeover vectors (dangling cloud IP with
    no CNAME) be scored: each IP's PTR hostname is matched against the
    fingerprint keys so the service can still be identified without a CNAME.
    ``ptr_hosts`` may be passed pre-resolved (so the blocking reverse-DNS stays
    off the event loop); when omitted the PTRs are resolved inline.

    VERIFY tier (precedence HIGH > VERIFY > MEDIUM > LOW > NONE): if the
    fingerprint loop did NOT already return a HIGH/MEDIUM/LOW finding, and the
    final CNAME-chain target points at a known cloud resource
    (CLOUD_RESOURCE_PATTERNS) while the HTTP signal looks "gone" (http_status
    or https_status in {404, 503}, or both statuses None alongside a
    cloud-resource CNAME), return a VERIFY finding. VERIFY NEVER overrides an
    earlier HIGH/MEDIUM fingerprint match — it only fires when the stronger
    check did not. It uses ONLY already-gathered data (CNAME string + the
    HTTP statuses passed in) and issues NO new network request.
    """
    body_lower = (http_body or "").lower()
    cname_lower = (cname or "").lower()
    sub_lower = subdomain.lower()

    # Reverse-resolve A records once so an IP-only dangling record can match.
    if ptr_hosts is None:
        ptr_hosts = []
        for ip in a_records or []:
            ptr = _reverse_ptr(ip)
            if ptr:
                ptr_hosts.append(ptr)

    # A confirmed HIGH/MEDIUM fingerprint match returns immediately. A
    # service match WITHOUT body confirmation is a LOW; we hold (do not return)
    # the first such LOW so the VERIFY tier below can supersede it when the
    # dangling-cloud-resource signal holds (precedence HIGH > VERIFY > LOW).
    held_low: Optional[tuple[str, Optional[str], Optional[str]]] = None
    for key, meta in TAKEOVER_FINGERPRINTS.items():
        via_cname = key in cname_lower
        via_name = sub_lower.endswith(key)
        matched_ptr = next((p for p in ptr_hosts if key in p), None)
        matched = via_cname or via_name or matched_ptr is not None
        if not matched:
            continue
        fingerprint = meta["fingerprint"].lower()
        if fingerprint and fingerprint in body_lower:
            detail = (
                f"{meta['service']} fingerprint matched: "
                f"\"{meta['fingerprint']}\""
            )
            return meta["severity"], meta["service"], detail
        # Service matched (CNAME / host / A-record PTR) but body did not
        # confirm → low confidence. Remember only the first such match.
        if held_low is None:
            if matched_ptr and not via_cname and not via_name:
                pointer = f"A-record {matched_ptr}"
            else:
                pointer = "CNAME/host"
            held_low = (
                "LOW",
                meta["service"],
                f"{pointer} points to {meta['service']} but no takeover fingerprint confirmed",
            )

    # VERIFY tier — evaluated AFTER the fingerprint loop and only when no
    # HIGH/MEDIUM already returned (those return above). Precedence
    # HIGH > VERIFY > MEDIUM > LOW > NONE: VERIFY may supersede a held LOW
    # (e.g. an AWS CNAME that only matched the broad "amazonaws.com" key) but
    # NEVER a confirmed HIGH/MEDIUM. The final CNAME-chain target must point at
    # a known cloud resource AND the HTTP signal must look "gone" — either an
    # explicit 404/503, or no HTTP response at all (both statuses None and no
    # body gathered). A live host returning real content stays LOW. Uses ONLY
    # already-gathered data (CNAME chain + the HTTP statuses passed in) and
    # issues NO new network request.
    # BUG 2: a host whose HTTP or HTTPS probe returns a healthy status is LIVE
    # and claimed, so it is NEVER assigned a VERIFY/takeover risk purely from a
    # service match. "Healthy" = any 2xx, or a normal (non-takeover-signature)
    # redirect 301/302/307/308. When alive, a legitimately-detected cloud
    # resource is returned as LOW so the row still flows through the
    # cloud_low -> verify_takeover path and renders a concrete NOT_VULNERABLE
    # verdict — never a VERIFY flag and never an INCONCLUSIVE "remove if
    # dangling" action. The dangling signal (404/503/no-response) is unchanged.
    def _is_healthy(status: Optional[int]) -> bool:
        return status is not None and (
            200 <= status < 300 or status in (301, 302, 307, 308)
        )

    http_alive = _is_healthy(http_status) or _is_healthy(https_status)

    chain = cname_chain or []
    final_target = chain[-1] if chain else cname
    provider = _match_cloud_resource(final_target)
    if provider is not None:
        gone_signal = http_status in (404, 503) or https_status in (404, 503)
        no_response = (
            http_status is None
            and https_status is None
            and not (http_body or "").strip()
        )
        # A live cloud host (healthy 2xx/redirect) is claimed, not dangling.
        # It is still a real cloud resource, so return LOW (not VERIFY): the
        # cloud_low path routes it into verify_takeover for a concrete
        # NOT_VULNERABLE verdict. ELB is included — a live ELB is owned, never
        # a flag.
        if http_alive:
            target_display = (final_target or "").strip().rstrip(".").lower()
            detail = (
                f"CNAME points to {provider} ({target_display}) and the host is "
                "live (healthy HTTP response) — the resource is claimed; confirm "
                "ownership only if decommissioning."
            )
            return "LOW", provider, detail
        # AWS ELB/ALB CNAMEs reach the verify pass when NOT live: the ELB name
        # is AWS-assigned (not attacker-claimable), and routing a non-live ELB
        # into verify_takeover yields a concrete verdict instead of a bare LOW
        # with an empty verdict.
        if provider == "AWS ELB":
            target_display = (final_target or "").strip().rstrip(".").lower()
            detail = (
                f"CNAME points to an AWS ELB/ALB ({target_display}). The ELB name "
                "is AWS-assigned (not attacker-claimable); confirm the load "
                "balancer still exists and is owned by you before assuming it is "
                "safe."
            )
            return "VERIFY", provider, detail
        if gone_signal or no_response:
            if gone_signal:
                status_val = (
                    http_status if http_status in (404, 503) else https_status
                )
                status_text = str(status_val)
            else:
                status_text = "no HTTP response"
            target_display = (final_target or "").strip().rstrip(".").lower()
            detail = (
                f"Dangling CNAME to {provider} ({target_display}) returning "
                f"{status_text} — confirm the resource still exists and is "
                "owned by you before assuming it is safe."
            )
            return "VERIFY", provider, detail

    # CloudFront A-record VERIFY tier. A host served DIRECTLY by CloudFront A
    # records (no *.cloudfront.net CNAME — the PTR of the edge IP is what
    # identifies the provider) is still a takeover candidate: a CloudFront
    # alias is attacker-claimable when NO distribution owns it, and that is
    # decided by probing the ALIAS (this subdomain), not the edge IP's PTR.
    # Unlike S3/ELB (whose target names are not attacker-choosable here, so an
    # A-record-only match stays LOW), CloudFront's alias claimability is
    # verifiable, so we route it into verify_takeover for a concrete verdict
    # instead of dropping it at LOW. This fires ONLY when no CNAME-based VERIFY
    # or HIGH/MEDIUM fingerprint already returned above, and only for a
    # CloudFront A-record PTR (not S3/ELB/etc.), so existing LOW behavior for
    # those providers is unchanged. The verify pass decides VULNERABLE vs
    # NOT_VULNERABLE on the alias's own response signature.
    if provider is None and not (chain or cname):
        cf_ptr = next(
            (p for p in ptr_hosts if _match_cloud_resource(p) == "AWS CloudFront"),
            None,
        )
        if cf_ptr is not None:
            # A live (healthy) CloudFront alias is claimed by a distribution, so
            # it is never a VERIFY flag — return LOW so it still routes through
            # verify_takeover for a concrete NOT_VULNERABLE verdict. Only a
            # non-live alias remains a VERIFY candidate.
            if http_alive:
                detail = (
                    "Served directly by AWS CloudFront edge IPs "
                    f"(PTR {cf_ptr}) with no CNAME and the host is live "
                    "(healthy HTTP response) — a distribution claims this alias."
                )
                return "LOW", "AWS CloudFront", detail
            detail = (
                "Served directly by AWS CloudFront edge IPs "
                f"(PTR {cf_ptr}) with no CNAME — verify a CloudFront "
                "distribution still claims this alias; an unclaimed alias is "
                "attacker-registerable."
            )
            return "VERIFY", "AWS CloudFront", detail

    if held_low is not None:
        return held_low
    return "NONE", None, None


async def verify_takeover(
    result: SubdomainResult,
    probe_client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
) -> dict:
    """Active confirmation pass for a flagged (VERIFY/HIGH) takeover candidate.

    Turns the heuristic risk tier into a concrete verdict with evidence:
    {'verdict': VULNERABLE|NOT_VULNERABLE|INCONCLUSIVE, 'evidence': <str>}.
    Non-flagged rows (risk not in {VERIFY, HIGH}) get {'verdict':'','evidence':''}.

    Security invariants (identical to analyze_subdomain):
      * Resolve-then-guard: resolve the final CNAME target's own DNS and only
        probe when at least one resolved IP satisfies _is_safe_public_ip. If
        the target resolved to IP(s) but none are public, the probe is SKIPPED
        and the verdict is INCONCLUSIVE (SSRF guard).
      * Every probe is bounded by the SAME semaphore passed in (no new
        semaphore, no unbounded fan-out) and uses VERIFY_HTTP_TIMEOUT.
      * The whole body is wrapped in try/except — this function NEVER raises;
        any error becomes an INCONCLUSIVE verdict noting the error.

    The per-provider decision follows the GENERAL RULE: VULNERABLE requires
    either a provider "resource-does-not-exist"/claimable signature, or the
    target hostname being NXDOMAIN for a user-chosen-name provider (S3, GitHub
    Pages, Heroku, Azure sites, GCP, Fastly). ELB/CloudFront names are NOT
    attacker-choosable, so they prefer NOT_VULNERABLE/INCONCLUSIVE.
    """
    risk = result.get("takeover_risk")
    # Flagged candidates (VERIFY/HIGH) always run the active pass. A LOW row is
    # normally non-actionable and gets an empty verdict — EXCEPT a LOW that was
    # produced by cloud-resource detection (a non-empty takeover_service, e.g.
    # the held_low S3/ELB A-record-PTR path). Such a row names a detected cloud
    # service, so it must END in a concrete verdict, never a dead-end empty one.
    # Routing it here lets the per-provider branch render NOT_VULNERABLE /
    # VULNERABLE / INCONCLUSIVE instead of leaving takeover_verdict empty.
    cloud_low = risk == "LOW" and bool(result.get("takeover_service"))
    if risk not in ("VERIFY", "HIGH") and not cloud_low:
        return {"verdict": "", "evidence": ""}

    try:
        chain = result.get("cname_chain") or []
        cname = result.get("cname")
        final_target = chain[-1] if chain else cname
        provider = _match_cloud_resource(final_target)
        # A-record cloud detection: the host was identified as a cloud resource
        # from an edge IP's PTR (check_takeover) with NO CNAME target, so
        # final_target is empty and _match_cloud_resource gave None. Recover the
        # provider from the detected takeover_service and probe the ALIAS (this
        # subdomain) directly — CloudFront claimability, and any provider's live
        # response, is decided by probing the alias, not the edge IP's PTR. This
        # never changes the CNAME-based path (final_target is set there). It is
        # what keeps an A-record cloud row (CloudFront bimi, or a held-LOW S3/ELB
        # PTR) from ending with an empty verdict.
        # provider_from_cname is True only when the provider was derived from an
        # actual CNAME target that matched a cloud pattern. The "user-chosen
        # bucket/site name is attacker-registerable" logic (S3 NXDOMAIN =>
        # VULNERABLE, S3-specific wording) is ONLY valid in that case. For an
        # A-record host whose provider was recovered from the edge IP's PTR
        # (below), the subdomain is NOT a bucket/site name, so that reasoning
        # and S3-specific wording must NOT be applied (user note: a Lightsail/
        # Bitnami A-record host was wrongly labeled "Inconclusive (AWS S3)").
        provider_from_cname = provider is not None
        detected_service = result.get("takeover_service")
        if provider is None and not final_target and detected_service:
            provider = detected_service
            final_target = result.get("subdomain")
        # Strip the trailing dot (and whitespace) ONCE up front and resolve/
        # probe the clean name. A trailing-dotted CNAME target (e.g.
        # "...elb.amazonaws.com.") otherwise fails resolution and never maps to
        # RESOLVED — the ELB-verdict bug. _match_cloud_resource already strips.
        final_target_norm = (final_target or "").strip().rstrip(".")
        target_display = final_target_norm.lower()

        # Resolve the TARGET's own DNS (NXDOMAIN-of-target is the key signal
        # for user-chosen-name providers).
        if final_target_norm:
            target_ips, target_dns_status = await resolve_dns_detailed(final_target_norm)
        else:
            target_ips, target_dns_status = [], "ERROR"

        target_nxdomain = target_dns_status == "NXDOMAIN"
        target_resolved = target_dns_status == "RESOLVED"
        # True iff at least one resolved IP is a public/routable address.
        target_has_public_ip = any(_is_safe_public_ip(ip) for ip in target_ips)

        # SSRF guard: if the target resolved to IP(s) and NONE are public, the
        # target points only at private/internal/metadata space — do NOT probe
        # and report INCONCLUSIVE early (unchanged behavior).
        probe_blocked = bool(target_ips) and not target_has_public_ip

        # SSRF rebinding guard (A10/API7): a CNAME-only target with NO resolved
        # public IP (empty target_ips, or NXDOMAIN/ERROR) must NOT be probed by
        # hostname — httpx would re-resolve at connect, re-opening a DNS-
        # rebinding / internal-reach window. We therefore SKIP the probe when
        # there is no public IP, but (unlike probe_blocked) we do NOT early-
        # return: the per-provider branches below still decide on DNS evidence
        # (e.g. NXDOMAIN of a user-chosen-name target => VULNERABLE). This keeps
        # existing DNS-based verdicts intact while never reaching an internal
        # host via a probe.
        #
        # Residual: a small resolve->connect TOCTOU window remains for the
        # probed case — we resolve here, then httpx re-resolves at connect, so a
        # hostile resolver could flip the answer between the two. Fully
        # eliminating it needs a pinned-IP transport; documented in the audit as
        # an accepted residual risk.
        probe_allowed = target_has_public_ip

        http_status: Optional[int] = None
        https_status: Optional[int] = None
        body = ""
        probed = False
        # Captures a probe-local failure (never a bare empty str()). Folded into
        # the status-is-None INCONCLUSIVE evidence so a real failure is
        # diagnosable instead of silently masked.
        probe_error: Optional[str] = None
        if probe_blocked:
            return {
                "verdict": VERDICT_INCONCLUSIVE,
                "evidence": (
                    f"Probe of target {target_display or final_target_norm} skipped by "
                    "the SSRF guard (target resolves only to private/internal/"
                    "metadata addresses); cannot confirm takeover remotely."
                ),
            }

        # Probe the target endpoint, bounded by the shared semaphore. Only
        # probed when the target resolved to a PUBLIC IP (probe_allowed); a
        # CNAME-only / no-public-IP target is NOT probed (SSRF rebinding guard)
        # and the per-provider branch decides on DNS evidence alone.
        #
        # BUG 1: this probe is wrapped in its OWN try/except so a probe failure
        # (asyncio.TimeoutError / socket.gaierror / httpx.ConnectError — all of
        # which have an EMPTY str()) does NOT propagate to the outer catch-all
        # and get stringified into "Verification could not complete (error: )".
        # On failure we leave status None and let the per-provider branch decide
        # on DNS evidence alone (e.g. a resolving ELB -> NOT_VULNERABLE even when
        # it refuses a bare HTTP probe). The failure is recorded in probe_error.
        if final_target_norm and probe_allowed:
            try:
                async with sem:
                    http_status, https_status, body = await asyncio.wait_for(
                        check_http(probe_client, final_target_norm),
                        timeout=VERIFY_HTTP_TIMEOUT,
                    )
                probed = True
            except Exception as probe_exc:  # noqa: BLE001 — never re-raise.
                http_status, https_status, body = None, None, ""
                probed = False
                probe_error = f"{type(probe_exc).__name__}: {probe_exc!r}"

        body_lower = (body or "").lower()
        status = http_status if http_status is not None else https_status
        obs = (
            f"target={target_display or final_target_norm}, "
            f"dns={target_dns_status}, "
            f"http_status={http_status}, https_status={https_status}"
        )

        # ---- Per-provider decision ------------------------------------
        if provider == "AWS S3" and not provider_from_cname:
            # The "AWS S3" label here came from an A-record PTR heuristic, NOT a
            # real *.s3[...].amazonaws.com CNAME target. The subdomain is a plain
            # A-record host (e.g. a Lightsail/Bitnami/EC2 instance whose edge-IP
            # PTR merely lives under amazonaws.com), so S3 bucket-name reasoning
            # and S3-specific wording do NOT apply. Give a provider-neutral
            # verdict from the alias's own liveness/DNS instead.
            if status == 200 or (200 <= (status or 0) < 400):
                return {
                    "verdict": VERDICT_NOT_VULNERABLE,
                    "evidence": (
                        "A-record host is live (healthy HTTP response) — the "
                        f"resource is in use and claimed ({obs})."
                    ),
                }
            if target_nxdomain:
                return {
                    "verdict": VERDICT_INCONCLUSIVE,
                    "evidence": (
                        "A-record host no longer resolves (NXDOMAIN). This is a "
                        "plain compute/instance address, not an attacker-choosable "
                        "resource name — manually verify ownership of the "
                        f"underlying instance in the cloud provider console ({obs})."
                    ),
                }
            return {
                "verdict": VERDICT_INCONCLUSIVE,
                "evidence": (
                    "A-record host gave no decisive signal. This is a plain "
                    "compute/instance address (e.g. Lightsail/Bitnami/EC2), not "
                    "an attacker-choosable resource name — manually verify "
                    f"ownership of the instance in the provider console ({obs})."
                    + (f" [probe_error: {probe_error}]" if probe_error else "")
                ),
            }

        if provider == "AWS S3":
            if "nosuchbucket" in body_lower:
                return {
                    "verdict": VERDICT_VULNERABLE,
                    "evidence": (
                        "AWS S3 bucket returned 'NoSuchBucket' — the bucket name "
                        f"is unclaimed and attacker-registerable ({obs})."
                    ),
                }
            if "accessdenied" in body_lower or status == 200:
                return {
                    "verdict": VERDICT_NOT_VULNERABLE,
                    "evidence": (
                        "AWS S3 target serves content/AccessDenied — the bucket "
                        f"exists and is owned ({obs})."
                    ),
                }
            if target_nxdomain:
                return {
                    "verdict": VERDICT_VULNERABLE,
                    "evidence": (
                        "AWS S3 target hostname is NXDOMAIN for a user-chosen "
                        f"bucket name — re-registerable by an attacker ({obs})."
                    ),
                }
            return {
                "verdict": VERDICT_INCONCLUSIVE,
                "evidence": (
                    "AWS S3 target gave no decisive NoSuchBucket/AccessDenied/200 "
                    f"signal — confirm bucket ownership in AWS ({obs})."
                ),
            }

        if provider == "AWS ELB":
            if target_resolved:
                return {
                    "verdict": VERDICT_NOT_VULNERABLE,
                    "evidence": (
                        "AWS ELB target still resolves. An ELB DNS name is NOT "
                        "attacker-choosable (unlike S3/GitHub) — it is assigned by "
                        "AWS, so a dangling CNAME to it is likely an internal/down "
                        "service (503 = no healthy targets), not a takeover. "
                        f"Confirm ownership in AWS ({obs})."
                    ),
                }
            if target_nxdomain:
                return {
                    "verdict": VERDICT_INCONCLUSIVE,
                    "evidence": (
                        "ELB target no longer resolves; cannot be re-registered by "
                        "an attacker via a chosen name, but confirm in AWS "
                        f"({obs})."
                    ),
                }
            # The ELB branch handles its OWN resolution errors locally (never
            # the outer catch-all): a resolver timeout/SERVFAIL/ERROR is a
            # transient DNS condition, not a takeover. Report a SPECIFIC,
            # retriable message distinct from the generic indeterminate case.
            if target_dns_status in ("TIMEOUT", "ERROR", "SERVFAIL"):
                return {
                    "verdict": VERDICT_INCONCLUSIVE,
                    "evidence": (
                        "ELB target resolution did not complete "
                        f"(status={target_dns_status}); retry or verify ownership "
                        f"in AWS ({obs})."
                        + (f" [probe_error: {probe_error}]" if probe_error else "")
                    ),
                }
            return {
                "verdict": VERDICT_INCONCLUSIVE,
                "evidence": (
                    "AWS ELB target gave an indeterminate signal; ELB names are not "
                    f"attacker-claimable — confirm ownership in AWS ({obs})."
                    + (f" [probe_error: {probe_error}]" if probe_error else "")
                ),
            }

        if provider == "AWS CloudFront":
            # Active no-distribution detection. CloudFront serves a distinctive
            # error page ("The request could not be satisfied") when the CNAME
            # points at *.cloudfront.net but NO distribution claims that alias —
            # the dangling alias is then attacker-claimable. check_http discards
            # response headers, so we detect from the BODY signature + status
            # (the X-Cache/Via header path is intentionally not plumbed here).
            no_distribution_sig = (
                "the request could not be satisfied" in body_lower
                or (
                    "bad request" in body_lower
                    and status in (400, 403, 404)
                )
            )
            if not probed:
                reason = (
                    f"probe failed ({probe_error})"
                    if probe_error
                    else "no final target to probe"
                )
                return {
                    "verdict": VERDICT_INCONCLUSIVE,
                    "evidence": (
                        f"AWS CloudFront target could not be probed ({reason}) — "
                        "manually verify the distribution in the AWS CloudFront "
                        f"console ({obs})."
                    ),
                }
            if no_distribution_sig:
                return {
                    "verdict": VERDICT_VULNERABLE,
                    "evidence": (
                        f"AWS CloudFront no-distribution signature observed "
                        f"(status={status}, body: 'The request could not be "
                        "satisfied'). The CNAME points at a *.cloudfront.net alias "
                        "that no distribution claims — an attacker can create a "
                        "CloudFront distribution with this alias and take it over. "
                        "Recommended action: remove the dangling CNAME or claim "
                        f"the alias on an owned distribution immediately ({obs})."
                    ),
                }
            if status in (200, 301, 302):
                return {
                    "verdict": VERDICT_NOT_VULNERABLE,
                    "evidence": (
                        "AWS CloudFront target served a healthy response "
                        f"(status={status}) — the distribution exists and is "
                        f"owned ({obs})."
                    ),
                }
            if status is None:
                return {
                    "verdict": VERDICT_INCONCLUSIVE,
                    "evidence": (
                        "AWS CloudFront probe timed out / was blocked with no "
                        "status. Recommended action: manually verify the "
                        f"distribution alias in the AWS CloudFront console ({obs})."
                        + (f" [probe_error: {probe_error}]" if probe_error else "")
                    ),
                }
            # A bare 403/404 (or other app error) WITHOUT the no-distribution
            # signature is NOT a takeover — do not false-positive.
            return {
                "verdict": VERDICT_INCONCLUSIVE,
                "evidence": (
                    f"AWS CloudFront returned status={status} without the "
                    "no-distribution signature — not a confirmed takeover. "
                    "Recommended action: manually verify the distribution in the "
                    f"AWS CloudFront console ({obs})."
                ),
            }

        if provider == "GitHub Pages":
            if "there isn't a github pages site here" in body_lower:
                return {
                    "verdict": VERDICT_VULNERABLE,
                    "evidence": (
                        "GitHub Pages returned \"There isn't a GitHub Pages site "
                        "here\" — the repository/pages name is unclaimed and "
                        f"attacker-registerable ({obs})."
                    ),
                }
            if target_nxdomain:
                return {
                    "verdict": VERDICT_VULNERABLE,
                    "evidence": (
                        "GitHub Pages target hostname is NXDOMAIN for a user-chosen "
                        f"name — claimable by an attacker ({obs})."
                    ),
                }
            return {
                "verdict": VERDICT_NOT_VULNERABLE,
                "evidence": (
                    "GitHub Pages target serves a site (no 'no site here' "
                    f"signature) — appears owned ({obs})."
                ),
            }

        if provider == "Heroku":
            if "no such app" in body_lower:
                return {
                    "verdict": VERDICT_VULNERABLE,
                    "evidence": (
                        "Heroku returned 'No such app' — the app name is unclaimed "
                        f"and attacker-registerable ({obs})."
                    ),
                }
            if target_nxdomain:
                return {
                    "verdict": VERDICT_VULNERABLE,
                    "evidence": (
                        "Heroku target hostname is NXDOMAIN for a user-chosen app "
                        f"name — claimable by an attacker ({obs})."
                    ),
                }
            return {
                "verdict": VERDICT_NOT_VULNERABLE,
                "evidence": (
                    "Heroku target responded without a 'No such app' signature — "
                    f"appears owned ({obs})."
                ),
            }

        if provider in (
            "Azure Web Apps",
            "Azure Cloud App",
            "Azure Traffic Manager",
            "Azure Blob Storage",
        ):
            azure_404_sig = (
                "404 web site not found" in body_lower
                or "error 404 - web app not found" in body_lower
                or "the specified blob does not exist" in body_lower
                or "web app not found" in body_lower
            )
            if target_nxdomain and (azure_404_sig or status == 404):
                return {
                    "verdict": VERDICT_VULNERABLE,
                    "evidence": (
                        f"{provider} target is NXDOMAIN for a user-chosen name and "
                        "returns a known not-found signature — claimable by an "
                        f"attacker ({obs})."
                    ),
                }
            if azure_404_sig or status == 404:
                return {
                    "verdict": VERDICT_INCONCLUSIVE,
                    "evidence": (
                        f"{provider} returned a not-found signature but the target "
                        "name still resolves — confirm the resource exists and is "
                        f"owned in Azure ({obs})."
                    ),
                }
            return {
                "verdict": VERDICT_NOT_VULNERABLE,
                "evidence": (
                    f"{provider} target responded without a claimable not-found "
                    f"signature — appears owned ({obs})."
                ),
            }

        if provider in ("Google Cloud Storage", "Google App Engine"):
            gcp_sig = (
                "nosuchbucket" in body_lower
                or "the specified bucket does not exist" in body_lower
                or "requested url was not found" in body_lower
            )
            if gcp_sig:
                return {
                    "verdict": VERDICT_VULNERABLE,
                    "evidence": (
                        f"{provider} returned a resource-not-found signature — the "
                        f"name is unclaimed and attacker-registerable ({obs})."
                    ),
                }
            if target_nxdomain:
                return {
                    "verdict": VERDICT_VULNERABLE,
                    "evidence": (
                        f"{provider} target hostname is NXDOMAIN for a user-chosen "
                        f"name — claimable by an attacker ({obs})."
                    ),
                }
            return {
                "verdict": VERDICT_NOT_VULNERABLE,
                "evidence": (
                    f"{provider} target responded without a not-found signature — "
                    f"appears owned ({obs})."
                ),
            }

        if provider == "Fastly":
            if "fastly error: unknown domain" in body_lower:
                return {
                    "verdict": VERDICT_VULNERABLE,
                    "evidence": (
                        "Fastly returned 'Fastly error: unknown domain' — the "
                        f"domain is unconfigured and attacker-claimable ({obs})."
                    ),
                }
            if target_nxdomain:
                return {
                    "verdict": VERDICT_VULNERABLE,
                    "evidence": (
                        "Fastly target hostname is NXDOMAIN for a user-chosen name "
                        f"— claimable by an attacker ({obs})."
                    ),
                }
            return {
                "verdict": VERDICT_NOT_VULNERABLE,
                "evidence": (
                    "Fastly target responded without an 'unknown domain' signature "
                    f"— appears owned ({obs})."
                ),
            }

        # default / unknown provider: list observations only.
        probe_note = "probed target" if probed else "no target probed"
        return {
            "verdict": VERDICT_INCONCLUSIVE,
            "evidence": (
                f"No provider-specific takeover signature available ({probe_note}). "
                f"Observations: {obs}. Manually confirm resource ownership."
                + (f" [probe_error: {probe_error}]" if probe_error else "")
            ),
        }
    except Exception as exc:  # noqa: BLE001
        # BUG 1: NEVER stringify a bare exception whose str() is empty (e.g.
        # asyncio.TimeoutError, socket.gaierror, httpx.ConnectError('')) — that
        # produced the opaque "Verification could not complete (error: )."
        # evidence. Record the exception TYPE and repr so the evidence is always
        # a non-empty, diagnosable string.
        return {
            "verdict": VERDICT_INCONCLUSIVE,
            "evidence": (
                f"Verification could not complete "
                f"(error: {type(exc).__name__}: {exc!r})."
            ),
        }


async def analyze_subdomain(
    probe_client: httpx.AsyncClient, sub: str, sources: list[str], sem: asyncio.Semaphore
) -> SubdomainResult:
    # Hostname gate: subdomains arrive from untrusted third-party passive-DNS
    # sources. Only strictly-valid RFC-1035 hostnames reach `dig`/HTTP probes.
    if not is_valid_hostname(sub):
        return SubdomainResult(
            subdomain=sub,
            ip_addresses=[],
            cname=None,
            http_status=None,
            https_status=None,
            sources=sorted(sources),
            takeover_risk="NONE",
            takeover_service=None,
            takeover_detail=None,
            takeover_verdict="",
            takeover_evidence="",
            resolved=False,
            alive=False,
            dns_status="ERROR",
            cname_chain=[],
            dns_records={},
            recommended_action="",
        )

    async with sem:
        ip_addresses, dns_status = await resolve_dns_detailed(sub)
        # BUG 2: resolve the CNAME chain INDEPENDENTLY of dns_status and NEVER
        # clear it when dns_status is NXDOMAIN/NO_ANSWER. A dangling CNAME (the
        # subdomain has no A record but still CNAMEs to a cloud provider whose
        # resource was deleted) is the whole point of takeover detection: the
        # captured cname/cname_chain is what lets check_takeover flag VERIFY and
        # verify_takeover render a verdict. resolve_cname_chain uses a dedicated
        # dig CNAME-TYPE query, so it returns the CNAME RR even with no A record.
        cname_chain = await resolve_cname_chain(sub)
        cname = cname_chain[0] if cname_chain else await resolve_cname(sub)
        # Additive (FEAT-002): enumerate ALL DNS record types for this host,
        # reusing the SAME semaphore-bound block (no new concurrency).
        dns_records = await resolve_dns_records(sub)
        # SSRF guard: never probe a host that resolves to a private/internal/
        # loopback/link-local/metadata address. If the host resolved to IP(s)
        # but none are public, skip the HTTP probe entirely (status stays None,
        # alive=False). Hosts with no A/AAAA records (CNAME-only) are probed via
        # their CNAME chain, which httpx re-resolves at connect time.
        if ip_addresses and not any(_is_safe_public_ip(ip) for ip in ip_addresses):
            http_status, https_status, body = None, None, ""
        else:
            http_status, https_status, body = await check_http(probe_client, sub)
        ptr_hosts = await _resolve_ptrs(ip_addresses)

    # resolved is true iff DNS actually returned addresses (dns_status
    # RESOLVED). CNAME-only hosts are still probed via their chain but are not
    # considered "resolved" by the A/AAAA definition the summary counts use.
    resolved = dns_status == "RESOLVED"
    alive = http_status is not None or https_status is not None
    risk, service, detail = check_takeover(
        sub,
        cname,
        ip_addresses,
        body,
        ptr_hosts=ptr_hosts,
        http_status=http_status,
        https_status=https_status,
        cname_chain=cname_chain,
    )

    # Active verification pass: only for flagged candidates (VERIFY/HIGH). Reuse
    # the SAME semaphore already in scope (no new semaphore, no unbounded
    # fan-out) and the SSRF-guarded probe_client. verify_takeover never raises.
    takeover_verdict = ""
    takeover_evidence = ""
    # Run the active verification pass for flagged candidates (VERIFY/HIGH) AND
    # for a LOW row that nonetheless named a detected cloud service (held_low
    # from a CNAME/host or A-record-PTR match). The latter must END in a
    # concrete verdict — a row whose takeover_service is set must never be left
    # with an empty takeover_verdict. verify_takeover itself re-checks this gate
    # and returns empty for a LOW row with no service.
    cloud_low = risk == "LOW" and bool(service)
    if risk in ("VERIFY", "HIGH") or cloud_low:
        verdict_result = await verify_takeover(
            SubdomainResult(
                subdomain=sub,
                ip_addresses=ip_addresses,
                cname=cname,
                http_status=http_status,
                https_status=https_status,
                sources=sorted(sources),
                takeover_risk=risk,
                takeover_service=service,
                takeover_detail=detail,
                takeover_verdict="",
                takeover_evidence="",
                resolved=resolved,
                alive=alive,
                dns_status=dns_status,
                cname_chain=cname_chain,
                dns_records=dns_records,
                recommended_action="",
            ),
            probe_client,
            sem,
        )
        takeover_verdict = verdict_result.get("verdict", "")
        takeover_evidence = verdict_result.get("evidence", "")
        # A confirmed VULNERABLE verdict may promote the risk to HIGH; note it.
        if takeover_verdict == VERDICT_VULNERABLE and risk != "HIGH":
            risk = "HIGH"
            takeover_evidence = (
                f"{takeover_evidence} [risk promoted VERIFY -> HIGH on confirmed "
                "VULNERABLE verdict]"
            )

    return SubdomainResult(
        subdomain=sub,
        ip_addresses=ip_addresses,
        cname=cname,
        http_status=http_status,
        https_status=https_status,
        sources=sorted(sources),
        takeover_risk=risk,
        takeover_service=service,
        takeover_detail=detail,
        takeover_verdict=takeover_verdict,
        takeover_evidence=takeover_evidence,
        resolved=resolved,
        alive=alive,
        dns_status=dns_status,
        cname_chain=cname_chain,
        dns_records=dns_records,
        recommended_action=_recommended_action(risk, takeover_verdict, service),
    )


async def resolve_candidates(
    probe_client: httpx.AsyncClient,
    candidates: list[str],
    sem: asyncio.Semaphore,
    source_tag: str,
    on_done=None,
) -> dict[str, SubdomainResult]:
    """Resolve active-discovery candidates through the SHARED analysis path.

    This is the ONLY place active discovery touches the network, and it does so
    exclusively via `analyze_subdomain` under the SHARED semaphore `sem`. That
    means the `is_valid_hostname` gate and the `_is_safe_public_ip` SSRF guard
    both apply to brute-force/permutation hosts identically to passive hosts —
    there is no parallel probe path that could bypass the IP guard.

    Returns only the candidates that are HITS (`resolved` is True), keyed by
    subdomain, each tagged with `source_tag`. `on_done`, if given, is called
    once per completed candidate (used to update progress counters).
    """
    hits: dict[str, SubdomainResult] = {}

    async def analyze_candidate(cand: str) -> None:
        res = await analyze_subdomain(probe_client, cand, [source_tag], sem)
        if res["resolved"]:
            hits[cand] = res
        if on_done is not None:
            on_done()

    await asyncio.gather(
        *(analyze_candidate(c) for c in candidates),
        return_exceptions=True,
    )
    return hits


# ---------------------------------------------------------------------------
# Job engine
# ---------------------------------------------------------------------------
def cleanup_old_jobs() -> None:
    now = time.time()
    stale = [
        jid
        for jid, job in JOBS.items()
        if now - job.created_at > JOB_TTL_SECONDS and job.status != "running"
    ]
    for jid in stale:
        JOBS.pop(jid, None)


def cleanup_old_lookalike_jobs() -> None:
    """Prune finished lookalike jobs older than JOB_TTL_SECONDS.

    Mirrors cleanup_old_jobs() for the SEPARATE LOOKALIKE_JOBS store; running
    jobs are never pruned.
    """
    now = time.time()
    stale = [
        jid
        for jid, job in LOOKALIKE_JOBS.items()
        if now - job.created_at > JOB_TTL_SECONDS and job.status != "running"
    ]
    for jid in stale:
        LOOKALIKE_JOBS.pop(jid, None)


def cleanup_old_breach_jobs() -> None:
    """Prune finished breach jobs older than JOB_TTL_SECONDS.

    Mirrors cleanup_old_lookalike_jobs() for the SEPARATE BREACH_JOBS store;
    running jobs are never pruned.
    """
    now = time.time()
    stale = [
        jid
        for jid, job in BREACH_JOBS.items()
        if now - job.created_at > JOB_TTL_SECONDS and job.status != "running"
    ]
    for jid in stale:
        BREACH_JOBS.pop(jid, None)


async def _periodic_cleanup() -> None:
    while True:
        try:
            await asyncio.sleep(300)
            cleanup_old_jobs()
            cleanup_old_lookalike_jobs()
            cleanup_old_breach_jobs()
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            logger.debug("cleanup error: %s", exc)


async def run_lookalike(job_id: str, domain: str, check_whois: bool) -> None:
    """Run a lookalike-domain job: generate candidates, analyze, score.

    Wraps the whole body in try/except like run_enumeration so a failure marks
    the job ``error`` instead of crashing the task. Candidate generation is
    already capped by MAX_LOOKALIKE_CANDIDATES. All network work is bounded by
    two semaphores (analysis + RDAP). A09 logging records job_id + domain +
    check_whois ONLY (never bodies/titles).
    """
    job = LOOKALIKE_JOBS.get(job_id)
    if job is None:
        return
    probe_client: httpx.AsyncClient = app.state.probe_client
    verified_client: httpx.AsyncClient = app.state.client
    cleanup_old_lookalike_jobs()

    logger.info(
        "lookalike job %s started: domain=%s check_whois=%s",
        job_id,
        domain,
        check_whois,
    )

    job.status = "running"
    job.progress = 0
    try:
        candidates = sorted(generate_lookalikes(domain))
        job.candidates_generated = len(candidates)

        # Best-effort original page title (once), never fatal. Derive the
        # brand label + distinctive brand tokens ONCE for the whole job so each
        # candidate's resemblance check is cheap and consistent. If the fetch
        # failed, brand_tokens still contains the label-derived stems and
        # resemblance degrades to label-containment only.
        original_title = await fetch_title(probe_client, domain)
        brand_label, _brand_tld = split_domain(domain)
        brand_tokens = _brand_tokens(brand_label, original_title)

        sem = asyncio.Semaphore(ANALYSIS_CONCURRENCY)
        rdap_sem = asyncio.Semaphore(RDAP_CONCURRENCY)
        total = len(candidates) or 1

        async def _analyze(cand: str) -> dict:
            res = await analyze_candidate(
                probe_client,
                verified_client,
                cand,
                "lookalike",
                original_title,
                check_whois,
                sem,
                rdap_sem,
                brand_label,
                brand_tokens,
            )
            job.candidates_checked += 1
            if res.get("registered") is True:
                job.registered_count += 1
            # Progress 0->100 across the analysis phase.
            job.progress = min(100, int(job.candidates_checked * 100 / total))
            return res

        gathered = await asyncio.gather(
            *(_analyze(c) for c in candidates),
            return_exceptions=True,
        )
        job.results = [r for r in gathered if isinstance(r, dict)]
        job.progress = 100
        job.status = "done"
        logger.info(
            "lookalike job %s done: domain=%s candidates=%s registered=%s",
            job_id,
            domain,
            job.candidates_generated,
            job.registered_count,
        )
    except Exception as exc:  # noqa: BLE001
        job.status = "error"
        job.error = str(exc)
        logger.debug("lookalike job %s failed: %s", job_id, exc)


async def run_breach(
    job_id: str, domain: str, emails: Optional[str], names: Optional[str]
) -> None:
    """Run a keyless breach-exposure job: discover/collect candidate addresses,
    check each against XposedOrNot, and surface the exposed/supplied hits.

    Candidate set = supplied emails | keyless-discovered emails (crt.sh + the
    domain's own scraped public pages) | name/role pattern emails, capped at
    MAX_BREACH_EMAILS. All breach calls go through the
    VERIFIED client (app.state.client) to the FIXED host api.xposedornot.com
    under a bounded Semaphore(BREACH_CONCURRENCY) with a polite inter-call
    sleep. A supplied address is kept regardless of outcome; a discovered /
    pattern address is DROPPED when the check returns None ('Not found') so only
    addresses the breach DB knows OR the user supplied are surfaced. The whole
    body is wrapped in try/except so a failure marks the job 'error'. A09:
    logs job_id + domain + counts ONLY — never emails, breach names, or data.
    """
    job = BREACH_JOBS.get(job_id)
    if job is None:
        return
    verified_client: httpx.AsyncClient = app.state.client
    cleanup_old_breach_jobs()

    logger.info("breach job %s started: domain=%s", job_id, domain)

    probe_client: Optional[httpx.AsyncClient] = getattr(
        app.state, "probe_client", None
    )

    job.status = "running"
    job.progress = 0
    try:
        supplied = set(parse_email_lines(emails, domain))
        supplied_names = parse_name_lines(names)

        # Keyless discovery: when the user supplied no emails/names (domain-only)
        # OR to augment a supplied run, crawl the domain's own public pages
        # (subdomain-reuse + SSRF-guarded probe scrape) + crt.sh for published
        # addresses, and harvest conservative person names for pattern-gen.
        rich = await discover_emails_rich(
            verified_client, probe_client, domain, job
        )
        discovered = rich["discovered"]
        harvested_names = rich["names"]

        # Name patterns come from BOTH supplied names and names harvested off
        # the domain's own pages. These are speculative: a pattern address is
        # only ever surfaced when the breach API confirms it (verify-then-keep),
        # so harvested-name noise can never leak into results.
        pattern = generate_email_patterns(
            supplied_names + sorted(harvested_names), domain
        )
        # Common keyless role-based locals (info@, careers@, hr@, ...). Tagged
        # 'pattern' and subject to the same verify-then-keep rule.
        role = {
            f"{local}@{domain}"
            for local in BREACH_ROLE_LOCALS
            if _valid_email_for_domain(f"{local}@{domain}", domain)
        }

        # Source label per address; 'supplied' wins over 'discovered' over
        # 'pattern' when an address appears in more than one set.
        source_of: dict[str, str] = {}
        for addr in role:
            source_of[addr] = "pattern"
        for addr in pattern:
            source_of[addr] = "pattern"
        for addr in discovered:
            source_of[addr] = "discovered"
        for addr in supplied:
            source_of[addr] = "supplied"

        candidates = list(source_of.keys())[:MAX_BREACH_EMAILS]
        # source_of may contain more than the cap; trim to the kept candidates.
        candidates_set = set(candidates)
        job.emails_discovered = len(candidates)

        total = len(candidates) or 1
        # Serialize the XposedOrNot calls (BREACH_CONCURRENCY == 1 by design —
        # the keyless API cannot tolerate parallelism). Kept as a Semaphore so
        # the constant stays tunable without restructuring.
        sem = asyncio.Semaphore(BREACH_CONCURRENCY)
        results: dict[str, dict] = {}
        counters = {"checked": 0, "clean": 0, "unknown": 0}
        # Adaptive inter-call delay: starts at the polite base and grows (capped)
        # the first time this job is throttled, so one 429 doesn't cascade into
        # all-429s for the rest of the list.
        pacing = {"delay": BREACH_CALL_DELAY, "throttled": False}

        async def _paced_sleep() -> None:
            await asyncio.sleep(pacing["delay"])

        def _note_throttle() -> None:
            if not pacing["throttled"]:
                pacing["throttled"] = True
            pacing["delay"] = min(
                pacing["delay"] + BREACH_ADAPTIVE_STEP, BREACH_ADAPTIVE_MAX
            )

        async def _check(addr: str) -> None:
            async with sem:
                res = await check_email_exposed(verified_client, addr)
                # If the check came back indeterminate, assume we hit the
                # throttle and slow the whole job down for the next calls.
                if res == BREACH_UNKNOWN:
                    _note_throttle()
                # Polite (possibly slowed) pause so the keyless API is not hammered.
                await _paced_sleep()
            counters["checked"] += 1
            job.emails_checked = counters["checked"]
            job.progress = min(100, int(counters["checked"] * 100 / total))

            source = source_of.get(addr, "discovered")
            is_supplied = source == "supplied"

            if res is None:
                # 'Not found': a CONFIRMED clean address. Keep the count only if
                # the user supplied it; otherwise drop the speculative candidate.
                if is_supplied:
                    counters["clean"] += 1
                return
            if res == BREACH_UNKNOWN:
                # Indeterminate (throttled/error after backoff): NEVER counted as
                # clean. Reported distinctly so '0 exposed' can't masquerade as a
                # confirmed-clean result. Counted for every candidate so the user
                # sees the full coverage gap.
                counters["unknown"] += 1
                return

            # res is a (possibly empty) list of breach names -> exposed. Enrich
            # with detailed analytics (never raises).
            analytics = await breach_analytics(verified_client, addr)
            await _paced_sleep()
            breach_names = sorted(set(res) | set(analytics.get("breaches", [])))
            results[addr] = {
                "email": addr,
                "breaches": breach_names,
                "exposed_data": analytics.get("exposed_data", []),
                "risk_label": analytics.get("risk_label", ""),
                "risk_score": analytics.get("risk_score", ""),
                "source": source,
            }

        await asyncio.gather(
            *(_check(addr) for addr in candidates),
            return_exceptions=True,
        )

        job.results = [results[a] for a in candidates if a in results]
        job.exposed_count = len(job.results)
        job.checked_clean = counters["clean"]
        job.checked_unknown = counters["unknown"]
        job.progress = 100
        job.status = "done"
        logger.info(
            "breach job %s done: domain=%s candidates=%d checked=%d exposed=%d "
            "clean=%d unknown=%d",
            job_id,
            domain,
            len(candidates_set),
            job.emails_checked,
            job.exposed_count,
            job.checked_clean,
            job.checked_unknown,
        )
    except Exception as exc:  # noqa: BLE001
        job.status = "error"
        job.error = str(exc)
        logger.debug("breach job %s failed: %s", job_id, exc)


async def run_enumeration(
    job_id: str,
    domain: str,
    keys: dict,
    active: bool = False,
    wordlist: Optional[str] = None,
    wordlist_mode: str = "replace",
    permutations: bool = False,
) -> None:
    job = JOBS.get(job_id)
    if job is None:
        return
    client: httpx.AsyncClient = app.state.client
    probe_client: httpx.AsyncClient = app.state.probe_client
    cleanup_old_jobs()

    # A09 lifecycle logging: job_id + domain + mode ONLY. Never log API keys,
    # the keys dict, request bodies, or response bodies.
    logger.info("job %s started: domain=%s active=%s", job_id, domain, active)

    job.status = "running"
    job.progress = 0
    for name in SOURCES:
        job.source_statuses[name] = "pending"
    # Register the active phases as extra "sources" ONLY when active mode is on,
    # so a passive-only job's status payload is identical to today's.
    if active:
        job.source_statuses["bruteforce"] = "pending"
        if permutations:
            job.source_statuses["permutation"] = "pending"

    collected: set[str] = set()
    # Per-subdomain source attribution, built as each source returns.
    subdomain_sources: dict[str, set[str]] = {}
    # Results produced by the active phases (already analyzed), keyed by host.
    analyzed: dict[str, SubdomainResult] = {}

    async def run_source(name: str, fn) -> None:
        job.source_statuses[name] = "running"
        job.current_source = name
        try:
            found = await fn(client, domain, keys)
            collected.update(found)
            for sub in found:
                subdomain_sources.setdefault(sub, set()).add(name)
            job.subdomains_found = len(collected)
            job.source_statuses[name] = "done"
        except Exception as exc:  # noqa: BLE001
            logger.debug("source %s failed: %s", name, exc)
            job.source_statuses[name] = "error"

    # Progress split: passive analysis fills 0->50 / 50->100 when inactive;
    # when active, passive fills 0->40, active discovery 40->50, analysis
    # 50->100.
    passive_cap = 40 if active else 50

    try:
        await asyncio.gather(
            *(run_source(name, fn) for name, fn in SOURCES.items()),
            return_exceptions=True,
        )
        job.progress = passive_cap

        sem = asyncio.Semaphore(ANALYSIS_CONCURRENCY)

        # ---------------- Active discovery phases ----------------
        # These run AFTER all passive sources complete. Every candidate flows
        # through resolve_candidates -> analyze_subdomain (shared semaphore,
        # same SSRF/hostname guards). Candidate growth is bounded by
        # MAX_ACTIVE_CANDIDATES at every generation point.
        active_generated = 0
        if active:
            # --- Brute-force phase ---
            job.source_statuses["bruteforce"] = "running"
            job.current_source = "bruteforce"
            custom = parse_custom_wordlist(wordlist)
            if custom:
                if wordlist_mode == "append":
                    # dedupe preserving order: default first, then custom.
                    seen: set[str] = set()
                    labels: list[str] = []
                    for lbl in DEFAULT_WORDLIST + custom:
                        if lbl not in seen:
                            seen.add(lbl)
                            labels.append(lbl)
                else:  # "replace"
                    labels = custom
            else:
                # No valid custom labels: fall back to the built-in default.
                labels = DEFAULT_WORDLIST

            bf_candidates, bf_trunc = build_bruteforce_candidates(
                domain, labels, MAX_ACTIVE_CANDIDATES
            )
            active_generated += len(bf_candidates)
            if bf_trunc:
                job.notes.append(
                    f"candidate cap of {MAX_ACTIVE_CANDIDATES} reached; some "
                    "brute-force candidates were skipped"
                )

            def _bump() -> None:
                job.subdomains_found = len(collected) + len(analyzed)

            bf_hits = await resolve_candidates(
                probe_client, bf_candidates, sem, "bruteforce", on_done=_bump
            )
            for host, res in bf_hits.items():
                analyzed[host] = res
                subdomain_sources.setdefault(host, set()).add("bruteforce")
                collected.add(host)
            job.source_statuses["bruteforce"] = "done"
            job.progress = max(job.progress, passive_cap + 3)

            # --- Permutation phase ---
            if permutations:
                job.source_statuses["permutation"] = "running"
                job.current_source = "permutation"
                # Seed = everything discovered so far (passive + brute-force).
                seed = {
                    s for s in collected
                    if s and "*" not in s and s != domain.lower()
                }
                remaining_cap = max(0, MAX_ACTIVE_CANDIDATES - active_generated)
                perm_candidates, perm_trunc = generate_permutations(
                    seed, domain, PERMUTATION_WORDS, PERMUTATION_SEPARATORS,
                    remaining_cap,
                )
                active_generated += len(perm_candidates)
                if perm_trunc:
                    job.notes.append(
                        f"candidate cap of {MAX_ACTIVE_CANDIDATES} reached; "
                        "some permutation candidates were skipped"
                    )
                perm_hits = await resolve_candidates(
                    probe_client, perm_candidates, sem, "permutation",
                    on_done=_bump,
                )
                for host, res in perm_hits.items():
                    analyzed[host] = res
                    subdomain_sources.setdefault(host, set()).add("permutation")
                    collected.add(host)
                job.source_statuses["permutation"] = "done"

            job.progress = max(job.progress, 50)

        # ---------------- Shared analysis pass ----------------
        # Deduplicate: lowercase, drop wildcards and the base domain itself.
        subs = sorted(
            s for s in collected if s and "*" not in s and s != domain.lower()
        )
        # DoS cap: bound the number of hosts analyzed per job so an enormous
        # result set cannot exhaust DNS/HTTP probe resources.
        subs = subs[:MAX_SUBDOMAINS_PER_JOB]
        job.subdomains_found = len(subs)

        # Analyze only hosts not already analyzed in an active phase; active
        # hosts are reused as-is (no double-probing).
        pending = [s for s in subs if s not in analyzed]
        analysis_base = 50
        results_map: dict[str, SubdomainResult] = {}
        done_count = 0

        async def analyze_one(sub: str) -> None:
            nonlocal done_count
            res = await analyze_subdomain(
                probe_client, sub, sorted(subdomain_sources.get(sub, set())), sem
            )
            results_map[sub] = res
            done_count += 1
            if pending:
                job.progress = analysis_base + int(
                    (100 - analysis_base) * done_count / len(pending)
                )

        await asyncio.gather(
            *(analyze_one(sub) for sub in pending),
            return_exceptions=True,
        )

        # Merge: active-analyzed hosts carry the full union of their sources
        # (bruteforce/permutation + any passive source that also found them).
        final_results: list = []
        for sub in subs:
            if sub in results_map:
                final_results.append(results_map[sub])
            elif sub in analyzed:
                res = analyzed[sub]
                res["sources"] = sorted(subdomain_sources.get(sub, set()))
                final_results.append(res)

        job.results = final_results
        job.progress = 100
        job.current_source = ""
        job.status = "done"
        logger.info(
            "job %s done: domain=%s results=%d", job_id, domain, len(final_results)
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("enumeration failed")
        job.status = "error"
        job.error = str(exc)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Verified client for data-source and authenticated API calls (SecurityTrails,
    # Shodan). TLS is validated so API keys never travel over unauthenticated TLS.
    # A10/API7: follow_redirects is DISABLED on the verified source client so a
    # hostile source cannot 3xx-redirect an authenticated/verified request to an
    # internal host (SSRF via redirect). Sources return data on the first
    # response; a 3xx is simply treated as a non-200 and yields no subdomains.
    app.state.client = httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=False,
        timeout=SOURCE_TIMEOUT,
        verify=True,
    )
    # Separate probe client with TLS verification disabled, used only to fetch
    # target subdomain bodies (which frequently present invalid/self-signed
    # certs) for liveness and takeover-fingerprint checks. No credentials are
    # ever sent on this client. Redirects stay ENABLED here because target
    # liveness/fingerprint detection often depends on following a 3xx to the
    # provider's "gone" page; the probe is already IP-guarded at every call site
    # (_is_safe_public_ip in analyze_subdomain / probe_allowed in verify_takeover).
    app.state.probe_client = httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
        timeout=HTTP_PROBE_TIMEOUT,
        verify=False,
    )
    cleanup_task = asyncio.create_task(_periodic_cleanup())
    try:
        yield
    finally:
        cleanup_task.cancel()
        await app.state.client.aclose()
        await app.state.probe_client.aclose()


# FastAPI debug is left OFF (default) so tracebacks are never returned to
# clients; handlers raise HTTPException with generic messages and the generic
# 500 handler returns {"detail": "Internal Server Error"} with no stack trace.
app = FastAPI(title="ReconGuard Pro", lifespan=lifespan)

# CORS: scoped to localhost origins by default for this local single-user tool.
# Override with the SUBRECON_CORS_ORIGINS env var (comma-separated list of
# origins). Credentials are intentionally NOT enabled, so a wildcard origin is
# never paired with allow_credentials=True (which browsers forbid anyway).
_default_cors = "http://localhost:8080,http://127.0.0.1:8080"
_cors_origins = [
    o.strip()
    for o in os.environ.get("SUBRECON_CORS_ORIGINS", _default_cors).split(",")
    if o.strip()
]
# Security headers are applied by a pure-ASGI middleware (defined above) rather
# than an ``@app.middleware("http")`` wrapper so the four hardening headers
# reach EVERY response on the live uvicorn server — including the StaticFiles
# SPA mount at ``/`` and the vendored ``/tailwind.css``, which a Response-level
# wrapper can miss. It is added AFTER CORS so it sits outermost in the ASGI
# stack: CORS headers are preserved and the security headers are never
# duplicated (setdefault semantics inside the middleware).
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)


# ---------------------------------------------------------------------------
# Per-client rate limit (A04/API4)
# ---------------------------------------------------------------------------
# In-memory token bucket keyed by client IP. Not shared across processes (this
# is a single-process local tool); it bounds abusive bursts from one client.
# Each bucket is [tokens, last_refill_ts]. Access is single-threaded under the
# asyncio event loop, so no lock is needed.
_RATE_BUCKETS: dict[str, list[float]] = {}


def _rate_limit_ok(client_ip: Optional[str]) -> bool:
    """Return True if a request from client_ip is within its token budget.

    FAILS OPEN: any internal error (or a missing client IP) returns True so the
    limiter never blocks legitimate work. Buckets refill continuously up to
    RATE_LIMIT_BURST and are pruned opportunistically to bound memory.
    """
    try:
        if not client_ip:
            return True
        now = time.monotonic()
        refill_rate = RATE_LIMIT_PER_MINUTE / RATE_LIMIT_WINDOW  # tokens/sec

        # Opportunistic prune of stale buckets (full-and-idle) when the table
        # grows large, so a flood of distinct IPs cannot grow memory unbounded.
        if len(_RATE_BUCKETS) > RATE_LIMIT_MAX_BUCKETS:
            for ip in list(_RATE_BUCKETS.keys()):
                tokens, last = _RATE_BUCKETS[ip]
                refilled = min(RATE_LIMIT_BURST, tokens + (now - last) * refill_rate)
                if refilled >= RATE_LIMIT_BURST:
                    del _RATE_BUCKETS[ip]

        bucket = _RATE_BUCKETS.get(client_ip)
        if bucket is None:
            # First request from this IP: full burst minus this one.
            _RATE_BUCKETS[client_ip] = [RATE_LIMIT_BURST - 1.0, now]
            return True
        tokens, last = bucket
        tokens = min(RATE_LIMIT_BURST, tokens + (now - last) * refill_rate)
        if tokens < 1.0:
            bucket[0] = tokens
            bucket[1] = now
            return False
        bucket[0] = tokens - 1.0
        bucket[1] = now
        return True
    except Exception:  # noqa: BLE001 — fail open, never block on limiter error.
        return True


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/enumerate")
async def enumerate_domain(req: EnumerateRequest, request: Request):
    # Per-client rate limit (A04/API4): bound abusive bursts from a single IP.
    # Fails open; returns a generic 429 when the budget is exhausted. Adding
    # `request` does NOT change the JSON request/response schema.
    client_ip = request.client.host if request.client else None
    if not _rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded, retry later")

    domain = req.domain.strip().lower().rstrip(".")
    # Strict RFC-1035 validation (length cap, label sizes, no scheme/slash/@/
    # whitespace, no IP literals) BEFORE the value ever reaches an outbound URL.
    if not is_valid_hostname(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    cleanup_old_jobs()
    # DoS cap: reject new work when too many jobs are already in flight.
    active = sum(1 for j in JOBS.values() if j.status in ("pending", "running"))
    if active >= MAX_ACTIVE_JOBS:
        raise HTTPException(status_code=429, detail="Too many active jobs, retry later")

    job_id = uuid.uuid4().hex
    JOBS[job_id] = JobState(job_id=job_id, domain=domain)
    keys = {
        "securitytrails_key": req.securitytrails_key,
        "shodan_key": req.shodan_key,
        "c99_key": req.c99_key,
    }
    # Normalize wordlist_mode to the accepted set; any other value -> "replace".
    wordlist_mode = req.wordlist_mode if req.wordlist_mode == "append" else "replace"
    asyncio.create_task(
        run_enumeration(
            job_id,
            domain,
            keys,
            active=req.active,
            wordlist=req.wordlist,
            wordlist_mode=wordlist_mode,
            permutations=req.permutations,
        )
    )
    return {"job_id": job_id}


@app.get("/api/status/{job_id}")
async def job_status(job_id: str):
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "status": job.status,
        "progress": job.progress,
        "current_source": job.current_source,
        "subdomains_found": job.subdomains_found,
        "source_statuses": job.source_statuses,
        "notes": job.notes,
        "error": job.error,
    }


def _summarize(results: list) -> dict:
    resolved = sum(1 for r in results if r["resolved"])
    alive = sum(1 for r in results if r["alive"])
    high = sum(1 for r in results if r["takeover_risk"] == "HIGH")
    medium = sum(1 for r in results if r["takeover_risk"] == "MEDIUM")
    verify = sum(1 for r in results if r["takeover_risk"] == "VERIFY")
    vulnerable = sum(1 for r in results if r.get("takeover_verdict") == "VULNERABLE")
    return {
        "resolved": resolved,
        "alive": alive,
        "high_risk": high,
        "medium_risk": medium,
        "verify": verify,
        "vulnerable": vulnerable,
    }


@app.get("/api/results/{job_id}")
async def job_results(job_id: str):
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "done":
        raise HTTPException(status_code=409, detail=f"Job not ready (status={job.status})")
    summary = _summarize(job.results)
    return {
        "job_id": job.job_id,
        "domain": job.domain,
        "subdomains": job.results,
        "total": len(job.results),
        **summary,
    }


def _dns_records_to_cell(records: dict) -> str:
    """Serialize a dns_records dict into one compact CSV-safe line (FEAT-002).

    Values within a record type are joined by ',' and types by ';', in
    DNS_RECORD_TYPES order, e.g. ``A=1.2.3.4;MX=10 mail.x;NS=ns1.x,ns2.x``.
    The ';' type-delimiter keeps the whole thing inside a single comma-CSV
    cell. The caller passes the result through _csv_safe. Returns '' for an
    empty/missing dict.
    """
    if not records:
        return ""
    parts: list[str] = []
    ordered = DNS_RECORD_TYPES + [t for t in records if t not in DNS_RECORD_TYPES]
    for rtype in ordered:
        values = records.get(rtype)
        if not values:
            continue
        joined = ",".join(str(v) for v in values)
        parts.append(f"{rtype}={joined}")
    return ";".join(parts)


CSV_COLUMNS = [
    "subdomain",
    "ip_addresses",
    "cname",
    "http_status",
    "https_status",
    "sources",
    "resolved",
    "alive",
    "takeover_risk",
    "takeover_service",
    "takeover_detail",
    "dns_status",
    "takeover_verdict",
    "takeover_evidence",
    "dns_records",
    # PART 4: appended LAST (16th) — columns 1-15 above are unchanged.
    "recommended_action",
]


@app.get("/api/download/{job_id}")
async def download_csv(job_id: str):
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "done":
        raise HTTPException(status_code=409, detail=f"Job not ready (status={job.status})")

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_COLUMNS)
    for r in job.results:
        # Text columns are passed through _csv_safe to neutralize spreadsheet
        # formula/injection (values from attacker-poisonable cert logs). The
        # first 15 columns keep their exact order; recommended_action is
        # appended LAST as the 16th (also _csv_safe'd). Numeric/bool columns
        # (http_status, https_status, resolved, alive) pass through as-is.
        writer.writerow([
            _csv_safe(r["subdomain"]),
            _csv_safe(";".join(r["ip_addresses"])),
            _csv_safe(r["cname"] or ""),
            r["http_status"] if r["http_status"] is not None else "",
            r["https_status"] if r["https_status"] is not None else "",
            _csv_safe(";".join(r["sources"])),
            r["resolved"],
            r["alive"],
            _csv_safe(r["takeover_risk"]),
            _csv_safe(r["takeover_service"] or ""),
            _csv_safe(r["takeover_detail"] or ""),
            _csv_safe(r["dns_status"]),
            _csv_safe(r.get("takeover_verdict", "")),
            _csv_safe(r.get("takeover_evidence", "")),
            _csv_safe(_dns_records_to_cell(r.get("dns_records", {}))),
            _csv_safe(r.get("recommended_action", "")),
        ])
    buffer.seek(0)
    # Sanitize the filename so no CRLF/quote can break the Content-Disposition
    # header. job.domain is already is_valid_hostname-validated, but strip to a
    # safe charset as defense-in-depth.
    safe_domain = re.sub(r"[^a-z0-9.-]", "_", job.domain.lower()) or "domain"
    filename = f"reconguard_{safe_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Lookalike domain API (FEAT-001) — SEPARATE from the subdomain routes.
# ---------------------------------------------------------------------------
LOOKALIKE_CSV_COLUMNS = [
    "candidate",
    "technique",
    "dns_status",
    "ip_addresses",
    "http_status",
    "https_status",
    "page_title",
    "has_mx",
    "registered",
    "registrar",
    "creation_date",
    "resembles_original",
    "risk",
    "recommended_action",
]


def _build_lookalike_csv(results: list) -> str:
    """Serialize lookalike results into CSV using LOOKALIKE_CSV_COLUMNS order.

    Every text column is passed through _csv_safe (page_title and registrar are
    attacker-influenced, as is candidate). ip_addresses (a list) is joined with
    ';'. Numeric/bool columns pass through as-is (blank for None).
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(LOOKALIKE_CSV_COLUMNS)
    for r in results:
        writer.writerow([
            _csv_safe(r.get("candidate", "")),
            _csv_safe(r.get("technique", "")),
            _csv_safe(r.get("dns_status", "")),
            _csv_safe(";".join(r.get("ip_addresses") or [])),
            r["http_status"] if r.get("http_status") is not None else "",
            r["https_status"] if r.get("https_status") is not None else "",
            _csv_safe(r.get("page_title") or ""),
            r.get("has_mx", False),
            _csv_safe(r.get("registered", "")),
            _csv_safe(r.get("registrar", "")),
            _csv_safe(r.get("creation_date", "")),
            r.get("resembles_original", False),
            _csv_safe(r.get("risk", "")),
            _csv_safe(r.get("recommended_action", "")),
        ])
    buffer.seek(0)
    return buffer.getvalue()


def _summarize_lookalike(results: list) -> dict:
    """Summary counts for the lookalike results payload."""
    total = len(results)
    registered = sum(1 for r in results if r.get("registered") is True)
    live = sum(
        1
        for r in results
        if _http_live(r.get("http_status")) or _http_live(r.get("https_status"))
    )
    high = sum(1 for r in results if r.get("risk") == "HIGH")
    available = sum(1 for r in results if r.get("risk") == "AVAILABLE")
    return {
        "total": total,
        "registered": registered,
        "live": live,
        "high": high,
        "available": available,
    }


class LookalikeRequest(BaseModel):
    domain: str
    check_whois: bool = False


@app.post("/api/lookalike")
async def lookalike_start(req: LookalikeRequest, request: Request):
    # Per-client rate limit (A04/API4), shared limiter with /api/enumerate.
    client_ip = request.client.host if request.client else None
    if not _rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded, retry later")

    domain = req.domain.strip().lower().rstrip(".")
    if not is_valid_hostname(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    cleanup_old_lookalike_jobs()
    cleanup_old_breach_jobs()
    # DoS cap over the COMBINED in-flight jobs of ALL THREE stores.
    active = sum(
        1 for j in JOBS.values() if j.status in ("pending", "running")
    ) + sum(
        1 for j in LOOKALIKE_JOBS.values() if j.status in ("pending", "running")
    ) + sum(
        1 for j in BREACH_JOBS.values() if j.status in ("pending", "running")
    )
    if active >= MAX_ACTIVE_JOBS:
        raise HTTPException(status_code=429, detail="Too many active jobs, retry later")

    job_id = uuid.uuid4().hex
    LOOKALIKE_JOBS[job_id] = LookalikeJobState(
        job_id=job_id, domain=domain, check_whois=req.check_whois
    )
    asyncio.create_task(run_lookalike(job_id, domain, req.check_whois))
    return {"job_id": job_id}


@app.get("/api/lookalike/status/{job_id}")
async def lookalike_status(job_id: str):
    job = LOOKALIKE_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "status": job.status,
        "progress": job.progress,
        "candidates_generated": job.candidates_generated,
        "candidates_checked": job.candidates_checked,
        "registered_count": job.registered_count,
        "error": job.error,
    }


@app.get("/api/lookalike/results/{job_id}")
async def lookalike_results(job_id: str):
    job = LOOKALIKE_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "done":
        raise HTTPException(status_code=409, detail=f"Job not ready (status={job.status})")
    return {
        "job_id": job.job_id,
        "domain": job.domain,
        "candidates": job.results,
        "summary": _summarize_lookalike(job.results),
    }


@app.get("/api/lookalike/download/{job_id}")
async def lookalike_download(job_id: str):
    job = LOOKALIKE_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "done":
        raise HTTPException(status_code=409, detail=f"Job not ready (status={job.status})")
    content = _build_lookalike_csv(job.results)
    safe_domain = re.sub(r"[^a-z0-9.-]", "_", job.domain.lower()) or "domain"
    filename = f"lookalike_{safe_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([content]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Breach-exposure API (FEAT-001) — SEPARATE from the subdomain + lookalike
# routes, with its own 6-column CSV contract.
# ---------------------------------------------------------------------------
BREACH_CSV_COLUMNS = [
    "email",
    "breaches",
    "exposed_data",
    "risk_label",
    "risk_score",
    "source",
]

# Honest coverage disclaimer surfaced in the results payload. The keyless
# engine only checks addresses it discovered or the user supplied, so this is
# explicitly NOT an exhaustive domain report.
BREACH_COVERAGE_NOTE = (
    "Coverage is limited to supplied addresses plus those discovered by "
    "crawling the domain's own public pages (mailto:/inline harvest) and "
    "name/role patterns confirmed against the breach database; this is not an "
    "exhaustive domain report. The keyless XposedOrNot API is rate-limited, so "
    "checks are serialized with exponential backoff (large lists take longer "
    "but are reliable); any check that stays indeterminate after backoff is "
    "reported as UNKNOWN (checked_unknown), never as confirmed clean. "
    "Source: XposedOrNot keyless API."
)


def _build_breach_csv(results: list) -> str:
    """Serialize breach results into CSV using BREACH_CSV_COLUMNS order.

    breaches/exposed_data lists are joined with ';'. EVERY text column is passed
    through _csv_safe (email/breach names are attacker-influenced third-party
    data). risk_score passes through numeric (blank when '').
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(BREACH_CSV_COLUMNS)
    for r in results:
        score = r.get("risk_score", "")
        writer.writerow([
            _csv_safe(r.get("email", "")),
            _csv_safe(";".join(r.get("breaches") or [])),
            _csv_safe(";".join(r.get("exposed_data") or [])),
            _csv_safe(r.get("risk_label", "")),
            score if isinstance(score, int) else "",
            _csv_safe(r.get("source", "")),
        ])
    buffer.seek(0)
    return buffer.getvalue()


def _summarize_breach(
    results: list,
    emails_checked: int,
    checked_clean: int,
    checked_unknown: int = 0,
) -> dict:
    """Summary counts for the breach results payload.

    ``breaches_count`` is the total breach mentions across all exposed emails;
    ``distinct_breaches`` is the count of unique breach names; ``by_risk`` tiers
    the exposed emails by their risk_label (high/medium/low, case-insensitive).
    ``checked_unknown`` surfaces how many checks were INDETERMINATE (throttled /
    Cloudflare / error after backoff) so a "0 exposed" is never silently a
    throttled result mistaken for "confirmed clean".
    """
    exposed_count = len(results)
    breaches_count = 0
    distinct: set[str] = set()
    by_risk = {"high": 0, "medium": 0, "low": 0}
    for r in results:
        names = r.get("breaches") or []
        breaches_count += len(names)
        distinct.update(names)
        label = str(r.get("risk_label", "") or "").strip().lower()
        if label in by_risk:
            by_risk[label] += 1
    return {
        "emails_checked": emails_checked,
        "exposed_count": exposed_count,
        "breaches_count": breaches_count,
        "distinct_breaches": len(distinct),
        "by_risk": by_risk,
        "checked_clean": checked_clean,
        "checked_unknown": checked_unknown,
    }


class BreachRequest(BaseModel):
    domain: str
    # A04/API4: cap the raw supplied-email / name blobs so an enormous payload
    # cannot be buffered/parsed into memory (mirrors EnumerateRequest.wordlist).
    emails: Optional[str] = Field(default=None, max_length=MAX_WORDLIST_BYTES)
    names: Optional[str] = Field(default=None, max_length=MAX_WORDLIST_BYTES)


@app.post("/api/breach")
async def breach_start(req: BreachRequest, request: Request):
    # Per-client rate limit (A04/API4), shared limiter with the other routes.
    client_ip = request.client.host if request.client else None
    if not _rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded, retry later")

    domain = req.domain.strip().lower().rstrip(".")
    if not is_valid_hostname(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    cleanup_old_jobs()
    cleanup_old_lookalike_jobs()
    cleanup_old_breach_jobs()
    # DoS cap over the COMBINED in-flight jobs of ALL THREE stores.
    active = sum(
        1 for j in JOBS.values() if j.status in ("pending", "running")
    ) + sum(
        1 for j in LOOKALIKE_JOBS.values() if j.status in ("pending", "running")
    ) + sum(
        1 for j in BREACH_JOBS.values() if j.status in ("pending", "running")
    )
    if active >= MAX_ACTIVE_JOBS:
        raise HTTPException(status_code=429, detail="Too many active jobs, retry later")

    job_id = uuid.uuid4().hex
    BREACH_JOBS[job_id] = BreachJobState(job_id=job_id, domain=domain)
    asyncio.create_task(run_breach(job_id, domain, req.emails, req.names))
    return {"job_id": job_id}


@app.get("/api/breach/status/{job_id}")
async def breach_status(job_id: str):
    job = BREACH_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "status": job.status,
        "progress": job.progress,
        "emails_discovered": job.emails_discovered,
        "emails_checked": job.emails_checked,
        "exposed_count": job.exposed_count,
        "checked_unknown": job.checked_unknown,
        "error": job.error,
    }


@app.get("/api/breach/results/{job_id}")
async def breach_results(job_id: str):
    job = BREACH_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "done":
        raise HTTPException(status_code=409, detail=f"Job not ready (status={job.status})")
    return {
        "job_id": job.job_id,
        "domain": job.domain,
        "exposed": job.results,
        "summary": _summarize_breach(
            job.results,
            job.emails_checked,
            job.checked_clean,
            job.checked_unknown,
        ),
        "coverage_note": BREACH_COVERAGE_NOTE,
    }


@app.get("/api/breach/download/{job_id}")
async def breach_download(job_id: str):
    job = BREACH_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "done":
        raise HTTPException(status_code=409, detail=f"Job not ready (status={job.status})")
    content = _build_breach_csv(job.results)
    safe_domain = re.sub(r"[^a-z0-9.-]", "_", job.domain.lower()) or "domain"
    filename = f"breach_{safe_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([content]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# Static files mounted last so API routes take precedence.
_static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.isdir(_static_dir):
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")


if __name__ == "__main__":
    # A05: bind to localhost by default so the tool (which has no auth) is not
    # exposed on all interfaces. Override with SUBRECON_HOST to bind elsewhere
    # (e.g. behind an authenticating reverse proxy).
    _host = os.environ.get("SUBRECON_HOST", "127.0.0.1")
    uvicorn.run("main:app", host=_host, port=8080, reload=False)
