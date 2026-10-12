"""SubRecon Pro — subdomain enumeration and takeover-risk analysis backend.

A FastAPI application that aggregates subdomains from 11 public passive-DNS
sources, resolves and probes each one, scores subdomain-takeover risk, and
exposes an in-memory job API plus a single-file dark-themed frontend.
"""

import asyncio
import csv
import io
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
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("subrecon")

USER_AGENT = "Mozilla/5.0 (compatible; SubRecon/1.0)"
SOURCE_TIMEOUT = 15.0
HTTP_PROBE_TIMEOUT = 5.0
ANALYSIS_CONCURRENCY = 50
JOB_TTL_SECONDS = 3600

DOMAIN_RE = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# ---------------------------------------------------------------------------
# Takeover fingerprints
# ---------------------------------------------------------------------------
TAKEOVER_FINGERPRINTS = {
    "github.io": {"service": "GitHub Pages", "fingerprint": "There isn't a GitHub Pages site here", "severity": "HIGH"},
    "s3.amazonaws.com": {"service": "AWS S3", "fingerprint": "NoSuchBucket", "severity": "HIGH"},
    "amazonaws.com": {"service": "AWS S3", "fingerprint": "NoSuchBucket", "severity": "HIGH"},
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
# Typing
# ---------------------------------------------------------------------------
class SubdomainResult(TypedDict):
    subdomain: str
    ip_addresses: list[str]
    cname: Optional[str]
    http_status: Optional[int]
    https_status: Optional[int]
    sources: list[str]
    takeover_risk: str  # HIGH | MEDIUM | LOW | NONE
    takeover_service: Optional[str]
    takeover_detail: Optional[str]
    resolved: bool
    alive: bool


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


JOBS: dict[str, JobState] = {}


class EnumerateRequest(BaseModel):
    domain: str
    securitytrails_key: Optional[str] = None
    shodan_key: Optional[str] = None


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
    if host == domain or host.endswith("." + domain):
        return host
    return None


async def _get(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
    return await asyncio.wait_for(client.get(url, **kwargs), timeout=SOURCE_TIMEOUT)


async def query_crtsh(client: httpx.AsyncClient, domain: str, keys: dict) -> set[str]:
    out: set[str] = set()
    try:
        resp = await _get(client, f"https://crt.sh/?q=%25.{domain}&output=json")
        data = resp.json()
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                norm = _normalize_host(name, domain)
                if norm:
                    out.add(norm)
    except Exception as exc:  # noqa: BLE001
        logger.debug("crtsh failed: %s", exc)
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
    "SecurityTrails": query_securitytrails,
    "Shodan": query_shodan,
}


# ---------------------------------------------------------------------------
# Per-subdomain analysis
# ---------------------------------------------------------------------------
async def resolve_dns(host: str) -> list[str]:
    """Return the set of A/AAAA addresses for host, or [] on failure."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.run_in_executor(
            None, socket.getaddrinfo, host, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except Exception:  # noqa: BLE001
        return []
    ips: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in ips:
            ips.append(addr)
    return ips


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
    """Resolve a CNAME via the `dig` binary (fast, authoritative when present)."""
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
    """Try `dig` first, then fall back to the stdlib socket resolver."""
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


async def check_http(client: httpx.AsyncClient, host: str) -> tuple[Optional[int], Optional[int], str]:
    """Probe http:// and https://; return (http_status, https_status, body).

    ``client`` here is the probe client (TLS verification disabled) so that
    arbitrary target subdomains presenting expired or self-signed certs do not
    produce spurious failures. It is never used for authenticated API calls.
    """
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    body = ""
    for scheme in ("http", "https"):
        try:
            resp = await client.get(
                f"{scheme}://{host}", timeout=HTTP_PROBE_TIMEOUT
            )
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
        # confirm → low confidence.
        if matched_ptr and not via_cname and not via_name:
            pointer = f"A-record {matched_ptr}"
        else:
            pointer = "CNAME/host"
        return (
            "LOW",
            meta["service"],
            f"{pointer} points to {meta['service']} but no takeover fingerprint confirmed",
        )
    return "NONE", None, None


async def analyze_subdomain(
    probe_client: httpx.AsyncClient, sub: str, sources: list[str], sem: asyncio.Semaphore
) -> SubdomainResult:
    async with sem:
        ip_addresses = await resolve_dns(sub)
        cname = await resolve_cname(sub)
        http_status, https_status, body = await check_http(probe_client, sub)
        ptr_hosts = await _resolve_ptrs(ip_addresses)

    resolved = bool(ip_addresses) or bool(cname)
    alive = http_status is not None or https_status is not None
    risk, service, detail = check_takeover(
        sub, cname, ip_addresses, body, ptr_hosts=ptr_hosts
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
        resolved=resolved,
        alive=alive,
    )


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


async def _periodic_cleanup() -> None:
    while True:
        try:
            await asyncio.sleep(300)
            cleanup_old_jobs()
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            logger.debug("cleanup error: %s", exc)


async def run_enumeration(job_id: str, domain: str, keys: dict) -> None:
    job = JOBS.get(job_id)
    if job is None:
        return
    client: httpx.AsyncClient = app.state.client
    probe_client: httpx.AsyncClient = app.state.probe_client
    cleanup_old_jobs()

    job.status = "running"
    job.progress = 0
    for name in SOURCES:
        job.source_statuses[name] = "pending"

    collected: set[str] = set()
    # Per-subdomain source attribution, built as each source returns.
    subdomain_sources: dict[str, set[str]] = {}

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

    try:
        await asyncio.gather(
            *(run_source(name, fn) for name, fn in SOURCES.items()),
            return_exceptions=True,
        )
        job.progress = 50

        # Deduplicate: lowercase, drop wildcards and the base domain itself.
        subs = sorted(
            s for s in collected if s and "*" not in s and s != domain.lower()
        )
        job.subdomains_found = len(subs)

        sem = asyncio.Semaphore(ANALYSIS_CONCURRENCY)
        results: list = [None] * len(subs)
        done_count = 0

        async def analyze_one(idx: int, sub: str) -> None:
            nonlocal done_count
            res = await analyze_subdomain(
                probe_client, sub, sorted(subdomain_sources.get(sub, set())), sem
            )
            results[idx] = res
            done_count += 1
            if subs:
                job.progress = 50 + int(50 * done_count / len(subs))

        await asyncio.gather(
            *(analyze_one(i, sub) for i, sub in enumerate(subs)),
            return_exceptions=True,
        )

        job.results = [r for r in results if r is not None]
        job.progress = 100
        job.current_source = ""
        job.status = "done"
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
    app.state.client = httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
        timeout=SOURCE_TIMEOUT,
        verify=True,
    )
    # Separate probe client with TLS verification disabled, used only to fetch
    # target subdomain bodies (which frequently present invalid/self-signed
    # certs) for liveness and takeover-fingerprint checks. No credentials are
    # ever sent on this client.
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


app = FastAPI(title="SubRecon Pro", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/enumerate")
async def enumerate_domain(req: EnumerateRequest):
    domain = req.domain.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    cleanup_old_jobs()
    job_id = uuid.uuid4().hex
    JOBS[job_id] = JobState(job_id=job_id, domain=domain)
    keys = {
        "securitytrails_key": req.securitytrails_key,
        "shodan_key": req.shodan_key,
    }
    asyncio.create_task(run_enumeration(job_id, domain, keys))
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
        "error": job.error,
    }


def _summarize(results: list) -> dict:
    resolved = sum(1 for r in results if r["resolved"])
    alive = sum(1 for r in results if r["alive"])
    high = sum(1 for r in results if r["takeover_risk"] == "HIGH")
    medium = sum(1 for r in results if r["takeover_risk"] == "MEDIUM")
    return {"resolved": resolved, "alive": alive, "high_risk": high, "medium_risk": medium}


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
        writer.writerow([
            r["subdomain"],
            ";".join(r["ip_addresses"]),
            r["cname"] or "",
            r["http_status"] if r["http_status"] is not None else "",
            r["https_status"] if r["https_status"] is not None else "",
            ";".join(r["sources"]),
            r["resolved"],
            r["alive"],
            r["takeover_risk"],
            r["takeover_service"] or "",
            r["takeover_detail"] or "",
        ])
    buffer.seek(0)
    filename = f"subrecon_{job.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# Static files mounted last so API routes take precedence.
_static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.isdir(_static_dir):
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
