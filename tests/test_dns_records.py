
"""Offline tests for the additive per-subdomain DNS records listing (FEAT-002).

These monkeypatch the subprocess runner (main.subprocess.run) to return canned
`dig +noall +answer <TYPE>` answer-section output per record type so no real
DNS/subprocess work happens, and assert that _dig_records /
resolve_dns_records populate the dns_records dict keyed by the TRUE
answer-section TYPE of each line. A separate dig-absent path (subprocess.run
raising FileNotFoundError) exercises the stdlib fallback: A/AAAA via
socket.getaddrinfo and CNAME via _socket_cname, with MX/NS/TXT/SOA empty.

The CNAME-leak test directly encodes the acme.com `cdn.acme.com` bug:
`dig +short` echoed the CloudFront CNAME target under every record type; the
`+noall +answer` parser filters each line by its real TYPE column so the CNAME
target no longer leaks into A/MX/NS/TXT/SOA.
"""

import subprocess

import pytest

import main


class _FakeCompleted:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.returncode = 0


def _make_runner(answers):
    """Return a fake subprocess.run keyed on the dig record TYPE argument.

    ``args`` is the ['dig', '+noall', '+answer', '<TYPE>', host] argument list;
    we look up the canned answer-section stdout for '<TYPE>' and default to
    empty output.
    """

    def _run(args, capture_output=True, text=True, timeout=None):
        # args == ['dig', '+noall', '+answer', '<TYPE>', host]
        assert args[0] == "dig"
        assert args[1] == "+noall"
        assert args[2] == "+answer"
        assert "shell" not in str(args)  # defensive: never a shell string
        rtype = args[3]
        return _FakeCompleted(answers.get(rtype, ""))

    return _run


async def test_dig_records_parses_all_types(monkeypatch):
    # Full answer-section output per query (NAME TTL CLASS TYPE RDATA...).
    answers = {
        "A": (
            "live.example.com.\t60\tIN\tA\t1.2.3.4\n"
            "live.example.com.\t60\tIN\tA\t5.6.7.8\n"
        ),
        "AAAA": "",
        "CNAME": "live.example.com.\t300\tIN\tCNAME\ttarget.example.net.\n",
        "MX": (
            "example.com.\t300\tIN\tMX\t10 mail1.example.com.\n"
            "example.com.\t300\tIN\tMX\t20 mail2.example.com.\n"
        ),
        "NS": (
            "example.com.\t172800\tIN\tNS\tns1.example.com.\n"
            "example.com.\t172800\tIN\tNS\tns2.example.com.\n"
        ),
        "TXT": 'example.com.\t300\tIN\tTXT\t"v=spf1 include:_spf.example.com ~all"\n',
        "SOA": (
            "example.com.\t900\tIN\tSOA\t"
            "ns1.example.com. hostmaster.example.com. 1 2 3 4 5\n"
        ),
    }
    monkeypatch.setattr(main.subprocess, "run", _make_runner(answers))

    records = main._dig_records("live.example.com")

    assert records["A"] == ["1.2.3.4", "5.6.7.8"]
    # Trailing dots stripped on hostname-valued record types.
    assert records["CNAME"] == ["target.example.net"]
    # MX keeps the priority and strips the trailing dot off the host token.
    assert records["MX"] == ["10 mail1.example.com", "20 mail2.example.com"]
    assert records["NS"] == ["ns1.example.com", "ns2.example.com"]
    # TXT preserved verbatim (no trailing-dot stripping).
    assert records["TXT"] == ['"v=spf1 include:_spf.example.com ~all"']
    assert records["SOA"] == ["ns1.example.com. hostmaster.example.com. 1 2 3 4 5"]
    # AAAA produced no answers → omitted from the dict (additive, only present
    # types appear).
    assert "AAAA" not in records


async def test_cname_target_does_not_leak_into_other_types(monkeypatch):
    """acme.com cdn.acme.com regression: a CNAME-to-CloudFront host.

    Every query echoes the CNAME line in its answer section; only the lines
    whose TYPE matches the query must survive. So A gets only real IPs, MX is
    empty, NS/SOA get their real values, TXT is empty, and CNAME keeps the
    CloudFront target.
    """
    cf = "d2nw98z1ioq9pm.cloudfront.net."
    cname_line = f"cdn.acme.com.\t300\tIN\tCNAME\t{cf}\n"
    answers = {
        # A query: CNAME chain echoed first, then the real A answers.
        "A": (
            cname_line
            + f"{cf.rstrip()}\t60\tIN\tA\t3.175.86.76\n"
            + f"{cf.rstrip()}\t60\tIN\tA\t3.175.86.100\n"
        ),
        "AAAA": "",
        # CNAME query: just the CNAME line.
        "CNAME": cname_line,
        # MX query: only the echoed CNAME line, no MX record → MX must be empty.
        "MX": cname_line,
        # NS query: CNAME line echoed + the real delegated nameservers.
        "NS": (
            cname_line
            + "acme.com.\t172800\tIN\tNS\tns-669.awsdns-19.net.\n"
            + "acme.com.\t172800\tIN\tNS\tns-1354.awsdns-41.org.\n"
            + "acme.com.\t172800\tIN\tNS\tns-424.awsdns-53.com.\n"
            + "acme.com.\t172800\tIN\tNS\tns-1862.awsdns-48.co.uk.\n"
        ),
        # SOA query: CNAME line echoed + the real SOA.
        "SOA": (
            cname_line
            + "acme.com.\t900\tIN\tSOA\t"
            + "ns-669.awsdns-19.net. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400\n"
        ),
        # TXT query: only the echoed CNAME line → TXT must be absent.
        "TXT": cname_line,
    }
    monkeypatch.setattr(main.subprocess, "run", _make_runner(answers))

    records = main._dig_records("cdn.acme.com")

    # A: real IPs only, NO cloudfront hostname.
    assert records["A"] == ["3.175.86.76", "3.175.86.100"]
    assert "d2nw98z1ioq9pm.cloudfront.net" not in records["A"]
    # CNAME: the cloudfront target (trailing dot stripped).
    assert records["CNAME"] == ["d2nw98z1ioq9pm.cloudfront.net"]
    # MX: absent (CloudFront has no MX; the echoed CNAME was filtered out).
    assert "MX" not in records
    # NS: the real delegated nameservers, NO cloudfront hostname.
    assert records["NS"] == [
        "ns-669.awsdns-19.net",
        "ns-1354.awsdns-41.org",
        "ns-424.awsdns-53.com",
        "ns-1862.awsdns-48.co.uk",
    ]
    assert "d2nw98z1ioq9pm.cloudfront.net" not in records["NS"]
    # SOA: the real SOA, not the bare cloudfront hostname.
    assert records["SOA"] == [
        "ns-669.awsdns-19.net. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400"
    ]
    assert records["SOA"] != ["d2nw98z1ioq9pm.cloudfront.net"]
    # TXT: absent (only the echoed CNAME line, filtered out).
    assert "TXT" not in records


async def test_plain_a_host_unchanged(monkeypatch):
    # A plain A-record host (no CNAME) returns real IPs; others empty.
    answers = {
        "A": (
            "plain.example.com.\t60\tIN\tA\t93.184.216.34\n"
            "plain.example.com.\t60\tIN\tA\t93.184.216.35\n"
        ),
    }
    monkeypatch.setattr(main.subprocess, "run", _make_runner(answers))

    records = main._dig_records("plain.example.com")
    assert records["A"] == ["93.184.216.34", "93.184.216.35"]
    assert "CNAME" not in records
    assert "MX" not in records
    assert "NS" not in records
    assert "TXT" not in records
    assert "SOA" not in records


async def test_mx_multi_token_rdata(monkeypatch):
    # Multi-token MX RDATA parses to '<priority> <host>' with the host's
    # trailing dot stripped and the priority kept.
    answers = {"MX": "example.com.\t300\tIN\tMX\t10 mail.example.com.\n"}
    monkeypatch.setattr(main.subprocess, "run", _make_runner(answers))

    records = main._dig_records("example.com")
    assert records["MX"] == ["10 mail.example.com"]


async def test_resolve_dns_records_async_wrapper(monkeypatch):
    answers = {
        "A": "ok.example.com.\t60\tIN\tA\t9.9.9.9\n",
        "TXT": 'ok.example.com.\t300\tIN\tTXT\t"hello"\n',
    }
    monkeypatch.setattr(main.subprocess, "run", _make_runner(answers))

    records = await main.resolve_dns_records("ok.example.com")
    assert records["A"] == ["9.9.9.9"]
    assert records["TXT"] == ['"hello"']


async def test_dig_records_invalid_host_returns_empty(monkeypatch):
    # Invalid hostnames are gated before any subprocess call.
    def _boom(*a, **k):  # pragma: no cover - must never be called
        raise AssertionError("subprocess.run must not run for invalid hosts")

    monkeypatch.setattr(main.subprocess, "run", _boom)
    assert main._dig_records("not a host/@") == {}


async def test_dig_records_timeout_skips_type(monkeypatch):
    # A TimeoutExpired on one type must not kill the whole enumeration.
    def _run(args, capture_output=True, text=True, timeout=None):
        rtype = args[3]
        if rtype == "MX":
            raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)
        return _FakeCompleted(
            "partial.example.com.\t60\tIN\tA\t1.2.3.4\n" if rtype == "A" else ""
        )

    monkeypatch.setattr(main.subprocess, "run", _run)
    records = main._dig_records("partial.example.com")
    assert records["A"] == ["1.2.3.4"]
    assert "MX" not in records


async def test_dig_absent_falls_back_to_stdlib(monkeypatch):
    # dig missing → FileNotFoundError → stdlib fallback populates A/AAAA/CNAME
    # only; MX/NS/TXT/SOA stay empty (documented limitation).
    def _no_dig(*a, **k):
        raise FileNotFoundError("dig not installed")

    monkeypatch.setattr(main.subprocess, "run", _no_dig)
    monkeypatch.setattr(
        main.socket,
        "getaddrinfo",
        lambda *a, **k: [
            (main.socket.AF_INET, None, None, "", ("1.2.3.4", 0)),
            (main.socket.AF_INET6, None, None, "", ("2001:db8::1", 0)),
        ],
    )
    monkeypatch.setattr(main, "_socket_cname", lambda host: "canonical.example.net")

    records = main._dig_records("fallback.example.com")
    assert records["A"] == ["1.2.3.4"]
    assert records["AAAA"] == ["2001:db8::1"]
    assert records["CNAME"] == ["canonical.example.net"]
    # Types the stdlib resolver cannot provide are absent.
    assert "MX" not in records
    assert "NS" not in records
    assert "TXT" not in records
    assert "SOA" not in records


def test_dns_records_to_cell_serialization():
    records = {
        "A": ["1.2.3.4"],
        "MX": ["10 mail.x"],
        "NS": ["ns1.x", "ns2.x"],
    }
    cell = main._dns_records_to_cell(records)
    # Values joined by ',', types by ';', in DNS_RECORD_TYPES order.
    assert cell == "A=1.2.3.4;MX=10 mail.x;NS=ns1.x,ns2.x"
    # Empty dict → empty cell.
    assert main._dns_records_to_cell({}) == ""
