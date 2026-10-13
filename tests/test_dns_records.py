"""Offline tests for the additive per-subdomain DNS records listing (FEAT-002).

These monkeypatch the subprocess runner (main.subprocess.run) to return canned
`dig +short <TYPE>` output per record type so no real DNS/subprocess work
happens, and assert that _dig_records / resolve_dns_records populate the
dns_records dict for A/MX/NS/TXT. A separate dig-absent path (subprocess.run
raising FileNotFoundError) exercises the stdlib fallback: A/AAAA via
socket.getaddrinfo and CNAME via _socket_cname, with MX/NS/TXT/SOA empty.
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

    ``args`` is the ['dig', '+short', '<TYPE>', host] argument list; we look up
    the canned stdout for '<TYPE>' and default to empty output.
    """

    def _run(args, capture_output=True, text=True, timeout=None):
        # args == ['dig', '+short', '<TYPE>', host]
        assert args[0] == "dig"
        assert args[1] == "+short"
        assert "shell" not in str(args)  # defensive: never a shell string
        rtype = args[2]
        return _FakeCompleted(answers.get(rtype, ""))

    return _run


async def test_dig_records_parses_all_types(monkeypatch):
    answers = {
        "A": "1.2.3.4\n5.6.7.8\n",
        "AAAA": "",
        "CNAME": "target.example.net.\n",
        "MX": "10 mail1.example.com.\n20 mail2.example.com.\n",
        "NS": "ns1.example.com.\nns2.example.com.\n",
        "TXT": '"v=spf1 include:_spf.example.com ~all"\n',
        "SOA": "ns1.example.com. hostmaster.example.com. 1 2 3 4 5\n",
    }
    monkeypatch.setattr(main.subprocess, "run", _make_runner(answers))

    records = main._dig_records("live.example.com")

    assert records["A"] == ["1.2.3.4", "5.6.7.8"]
    # Trailing dots stripped on hostname-valued record types.
    assert records["CNAME"] == ["target.example.net"]
    assert records["MX"] == ["10 mail1.example.com", "20 mail2.example.com"]
    assert records["NS"] == ["ns1.example.com", "ns2.example.com"]
    # TXT preserved verbatim (no trailing-dot stripping).
    assert records["TXT"] == ['"v=spf1 include:_spf.example.com ~all"']
    # AAAA produced no answers → omitted from the dict (additive, only present
    # types appear).
    assert "AAAA" not in records


async def test_resolve_dns_records_async_wrapper(monkeypatch):
    answers = {"A": "9.9.9.9\n", "TXT": "hello\n"}
    monkeypatch.setattr(main.subprocess, "run", _make_runner(answers))

    records = await main.resolve_dns_records("ok.example.com")
    assert records["A"] == ["9.9.9.9"]
    assert records["TXT"] == ["hello"]


async def test_dig_records_invalid_host_returns_empty(monkeypatch):
    # Invalid hostnames are gated before any subprocess call.
    def _boom(*a, **k):  # pragma: no cover - must never be called
        raise AssertionError("subprocess.run must not run for invalid hosts")

    monkeypatch.setattr(main.subprocess, "run", _boom)
    assert main._dig_records("not a host/@") == {}


async def test_dig_records_timeout_skips_type(monkeypatch):
    # A TimeoutExpired on one type must not kill the whole enumeration.
    def _run(args, capture_output=True, text=True, timeout=None):
        if args[2] == "MX":
            raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)
        return _FakeCompleted("1.2.3.4\n" if args[2] == "A" else "")

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
