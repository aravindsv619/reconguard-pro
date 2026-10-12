"""Offline tests for resolve_dns_detailed / resolve_cname_chain in main.py.

These monkeypatch the blocking sync resolver helpers (_dig_dns_status,
_socket_dns_status, _resolve_cname_sync) so no real DNS lookup happens. They
assert the dns_status vocabulary (RESOLVED / NXDOMAIN / NO_ANSWER / ...), the
derived resolved boolean, and that cname_chain captures a multi-hop chain
whose first element equals the single-hop cname.
"""

import pytest

import main


async def test_dns_status_nxdomain(monkeypatch):
    # dig signals NXDOMAIN with no addresses.
    monkeypatch.setattr(main, "_dig_dns_status", lambda host: ([], "NXDOMAIN"))
    ips, status = await main.resolve_dns_detailed("gone.example.com")
    assert ips == []
    assert status == "NXDOMAIN"
    assert (status == "RESOLVED") is False  # resolved derivation


async def test_dns_status_resolved(monkeypatch):
    monkeypatch.setattr(
        main, "_dig_dns_status", lambda host: (["1.2.3.4", "5.6.7.8"], "RESOLVED")
    )
    ips, status = await main.resolve_dns_detailed("live.example.com")
    assert ips == ["1.2.3.4", "5.6.7.8"]
    assert status == "RESOLVED"
    assert (status == "RESOLVED") is True


async def test_dns_status_no_answer(monkeypatch):
    # CNAME-only host: NOERROR but no A/AAAA answer → NO_ANSWER.
    monkeypatch.setattr(main, "_dig_dns_status", lambda host: ([], "NO_ANSWER"))
    ips, status = await main.resolve_dns_detailed("cname-only.example.com")
    assert ips == []
    assert status == "NO_ANSWER"
    assert (status == "RESOLVED") is False


async def test_dns_status_socket_fallback_nxdomain(monkeypatch):
    # dig absent → stdlib fallback maps EAI_NONAME gaierror to NXDOMAIN.
    import socket as _socket

    monkeypatch.setattr(main, "_dig_dns_status", lambda host: None)

    def _boom(*args, **kwargs):
        raise _socket.gaierror(_socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(main.socket, "getaddrinfo", _boom)
    ips, status = await main.resolve_dns_detailed("nope.example.com")
    assert ips == []
    assert status == "NXDOMAIN"


async def test_dns_status_socket_fallback_resolved(monkeypatch):
    monkeypatch.setattr(main, "_dig_dns_status", lambda host: None)
    monkeypatch.setattr(
        main.socket,
        "getaddrinfo",
        lambda *a, **k: [(None, None, None, "", ("9.9.9.9", 0))],
    )
    ips, status = await main.resolve_dns_detailed("ok.example.com")
    assert ips == ["9.9.9.9"]
    assert status == "RESOLVED"


async def test_cname_chain_multi_hop(monkeypatch):
    # Model a two-hop chain: host -> a.herokudns.com -> app.herokuapp.com.
    hops = {
        "foo.example.com": "a.herokudns.com",
        "a.herokudns.com": "app.herokuapp.com",
        "app.herokuapp.com": None,
    }
    monkeypatch.setattr(main, "_resolve_cname_sync", lambda host: hops.get(host))

    chain = await main.resolve_cname_chain("foo.example.com")
    assert chain == ["a.herokudns.com", "app.herokuapp.com"]

    # cname_chain[0] must equal the single-hop cname.
    single = await main.resolve_cname("foo.example.com")
    assert chain[0] == single


async def test_cname_chain_loop_protection(monkeypatch):
    # A -> B -> A loop must terminate and not exceed the hop cap.
    hops = {"a.example.com": "b.example.com", "b.example.com": "a.example.com"}
    monkeypatch.setattr(main, "_resolve_cname_sync", lambda host: hops.get(host))
    chain = await main.resolve_cname_chain("a.example.com")
    assert len(chain) <= main.MAX_CNAME_HOPS
    assert chain[0] == "b.example.com"


async def test_cname_chain_empty_when_no_cname(monkeypatch):
    monkeypatch.setattr(main, "_resolve_cname_sync", lambda host: None)
    chain = await main.resolve_cname_chain("plain.example.com")
    assert chain == []
