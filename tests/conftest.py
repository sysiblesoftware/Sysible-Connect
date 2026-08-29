"""Shared fixtures for the Sysible Connect test-suite.

The data dir is redirected to a temp path BEFORE any backend import, so
auth.DATA_DIR (and hosts.py, which imports it) resolve to an isolated store
rather than the developer's ~/.sysible-connect. The admin is seeded from the
env so login works with a known password.
"""
import os
import tempfile

os.environ["SYSIBLE_CONNECT_DATA"] = tempfile.mkdtemp(prefix="connect-test-")
os.environ.setdefault("SYSIBLE_CONNECT_USER", "admin")
os.environ.setdefault("SYSIBLE_CONNECT_PASSWORD", "test1234")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import backend.app as app_module  # noqa: E402
import backend.auth as auth  # noqa: E402
import backend.hosts as hosts  # noqa: E402


@pytest.fixture(autouse=True)
def _stub_controller_dns(monkeypatch):
    """The Controller SSRF guard now FAILS CLOSED on an unresolvable host. Tests use
    stand-in hostnames like 'ctrl' that don't resolve here, so map them to a benign
    public TEST-NET address; IP literals resolve to themselves so loopback/metadata
    rejection is still exercised (e.g. test_connect_refuses_loopback)."""
    import ipaddress
    import socket as _socket
    import backend.controller as controller

    def _fake_getaddrinfo(host, *a, **k):
        try:
            ipaddress.ip_address(host)
            addr = host
        except ValueError:
            addr = "203.0.113.10"   # TEST-NET-3 (RFC 5737): public, not blocked
        return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", (addr, 0))]

    monkeypatch.setattr(controller.socket, "getaddrinfo", _fake_getaddrinfo)
    yield


@pytest.fixture(autouse=True)
def _isolate():
    """Empty host store, no Controller connection, and a seeded admin before every
    test, so order never matters."""
    with hosts._LOCK:
        hosts._save({})
    import backend.controller as controller
    controller.disconnect()
    app_module._LOGIN_FAIL.clear()
    auth.ensure_admin()
    yield


@pytest.fixture
def client():
    """Unauthenticated TestClient."""
    return TestClient(app_module.app)


@pytest.fixture
def auth_client():
    """TestClient with a live admin session (cookies persist on the instance)."""
    c = TestClient(app_module.app)
    r = c.post("/api/login", json={"username": "admin", "password": "test1234"})
    assert r.status_code == 200, r.text
    return c
