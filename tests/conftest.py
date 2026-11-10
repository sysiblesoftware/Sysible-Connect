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

# A stand-in for the built SPA, also before any backend import.
#
# backend/app.py registers the /assets mount and the catch-all SPA route only
# when the dist tree EXISTS, and a fresh clone has not been built -- so in a
# fresh clone those routes were absent, every request to them 404'd, and the six
# tests asserting that the catch-all CONTAINS a path traversal were asserting it
# about a route that was not there. Red in every clone, and vacuous: a genuine
# containment bug would not have moved them.
#
# A handful of files is enough. The security question is what the catch-all does
# with "/../auth.json", not what is in index.html.
_DIST = tempfile.mkdtemp(prefix="connect-test-dist-")
os.makedirs(os.path.join(_DIST, "assets"), exist_ok=True)
with open(os.path.join(_DIST, "index.html"), "w", encoding="utf-8") as _fh:
    _fh.write("<!doctype html><html><body>Sysible Connect</body></html>")
with open(os.path.join(_DIST, "favicon.svg"), "w", encoding="utf-8") as _fh:
    _fh.write('<svg xmlns="http://www.w3.org/2000/svg"/>')
with open(os.path.join(_DIST, "assets", "index.js"), "w", encoding="utf-8") as _fh:
    _fh.write("// built bundle\n")
os.environ.setdefault("SYSIBLE_CONNECT_DIST", _DIST)

# Something OUTSIDE the dist tree, next to it, with the shape of the file the
# traversal tests are trying to reach. If containment ever broke, "/../auth.json"
# would now actually find something -- which is what makes those tests able to
# fail for the right reason rather than for a missing route.
with open(os.path.join(os.path.dirname(_DIST), "auth.json"), "w",
          encoding="utf-8") as _fh:
    _fh.write('{"salt": "NOT-FOR-DISCLOSURE", "hash": "NOT-FOR-DISCLOSURE"}')

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
