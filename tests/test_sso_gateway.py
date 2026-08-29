"""SLOP SSO gateway trust mode (SYSIBLE_CONNECT_TRUST_GATEWAY_AUTH).

Connect trusts the gateway-asserted X-Sysible-* identity ONLY when trust mode is
enabled AND the request presents the shared secret in X-Sysible-Auth. It is off by
default and fails closed when the secret is unset/mismatched.

The trust config is read once at module load, so these tests flip the resolved
module-level flags directly (monkeypatch), rather than relying on env at import.
"""
import pytest
from fastapi.testclient import TestClient

import backend.app as app_module

_SECRET = "shhh-gateway-secret"
_HDRS = {"X-Sysible-User": "alice", "X-Sysible-Role": "operator",
         "X-Sysible-Auth": _SECRET}


@pytest.fixture
def trust_on(monkeypatch):
    """Enable trust mode with a configured shared secret."""
    monkeypatch.setattr(app_module, "_TRUST_GATEWAY", True)
    monkeypatch.setattr(app_module, "_SSO_SECRET", _SECRET)


def test_off_by_default_header_ignored(client):
    # Trust mode is off out of the box: identity headers must be ignored entirely.
    assert app_module._TRUST_GATEWAY is False
    r = client.get("/api/me", headers=_HDRS)
    assert r.status_code == 200 and r.json()["user"] is None
    # And a protected route stays 401 despite the headers.
    assert client.get("/api/hosts", headers=_HDRS).status_code == 401


def test_trust_on_correct_secret_honored(client, trust_on):
    r = client.get("/api/me", headers=_HDRS)
    assert r.status_code == 200 and r.json() == {"user": "alice", "must_change": False}
    # Protected route is reachable with no cookie — the gateway identity carries it.
    assert client.get("/api/hosts", headers=_HDRS).status_code == 200


def test_wrong_secret_ignored(client, trust_on):
    bad = {**_HDRS, "X-Sysible-Auth": "not-the-secret"}
    assert client.get("/api/me", headers=bad).json()["user"] is None
    assert client.get("/api/hosts", headers=bad).status_code == 401


def test_missing_secret_ignored(client, trust_on):
    no_auth = {"X-Sysible-User": "alice", "X-Sysible-Role": "operator"}
    assert client.get("/api/me", headers=no_auth).json()["user"] is None
    assert client.get("/api/hosts", headers=no_auth).status_code == 401


def test_fail_closed_when_secret_unset(client, monkeypatch):
    # Trust mode on but no shared secret configured -> never honor the headers,
    # even if the request tries to present an empty X-Sysible-Auth.
    monkeypatch.setattr(app_module, "_TRUST_GATEWAY", True)
    monkeypatch.setattr(app_module, "_SSO_SECRET", "")
    assert app_module.gateway_identity({"x-sysible-user": "alice",
                                         "x-sysible-auth": ""}) is None
    assert client.get("/api/hosts", headers=_HDRS).status_code == 401


def test_empty_user_ignored(trust_on):
    # Correct secret but a blank asserted user is not a valid identity.
    assert app_module.gateway_identity(
        {"x-sysible-user": "  ", "x-sysible-auth": _SECRET}) is None


def test_websocket_accepts_gateway_identity(trust_on):
    # The WS upgrade carries the X-Sysible-* headers; trust mode authenticates the
    # socket without a session cookie. A local shell session opens, so no 4401.
    with TestClient(app_module.app) as c:
        with c.websocket_connect("/api/terminal/ws?kind=local", headers=_HDRS) as ws:
            msg = ws.receive_json()
            assert msg["t"] in ("o", "exit")


def test_websocket_rejects_wrong_secret(trust_on):
    bad = {**_HDRS, "X-Sysible-Auth": "nope"}
    with TestClient(app_module.app) as c:
        with pytest.raises(Exception):
            with c.websocket_connect("/api/terminal/ws?kind=local", headers=bad) as ws:
                ws.receive_json()
