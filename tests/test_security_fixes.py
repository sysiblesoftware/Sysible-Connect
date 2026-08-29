"""Regression tests for the pentest fixes:

  * SPA catch-all path traversal is contained (arbitrary host files are never served).
  * The terminal websocket enforces a strict Origin allowlist (anti-CSWSH).
  * The SSO role floor denies a read-only auditor a terminal and the state-changing
    routes in gateway-trust mode, and fails closed on an empty/unknown role.
  * The local password login is disabled in gateway-trust mode.
  * The Controller SSRF guard fails closed on resolution error and blocks metadata /
    IPv4-mapped forms; the peer re-check refuses a blocked connected address.
  * secret.key / auth.json refuse to follow a pre-planted symlink (O_NOFOLLOW).
"""
import os

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import backend.app as app_module
import backend.auth as auth
import backend.controller as controller
import backend.secret as secret

_SECRET = "shhh-gateway-secret"
_ORIGIN = "https://connect.slop.lan"


@pytest.fixture
def trust_on(monkeypatch):
    monkeypatch.setattr(app_module, "_TRUST_GATEWAY", True)
    monkeypatch.setattr(app_module, "_SSO_SECRET", _SECRET)


def _gw(role):
    return {"X-Sysible-User": "alice", "X-Sysible-Role": role,
            "X-Sysible-Auth": _SECRET, "Origin": _ORIGIN}


# --------------------------------------------------- CRITICAL: SPA path traversal
def test_spa_serves_index_fallback_for_unknown_route(client):
    r = client.get("/some/client/side/route")
    assert r.status_code == 200 and b"<!doctype html" in r.content.lower()


def test_spa_serves_real_asset(client):
    # A genuine file in the dist tree is still served (containment doesn't over-block).
    r = client.get("/favicon.svg")
    assert r.status_code == 200 and "svg" in r.headers.get("content-type", "")


@pytest.mark.parametrize("path", [
    "/../auth.json",
    "/..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/app/../../../../../../etc/passwd",
])
def test_spa_path_traversal_is_contained(client, path):
    # Any attempt to escape the dist tree collapses to the SPA index.html — the
    # process environment, /etc/passwd, and the credential store are never disclosed.
    r = client.get(path)
    assert r.status_code == 200
    body = r.content.lower()
    assert b"<!doctype html" in body
    assert b"root:" not in body          # /etc/passwd content
    assert b'"salt"' not in body and b'"hash"' not in body   # auth.json content


# ----------------------------------------------- HIGH: terminal WS Origin allowlist
def test_ws_rejected_on_sibling_origin(auth_client):
    with pytest.raises(WebSocketDisconnect) as ei:
        with auth_client.websocket_connect(
                "/api/terminal/ws?kind=local",
                headers={"Origin": "https://evil.slop.lan"}) as ws:
            ws.receive_json()
    assert ei.value.code == 4403


def test_ws_rejected_on_absent_origin(auth_client):
    with pytest.raises(WebSocketDisconnect) as ei:
        with auth_client.websocket_connect("/api/terminal/ws?kind=local") as ws:
            ws.receive_json()
    assert ei.value.code == 4403


def test_ws_accepted_on_allowed_origin(auth_client):
    with auth_client.websocket_connect(
            "/api/terminal/ws?kind=local", headers={"Origin": _ORIGIN}) as ws:
        assert ws.receive_json()["t"] in ("o", "exit")


def test_ws_origin_allowlist_is_configurable(auth_client, monkeypatch):
    monkeypatch.setattr(app_module, "_ALLOWED_ORIGINS", {"https://console.example.test"})
    # The previous default is now rejected...
    with pytest.raises(WebSocketDisconnect):
        with auth_client.websocket_connect(
                "/api/terminal/ws?kind=local", headers={"Origin": _ORIGIN}) as ws:
            ws.receive_json()
    # ...and the newly-allowed origin is accepted.
    with auth_client.websocket_connect(
            "/api/terminal/ws?kind=local",
            headers={"Origin": "https://console.example.test"}) as ws:
        assert ws.receive_json()["t"] in ("o", "exit")


# ------------------------------------------------------- HIGH: SSO role floor
def test_auditor_denied_terminal_in_trust_mode(trust_on):
    with TestClient(app_module.app) as c:
        with pytest.raises(WebSocketDisconnect) as ei:
            with c.websocket_connect("/api/terminal/ws?kind=local",
                                     headers=_gw("auditor")) as ws:
                ws.receive_json()
        assert ei.value.code == 4403


def test_operator_allowed_terminal_in_trust_mode(trust_on):
    with TestClient(app_module.app) as c:
        with c.websocket_connect("/api/terminal/ws?kind=local",
                                 headers=_gw("operator")) as ws:
            assert ws.receive_json()["t"] in ("o", "exit")


def test_unknown_role_fails_closed_terminal(trust_on):
    # An empty / unrecognized asserted role is denied, not defaulted to full access.
    for role in ("", "wheel", "  "):
        with TestClient(app_module.app) as c:
            with pytest.raises(WebSocketDisconnect):
                with c.websocket_connect("/api/terminal/ws?kind=local",
                                         headers=_gw(role)) as ws:
                    ws.receive_json()


def test_auditor_denied_state_changing_http_routes(client, trust_on):
    a = _gw("auditor")
    assert client.post("/api/fleet/run", json={"command": "id"}, headers=a).status_code == 403
    assert client.post("/api/hosts", json={"name": "x", "address": "1.2.3.4"}, headers=a).status_code == 403
    assert client.delete("/api/hosts/x", headers=a).status_code == 403
    assert client.post("/api/controller", json={"base_url": "https://c:9000", "api_key": "k"},
                       headers=a).status_code == 403
    assert client.post("/api/controller/sync", headers=a).status_code == 403


def test_auditor_may_still_read(client, trust_on):
    # Read-only oversight is preserved: listing hosts / controller status is allowed.
    a = _gw("auditor")
    assert client.get("/api/hosts", headers=a).status_code == 200
    assert client.get("/api/controller", headers=a).status_code == 200


def test_operator_allowed_state_changing_http(client, trust_on):
    o = _gw("operator")
    assert client.post("/api/hosts", json={"name": "box", "address": "10.0.0.9",
                                           "user": "root"}, headers=o).status_code == 200


def test_standalone_single_user_unchanged(auth_client):
    # No gateway identity → no role floor: the single admin keeps full access.
    assert auth_client.post("/api/hosts", json={"name": "box", "address": "10.0.0.9",
                                                "user": "root"}).status_code == 200


# ---------------------------------------------- LOW: local login disabled in SSO mode
def test_local_login_disabled_in_trust_mode(client, trust_on):
    r = client.post("/api/login", json={"username": "admin", "password": "test1234"})
    assert r.status_code == 403


# ---------------------------------------------------- MEDIUM: SSRF guard hardening
def test_guard_url_fails_closed_on_resolution_error(monkeypatch):
    import socket
    def boom(*a, **k):
        raise socket.gaierror("nope")
    monkeypatch.setattr(controller.socket, "getaddrinfo", boom)
    with pytest.raises(controller.ControllerError):
        controller._guard_url("https://unresolvable.example.test:9000")


def test_guard_url_blocks_metadata(monkeypatch):
    import socket
    monkeypatch.setattr(controller.socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))])
    with pytest.raises(controller.ControllerError):
        controller._guard_url("https://rebind.example.test:9000")


def test_guard_url_rejects_when_any_address_blocked(monkeypatch):
    import socket
    # A split answer with one public and one loopback address is rejected wholesale.
    monkeypatch.setattr(controller.socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.5", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
    ])
    with pytest.raises(controller.ControllerError):
        controller._guard_url("https://split.example.test:9000")


def test_vet_addr_collapses_ipv4_mapped():
    ip = controller._vet_addr("::ffff:169.254.169.254")
    assert ip is not None and controller._blocked_ip(ip)


def test_peer_recheck_blocks_internal_connected_address():
    class _Sock:
        def __init__(self, ip): self._ip = ip; self.closed = False
        def getpeername(self): return (self._ip, 443)
        def close(self): self.closed = True
    blocked = _Sock("169.254.169.254")
    with pytest.raises(OSError):
        controller._assert_peer_allowed(blocked)
    assert blocked.closed
    # A public peer is allowed through untouched.
    controller._assert_peer_allowed(_Sock("203.0.113.7"))


# ------------------------------------ MEDIUM: symlink/O_NOFOLLOW on key + credentials
def test_secret_key_refuses_planted_symlink(tmp_path, monkeypatch):
    victim = tmp_path / "attacker-readable"
    victim.write_bytes(b"not-a-key")
    link = tmp_path / "secret.key"
    os.symlink(victim, link)
    monkeypatch.setattr(secret, "_KEY_FILE", link)
    # _fernet must not follow the symlink to read/overwrite the victim file.
    with pytest.raises(OSError):
        secret._fernet()
    assert victim.read_bytes() == b"not-a-key"   # untouched


def test_secret_key_created_race_safe(tmp_path, monkeypatch):
    kf = tmp_path / "secret.key"
    monkeypatch.setattr(secret, "_KEY_FILE", kf)
    secret._fernet()
    assert kf.exists() and not kf.is_symlink()
    assert (kf.stat().st_mode & 0o777) == 0o600


def test_auth_store_refuses_planted_symlink(tmp_path):
    victim = tmp_path / "loot"
    victim.write_text("{}")
    link = tmp_path / "auth.json"
    os.symlink(victim, link)
    orig = auth._AUTH_FILE
    auth._AUTH_FILE = link
    try:
        with pytest.raises(OSError):
            auth._save({"user": "admin"})
        assert victim.read_text() == "{}"   # not overwritten through the link
    finally:
        auth._AUTH_FILE = orig
