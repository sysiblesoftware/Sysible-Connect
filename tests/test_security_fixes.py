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


# ---- propagated SLOP-audit fixes -------------------------------------------
def test_security_headers_present(client):
    # Every response carries the clickjacking + sniffing + referrer defenses.
    r = client.get("/api/ping")
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("Referrer-Policy") == "no-referrer"
    assert "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", "")


def test_throttle_key_uses_trusted_last_xff_hop():
    # The per-IP login throttle keys on the rightmost X-Forwarded-For hop (the one a
    # front proxy appends), so a client-injected leftmost entry can't dodge the
    # throttle or forge a victim's IP.
    class _Req:
        def __init__(self, xff, peer):
            self.headers = {"x-forwarded-for": xff} if xff else {}
            self.client = type("C", (), {"host": peer})() if peer else None

    assert app_module._client_ip(_Req("1.2.3.4, 10.0.0.9", "172.16.0.1")) == "10.0.0.9"
    assert app_module._client_ip(_Req("", "192.168.1.5")) == "192.168.1.5"
    assert app_module._throttle_key(_Req("1.2.3.4, 10.0.0.9", "172.16.0.1"), "Admin") == "10.0.0.9:admin"


def test_oversized_body_rejected_413(client):
    # An oversized Content-Length is refused before the body is read (memory-DoS guard).
    huge = app_module._MAX_REQUEST_BYTES + 1
    r = client.post("/api/login", content=b"x" * 16,
                    headers={"Content-Type": "application/json", "Content-Length": str(huge)})
    assert r.status_code == 413


# ---- audit trail -----------------------------------------------------------
def test_audit_records_actions_and_is_readable(auth_client):
    # A recorded action shows up newest-first with actor/action/target.
    auth_client.post("/api/hosts", json={"name": "h1", "address": "10.0.0.1",
                                         "user": "root", "port": 22, "password": "s3cret-pw"})
    r = auth_client.get("/api/audit")
    assert r.status_code == 200
    entries = r.json()["entries"]
    actions = [e["action"] for e in entries]
    assert "host_add" in actions and "login" in actions
    assert entries[0]["id"] > entries[-1]["id"]          # newest first
    add = next(e for e in entries if e["action"] == "host_add")
    assert add["target"] == "h1" and add["actor"] == "admin"


def test_audit_never_records_secrets(auth_client):
    # The host credential, and a fleet command's OUTPUT, must never reach the trail.
    auth_client.post("/api/hosts", json={"name": "h2", "address": "10.0.0.2",
                                         "user": "root", "port": 22,
                                         "password": "TOP-SECRET-PASSWORD",
                                         "key": "-----BEGIN OPENSSH PRIVATE KEY-----"})
    blob = auth_client.get("/api/audit").text
    assert "TOP-SECRET-PASSWORD" not in blob
    assert "BEGIN OPENSSH PRIVATE KEY" not in blob


def test_audit_since_id_cursor(auth_client):
    first = auth_client.get("/api/audit").json()["entries"]
    top = first[0]["id"]
    auth_client.post("/api/hosts", json={"name": "h3", "address": "10.0.0.3",
                                         "user": "root", "port": 22})
    fresh = auth_client.get("/api/audit", params={"since_id": top}).json()["entries"]
    assert fresh and all(e["id"] > top for e in fresh)


def test_audit_requires_a_session(client):
    assert client.get("/api/audit").status_code == 401


def test_audit_write_failure_never_breaks_the_action(auth_client, monkeypatch):
    # An audit write is a record of the work, not part of it: if it fails the user's
    # action must still succeed.
    import backend.audit as audit_mod
    monkeypatch.setattr(audit_mod, "_read_all", lambda: (_ for _ in ()).throw(OSError("boom")))
    monkeypatch.setattr(audit_mod, "_next_id", None)
    r = auth_client.post("/api/hosts", json={"name": "h4", "address": "10.0.0.4",
                                             "user": "root", "port": 22})
    assert r.status_code == 200
