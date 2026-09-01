"""Controller integration: connect + sync the fleet, and proxy a terminal through
the Controller. The Controller's HTTP API is mocked (requests.request)."""
import backend.controller as controller


class _Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._p = payload

    def json(self):
        if self._p is None:
            raise ValueError("not json")
        return self._p


def _fake_api(routes, *, record=None):
    """routes: {(METHOD, path_suffix): _Resp}. path matched by endswith. Mocks the
    controller._do_request seam (all outbound Controller HTTP funnels through it)."""
    def req(method, url, headers=None, json_body=None, verify=None, timeout=None):
        if record is not None:
            record.append((method, url, json_body))
        for (m, suffix), resp in routes.items():
            if method == m and url.endswith(suffix):
                return resp() if callable(resp) else resp
        return _Resp(404, {"detail": "not found"})
    return req


# -------------------------------------------------------------- connect + sync
def test_status_disconnected(auth_client):
    assert auth_client.get("/api/controller").json() == {
        "connected": False, "base_url": "", "sso": False, "run_as": ""}


def test_requires_auth(client):
    assert client.get("/api/controller").status_code == 401
    assert client.post("/api/controller/sync").status_code == 401


def test_connect_bad_key(auth_client, monkeypatch):
    monkeypatch.setattr(controller, "_do_request",
                        _fake_api({("GET", "/remote/hosts"): _Resp(401)}))
    r = auth_client.post("/api/controller", json={"base_url": "https://ctrl:9000", "api_key": "bad"})
    assert r.status_code == 400 and "rejected" in r.json()["detail"].lower()


def test_connect_then_sync_imports_fleet(auth_client, monkeypatch):
    monkeypatch.setattr(controller, "_do_request", _fake_api({
        ("GET", "/remote/hosts"): _Resp(200, {"db1": {"ip": "10.0.0.21", "user": "deploy",
                                                       "port": 2222, "environment": "prod"}}),
        ("GET", "/agents"): _Resp(200, {"agents": [
            {"hostname": "web1", "ip": "10.0.0.11", "environment": "prod"},
            {"hostname": "nat-box", "ip": "", "environment": "dev"}]}),  # NAT'd: no ip
    }))
    # connect
    s = auth_client.post("/api/controller", json={"base_url": "https://ctrl:9000", "api_key": "K"}).json()
    assert s["connected"] and s["base_url"] == "https://ctrl:9000"
    # sync
    d = auth_client.post("/api/controller/sync").json()
    assert d["imported"] == 3 and d["agents"] == 2 and d["ssh_hosts"] == 1
    # hosts show up, tagged as controller-sourced with their transport
    hosts = {h["name"]: h for h in auth_client.get("/api/hosts").json()["hosts"]}
    assert hosts["db1"]["source"] == "controller" and hosts["db1"]["transport"] == "ssh"
    assert hosts["web1"]["transport"] == "agent" and hosts["web1"]["address"] == "10.0.0.11"
    assert hosts["nat-box"]["transport"] == "agent" and hosts["nat-box"]["address"] == ""  # proxied by name


def test_disconnect(auth_client, monkeypatch):
    monkeypatch.setattr(controller, "_do_request",
                        _fake_api({("GET", "/remote/hosts"): _Resp(200, {})}))
    auth_client.post("/api/controller", json={"base_url": "https://ctrl:9000", "api_key": "K"})
    assert auth_client.get("/api/controller").json()["connected"] is True
    auth_client.delete("/api/controller")
    assert auth_client.get("/api/controller").json()["connected"] is False


# --------------------------------------------------------- terminal proxy unit
def test_terminal_proxy_open_read_write(monkeypatch):
    # A connected Controller (so TerminalProxy can load the config).
    monkeypatch.setattr(controller, "_do_request",
                        _fake_api({("GET", "/remote/hosts"): _Resp(200, {})}))
    controller.connect("https://ctrl:9000", "K")

    reads = iter([
        _Resp(200, {"data": "hello", "closed": False}),
        _Resp(200, {"data": "", "closed": True}),   # shell ended
    ])
    sent = []
    monkeypatch.setattr(controller, "_do_request", _fake_api({
        ("POST", "/terminal/open"): _Resp(200, {"session_id": "sid123", "opened": True}),
        ("GET", "/terminal/sid123/read"): lambda: next(reads),
        ("POST", "/terminal/sid123/write"): _Resp(200, {"written": 3}),
        ("POST", "/terminal/sid123/close"): _Resp(200, {"closed": True}),
    }, record=sent))

    sess = controller.TerminalProxy("web1", cols=80, rows=24)
    assert sess.read() == b"hello"          # first poll returns output
    assert sess.read() == b""               # second poll: closed → EOF
    sess.write(b"ls\n")
    assert any("/terminal/sid123/write" in u and j == {"data": "ls\n"} for (_, u, j) in sent)
    sess.close()


def test_terminal_proxy_agent_offline(monkeypatch):
    monkeypatch.setattr(controller, "_do_request",
                        _fake_api({("GET", "/remote/hosts"): _Resp(200, {})}))
    controller.connect("https://ctrl:9000", "K")
    monkeypatch.setattr(controller, "_do_request",
                        _fake_api({("POST", "/terminal/open"): _Resp(503, {"detail": "agent offline"})}))
    try:
        controller.TerminalProxy("web1")
        assert False, "should have raised"
    except controller.ControllerError as e:
        assert "agent" in str(e).lower()


def test_connect_refuses_loopback(auth_client):
    # SSRF guard: a Controller URL resolving to loopback/metadata is rejected before
    # any request is made.
    r = auth_client.post("/api/controller", json={"base_url": "https://127.0.0.1:9000", "api_key": "K"})
    assert r.status_code == 400 and "loopback" in r.json()["detail"].lower()


def test_controller_key_encrypted_at_rest(auth_client, monkeypatch):
    # The machine API key must not sit in plaintext on disk (F2).
    monkeypatch.setattr(controller, "_do_request",
                        _fake_api({("GET", "/remote/hosts"): _Resp(200, {})}))
    auth_client.post("/api/controller", json={"base_url": "https://ctrl:9000", "api_key": "SECRET-KEY-123"})
    raw = controller._CFG.read_text()
    assert "SECRET-KEY-123" not in raw          # not plaintext
    assert "api_key_enc" in raw                  # stored encrypted
    assert controller._load()["api_key"] == "SECRET-KEY-123"   # round-trips in memory


def test_connect_with_username_password(auth_client, monkeypatch):
    # Username/password path: exchange creds at /auth/api-key, then validate the key.
    # /admin/login (best-effort run-as token) is left to default 404 → tokenless connect.
    monkeypatch.setattr(controller, "_do_request", _fake_api({
        ("POST", "/auth/api-key"): _Resp(200, {"api_key": "EXCH-KEY"}),
        ("GET", "/remote/hosts"): _Resp(200, {}),
    }))
    r = auth_client.post("/api/controller", json={"base_url": "https://ctrl:9000",
                                                  "username": "admin", "password": "pw"})
    assert r.status_code == 200 and r.json()["connected"] is True
    assert controller._load()["api_key"] == "EXCH-KEY"


def test_connect_creds_rejected(auth_client, monkeypatch):
    monkeypatch.setattr(controller, "_do_request", _fake_api({
        ("POST", "/auth/api-key"): _Resp(401, {"detail": "bad creds"}),
    }))
    r = auth_client.post("/api/controller", json={"base_url": "https://ctrl:9000",
                                                  "username": "admin", "password": "wrong"})
    assert r.status_code == 400 and "bad creds" in r.json()["detail"]
