"""Fleet run: one command across hosts via the terminal transport (Controller proxy
mocked)."""
import backend.controller as controller
import backend.hosts as hosts
import backend.fleet as fleet


class _Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._p = payload

    def json(self):
        return self._p


def _fake(routes):
    def req(method, url, headers=None, json=None, verify=None, timeout=None):
        for (m, suffix), resp in routes.items():
            if method == m and url.endswith(suffix):
                return resp() if callable(resp) else resp
        return _Resp(404, {"detail": "nf"})
    return req


def test_fleet_run_on_controller_host(monkeypatch):
    monkeypatch.setattr(controller.requests, "request",
                        _fake({("GET", "/remote/hosts"): _Resp(200, {})}))
    controller.connect("https://ctrl:9000", "K")
    hosts.upsert_controller_host("web1", address="10.0.0.11", transport="agent")

    reads = iter([_Resp(200, {"data": "load: 0.1\n", "closed": False}),
                  _Resp(200, {"data": "", "closed": True})])
    monkeypatch.setattr(controller.requests, "request", _fake({
        ("POST", "/terminal/open"): _Resp(200, {"session_id": "s1", "opened": True}),
        ("GET", "/terminal/s1/read"): lambda: next(reads),
        ("POST", "/terminal/s1/write"): _Resp(200, {"written": 1}),
        ("POST", "/terminal/s1/close"): _Resp(200, {"closed": True}),
    }))
    res = fleet.run("uptime", ["web1"])
    assert res[0]["name"] == "web1" and res[0]["ok"] and "load: 0.1" in res[0]["output"]


def test_fleet_missing_host_reports_error():
    res = fleet.run("x", ["nope"])
    assert res[0]["ok"] is False and "not found" in res[0]["output"]


def test_fleet_requires_command():
    try:
        fleet.run("  ", ["a"])
        assert False, "should raise"
    except ValueError:
        pass


def test_fleet_endpoint_requires_auth(client):
    assert client.post("/api/fleet/run", json={"command": "id"}).status_code == 401
