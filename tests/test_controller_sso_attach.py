"""SLOP SSO auto-attach: when Connect runs in gateway-trust mode and is told where the
local Controller is, it attaches automatically (no manual login) and authenticates to the
Controller with the shared secret (X-Sysible-Auth) instead of a machine API key."""
import backend.controller as controller


class _Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._p = payload

    def json(self):
        if self._p is None:
            raise ValueError("not json")
        return self._p


def _enable_sso(monkeypatch, secret="sso-shared-secret", url="https://sysible-controller:9000"):
    # Constants are read at import; patch the module attributes directly.
    monkeypatch.setattr(controller, "_TRUST_GATEWAY", True)
    monkeypatch.setattr(controller, "_SSO_SECRET", secret)
    monkeypatch.setattr(controller, "_LOCAL_CONTROLLER_URL", url)
    controller.disconnect()   # ensure no saved manual connection shadows the auto-attach


def test_auto_attaches_without_manual_login(monkeypatch):
    _enable_sso(monkeypatch)
    st = controller.status()
    assert st["connected"] is True
    assert st["sso"] is True
    assert st["base_url"] == "https://sysible-controller:9000"


def test_no_autoattach_without_url(monkeypatch):
    _enable_sso(monkeypatch, url="")
    monkeypatch.setattr(controller, "_LOCAL_CONTROLLER_URL", "")
    assert controller.status()["connected"] is False


def test_sync_authenticates_with_shared_secret_not_api_key(monkeypatch):
    _enable_sso(monkeypatch)
    seen = []

    def _capture(method, url, headers=None, json_body=None, verify=None, timeout=None):
        seen.append((url, dict(headers or {})))
        if url.endswith("/remote/hosts"):
            return _Resp(200, {})
        if url.endswith("/agents"):
            return _Resp(200, {"agents": []})
        return _Resp(404, {"detail": "nf"})

    monkeypatch.setattr(controller, "_do_request", _capture)
    out = controller.sync()
    assert out["controller"] == "https://sysible-controller:9000"
    # Every Controller call carried the gateway shared secret and NO machine API key.
    assert seen, "no Controller calls were made"
    for url, headers in seen:
        assert headers.get("X-Sysible-Auth") == "sso-shared-secret", (url, headers)
        assert "X-API-Key" not in headers, (url, headers)


def test_auto_attaches_by_deriving_url_from_gateway_host(monkeypatch):
    # No explicit SYSIBLE_CONNECT_CONTROLLER_URL: derive the local Controller from the
    # host the browser reached Connect on (the gateway host) + :9000 — so it "just works"
    # behind the gateway with zero config.
    monkeypatch.setattr(controller, "_TRUST_GATEWAY", True)
    monkeypatch.setattr(controller, "_SSO_SECRET", "sso-shared-secret")
    monkeypatch.setattr(controller, "_LOCAL_CONTROLLER_URL", "")
    monkeypatch.setattr(controller, "_DERIVED_CONTROLLER_URL", None)
    controller.disconnect()
    st = controller.status(host="192.168.8.139")
    assert st["connected"] is True and st["sso"] is True
    assert st["base_url"] == "https://192.168.8.139:9000"


def test_explicit_url_wins_over_derivation(monkeypatch):
    monkeypatch.setattr(controller, "_TRUST_GATEWAY", True)
    monkeypatch.setattr(controller, "_SSO_SECRET", "sso-shared-secret")
    monkeypatch.setattr(controller, "_LOCAL_CONTROLLER_URL", "https://sysible-controller:9000")
    monkeypatch.setattr(controller, "_DERIVED_CONTROLLER_URL", None)
    controller.disconnect()
    assert controller.status(host="10.0.0.5")["base_url"] == "https://sysible-controller:9000"
