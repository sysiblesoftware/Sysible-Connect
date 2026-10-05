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


# ---------------------------------------------------------------- stale seed
# SYSIBLE_CONNECT_CONTROLLER_URL is written once by SLOP's install.sh from a single
# `ip route get` and persisted into Connect's .env so it survives every recreate. On a
# real install the host's network changed, and that frozen address kept Connect dialling
# a host nobody answers at — through every restart, by design.

def _sso(monkeypatch, seed, derived=None):
    monkeypatch.setattr(controller, "_TRUST_GATEWAY", True)
    monkeypatch.setattr(controller, "_SSO_SECRET", "sso-shared-secret")
    monkeypatch.setattr(controller, "_LOCAL_CONTROLLER_URL", seed)
    monkeypatch.setattr(controller, "_DERIVED_CONTROLLER_URL", derived)
    controller.disconnect()


def test_the_observed_host_overrides_a_stale_ip_seed(monkeypatch):
    """The box moved from .22 to .40. The operator opens the portal at the new
    address, and that request is what moves Connect onto it."""
    _sso(monkeypatch, "https://192.168.1.22:9000")
    st = controller.status(host="192.168.1.40")
    assert st["base_url"] == "https://192.168.1.40:9000", "Connect is still on the dead address"


def test_a_configured_name_is_never_overridden(monkeypatch):
    """A compose service name does not go stale with a DHCP lease — it keeps
    resolving to wherever the Controller is. Only an IP literal rots."""
    _sso(monkeypatch, "https://sysible-controller:9000")
    assert controller.status(host="10.0.0.5")["base_url"] == "https://sysible-controller:9000"


def test_an_ipv6_seed_is_overridden_too(monkeypatch):
    _sso(monkeypatch, "https://[2001:db8::22]:9000")
    assert controller.status(host="192.168.1.40")["base_url"] == "https://192.168.1.40:9000"


def test_the_seed_is_used_until_a_browser_arrives(monkeypatch):
    """Nothing observed yet — a fresh install's first moments. The seed is right
    then, and must still be used."""
    _sso(monkeypatch, "https://192.168.1.22:9000")
    assert controller._preferred_url() == "https://192.168.1.22:9000"


def test_the_observed_host_survives_a_restart(monkeypatch, tmp_path):
    """The tokenless paths — terminal, sync — have no request to learn from. If the
    observation died with the process they would fall back to the stale seed until
    somebody happened to open the console."""
    monkeypatch.setattr(controller, "_TRUST_GATEWAY", True)
    monkeypatch.setattr(controller, "_SSO_SECRET", "sso-shared-secret")
    monkeypatch.setattr(controller, "_LOCAL_CONTROLLER_URL", "https://192.168.1.22:9000")
    monkeypatch.setattr(controller, "_HOST_FILE", tmp_path / "gateway_host")
    monkeypatch.setattr(controller, "DATA_DIR", tmp_path)
    monkeypatch.setattr(controller, "_DERIVED_CONTROLLER_URL", None)

    controller.note_gateway_host("192.168.1.40:443")
    assert (tmp_path / "gateway_host").read_text() == "https://192.168.1.40:9000"

    # ... the process restarts: nothing in memory, the file is all there is.
    monkeypatch.setattr(controller, "_DERIVED_CONTROLLER_URL", None)
    controller._load_noted_host()
    assert controller._preferred_url() == "https://192.168.1.40:9000"


def test_a_read_only_data_dir_does_not_break_the_request(monkeypatch, tmp_path):
    monkeypatch.setattr(controller, "_TRUST_GATEWAY", True)
    monkeypatch.setattr(controller, "_SSO_SECRET", "sso-shared-secret")
    monkeypatch.setattr(controller, "_LOCAL_CONTROLLER_URL", "")
    monkeypatch.setattr(controller, "_DERIVED_CONTROLLER_URL", None)
    monkeypatch.setattr(controller, "_HOST_FILE", tmp_path / "nope" / "gateway_host")

    def _boom(*a, **k):
        raise OSError("read-only file system")
    monkeypatch.setattr(controller.DATA_DIR.__class__, "mkdir", _boom)

    controller.note_gateway_host("192.168.1.40")
    assert controller._preferred_url() == "https://192.168.1.40:9000"


def test_observing_is_off_outside_sso_mode(monkeypatch, tmp_path):
    """Standalone Connect attaches with a machine API key to whatever the operator
    saved. Nothing here may touch that."""
    monkeypatch.setattr(controller, "_TRUST_GATEWAY", False)
    monkeypatch.setattr(controller, "_SSO_SECRET", "")
    monkeypatch.setattr(controller, "_DERIVED_CONTROLLER_URL", None)
    monkeypatch.setattr(controller, "_HOST_FILE", tmp_path / "gateway_host")
    controller.note_gateway_host("192.168.1.40")
    assert controller._DERIVED_CONTROLLER_URL is None
    assert not (tmp_path / "gateway_host").exists()
