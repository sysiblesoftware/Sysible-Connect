"""Who the fleet terminal runs as: Connect must forward the signed-in operator.

Connect proxies terminals for Controller-synced hosts through the Controller's
terminal API. The Controller decides whose account the shell runs as (and who the
audit trail names) from the identity on EACH request:

  * a manual username/password attach sends X-Sysible-Admin-Token,
  * an SSO auto-attach has no token at all — the operator has no local Controller
    password, because the SLOP sign-in is their login — so the acting identity has
    to travel per request as X-Sysible-User/-Role beside the shared secret.

_request grew the `identity` parameter to do that, and then nothing ever passed
it: every call site used the default None. Under SSO the Controller therefore saw
no identity, ran every shell as its default account, and the console reported
"API-key connect (no run-as)". These tests assert the identity is actually on the
wire for the open AND for every follow-up call in the session, and that a caller
who cannot prove it came through the gateway can never name one.
"""
import backend.app as capp
import backend.controller as controller


class _Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._p = payload

    def json(self):
        if self._p is None:
            raise ValueError("not json")
        return self._p


SECRET = "sso-shared-secret"
ALICE = {"user": "alice", "role": "sysadmin"}


def _enable_sso(monkeypatch, url="https://sysible-controller:9000"):
    monkeypatch.setattr(controller, "_TRUST_GATEWAY", True)
    monkeypatch.setattr(controller, "_SSO_SECRET", SECRET)
    monkeypatch.setattr(controller, "_LOCAL_CONTROLLER_URL", url)
    controller.disconnect()


def _capture(monkeypatch):
    """Stand in for the Controller; record (url, headers) of every call."""
    seen = []

    def _do(method, url, headers=None, json_body=None, verify=None, timeout=None):
        seen.append((method, url, dict(headers or {})))
        if url.endswith("/terminal/open"):
            return _Resp(200, {"session_id": "sess-1", "opened": True, "via": "agent"})
        if url.endswith("/read"):
            return _Resp(200, {"data": "hi", "closed": True})
        return _Resp(200, {})

    monkeypatch.setattr(controller, "_do_request", _do)
    return seen


# ---- the identity reaches the Controller ----------------------------------
def test_the_terminal_open_carries_the_acting_operator(monkeypatch):
    _enable_sso(monkeypatch)
    seen = _capture(monkeypatch)
    controller.TerminalProxy("web01", identity=ALICE)
    (_, url, h), = [c for c in seen if c[1].endswith("/terminal/open")]
    assert h["X-Sysible-Auth"] == SECRET, h
    assert h["X-Sysible-User"] == "alice", (
        "without this the Controller has no run-as and the shell lands as its "
        "default account")
    assert h["X-Sysible-Role"] == "sysadmin", h


def test_every_call_in_the_session_carries_it_not_just_the_open(monkeypatch):
    """The Controller resolves the identity per request, so a read/write/resize
    without it would drop back to the default account mid-session."""
    _enable_sso(monkeypatch)
    seen = _capture(monkeypatch)
    t = controller.TerminalProxy("web01", identity=ALICE)
    t.write(b"id\n")
    t.resize(120, 40)
    t.read()
    t.close()
    calls = [c for c in seen if "/terminal/" in c[1] or "/terminal/open" in c[1]]
    assert len(calls) >= 5, [c[1] for c in calls]
    for method, url, h in calls:
        assert h.get("X-Sysible-User") == "alice", (method, url, h)


def test_a_fleet_run_attributes_each_host_to_the_operator(monkeypatch):
    _enable_sso(monkeypatch)
    seen = _capture(monkeypatch)
    import backend.fleet as fleet
    import backend.hosts as hosts
    hosts.upsert_controller_host("web01", "10.0.0.21")   # source='controller'
    try:
        fleet.run("uptime", ["web01"], identity=ALICE)
    finally:
        hosts.delete_host("web01")
    ctl = [c for c in seen if "/terminal" in c[1]]
    assert ctl, "the fleet run never reached the Controller"
    for method, url, h in ctl:
        assert h.get("X-Sysible-User") == "alice", (url, h)


# ---- and only a proven gateway hop can name one --------------------------
def test_without_an_identity_no_identity_headers_are_sent(monkeypatch):
    """Standalone Connect / an api-key attach: absent, not guessed."""
    _enable_sso(monkeypatch)
    seen = _capture(monkeypatch)
    controller.TerminalProxy("web01")
    (_, _, h), = [c for c in seen if c[1].endswith("/terminal/open")]
    assert "X-Sysible-User" not in h and "X-Sysible-Role" not in h, h


def test_a_browser_cannot_assert_its_own_identity(monkeypatch):
    """acting_identity is built from the same trust check as gateway_identity: no
    shared secret on the inbound request → None, so the headers a browser sends
    are never relayed onward."""
    monkeypatch.setattr(capp, "_TRUST_GATEWAY", True)
    monkeypatch.setattr(capp, "_SSO_SECRET", SECRET)
    forged = {"x-sysible-user": "root", "x-sysible-role": "superuser"}
    assert capp.acting_identity(_H(forged)) is None
    assert capp.acting_identity(_H({**forged, "x-sysible-auth": "wrong"})) is None
    ok = capp.acting_identity(_H({**forged, "x-sysible-auth": SECRET}))
    assert ok == {"user": "root", "role": "superuser"}


def test_acting_identity_is_none_when_sso_is_off(monkeypatch):
    monkeypatch.setattr(capp, "_TRUST_GATEWAY", False)
    monkeypatch.setattr(capp, "_SSO_SECRET", SECRET)
    assert capp.acting_identity(_H({"x-sysible-auth": SECRET,
                                    "x-sysible-user": "root"})) is None


def _H(d):
    from starlette.datastructures import Headers
    return Headers(d)


# ---- the console must stop saying "no run-as" ----------------------------
def test_status_reports_the_sso_operator_as_the_run_as(monkeypatch):
    _enable_sso(monkeypatch)
    st = controller.status(identity=ALICE)
    assert st["sso"] is True and st["connected"] is True
    assert st["run_as"] == "alice", (
        'the console showed "API-key connect (no run-as)" for a signed-in SSO '
        "operator because status() only ever read the stored admin_user")


def test_status_has_no_run_as_without_an_acting_identity(monkeypatch):
    _enable_sso(monkeypatch)
    assert controller.status()["run_as"] == ""


# ---- a stalled terminal must not be a blank screen ------------------------
def _stall_capture(monkeypatch, why):
    """Controller stand-in whose read long-poll returns no data and a reason."""
    def _do(method, url, headers=None, json_body=None, verify=None, timeout=None):
        if url.endswith("/terminal/open"):
            return _Resp(200, {"session_id": "sess-1", "opened": True, "via": "agent"})
        if url.endswith("/read"):
            body = {"data": "", "closed": False}
            if why:
                body["waiting"] = why
            return _Resp(200, body)
        return _Resp(200, {})
    monkeypatch.setattr(controller, "_do_request", _do)


WHY = ("this host's agent collected the terminal request but has not sent any "
       "output. Check the agent log: journalctl -u sysible-agent -n 50")


def test_a_stalled_terminal_prints_the_reason_instead_of_staying_blank(monkeypatch):
    _enable_sso(monkeypatch)
    _stall_capture(monkeypatch, WHY)
    t = controller.TerminalProxy("web01", identity=ALICE)
    out = t.read().decode()
    assert "journalctl -u sysible-agent" in out
    assert "[sysible]" in out and "\x1b[90m" in out, "shown dimmed, as status not output"


def test_the_reason_is_shown_once_not_on_every_poll(monkeypatch):
    """The read loop polls continuously; repeating the notice would bury the shell
    under it the moment output finally arrives."""
    _enable_sso(monkeypatch)
    _stall_capture(monkeypatch, WHY)
    t = controller.TerminalProxy("web01", identity=ALICE)
    assert "[sysible]" in t.read().decode()
    t._closed = True                      # stop the second call's infinite poll
    assert t.read() == b""


def test_no_reason_means_no_noise(monkeypatch):
    """A healthy idle shell long-polls forever with nothing to say — it must not
    have anything written into it."""
    _enable_sso(monkeypatch)
    _stall_capture(monkeypatch, None)
    t = controller.TerminalProxy("web01", identity=ALICE)
    t._closed = True
    assert t.read() == b""
