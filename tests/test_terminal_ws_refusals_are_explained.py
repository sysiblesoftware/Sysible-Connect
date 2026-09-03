"""A refused terminal websocket must say WHY, in the terminal.

The reported symptom, three times: "Connect still not working" with a screenshot
of a terminal pane containing a blinking cursor and nothing else. Every refusal
in terminal_ws happens BEFORE accept(), and a pre-accept close sends no message
frame — so the browser had nothing to display. A refused websocket and a session
that opened and stayed silent looked identical, which is why the search kept
going to the wrong layer (the Controller API, then the agent).

The close frame's REASON does reach the browser even on a pre-accept close.
These tests assert each refusal carries one, that it names the cause, and that a
client really receives it — the reason is worthless if Starlette drops it.
"""
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import backend.app as capp

SECRET = "sso-shared-secret"
ORIGIN = "https://slop.lan"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(capp, "_TRUST_GATEWAY", True)
    monkeypatch.setattr(capp, "_SSO_SECRET", SECRET)
    return TestClient(capp.app)


def _hdrs(**over):
    h = {"origin": ORIGIN, "host": "slop.lan", "x-sysible-auth": SECRET,
         "x-sysible-user": "alice", "x-sysible-role": "operator"}
    h.update(over)
    return {k: v for k, v in h.items() if v is not None}


def _refusal(client, headers):
    """Open the terminal websocket and return the (code, reason) it closed with."""
    with pytest.raises(WebSocketDisconnect) as ei:
        with client.websocket_connect("/api/terminal/ws?kind=controller&host=web01",
                                      headers=headers) as ws:
            ws.receive_text()
    return ei.value.code, (ei.value.reason or "")


def test_a_foreign_origin_is_told_it_was_the_origin(client):
    code, why = _refusal(client, _hdrs(origin="https://evil.example"))
    assert code == 4403
    assert why, "a pre-accept close with no reason leaves a blank terminal"
    assert "origin" in why.lower(), why


def test_a_missing_identity_is_told_it_is_not_signed_in(client):
    code, why = _refusal(client, _hdrs(**{"x-sysible-user": None}))
    assert code == 4401
    assert "not signed in" in why.lower(), why
    assert "x-sysible-user" in why.lower(), \
        "name the header, so the gateway config can be checked"


def test_an_auditor_is_told_which_role_a_terminal_needs(client):
    code, why = _refusal(client, _hdrs(**{"x-sysible-role": "auditor"}))
    assert code == 4403
    assert "auditor" in why, "name the role they actually have"
    assert "operator" in why and "superuser" in why, "and the ones that would work"
    assert "Administration" in why, "and where to change it"
    assert len(why.encode("utf-8")) <= 123


def test_an_unknown_role_is_refused_and_explained(client):
    code, why = _refusal(client, _hdrs(**{"x-sysible-role": "wizard"}))
    assert code == 4403 and "wizard" in why


def test_an_empty_role_is_refused_and_says_none(client):
    code, why = _refusal(client, _hdrs(**{"x-sysible-role": ""}))
    assert code == 4403 and "(none)" in why


def test_a_wrong_shared_secret_cannot_pass_the_identity_gate(client):
    """The secret is the trust boundary: without it the asserted user is ignored,
    so this must land on the not-signed-in refusal, not open a shell."""
    code, why = _refusal(client, _hdrs(**{"x-sysible-auth": "wrong"}))
    assert code == 4401 and "not signed in" in why.lower()


def test_every_refusal_reason_fits_a_websocket_close_frame(client):
    """A close reason is capped at 123 BYTES by the protocol; anything longer is
    silently dropped or kills the frame, putting the blank pane straight back."""
    seen = []
    for hdrs in (_hdrs(origin="https://evil.example"),
                 _hdrs(**{"x-sysible-user": None}),
                 _hdrs(**{"x-sysible-role": "auditor"})):
        _, why = _refusal(client, hdrs)
        seen.append(why)
    for why in seen:
        assert len(why.encode("utf-8")) <= 123, \
            f"{len(why.encode('utf-8'))} bytes — too long for a close frame: {why!r}"
