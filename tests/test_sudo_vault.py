"""The sudo-password vault.

Connect is a terminal, so on a host that forbids passwordless sudo an operator
either retypes their password into every session or logs in as root — which is
the thing per-operator run-as exists to avoid. This stores it once.

The whole design rests on one property, and most of these tests are about it:
**the password never reaches the browser.** It is written once and after that the
console can only ask WHETHER one is stored. "Send sudo password" is a signal over
the terminal websocket; the server reads the vault and writes the password
straight into the PTY. If any of that leaks the value back to the page, the
feature is worse than making people type it.
"""
import time

import pytest

import backend.app as app_module
import backend.sudo_vault as vault


@pytest.fixture(autouse=True)
def _clean_vault():
    for user in ("admin", "alice", "bob"):
        vault.clear(user)
    yield
    for user in ("admin", "alice", "bob"):
        vault.clear(user)


# --- the property that matters ---------------------------------------------
def test_the_password_is_never_returned_by_any_route(auth_client):
    """Set it, then look for it in every response the console can obtain."""
    secret = "correct-horse-battery-staple"
    assert auth_client.post("/api/sudo", json={"password": secret}).status_code == 200

    bodies = [
        auth_client.get("/api/sudo").text,
        auth_client.get("/api/me").text,
        auth_client.get("/api/audit").text,
    ]
    for body in bodies:
        assert secret not in body, "the sudo password came back over HTTP"


def test_status_says_only_whether_one_is_stored(auth_client):
    before = auth_client.get("/api/sudo").json()
    assert before["set"] is False and before["expires_at"] is None
    auth_client.post("/api/sudo", json={"password": "s3cret"})
    after = auth_client.get("/api/sudo").json()
    assert after["set"] is True and after["expires_at"] > time.time()
    # Nothing resembling the value, under any key.
    assert "s3cret" not in str(after)


def test_the_audit_trail_records_the_act_not_the_value(auth_client):
    auth_client.post("/api/sudo", json={"password": "hunter2"})
    trail = auth_client.get("/api/audit").text
    assert "sudo_password_stored" in trail
    assert "hunter2" not in trail


def test_it_is_encrypted_at_rest(auth_client):
    """A stolen backup or snapshot of the data dir must not hand over the
    password in plaintext."""
    auth_client.post("/api/sudo", json={"password": "plaintext-canary"})
    raw = vault._FILE.read_bytes()
    assert b"plaintext-canary" not in raw
    # ...and it is still recoverable server-side, which is the point.
    assert vault.get_password("admin") == "plaintext-canary"


# --- scoping ---------------------------------------------------------------
def test_one_operators_password_never_elevates_anothers_session():
    """Entries are keyed by operator. Sharing them would put the wrong human's
    name against a privileged action in every downstream audit trail."""
    vault.set_password("alice", "alice-pw")
    assert vault.get_password("alice") == "alice-pw"
    assert vault.get_password("bob") == ""


def test_an_expired_password_stops_working_on_its_own(monkeypatch):
    """A password left behind on a shared workstation must lapse rather than live
    until someone remembers to clear it."""
    vault.set_password("alice", "alice-pw")
    assert vault.get_password("alice") == "alice-pw"
    # Capture the real clock BEFORE patching, or the lambda calls the patched
    # time.time() and recurses.
    later = time.time() + vault.TTL_SECONDS + 60
    monkeypatch.setattr(vault.time, "time", lambda: later)
    assert vault.get_password("alice") == ""
    assert vault.status("alice")["set"] is False


def test_clearing_removes_it():
    vault.set_password("alice", "alice-pw")
    vault.clear("alice")
    assert vault.get_password("alice") == ""


def test_an_empty_password_is_refused():
    """Storing "" would read as "a password is set" while sending nothing into the
    PTY — a sudo prompt that silently hangs."""
    with pytest.raises(ValueError):
        vault.set_password("alice", "")


def test_an_unidentified_caller_stores_nothing():
    with pytest.raises(ValueError):
        vault.set_password("", "pw")
    assert vault.get_password("") == ""


# --- authorization ---------------------------------------------------------
def test_the_routes_need_a_session(client):
    assert client.get("/api/sudo").status_code == 401
    assert client.post("/api/sudo", json={"password": "x"}).status_code == 401
    assert client.delete("/api/sudo").status_code == 401


def test_a_read_only_auditor_cannot_store_one(monkeypatch):
    """Storing a sudo password is preparation for elevating on a host, so it sits
    behind the same operator floor as the shell itself."""
    from fastapi.testclient import TestClient
    monkeypatch.setattr(app_module, "_TRUST_GATEWAY", True)
    monkeypatch.setattr(app_module, "_SSO_SECRET", "shh")
    c = TestClient(app_module.app)
    hdrs = {"X-Sysible-Auth": "shh", "X-Sysible-User": "alice", "X-Sysible-Role": "auditor"}
    assert c.post("/api/sudo", json={"password": "x"}, headers=hdrs).status_code == 403


# --- the store itself ------------------------------------------------------
def test_the_store_file_is_not_world_readable(auth_client):
    import os
    import stat
    auth_client.post("/api/sudo", json={"password": "pw"})
    mode = stat.S_IMODE(os.stat(vault._FILE).st_mode)
    assert mode == 0o600, oct(mode)


def test_a_corrupt_store_does_not_take_the_app_down():
    """Best-effort: a hand-edited or truncated file should cost the stored
    passwords, not every terminal on the box."""
    vault.set_password("alice", "pw")
    vault._FILE.write_text("{ not json")
    assert vault.get_password("alice") == ""
    assert vault.status("alice")["set"] is False
    # And it recovers on the next write.
    vault.set_password("alice", "pw2")
    assert vault.get_password("alice") == "pw2"


# --- the send path ---------------------------------------------------------
# This is where the password actually moves. The browser sends {"t":"sudo"} and
# nothing else; everything secret happens on this side of the socket.
def test_the_send_signal_carries_no_secret_and_writes_into_the_pty(monkeypatch):
    """The frame the page sends must be a bare signal. If the password ever had to
    travel FROM the browser, storing it server-side would buy nothing."""
    import json
    from fastapi.testclient import TestClient

    vault.set_password("admin", "pty-secret")
    written = []

    import threading

    class _Sess:
        def __init__(self): self._stop = threading.Event()
        def write(self, b): written.append(b)
        def read(self):
            self._stop.wait(5)
            return b""
        def resize(self, c, r): pass
        def close(self): self._stop.set()

    monkeypatch.setattr(app_module.terminals, "open_session",
                        lambda kind, **kw: _Sess())
    c = TestClient(app_module.app)
    c.post("/api/login", json={"username": "admin", "password": "test1234"})
    with c.websocket_connect("/api/terminal/ws?kind=local",
                             headers={"Origin": "http://testserver"}) as ws:
        sent = {"t": "sudo"}                      # the ENTIRE client message
        assert "password" not in json.dumps(sent)
        ws.send_json(sent)
        # Give the server loop a moment to act on it.
        for _ in range(20):
            if written:
                break
            import time as _t
            _t.sleep(0.05)
    assert written, "the sudo signal wrote nothing into the session"
    assert written[0] == b"pty-secret\n", written


def test_sending_with_nothing_stored_explains_itself(monkeypatch):
    """Silence here would look exactly like a hung sudo prompt."""
    from fastapi.testclient import TestClient

    import threading

    class _Sess:
        # read() BLOCKS, like a real PTY. Returning immediately makes the reader
        # thread emit {"t":"exit"} first and the error we are testing for arrives
        # second — a race in the test, not in the product.
        def __init__(self): self._stop = threading.Event()
        def write(self, b): pass
        def read(self):
            self._stop.wait(5)
            return b""
        def resize(self, c, r): pass
        def close(self): self._stop.set()

    monkeypatch.setattr(app_module.terminals, "open_session", lambda kind, **kw: _Sess())
    c = TestClient(app_module.app)
    c.post("/api/login", json={"username": "admin", "password": "test1234"})
    with c.websocket_connect("/api/terminal/ws?kind=local",
                             headers={"Origin": "http://testserver"}) as ws:
        ws.send_json({"t": "sudo"})
        msg = ws.receive_json()
        assert msg["t"] == "error"
        assert "No sudo password stored" in msg["d"]


# --- the download filename ---------------------------------------------------
# It is the tail of an operator-supplied REMOTE path and it goes into a response
# header. Stripping only the quote left CR/LF in it, and h11 refuses to serialize
# a header value containing those — so a remote file whose name held a newline
# turned the download into an unexplained 500, and on a stack that did not refuse
# it would be header injection.
def test_a_hostile_remote_filename_cannot_reshape_the_response_headers(auth_client,
                                                                       monkeypatch):
    import backend.app as A
    monkeypatch.setattr(A.files, "download", lambda name, path: b"payload")
    monkeypatch.setattr(A.hosts, "get", lambda name: {"name": name}, raising=False)
    r = auth_client.get("/api/hosts/h1/files/download",
                        params={"path": "/tmp/a\r\nX-Injected: 1"})
    assert r.status_code == 200, r.text
    cd = r.headers["content-disposition"]
    # The text may survive as inert characters inside the quoted filename; what
    # must not survive is anything that could END the header.
    assert "\r" not in cd and "\n" not in cd
    assert cd.count('"') == 2 and cd.startswith('attachment; filename="')
    assert "x-injected" not in {k.lower() for k in r.headers}


def test_an_ordinary_filename_survives(auth_client, monkeypatch):
    import backend.app as A
    monkeypatch.setattr(A.files, "download", lambda name, path: b"payload")
    r = auth_client.get("/api/hosts/h1/files/download", params={"path": "/etc/nginx.conf"})
    assert r.headers["content-disposition"] == 'attachment; filename="nginx.conf"'
