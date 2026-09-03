"""Fleet actions for Sysible Connect: run one command across many hosts at once.

Uses the SAME transport as terminals (local shell / direct SSH / Controller proxy),
so it works uniformly on every host type — including NAT'd agent hosts reached via
the Controller — with no separate exec API. Output is captured from the session for
a bounded window; for reboot/power-off the session simply drops, which counts as
fired.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from . import hosts as host_store
from . import terminals

_CAPTURE_S = 8.0        # per-host output window
_MAX_OUT = 8000         # trim captured output per host


def _run_one(name: str, command: str, identity: dict | None = None) -> dict:
    h = host_store.get_host(name)
    if not h:
        return {"name": name, "ok": False, "output": "host not found"}
    kind = "controller" if h.get("source") == "controller" else "ssh"
    try:
        sess = terminals.open_session(kind, host=h, identity=identity)
    except Exception as e:  # noqa: BLE001 — surface the connect error per host
        return {"name": name, "ok": False, "output": str(e)}
    out = bytearray()
    try:
        sess.write((command.rstrip("\n") + "\n").encode())
        deadline = time.time() + _CAPTURE_S
        while time.time() < deadline:
            chunk = sess.read_available(0.7)
            if chunk:
                out += chunk
            elif out:
                break               # idle after some output → the command finished
    finally:
        try:
            sess.close()
        except Exception:  # noqa: BLE001
            pass
    return {"name": name, "ok": True, "output": out.decode("utf-8", "replace")[-_MAX_OUT:]}


def run(command: str, names, identity: dict | None = None) -> list:
    """Run `command` on each named host. `identity` is the acting operator, forwarded
    to the Controller for the proxied hosts so each command runs as their account and
    the Controller's audit trail names them rather than the default account."""
    if not (command or "").strip():
        raise ValueError("A command is required.")
    names = [n for n in (names or []) if n]
    if not names:
        return []
    with ThreadPoolExecutor(max_workers=12) as ex:
        return list(ex.map(lambda n: _run_one(n, command, identity), names))
