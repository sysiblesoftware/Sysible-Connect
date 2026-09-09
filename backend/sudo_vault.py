"""Per-operator sudo password vault for Sysible Connect.

WHY CONNECT HOLDS THIS AT ALL. Connect is a terminal: you type `sudo systemctl
restart nginx` and, on a host that does not allow passwordless sudo, sudo asks
for a password. Without somewhere to keep it, an operator either retypes it into
every session — in a pane whose scrollback and typing they do not fully control —
or gives up and logs in as root, which is exactly the thing per-operator run-as
exists to avoid.

THE SECRET NEVER REACHES THE BROWSER. It is written once (POST /api/sudo) and
after that the console can only ask *whether* one is stored. "Send sudo password"
sends a SIGNAL over the terminal websocket; the server reads the vault and writes
the password straight into the PTY. So the password is never in a websocket frame
the page can read, never in the DOM, and never in a response body — which is what
makes this different from the console simply remembering it in JavaScript.

SCOPED TO THE OPERATOR, AND IT EXPIRES. Entries are keyed by the signed-in
operator (the SLOP identity under SSO, the local account standalone), so one
operator's password is never used to elevate another's session — the audit trail
would name the wrong human. Every entry carries a TTL, so a password left behind
on a shared workstation stops working on its own rather than living until someone
remembers to clear it.

AT REST. Encrypted with Connect's per-install Fernet key (backend/secret.py), in
DATA_DIR/sudo.json at 0600, created and read O_EXCL/O_NOFOLLOW so a pre-planted
symlink cannot redirect the write or substitute the file. Lose the key file and
the entries are unrecoverable — by design; re-enter them.
"""
from __future__ import annotations

import json
import os
import time

from .auth import DATA_DIR
from .secret import decrypt, encrypt

_FILE = DATA_DIR / "sudo.json"

# How long a stored sudo password stays usable. Matches the session TTL default:
# the password should not outlive the working day it was entered for.
try:
    TTL_SECONDS = int(os.getenv("SYSIBLE_CONNECT_SUDO_TTL") or 12 * 3600)
except ValueError:
    TTL_SECONDS = 12 * 3600


def _read() -> dict:
    """The whole store. O_NOFOLLOW so a symlink planted at sudo.json cannot make
    this read a file someone else controls."""
    try:
        fd = os.open(str(_FILE), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return {}
    try:
        raw = os.read(fd, 1_000_000)
    finally:
        os.close(fd)
    try:
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(data: dict) -> None:
    """Replace the store at 0600. Written to a temp file in the same directory and
    renamed, so a crash mid-write cannot leave a truncated store that silently
    loses every operator's password."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = str(_FILE) + ".tmp"
    try:
        os.unlink(tmp)
    except OSError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, json.dumps(data).encode())
    finally:
        os.close(fd)
    os.replace(tmp, str(_FILE))


def _prune(data: dict) -> dict:
    """Drop expired entries. Done on every read so an expired password stops being
    usable at the moment it expires, not the next time someone happens to save."""
    now = time.time()
    return {u: e for u, e in data.items()
            if isinstance(e, dict) and float(e.get("expires") or 0) > now}


def set_password(user: str, password: str) -> dict:
    """Store this operator's sudo password. Returns the public status."""
    user = (user or "").strip()
    if not user:
        raise ValueError("No operator identity.")
    if not password:
        raise ValueError("A password is required.")
    data = _prune(_read())
    expires = time.time() + TTL_SECONDS
    data[user] = {"secret": encrypt(password), "expires": expires}
    _write(data)
    return {"set": True, "expires_at": expires}


def get_password(user: str) -> str:
    """The stored password for this operator, or "" — used ONLY server-side, to
    write into a PTY. Never returned over HTTP."""
    user = (user or "").strip()
    if not user:
        return ""
    entry = _prune(_read()).get(user)
    if not entry:
        return ""
    return decrypt(str(entry.get("secret") or ""))


def clear(user: str) -> dict:
    user = (user or "").strip()
    data = _prune(_read())
    existed = data.pop(user, None) is not None
    _write(data)
    return {"set": False, "expires_at": None, "cleared": existed}


def status(user: str) -> dict:
    """Whether a password is stored, and until when. Deliberately the ONLY thing
    the console can learn about it."""
    user = (user or "").strip()
    entry = _prune(_read()).get(user) if user else None
    return {"set": bool(entry),
            "expires_at": float(entry["expires"]) if entry else None,
            "ttl_seconds": TTL_SECONDS}
