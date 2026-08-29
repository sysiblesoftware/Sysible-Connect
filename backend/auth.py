"""Standalone local auth for Sysible Connect.

Self-contained — no dependency on the Controller. A single admin account, seeded on
first run from SYSIBLE_CONNECT_USER (default 'admin') and SYSIBLE_CONNECT_PASSWORD;
when no password is supplied a RANDOM one is generated, printed once to the logs, and
the account is flagged must-change — so there is never a standing admin/admin default.
The record is stored hashed at DATA_DIR/auth.json (0600, created O_EXCL|O_NOFOLLOW and
read/rewritten O_NOFOLLOW so a pre-planted symlink can't hijack the credential store).
Passwords are PBKDF2-HMAC-SHA256 (600k iterations); sessions are opaque random tokens
kept in memory and carried by an httponly cookie.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

DATA_DIR = Path(os.getenv("SYSIBLE_CONNECT_DATA") or (Path.home() / ".sysible-connect"))
_AUTH_FILE = DATA_DIR / "auth.json"
_ITERATIONS = 600_000
_SESSION_TTL = int(os.getenv("SYSIBLE_CONNECT_SESSION_TTL") or 12 * 3600)

# token -> {"user": str, "expires": epoch}
_SESSIONS: dict[str, dict] = {}


def _hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS).hex()


def _load() -> dict:
    # Read refusing to follow a symlink at the final component (O_NOFOLLOW), so a
    # pre-planted symlink at auth.json can't redirect the read to a substituted record.
    try:
        fd = os.open(str(_AUTH_FILE), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return {}
    try:
        raw = os.read(fd, 1_000_000)
    finally:
        os.close(fd)
    try:
        return json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return {}


def _save(rec: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    data = json.dumps(rec).encode()
    try:
        # First write: create race-safe (O_EXCL|O_NOFOLLOW at 0600) so a local user
        # can't pre-plant a symlink to redirect the credential store to an attacker
        # path, and there's no exists()->open() TOCTOU.
        fd = os.open(str(_AUTH_FILE),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        # Legitimate rewrite (password change / must_change flip): overwrite the
        # existing record in place, still refusing to follow a symlink (O_NOFOLLOW).
        fd = os.open(str(_AUTH_FILE), os.O_WRONLY | os.O_NOFOLLOW | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def ensure_admin() -> None:
    """Seed the admin account on first run (idempotent). If no password is provided
    via the env, generate a RANDOM one (printed once to the logs) and flag the
    account must-change — so there is never a standing admin/admin default login."""
    rec = _load()
    if rec.get("user"):
        return
    user = os.getenv("SYSIBLE_CONNECT_USER") or "admin"
    env_pw = os.getenv("SYSIBLE_CONNECT_PASSWORD")
    if env_pw:
        pw, must = env_pw, False
    else:
        pw, must = secrets.token_urlsafe(12), True
        print(f"[sysible-connect] first-run admin '{user}' password "
              f"(you'll be asked to change it on first login): {pw}", flush=True)
    salt = secrets.token_bytes(16)
    _save({"user": user, "salt": salt.hex(), "hash": _hash(pw, salt), "must_change": must})


def verify(user: str, password: str) -> bool:
    rec = _load()
    if not rec.get("user"):
        return False
    # Constant-time on both fields (compute the hash even on a user mismatch).
    salt = bytes.fromhex(rec["salt"])
    got = _hash(password or "", salt)
    ok_user = hmac.compare_digest(user or "", rec["user"])
    ok_pw = hmac.compare_digest(got, rec["hash"])
    return ok_user and ok_pw


def must_change() -> bool:
    return bool(_load().get("must_change"))


def set_password(new_password: str) -> None:
    rec = _load()
    salt = secrets.token_bytes(16)
    rec["salt"] = salt.hex()
    rec["hash"] = _hash(new_password, salt)
    rec["must_change"] = False
    _save(rec)


def current_user() -> str:
    return _load().get("user") or "admin"


def new_session(user: str) -> str:
    token = secrets.token_urlsafe(32)
    _SESSIONS[token] = {"user": user, "expires": time.time() + _SESSION_TTL}
    return token


def session_user(token: str | None) -> str | None:
    if not token:
        return None
    s = _SESSIONS.get(token)
    if not s:
        return None
    if s["expires"] < time.time():
        _SESSIONS.pop(token, None)
        return None
    return s["user"]


def revoke(token: str | None) -> None:
    if token:
        _SESSIONS.pop(token, None)
