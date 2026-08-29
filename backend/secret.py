"""At-rest encryption for Sysible Connect secrets (currently the Controller API key).

A per-install Fernet key lives in DATA_DIR/secret.key (0600). Secrets are encrypted
with it before they touch disk, so a stolen controller.json / backup / snapshot
doesn't leak the machine API key in plaintext. Lose the key file and stored secrets
are unrecoverable (just re-enter them) — by design.
"""
from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken

from .auth import DATA_DIR

_KEY_FILE = DATA_DIR / "secret.key"


def _read_nofollow(path) -> bytes:
    """Read a file refusing to follow a symlink at the final component (O_NOFOLLOW),
    so a pre-planted symlink at the path can't redirect the read to a substituted file."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return os.read(fd, 4096).strip()
    finally:
        os.close(fd)


def _fernet() -> Fernet:
    try:
        key = _read_nofollow(_KEY_FILE)
    except OSError:
        # No key yet (or a planted symlink was refused) — generate and create it
        # race-safe: O_EXCL|O_NOFOLLOW at 0600 (no O_TRUNC) means a local user can't
        # pre-plant a symlink to redirect the freshly-generated Fernet key to an
        # attacker-readable path, and there's no exists()->open() TOCTOU. Lose the
        # create race → read theirs back, still refusing to follow a symlink.
        key = Fernet.generate_key()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(_KEY_FILE),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, key)
            finally:
                os.close(fd)
        except FileExistsError:
            key = _read_nofollow(_KEY_FILE)
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return ""
