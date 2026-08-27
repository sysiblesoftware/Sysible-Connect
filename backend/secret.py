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


def _fernet() -> Fernet:
    try:
        key = _KEY_FILE.read_bytes()
    except OSError:
        key = Fernet.generate_key()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(_KEY_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
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
