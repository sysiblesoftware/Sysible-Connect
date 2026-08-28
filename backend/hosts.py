"""SSH host store for Sysible Connect.

A small JSON inventory of the hosts a terminal can SSH to, plus strict validation
of the fields that flow into an ssh/paramiko connection. Kept deliberately simple
and self-contained (DATA_DIR/hosts.json).
"""
from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path

from .auth import DATA_DIR

_HOSTS_FILE = DATA_DIR / "hosts.json"
_LOCK = threading.RLock()

# A host address must be a plain hostname / IPv4 / [IPv6]; a user a plain login name.
# These values reach an ssh command line, so anything else (spaces, an option-looking
# leading '-', shell metacharacters) is rejected.
_SAFE_HOST = re.compile(r"^(?:\[[0-9A-Fa-f:]+\]|[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)$")
_SAFE_USER = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9 ._-]*[A-Za-z0-9])?$")


def valid_name(v: str) -> bool:
    return bool(_SAFE_NAME.fullmatch(v or "")) and len(v) <= 64


def valid_host(v: str) -> bool:
    return bool(_SAFE_HOST.fullmatch(v or ""))


def valid_user(v: str) -> bool:
    return bool(_SAFE_USER.fullmatch(v or ""))


def _load() -> dict:
    try:
        d = json.loads(_HOSTS_FILE.read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save(hosts: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(_HOSTS_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(hosts, indent=2).encode())
    finally:
        os.close(fd)


def list_hosts() -> list[dict]:
    with _LOCK:
        hosts = _load()
    # Never expose stored secrets to the client; surface has_password/has_key flags.
    out = []
    for name, h in sorted(hosts.items()):
        out.append({
            "name": name, "address": h.get("address", ""), "user": h.get("user", "root"),
            "port": int(h.get("port", 22)),
            "has_password": bool(h.get("password")), "has_key": bool(h.get("key")),
            # Where the host came from and how a terminal reaches it: a "local" host
            # is dialed by direct SSH; a "controller" host proxies through the
            # connected Controller (transport = agent | ssh), so it works even with
            # no address / no inbound SSH.
            "source": h.get("source", "local"),
            "environment": h.get("environment", ""),
            "transport": h.get("transport", ""),
            # Controller's own view of an agent host at last sync: True=online,
            # False=offline (stale heartbeat), None=unknown/not applicable (SSH
            # hosts, local hosts). last_seen is the epoch of its last heartbeat.
            "online": h.get("online", None),
            "last_seen": h.get("last_seen", 0),
        })
    return out


def get_host(name: str) -> dict | None:
    with _LOCK:
        h = _load().get(name)
    return dict(h, name=name) if h else None


def add_host(name: str, address: str, user: str = "root", port: int = 22,
             password: str = "", key: str = "") -> None:
    if not valid_name(name):
        raise ValueError("Invalid host name.")
    if not valid_host(address):
        raise ValueError("Invalid address — hostname, IPv4 or [IPv6] only.")
    if not valid_user(user):
        raise ValueError("Invalid login user.")
    if not (1 <= int(port) <= 65535):
        raise ValueError("Port must be 1-65535.")
    with _LOCK:
        hosts = _load()
        hosts[name] = {"address": address, "user": user, "port": int(port),
                       "password": password or "", "key": key or "", "source": "local"}
        _save(hosts)


def upsert_controller_host(name: str, address: str = "", user: str = "root", port: int = 22,
                           environment: str = "", transport: str = "agent",
                           online: bool | None = None, last_seen: float = 0) -> None:
    """Add/update a host synced from the connected Controller. Its terminal proxies
    THROUGH the Controller (by name), so a blank/NAT'd address is fine — we just skip
    an invalid one rather than fail the whole sync. Overwrites a prior sync of the
    same name; carries no credentials (the Controller holds those). `online`/`last_seen`
    carry the Controller's liveness view so Connect can show offline hosts."""
    if not valid_name(name):
        raise ValueError("Invalid host name.")
    if address and not valid_host(address):
        address = ""           # unusable for display, but the proxy doesn't need it
    if not valid_user(user):
        user = "root"
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 22
    if not (1 <= port <= 65535):
        port = 22
    with _LOCK:
        hosts = _load()
        hosts[name] = {"address": address, "user": user, "port": port,
                       "password": "", "key": "", "source": "controller",
                       "environment": environment or "", "transport": transport or "agent",
                       "online": online, "last_seen": float(last_seen or 0)}
        _save(hosts)


def delete_host(name: str) -> bool:
    with _LOCK:
        hosts = _load()
        existed = name in hosts
        hosts.pop(name, None)
        _save(hosts)
    return existed
