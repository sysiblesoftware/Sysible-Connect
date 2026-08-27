"""Per-host file transfer for Sysible Connect.

DIRECT-SSH hosts (added locally with a credential) transfer over SFTP, with the
same host-key pinning as terminals. CONTROLLER-synced hosts can't (yet): the
Controller's file endpoints are superuser-gated and Connect authenticates with a
machine key only — see F1 in docs/SECURITY_REVIEW.md. Use a terminal for those, or
grant Connect a Controller-scoped token.
"""
from __future__ import annotations

import io
import stat

from . import hosts as host_store
from . import terminals   # reuse private-key loading + known-hosts pinning


class FileError(Exception):
    pass


def _connect(name: str):
    h = host_store.get_host(name)
    if not h:
        raise FileError("host not found")
    if h.get("source") == "controller":
        raise FileError("File transfer for Controller-managed hosts needs a Controller-scoped "
                        "token (F1). Open a terminal on this host instead.")
    addr = str(h.get("address", "")).strip("[]")
    if not addr:
        raise FileError("This host has no address to connect to.")
    import paramiko
    user, port = str(h.get("user") or "root"), int(h.get("port", 22))
    client = paramiko.SSHClient()
    terminals._load_known_hosts(client)
    client.set_missing_host_key_policy(terminals._tofu_policy())
    base = dict(hostname=addr, port=port, username=user, timeout=20)
    try:
        if h.get("key"):
            client.connect(pkey=terminals._load_private_key(h["key"]), allow_agent=False, look_for_keys=False, **base)
        elif h.get("password"):
            client.connect(password=h["password"], allow_agent=False, look_for_keys=False, **base)
        else:
            client.connect(allow_agent=True, look_for_keys=True, **base)
    except paramiko.BadHostKeyException as e:
        raise FileError(f"Host key changed for {addr} — refusing (possible MITM). {e}")
    except Exception as e:  # noqa: BLE001
        raise FileError(f"Could not connect: {e}")
    return client, client.open_sftp()


def list_dir(name: str, path: str = ".") -> dict:
    client, sftp = _connect(name)
    try:
        path = path or "."
        entries = []
        for a in sftp.listdir_attr(path):
            entries.append({"name": a.filename, "dir": stat.S_ISDIR(a.st_mode or 0),
                            "size": int(a.st_size or 0)})
        entries.sort(key=lambda e: (not e["dir"], e["name"].lower()))
        return {"path": sftp.normalize(path), "entries": entries}
    finally:
        client.close()


def download(name: str, path: str) -> bytes:
    if not path:
        raise FileError("A file path is required.")
    client, sftp = _connect(name)
    try:
        buf = io.BytesIO()
        sftp.getfo(path, buf)
        return buf.getvalue()
    finally:
        client.close()


def upload(name: str, path: str, data: bytes) -> int:
    if not path:
        raise FileError("A destination path is required.")
    client, sftp = _connect(name)
    try:
        sftp.putfo(io.BytesIO(data), path)
        return int(sftp.stat(path).st_size or 0)
    finally:
        client.close()
