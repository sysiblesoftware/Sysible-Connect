"""Terminal sessions for Sysible Connect.

Two kinds, one interface (read/write/resize/alive/close):
  * LocalSession — a shell on the Connect server itself, via a real PTY.
  * SshSession   — an interactive shell on a managed host, via paramiko.

Each session's read() BLOCKS until data (or EOF → b""), so the app runs one
reader thread per session and pumps bytes to the websocket. Writes and resizes
come back the other way. Secrets (host password/key) never leave the backend.
"""
from __future__ import annotations

import fcntl
import io
import os
import pty
import shutil
import struct
import subprocess
import termios

from .auth import DATA_DIR

# Persistent SSH known-hosts for the DIRECT-SSH path: trust a host's key on first
# contact and pin it, so a later key change (host rebuilt, or a man-in-the-middle)
# is rejected instead of silently trusted.
_KNOWN_HOSTS = DATA_DIR / "known_hosts"


def _load_known_hosts(client) -> None:
    try:
        if _KNOWN_HOSTS.exists():
            client.load_host_keys(str(_KNOWN_HOSTS))
    except Exception:  # noqa: BLE001 — a corrupt file must not block connecting
        pass


def _tofu_policy():
    """A paramiko MissingHostKeyPolicy that records an unknown host's key and saves
    it. A host already pinned with a DIFFERENT key raises BadHostKeyException in
    paramiko's own verification (before this runs), which is the pin."""
    import paramiko

    class _Tofu(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            hk = client.get_host_keys()
            hk.add(hostname, key.get_name(), key)
            try:
                DATA_DIR.mkdir(parents=True, exist_ok=True)
                hk.save(str(_KNOWN_HOSTS))
            except Exception:  # noqa: BLE001
                pass

    return _Tofu()


class LocalSession:
    """A login shell on the Connect host, wired to a PTY."""

    kind = "local"

    def __init__(self, cols: int = 80, rows: int = 24, cwd: str | None = None):
        shell = os.environ.get("SHELL") or shutil.which("bash") or "/bin/sh"
        self.master, slave = pty.openpty()
        self._set_size(cols, rows)
        env = dict(os.environ, TERM="xterm-256color")
        self.proc = subprocess.Popen(
            [shell, "-l"], stdin=slave, stdout=slave, stderr=slave,
            preexec_fn=os.setsid, env=env, cwd=cwd or os.path.expanduser("~"), close_fds=True)
        os.close(slave)

    def _set_size(self, cols: int, rows: int):
        try:
            fcntl.ioctl(self.master, termios.TIOCSWINSZ,
                        struct.pack("HHHH", max(1, rows), max(1, cols), 0, 0))
        except OSError:
            pass

    def read(self, n: int = 65536) -> bytes:
        try:
            return os.read(self.master, n)
        except OSError:
            return b""

    def read_available(self, timeout: float = 0.7) -> bytes:
        """Non-blocking-ish read for fleet capture: up to `timeout` seconds, b'' if idle."""
        import select
        r, _, _ = select.select([self.master], [], [], timeout)
        if not r:
            return b""
        try:
            return os.read(self.master, 65536)
        except OSError:
            return b""

    def write(self, data: bytes):
        try:
            os.write(self.master, data)
        except OSError:
            pass

    def resize(self, cols: int, rows: int):
        self._set_size(cols, rows)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def close(self):
        try:
            self.proc.terminate()
        except Exception:  # noqa: BLE001
            pass
        try:
            os.close(self.master)
        except OSError:
            pass


def _load_private_key(text: str):
    import paramiko
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except Exception:  # noqa: BLE001 — wrong type, try the next
            continue
    raise ValueError("Unsupported or encrypted private key.")


class SshSession:
    """An interactive shell on a managed host over SSH (paramiko)."""

    kind = "ssh"

    def __init__(self, host: dict, cols: int = 80, rows: int = 24):
        import paramiko
        addr = str(host.get("address", "")).strip("[]")
        user = str(host.get("user") or "root")
        port = int(host.get("port", 22))
        self.client = paramiko.SSHClient()
        # Pin host keys (trust-on-first-use): load what we've seen before, and record
        # a new host's key on first contact. A CHANGED key raises BadHostKeyException.
        _load_known_hosts(self.client)
        self.client.set_missing_host_key_policy(_tofu_policy())
        base = dict(hostname=addr, port=port, username=user, timeout=20, banner_timeout=20)
        try:
            if host.get("key"):
                self.client.connect(pkey=_load_private_key(host["key"]),
                                    allow_agent=False, look_for_keys=False, **base)
            elif host.get("password"):
                self.client.connect(password=host["password"],
                                    allow_agent=False, look_for_keys=False, **base)
            else:
                # No stored credential — fall back to the agent / default keys.
                self.client.connect(allow_agent=True, look_for_keys=True, **base)
        except paramiko.BadHostKeyException as e:
            raise ValueError(
                f"Host key for {addr} changed since first contact — refusing to connect "
                f"(possible man-in-the-middle, or the host was rebuilt). If you trust the "
                f"change, remove its line from {_KNOWN_HOSTS} and reconnect. ({e})")
        self.chan = self.client.invoke_shell(term="xterm-256color", width=cols, height=rows)
        self.chan.settimeout(None)   # blocking recv → one reader thread per session

    def read(self, n: int = 65536) -> bytes:
        try:
            return self.chan.recv(n)          # b"" on EOF
        except Exception:  # noqa: BLE001
            return b""

    def read_available(self, timeout: float = 0.7) -> bytes:
        self.chan.settimeout(timeout)
        try:
            return self.chan.recv(65536)
        except Exception:  # noqa: BLE001 — timeout / no data
            return b""
        finally:
            try:
                self.chan.settimeout(None)
            except Exception:  # noqa: BLE001
                pass

    def write(self, data: bytes):
        try:
            self.chan.sendall(data)
        except Exception:  # noqa: BLE001
            pass

    def resize(self, cols: int, rows: int):
        try:
            self.chan.resize_pty(width=max(1, cols), height=max(1, rows))
        except Exception:  # noqa: BLE001
            pass

    def alive(self) -> bool:
        return not self.chan.closed

    def close(self):
        try:
            self.chan.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.client.close()
        except Exception:  # noqa: BLE001
            pass


def open_session(kind: str, *, host: dict | None = None, cols: int = 80, rows: int = 24):
    """Factory: 'local' → a server shell; 'ssh' → direct SSH to `host`;
    'controller' → a shell on a Controller-managed host, proxied THROUGH the
    connected Controller (agent PTY or its SSH key), so no local credential and no
    inbound SSH to the host are needed."""
    if kind == "controller":
        if not host or not host.get("name"):
            raise ValueError("A Controller terminal needs a host.")
        from . import controller   # lazy: local shells don't need requests
        return controller.TerminalProxy(str(host["name"]), cols, rows)
    if kind == "ssh":
        if not host:
            raise ValueError("An SSH terminal needs a host.")
        return SshSession(host, cols, rows)
    return LocalSession(cols, rows)
